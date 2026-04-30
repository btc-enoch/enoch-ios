// WalletStore — app-lifetime @Observable that owns all wallet state
// and orchestrates EdgeClient + WalletKeystore.
//
// One store per app process; views observe it via SwiftUI's
// @Environment (wired in the EnochUI module). State mutations happen
// on the main actor so SwiftUI re-renders without thread surprises.
//
// Lifecycle:
//   - init(): inject keystore + edge client.
//   - bootstrap(): app launch — load identity, refresh state,
//                  start the SSE event loop.
//   - createWallet(): onboarding — generate a fresh key.
//   - refresh(): pull-to-refresh — re-pull balance/history/fees.
//   - deleteWallet(): settings reset — wipe key, stop event loop.
//
// The SSE loop drives automatic refresh on tx_applied for our
// address; the wallet UI doesn't need to poll.

import Foundation
import Observation

@MainActor
@Observable
public final class WalletStore {
    // MARK: - Identity

    public private(set) var address: String?
    public private(set) var pubkey: Secp256k1.PublicKey?

    public var hasWallet: Bool { address != nil }

    // MARK: - Live state

    public private(set) var balance: UInt64 = 0
    public private(set) var utxoCount: Int = 0
    public private(set) var history: [AddressHistoryEntry] = []
    public private(set) var feeRates: FeeRates?

    // MARK: - Connection state

    public enum ConnectionState: Equatable {
        case idle
        case connecting
        case connected
        case disconnected(String)
    }

    public private(set) var connectionState: ConnectionState = .idle
    public private(set) var lastError: String?

    // MARK: - Dependencies

    // @ObservationIgnored takes these out of @Observable's tracking
    // (they're dependencies, not state). nonisolated(unsafe) on the
    // immutable `let`s opts them out of the @MainActor isolation
    // envelope so a nonisolated init can write them once. Safe by
    // construction: no actor holds `self` until init returns, and
    // the values are never mutated thereafter.
    @ObservationIgnored private nonisolated(unsafe) let keystore: WalletKeystore
    @ObservationIgnored private nonisolated(unsafe) let client: EdgeClient

    @ObservationIgnored private var eventTask: Task<Void, Never>?

    /// `nonisolated` init so the SwiftUI environment-key default
    /// value (constructed from a nonisolated context) can build a
    /// stub WalletStore. Storage for the dependency `let`s is
    /// opted out of @MainActor via `nonisolated(unsafe)` so the
    /// assignments here are accepted by Swift 6.
    public nonisolated init(keystore: WalletKeystore, client: EdgeClient) {
        self.keystore = keystore
        self.client = client
    }

    // Intentionally no `deinit` cleanup — Swift 6 strict concurrency
    // forbids touching @MainActor state from a nonisolated deinit.
    // The event-loop Task captures `[weak self]`, so it exits at its
    // next await once self is released. WalletStore is app-lifetime
    // (one per process), so deinit really only fires at process
    // teardown where the OS reaps URLSession + Tasks anyway.

    // MARK: - Lifecycle

    /// Run once at app launch. If a key already exists in the
    /// keystore, populate identity, refresh state, and start the
    /// SSE event loop. If not, leaves the store in its empty
    /// onboarding-ready state.
    public func bootstrap() async {
        do {
            if let pub = try keystore.publicKey() {
                self.pubkey = pub
                self.address = try Address.encodeEnoch(publicKey: pub)
            }
        } catch {
            lastError = "load keystore: \(error.localizedDescription)"
        }
        if hasWallet {
            await refresh()
            startEventLoop()
        }
    }

    /// Onboarding — generate a fresh keypair, derive the address,
    /// and prime live state. Throws if a key already exists (the
    /// keystore guard) so we can't accidentally overwrite funds.
    public func createWallet() async throws {
        let pub = try keystore.createKey()
        self.pubkey = pub
        self.address = try Address.encodeEnoch(publicKey: pub)
        await refresh()
        startEventLoop()
    }

    /// Wipes the key and resets live state. Stops the SSE loop.
    /// Used by the settings "reset wallet" flow; idempotent on a
    /// keystore that already lacks a key.
    public func deleteWallet() throws {
        eventTask?.cancel()
        eventTask = nil
        try keystore.delete()
        pubkey = nil
        address = nil
        balance = 0
        utxoCount = 0
        history = []
        feeRates = nil
        connectionState = .idle
    }

    // MARK: - Refresh

    /// Re-pull balance, address history, and fee rates concurrently.
    /// Each network call is independent — partial failure (e.g. fee
    /// oracle 502) doesn't take the rest down. Errors land on
    /// `lastError` so the UI can surface a banner without panicking
    /// the user.
    public func refresh() async {
        guard let address else { return }

        async let balResult = result { try await self.client.getBalance(address: address) }
        async let histResult = result { try await self.client.getAddressHistory(address: address) }
        async let feeResult = result { try await self.client.getFeeOracle() }

        let bal = await balResult
        let hist = await histResult
        let fee = await feeResult

        if case .success(let b) = bal {
            self.balance = b.balanceSatoshi
            self.utxoCount = b.utxoCount
        }
        if case .success(let h) = hist {
            // Newest-first for UI display; the operator emits
            // ascending so we reverse on the wallet side.
            self.history = h.entries.sorted { $0.height > $1.height }
        }
        if case .success(let f) = fee {
            self.feeRates = f.ratesSatPerVB
        }

        // Surface the last failed call (if any) for the UI banner.
        // We can't put the heterogeneously-typed Results into a
        // single array (Swift loses the Result wrapper), so check
        // them inline.
        if case .failure(let e) = bal  { lastError = e.localizedDescription }
        if case .failure(let e) = hist { lastError = e.localizedDescription }
        if case .failure(let e) = fee  { lastError = e.localizedDescription }
    }

    // MARK: - SSE event loop

    /// Subscribe to /v1/events filtered to our address. Events drive
    /// automatic refresh on tx_applied; connection state events
    /// surface in the UI as a "syncing…" pill.
    private func startEventLoop() {
        guard let address else { return }
        eventTask?.cancel()
        connectionState = .connecting

        eventTask = Task { [weak self] in
            guard let self else { return }
            do {
                for try await event in self.client.eventStream(filter: [address]) {
                    if Task.isCancelled { break }
                    await self.handle(event: event)
                }
                self.connectionState = .disconnected("stream ended")
            } catch is CancellationError {
                // Normal shutdown via deleteWallet / deinit — leave state.
            } catch {
                self.connectionState = .disconnected(error.localizedDescription)
            }
        }
    }

    private func handle(event: EdgeEvent) async {
        switch event.kind {
        case .connected:
            connectionState = .connected
        case .txApplied:
            // Any tx that touched our address — refetch balance + history.
            await refresh()
        case .stateRootSigned:
            // Future: feed light-client verification. No-op for now.
            break
        case .unknown:
            break
        }
    }

    // MARK: - Helpers

    private func result<T>(_ body: @Sendable () async throws -> T) async -> Result<T, Swift.Error> {
        do {
            return .success(try await body())
        } catch {
            return .failure(error)
        }
    }
}
