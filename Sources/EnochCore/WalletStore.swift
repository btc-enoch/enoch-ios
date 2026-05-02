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

    /// All wallets currently stored in the keystore, ordered by
    /// createdAt. UI renders this as a switcher.
    public private(set) var wallets: [WalletDescriptor] = []

    /// id of the currently-active wallet (the one all balance /
    /// history / send / withdraw operations apply to). nil iff
    /// `wallets` is empty (= onboarding state).
    public private(set) var activeWalletID: String?

    public var hasWallet: Bool { address != nil }

    // MARK: - Live state

    public private(set) var balance: UInt64 = 0
    public private(set) var utxoCount: Int = 0
    public private(set) var history: [AddressHistoryEntry] = []
    public private(set) var feeRates: FeeRates?
    public private(set) var operatorInfo: OperatorInfo?

    /// Per-burn lifecycle status, keyed by burn_tx_hash (matches the
    /// tx_hash on history rows where role = .burn). Populated from
    /// /v1/pending_withdrawals on refresh + updated from
    /// withdrawal_status SSE events. Wallet UI looks up entries here
    /// to render "Pending bridge confirmation" → "Sent to Bitcoin:
    /// <txid>" badges on burn rows.
    public private(set) var withdrawalStatuses: [String: WithdrawalUIStatus] = [:]

    /// Convenience: the operator's flat per-tx L2 fee, or nil if
    /// `/v1/info` hasn't been fetched yet. SendView reads this to
    /// preview the fee before the user confirms.
    public var feePerTxSatoshi: UInt64? {
        operatorInfo?.feeSchedule?.perTxFeeSatoshi
    }

    /// Wallet-facing lifecycle states. Mapped from the operator's
    /// finer state machine; the wallet only needs three buckets to
    /// render UX. Future server states (e.g. "confirmed" once an
    /// L1 watcher lands) decode as `.unknownState` so older builds
    /// keep rendering meaningfully.
    public enum WithdrawalUIStatus: Equatable {
        case pending                     // queued / awaiting challenge window
        case broadcast(btcTxID: String)  // L1 tx out, not yet confirmed
        case unknownState(String)        // forward-compat for future server states
    }

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

    /// Run once at app launch. Loads the wallet list from the
    /// keystore and activates whichever wallet was active in the
    /// previous session (or the most recent, if the saved id is
    /// stale). On a fresh install the list is empty and the store
    /// stays in its onboarding-ready state.
    public func bootstrap() async {
        do {
            try refreshWalletList()
        } catch {
            lastError = "load keystore: \(error.localizedDescription)"
        }
        if hasWallet {
            await refresh()
            startEventLoop()
        }
    }

    /// Create a new wallet (fresh keypair) and switch to it.
    public func createWallet(name: String = "Wallet") async throws {
        _ = try keystore.createWallet(name: name)
        try refreshWalletList()
        await refresh()
        startEventLoop()
    }

    /// Import a wallet from a 32-byte hex private key. The new
    /// wallet is added alongside existing ones (no overwrite) and
    /// becomes active. Throws on invalid hex / wrong length /
    /// out-of-range scalar.
    public func importWallet(name: String, privateKeyHex: String) async throws {
        let trimmed = privateKeyHex.trimmingCharacters(in: .whitespacesAndNewlines)
        let raw = try Data(hex: trimmed)
        guard raw.count == 32 else {
            throw WalletKeystoreError.unhandledStatus(0)
        }
        let priv = try Secp256k1.PrivateKey(rawBytes: raw)
        _ = try keystore.importWallet(name: name, priv: priv)
        try refreshWalletList()
        await refresh()
        startEventLoop()
    }

    /// Switch the active wallet. Re-derives the address, restarts
    /// the SSE loop, and refreshes balance/history for the new
    /// wallet. No biometric prompt — only the public key is read.
    public func selectWallet(id: String) async throws {
        guard id != activeWalletID else { return }
        try keystore.selectWallet(id: id)
        eventTask?.cancel()
        eventTask = nil
        try refreshWalletList()
        // Reset live state so the previous wallet's balance/history
        // doesn't briefly flash through during the switch.
        balance = 0
        utxoCount = 0
        history = []
        withdrawalStatuses = [:]
        connectionState = .idle
        await refresh()
        startEventLoop()
    }

    /// Delete a wallet. If it's the active one, the most recent
    /// remaining wallet (if any) becomes active and lifecycle state
    /// rotates accordingly. Idempotent on an unknown id.
    public func deleteWallet(id: String) async throws {
        let wasActive = (id == activeWalletID)
        try keystore.deleteWallet(id: id)
        try refreshWalletList()
        if wasActive {
            eventTask?.cancel()
            eventTask = nil
            balance = 0
            utxoCount = 0
            history = []
            withdrawalStatuses = [:]
            connectionState = .idle
            if hasWallet {
                await refresh()
                startEventLoop()
            }
        }
    }

    /// Re-read the wallet list from the keystore and re-derive
    /// pubkey + address for the active wallet. Cheap (no biometric
    /// prompt) — both pubkey and metadata live in unprotected
    /// keychain attributes.
    private func refreshWalletList() throws {
        wallets = try keystore.listWallets()
        activeWalletID = keystore.activeWalletID()
        if let id = activeWalletID, let pub = try keystore.publicKey(walletID: id) {
            pubkey = pub
            address = try Self.taprootAddress(for: pub)
        } else {
            pubkey = nil
            address = nil
        }
    }

    /// Build, sign, and submit an L2 transfer to `recipient` for
    /// `amount` sats. Triggers a biometric prompt at the moment of
    /// signing (one prompt per input under the hood; for typical
    /// 1-2 input txs that's 1-2 Face ID confirmations). Refreshes
    /// state immediately on success so the UI doesn't have to wait
    /// for the SSE round-trip.
    public func send(to recipient: String, amount: UInt64, biometricPrompt: String) async throws {
        let builder = TxBuilder(edge: client, keystore: keystore)
        let tx = try await builder.buildSendTx(
            recipient: recipient,
            amountSatoshi: amount,
            biometricPrompt: biometricPrompt
        )
        _ = try await client.submitTx(tx)
        // SSE will deliver tx_applied for us, but a direct refresh
        // here gets the new balance + history visible immediately
        // — better UX than waiting on the round-trip event.
        await refresh()
    }

    /// Build, sign, and submit a peg-out (L2 → L1 withdrawal). The
    /// burn output marks `amount` sats for the bridge agents to
    /// pay out at `bitcoinAddress`. L2 balance drops immediately;
    /// L1 funds settle later, after the agents' challenge window
    /// + 3-of-5 sign + L1 broadcast + L1 confirmations.
    public func withdraw(to bitcoinAddress: String, amount: UInt64, biometricPrompt: String) async throws {
        let builder = TxBuilder(edge: client, keystore: keystore)
        let tx = try await builder.buildWithdrawTx(
            bitcoinAddress: bitcoinAddress,
            amountSatoshi: amount,
            biometricPrompt: biometricPrompt
        )
        _ = try await client.submitTx(tx)
        await refresh()
    }

    // MARK: - Refresh

    /// Re-pull balance, address history, fee rates, and operator
    /// info concurrently. Each network call is independent —
    /// partial failure (e.g. fee oracle 502) doesn't take the rest
    /// down. Errors land on `lastError` so the UI can surface a
    /// banner without panicking the user.
    public func refresh() async {
        guard let address else { return }

        async let balResult = result { try await self.client.getBalance(address: address) }
        async let histResult = result { try await self.client.getAddressHistory(address: address) }
        async let feeResult = result { try await self.client.getFeeOracle() }
        async let infoResult = result { try await self.client.getInfo() }
        async let pendingResult = result { try await self.client.getPendingWithdrawals() }

        let bal = await balResult
        let hist = await histResult
        let fee = await feeResult
        let info = await infoResult
        let pending = await pendingResult

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
        if case .success(let i) = info {
            self.operatorInfo = i.operator
        }
        if case .success(let p) = pending {
            // Anything in /pending_withdrawals is still awaiting
            // broadcast → mark as .pending unless we already saw
            // its broadcast SSE event (don't clobber a .broadcast
            // entry that arrived seconds before this refresh).
            for w in p.withdrawals where w.completed == false {
                if withdrawalStatuses[w.burnTxHash] == nil {
                    withdrawalStatuses[w.burnTxHash] = .pending
                }
            }
        }

        // Surface the last failed call (if any) for the UI banner.
        // We can't put the heterogeneously-typed Results into a
        // single array (Swift loses the Result wrapper), so check
        // them inline.
        if case .failure(let e) = bal  { lastError = e.localizedDescription }
        if case .failure(let e) = hist { lastError = e.localizedDescription }
        if case .failure(let e) = info { lastError = e.localizedDescription }
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
        case .withdrawalStatus:
            // Update the per-burn status map so HistoryRow can show
            // the up-to-date label without a refresh round-trip.
            if let payload = event.asWithdrawalStatus() {
                switch payload.status {
                case "queued":
                    withdrawalStatuses[payload.burnTxHash] = .pending
                case "broadcast":
                    if let id = payload.btcTxID, !id.isEmpty {
                        withdrawalStatuses[payload.burnTxHash] = .broadcast(btcTxID: id)
                    } else {
                        // Operator told us "broadcast" without a txid —
                        // shouldn't happen, but render gracefully.
                        withdrawalStatuses[payload.burnTxHash] = .unknownState("broadcast")
                    }
                default:
                    withdrawalStatuses[payload.burnTxHash] = .unknownState(payload.status)
                }
            }
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

    /// Derive the user's `enoch1p...` Taproot receive address from
    /// their pubkey. Pubkey-side derivation (BIP-341 keypath tweak)
    /// — no biometric prompt; safe to call at app launch / on every
    /// render of the Receive tab.
    static func taprootAddress(for pub: Secp256k1.PublicKey) throws -> String {
        let outputKey = try pub.taprootOutputKey()
        return try Address.encodeTaproot(outputKey: outputKey.bytes)
    }
}
