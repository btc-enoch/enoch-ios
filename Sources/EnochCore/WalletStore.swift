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
    //
    // Per-wallet state is keyed by wallet id rather than held as flat
    // properties. Computed accessors below project the active wallet's
    // entry, so views can keep reading `wallet.balance` etc. without
    // knowing about the dict. Switching wallets changes
    // `activeWalletID`; the previous wallet's state object stays in
    // the dict so a switch-back doesn't flash a fresh-zero balance
    // through the UI before refresh lands. Crucially this makes
    // cross-wallet leaks structurally impossible: an SSE event keyed
    // by recipient cannot land in a different wallet's slot, because
    // there is no shared slot.

    /// Per-wallet live state, keyed by wallet id. Mutated in place by
    /// `updateActive` / `updateState(walletID:)`. Public for tests +
    /// hypothetical multi-wallet UI that wants to peek at a non-active
    /// wallet's state.
    public private(set) var states: [String: WalletLiveState] = [:]

    /// Network-shared snapshot of the operator's fee oracle. Not
    /// per-wallet because every wallet on this operator pays the same
    /// rate.
    public private(set) var feeRates: FeeRates?

    /// Network-shared operator metadata (network, fee schedule,
    /// bridge redeem script, min_deposit_confirmations, …).
    public private(set) var operatorInfo: OperatorInfo?

    // MARK: - Per-wallet projections of the active state.
    //
    // These read through to `states[activeWalletID]`. SwiftUI
    // observation tracks the underlying `states` + `activeWalletID`
    // stored properties, so any mutation that goes through
    // `updateActive` triggers re-render of views bound to these
    // accessors.

    public var balance: UInt64 { activeState?.balance ?? 0 }
    public var utxoCount: Int { activeState?.utxoCount ?? 0 }
    public var history: [AddressHistoryEntry] { activeState?.history ?? [] }
    public var pendingDeposits: [String: PendingDepositUI] { activeState?.pendingDeposits ?? [:] }
    public var withdrawalStatuses: [String: WithdrawalUIStatus] { activeState?.withdrawalStatuses ?? [:] }

    private var activeState: WalletLiveState? {
        guard let id = activeWalletID else { return nil }
        return states[id]
    }

    /// Per-wallet live state. Each wallet owns one of these in
    /// `WalletStore.states`. Value type so mutations through the
    /// `states` dict are tracked by `@Observable`.
    public struct WalletLiveState: Equatable {
        public var balance: UInt64 = 0
        public var utxoCount: Int = 0
        public var history: [AddressHistoryEntry] = []

        /// In-flight L1 deposits at this wallet's per-user address
        /// (#108). Keyed by `btc_txid` so re-emitted `deposit_pending`
        /// events just update the existing entry's confirmation
        /// count. Cleared on the matching `deposit_minted` event.
        public var pendingDeposits: [String: PendingDepositUI] = [:]

        /// Per-burn withdrawal lifecycle, keyed by burn_tx_hash. UI
        /// renders "Pending bridge confirmation" → "Sent to Bitcoin:
        /// <txid>" badges on burn rows from this map.
        public var withdrawalStatuses: [String: WithdrawalUIStatus] = [:]

        public init() {}
    }

    /// Wallet-side view of an in-flight L1 deposit. Uses `Int` for
    /// `confirmations` because the wire shape is signed (the operator
    /// caps at zero so the UI never has to deal with negatives, but
    /// we keep the type honest).
    public struct PendingDepositUI: Equatable {
        public let btcTxID: String
        public let vout: UInt32
        public let amountSatoshi: UInt64
        public let confirmations: Int
        public let perUser: Bool
    }

    /// Convenience: the operator's flat per-tx L2 fee, or nil if
    /// `/v1/info` hasn't been fetched yet. SendView reads this to
    /// preview the fee before the user confirms.
    public var feePerTxSatoshi: UInt64? {
        operatorInfo?.feeSchedule?.perTxFeeSatoshi
    }

    /// Bitcoin confirmations the bridge agents wait for before
    /// signing a mint. Authoritative source is the operator's
    /// /v1/info `min_deposit_confirmations` (sourced from
    /// MIN_DEPOSIT_CONFS env / DefaultMinDepositConfs). Falls back
    /// to a network-name guess for older operators that don't yet
    /// emit the field, and to 1 when /v1/info hasn't loaded — the
    /// wallet gracefully renders "N/1" until it does, then redraws.
    public var minConfirmationsForDeposit: Int {
        if let n = operatorInfo?.minDepositConfirmations, n > 0 {
            return Int(n)
        }
        switch operatorInfo?.network {
        case "mainnet": return 6
        case "testnet", "testnet3", "signet": return 3
        default: return 1
        }
    }

    /// The wallet's per-user L1 Bitcoin deposit address (#108) — a
    /// bech32m P2TR derived from the wallet's L2 x-only pubkey + the
    /// bridge redeem script under the operator's network. nil when
    /// the wallet isn't loaded yet, when `/v1/info` hasn't been
    /// fetched, when the operator predates #108 (no
    /// `bridge_redeem_script`), or when the wallet's L2 address is
    /// legacy P2PKH (no per-user Taproot deposit address is defined
    /// for those). Wallets pay the same address every time — it's
    /// fully deterministic from the L2 identity, not a HD path —
    /// which keeps the QR + clipboard story simple and makes
    /// pre-printing the address (e.g. on a paper backup) safe.
    public var bridgeDepositAddress: String? {
        guard
            let l2Address = address,
            let info = operatorInfo,
            let redeem = info.bridgeRedeemScript,
            let reclaimR = info.depositReclaimR,
            let network = DepositAddress.Network(infoNetwork: info.network)
        else { return nil }
        guard case .p2tr(let outputKey) = try? Address.decode(l2Address) else {
            // Pre-#109 P2PKH addresses don't have a per-user deposit
            // address; older wallets fall back to the shared
            // bridge-deposit address with an OP_RETURN tag.
            return nil
        }
        return try? DepositAddress.derive(
            l2XOnly: outputKey,
            bridgeRedeemScriptHex: redeem,
            reclaimR: reclaimR,
            network: network
        )
    }

    /// The 32-byte x-only output key embedded in the wallet's L1
    /// deposit address. Same bytes as the bech32m payload of
    /// `bridgeDepositAddress`, exposed separately so SendView can
    /// detect "user is about to send L2 funds to their own deposit
    /// address" without re-parsing the address string. Mathematically
    /// the deposit output_key is `NUMS + tweak·G` — no one has the
    /// privkey for it under the current construction, so an L2 send
    /// to it produces a permanently-stuck UTXO.
    public var bridgeDepositOutputKey: Data? {
        guard
            let l2Address = address,
            let info = operatorInfo,
            let redeem = info.bridgeRedeemScript,
            let reclaimR = info.depositReclaimR
        else { return nil }
        guard case .p2tr(let outputKey) = try? Address.decode(l2Address) else {
            return nil
        }
        let redeemBytes: Data
        do {
            redeemBytes = try Data(hex: redeem)
        } catch {
            return nil
        }
        return try? DepositAddress.outputKey(
            l2XOnly: outputKey,
            bridgeRedeemScript: redeemBytes,
            reclaimR: reclaimR
        )
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
            // Pending-deposit pills are SSE-driven (#108): the
            // operator emits `deposit_pending` each watcher tick
            // while a deposit is in flight + a single
            // `deposit_minted` when the mint applies. If the wallet
            // was offline at the moment the mint event fired, the
            // entry would otherwise stick around stale. Clearing on
            // bootstrap and trusting SSE to repopulate within ~5s
            // is the simplest reconciliation.
            updateActive { $0.pendingDeposits.removeAll() }
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
    ///
    /// State for the previous wallet stays in `states[previousID]`
    /// so a switch-back doesn't flash a fresh-zero balance through
    /// the UI before refresh lands. Pending deposits for the *new*
    /// active wallet are cleared so SSE can repopulate from a clean
    /// baseline (same reasoning as bootstrap).
    public func selectWallet(id: String) async throws {
        guard id != activeWalletID else { return }
        try keystore.selectWallet(id: id)
        eventTask?.cancel()
        eventTask = nil
        try refreshWalletList()
        connectionState = .idle
        updateActive { $0.pendingDeposits.removeAll() }
        await refresh()
        startEventLoop()
    }

    /// Delete a wallet. If it's the active one, the most recent
    /// remaining wallet (if any) becomes active and lifecycle state
    /// rotates accordingly. Idempotent on an unknown id.
    public func deleteWallet(id: String) async throws {
        let wasActive = (id == activeWalletID)
        try keystore.deleteWallet(id: id)
        states.removeValue(forKey: id)
        try refreshWalletList()
        if wasActive {
            eventTask?.cancel()
            eventTask = nil
            connectionState = .idle
            if hasWallet {
                updateActive { $0.pendingDeposits.removeAll() }
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

        updateActive { state in
            if case .success(let b) = bal {
                state.balance = b.balanceSatoshi
                state.utxoCount = b.utxoCount
            }
            if case .success(let h) = hist {
                // Newest-first for UI display; the operator emits
                // ascending so we reverse on the wallet side.
                state.history = h.entries.sorted { $0.height > $1.height }
            }
            if case .success(let p) = pending {
                // Anything in /pending_withdrawals is still awaiting
                // broadcast → mark as .pending unless we already saw
                // its broadcast SSE event (don't clobber a .broadcast
                // entry that arrived seconds before this refresh).
                for w in p.withdrawals where w.completed == false {
                    if state.withdrawalStatuses[w.burnTxHash] == nil {
                        state.withdrawalStatuses[w.burnTxHash] = .pending
                    }
                }
            }
        }
        if case .success(let f) = fee {
            self.feeRates = f.ratesSatPerVB
        }
        if case .success(let i) = info {
            self.operatorInfo = i.operator
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
            // The operator-side SSE filter already restricts withdrawal_status
            // events to the active wallet's stream, so route to the
            // active state.
            if let payload = event.asWithdrawalStatus() {
                let status: WithdrawalUIStatus
                switch payload.status {
                case "queued":
                    status = .pending
                case "broadcast":
                    if let id = payload.btcTxID, !id.isEmpty {
                        status = .broadcast(btcTxID: id)
                    } else {
                        // Operator told us "broadcast" without a txid —
                        // shouldn't happen, but render gracefully.
                        status = .unknownState("broadcast")
                    }
                default:
                    status = .unknownState(payload.status)
                }
                updateActive { $0.withdrawalStatuses[payload.burnTxHash] = status }
            }
        case .depositPending:
            // L1 deposit detected at our per-user address; mint
            // hasn't applied yet. Re-emitted on each watcher tick so
            // the confirmation count advances toward the agent's
            // signing threshold — last write wins by design.
            if let payload = event.asDepositPending(), payload.recipient == address {
                let pd = PendingDepositUI(
                    btcTxID: payload.btcTxID,
                    vout: payload.vout,
                    amountSatoshi: payload.amountSatoshi,
                    confirmations: payload.confirmations,
                    perUser: payload.perUser
                )
                updateActive { $0.pendingDeposits[payload.btcTxID] = pd }
            }
        case .depositMinted:
            // Mint applied — clear the pending pill, then refresh
            // balance + history directly. We used to rely solely on
            // the matching tx_applied event for the refresh, but if
            // the SSE connection landed on a follower whose mint
            // replay path skipped publishTxApplied, the balance
            // would stick at 0 until the user pulled to refresh.
            // Refreshing here is idempotent with any tx_applied that
            // does arrive.
            if let payload = event.asDepositMinted(), payload.recipient == address {
                updateActive { $0.pendingDeposits.removeValue(forKey: payload.btcTxID) }
                await refresh()
            }
        case .unknown:
            break
        }
    }

    // MARK: - State mutation helper

    /// Mutate the active wallet's `WalletLiveState` in place,
    /// creating the entry on first access. All per-wallet writes go
    /// through this so SwiftUI observes a single `states` change per
    /// mutation block.
    private func updateActive(_ mutate: (inout WalletLiveState) -> Void) {
        guard let id = activeWalletID else { return }
        var s = states[id] ?? WalletLiveState()
        mutate(&s)
        states[id] = s
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
