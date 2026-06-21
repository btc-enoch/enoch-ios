// FederationDirectEvents — SSE fan-out across federation operators.
//
// The wallet opens one SSE subscription per operator (`/v1/events`
// on each operator's `enoch_peer` onion) and merges their event
// streams into a single `AsyncThrowingStream<EdgeEvent>` that the UI
// consumes. Cross-operator duplicates are collapsed via a computed
// dedupe key per event type.
//
// Trust framing per spec §4.9: SSE events are ADVISORY. They tell
// the wallet "something might have happened, refresh your views."
// The actual trust verification happens when the wallet then issues
// cross-checked REST queries (`getBalance`, `getUTXOs`, etc.). So
// this layer doesn't try to detect *missing* events across
// operators — only to suppress duplicate notifications that would
// otherwise flicker the UI.
//
// Reconnection: each per-operator subscriber auto-reconnects with
// exponential backoff (1s → 30s cap), identical to EdgeClient's
// path. A federation-level `.connected` event fires on the FIRST
// operator successfully connecting; subsequent operator (re)connects
// are silent. The wallet sees one stable stream.

import Foundation

/// LRU-bounded set of recently-seen event keys. When N operator
/// streams emit the same `tx_applied` (or `deposit_pending` etc.),
/// only the first to arrive at the merger fires; later arrivals
/// match in the cache and are dropped.
///
/// Capacity bounds memory: at ~32-byte keys, 1024 entries ≈ 32 KB.
/// More than enough for normal wallet event rates (most events at
/// most a few per second).
public actor EventDedupeCache {
    private var seen: Set<String> = []
    private var queue: [String] = []
    private let capacity: Int

    public init(capacity: Int = 1024) {
        precondition(capacity > 0, "capacity must be positive")
        self.capacity = capacity
    }

    /// Returns true the first time `key` is seen; false on every
    /// subsequent call until the key ages out of the LRU window.
    public func shouldEmit(_ key: String) -> Bool {
        if seen.contains(key) { return false }
        seen.insert(key)
        queue.append(key)
        if queue.count > capacity {
            let evicted = queue.removeFirst()
            seen.remove(evicted)
        }
        return true
    }

    /// Test/debug only — current LRU size. Production callers don't
    /// inspect this.
    public func sizeForTesting() -> Int { queue.count }
}

extension EdgeEvent {
    /// Stable key for dedupe across operator streams. Returns `nil`
    /// for events the merger should pass through unconditionally:
    ///
    ///   - `.connected` is per-stream synthetic; we suppress at a
    ///     higher level (see `FederationDirectEventState`) so the
    ///     wallet sees one connected per federation lifetime, not
    ///     one per operator.
    ///   - `.unknown` is unparseable — we can't compute a stable
    ///     key. The merger emits them all and lets the wallet decide
    ///     what to do.
    ///
    /// For typed events, the key embeds the natural idempotency
    /// fields:
    ///
    ///   - tx_applied: `tx_hash + height`. Same tx, same height =
    ///     same event.
    ///   - state_root_signed: `height + state_root`. Different
    ///     operators may emit DIFFERENT state_roots for the same
    ///     height — that's federation equivocation, and we let both
    ///     through so reconciliation (spec §7) can fire.
    ///   - withdrawal_status: `burn_tx_hash + status`. Same burn at
    ///     the same status = same event.
    ///   - deposit_pending: `btc_txid + vout + confirmations`.
    ///     `confirmations` advances per watcher tick, so a value
    ///     change = a real new event.
    ///   - deposit_minted: `btc_txid + vout`. Terminal.
    public func dedupeKey() -> String? {
        switch kind {
        case .connected, .unknown:
            return nil
        case .txApplied:
            guard let p = asTxApplied() else { return nil }
            return "tx_applied:\(p.txHash):\(p.height)"
        case .stateRootSigned:
            guard let p = asStateRootSigned() else { return nil }
            return "state_root_signed:\(p.height):\(p.stateRoot)"
        case .withdrawalStatus:
            guard let p = asWithdrawalStatus() else { return nil }
            return "withdrawal_status:\(p.burnTxHash):\(p.status)"
        case .depositPending:
            guard let p = asDepositPending() else { return nil }
            return "deposit_pending:\(p.btcTxID):\(p.vout):\(p.confirmations)"
        case .depositMinted:
            guard let p = asDepositMinted() else { return nil }
            return "deposit_minted:\(p.btcTxID):\(p.vout)"
        }
    }
}

/// Tracks whether the federation event stream has emitted its
/// initial `.connected` synthetic. Used so K operators connecting
/// only produce ONE wallet-visible connected event.
actor FederationConnectedGate {
    private var emitted = false

    /// Returns true the first time this is called and false on
    /// every subsequent call. Reset never happens within a single
    /// federation eventStream lifetime — restarts cancel and rebuild.
    func passFirstOnly() -> Bool {
        if emitted { return false }
        emitted = true
        return true
    }
}

public extension FederationDirectClient {
    /// Open an SSE stream against every operator in the manifest,
    /// merge their events, dedupe, and surface as one
    /// `AsyncThrowingStream`. Mirrors `EdgeClient.eventStream(filter:)`
    /// for migration — call sites swap clients without changing the
    /// for-await shape.
    ///
    /// `filter` is per-operator (each operator applies it
    /// independently). Empty = receive every event.
    ///
    /// Cancellation: exiting the consumer's for-await loop cancels
    /// all per-operator Tasks. There's no explicit `close()` — the
    /// AsyncStream contract handles it.
    func eventStream(filter: [String] = []) -> AsyncThrowingStream<EdgeEvent, Swift.Error> {
        AsyncThrowingStream { continuation in
            let dedupe = EventDedupeCache()
            let gate = FederationConnectedGate()

            let tasks: [Task<Void, Never>] = manifest.operators.map { op in
                Task { [weak self] in
                    guard let self else { return }
                    await self.runOperatorStream(
                        operator: op,
                        filter: filter,
                        dedupe: dedupe,
                        gate: gate,
                        continuation: continuation
                    )
                }
            }
            continuation.onTermination = { _ in tasks.forEach { $0.cancel() } }
        }
    }

    /// Run the auto-reconnecting SSE loop for one operator. Suppresses
    /// per-operator `.connected` events except the very first one
    /// (which is rebranded as the federation-level `connected`).
    private func runOperatorStream(
        operator op: FederationManifestOperator,
        filter: [String],
        dedupe: EventDedupeCache,
        gate: FederationConnectedGate,
        continuation: AsyncThrowingStream<EdgeEvent, Swift.Error>.Continuation
    ) async {
        var backoff: UInt64 = 1_000_000_000 // 1s in ns
        let maxBackoff: UInt64 = 30_000_000_000

        while !Task.isCancelled {
            do {
                try await self.runOneSSEConnection(
                    operator: op,
                    filter: filter,
                    dedupe: dedupe,
                    gate: gate,
                    continuation: continuation
                )
                backoff = 1_000_000_000 // reset after clean disconnect
            } catch is CancellationError {
                return
            } catch {
                try? await Task.sleep(nanoseconds: backoff)
                backoff = min(maxBackoff, backoff * 2)
            }
        }
    }

    /// One pass over one operator's `/v1/events` stream. SSE framing
    /// mirrors EdgeClient.runStream — extracted here so the
    /// federation-direct path doesn't depend on EdgeClient's
    /// internals (EdgeClient will be deleted entirely once #369 is
    /// fully migrated).
    private func runOneSSEConnection(
        operator op: FederationManifestOperator,
        filter: [String],
        dedupe: EventDedupeCache,
        gate: FederationConnectedGate,
        continuation: AsyncThrowingStream<EdgeEvent, Swift.Error>.Continuation
    ) async throws {
        var path = "/v1/events"
        if !filter.isEmpty {
            path += "?" + filter.map { "addr=\($0)" }.joined(separator: "&")
        }
        let url = try self.url(operator: op, path: path)

        var req = URLRequest(url: url)
        req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        req.timeoutInterval = .greatestFiniteMagnitude

        let (bytes, response) = try await session.bytes(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw L2ClientError.transport("non-HTTP response from operator_\(op.operatorID)")
        }
        guard http.statusCode == 200 else {
            throw L2ClientError.http(statusCode: http.statusCode, body: "")
        }

        // Federation-level connected: only the first operator's
        // first connection passes the gate; all others are silent.
        if await gate.passFirstOnly() {
            continuation.yield(EdgeEvent(kind: .connected, raw: Data()))
        }

        var eventName = ""
        var dataBuf = Data()
        func flushSync() async {
            guard !eventName.isEmpty, !dataBuf.isEmpty else { return }
            let event = EdgeEvent.parse(eventName: eventName, data: dataBuf)
            eventName = ""
            dataBuf = Data()

            if let key = event.dedupeKey() {
                if await dedupe.shouldEmit(key) {
                    continuation.yield(event)
                }
            } else {
                // No stable key (.unknown, or a typed event whose
                // payload didn't parse) — let it through.
                continuation.yield(event)
            }
        }

        for try await line in bytes.lines {
            if line.hasPrefix(":") || line.isEmpty {
                await flushSync()
                continue
            }
            if line.hasPrefix("event: ") {
                await flushSync()
                eventName = String(line.dropFirst("event: ".count))
            } else if line.hasPrefix("data: ") {
                if !dataBuf.isEmpty { dataBuf.append(0x0A) }
                dataBuf.append(Data(line.dropFirst("data: ".count).utf8))
            }
        }
        await flushSync()
    }
}
