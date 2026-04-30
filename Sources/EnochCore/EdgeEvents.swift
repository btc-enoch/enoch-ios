// EdgeEvents — SSE subscription to enoch-edge /v1/events.
//
// URLSession doesn't have a native SSE client, so we drive
// `URLSession.bytes(for:).lines` ourselves and parse the
// `event:`/`data:` framing per the SSE spec
// (https://html.spec.whatwg.org/multipage/server-sent-events.html).
//
// One AsyncThrowingStream per subscription. The stream errors only
// on construction failure; reconnect with exponential backoff is
// internal so wallet UIs see one continuous event stream across
// transient network blips. Wallets that want explicit reconnect
// signaling can read the `EdgeEvent.connected` events emitted on
// each successful connect.

import Foundation

/// What the wallet sees on the stream. Raw is the operator's
/// `data:` payload as JSON bytes, identical to what the operator
/// itself published — wallets decode by event type without an
/// edge-side schema in the way.
public struct EdgeEvent: Equatable {
    public enum Kind: String, Equatable {
        case connected            // synthetic, emitted on each successful upstream connect
        case txApplied            // tx_applied
        case stateRootSigned      // state_root_signed
        case unknown
    }
    public let kind: Kind
    public let raw: Data

    public static func parse(eventName: String, data: Data) -> EdgeEvent {
        let kind: Kind
        switch eventName {
        case "tx_applied":         kind = .txApplied
        case "state_root_signed":  kind = .stateRootSigned
        default:                   kind = .unknown
        }
        return EdgeEvent(kind: kind, raw: data)
    }
}

/// Typed payloads. Decode lazily from `EdgeEvent.raw` only when a
/// wallet caller asks for the typed view — events the wallet
/// doesn't care about (e.g. state_root_signed for a wallet not doing
/// light-client verification) cost nothing to drop.

public struct TxAppliedPayload: Codable, Equatable {
    public let txHash: String
    public let height: UInt64
    public let addresses: [String]
    public let burns: Int

    enum CodingKeys: String, CodingKey {
        case txHash = "tx_hash"
        case height
        case addresses
        case burns
    }
}

public struct StateRootSignedPayload: Codable, Equatable {
    public let height: UInt64
    public let stateRoot: String
    public let signature: String

    enum CodingKeys: String, CodingKey {
        case height
        case stateRoot = "state_root"
        case signature
    }
}

public extension EdgeEvent {
    /// Returns nil on shape mismatch — wallets typically `if let`
    /// rather than try/catch in event handling.
    func asTxApplied() -> TxAppliedPayload? {
        try? JSONDecoder().decode(TxAppliedPayload.self, from: raw)
    }

    func asStateRootSigned() -> StateRootSignedPayload? {
        try? JSONDecoder().decode(StateRootSignedPayload.self, from: raw)
    }
}

// MARK: - Subscription

public extension EdgeClient {
    /// Open an SSE stream filtered by zero or more enoch1 addresses.
    /// Empty filter = receive every event. The returned
    /// AsyncThrowingStream yields events as they arrive; on
    /// disconnect, the underlying connection is reopened with
    /// exponential backoff (1s → 30s cap) until the consumer cancels
    /// the stream by exiting its for-await loop.
    func eventStream(filter: [String] = []) -> AsyncThrowingStream<EdgeEvent, Swift.Error> {
        AsyncThrowingStream { continuation in
            let task = Task { [weak self] in
                guard let self else { return }
                var backoff: UInt64 = 1_000_000_000 // 1s in ns
                let maxBackoff: UInt64 = 30_000_000_000
                while !Task.isCancelled {
                    do {
                        try await self.runStream(filter: filter, continuation: continuation)
                        backoff = 1_000_000_000 // reset after a clean disconnect
                    } catch is CancellationError {
                        break
                    } catch {
                        // log via continuation? for now just retry. The
                        // synthetic .connected event on the next loop
                        // tells consumers we're back.
                        try? await Task.sleep(nanoseconds: backoff)
                        backoff = min(maxBackoff, backoff * 2)
                    }
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    private func runStream(
        filter: [String],
        continuation: AsyncThrowingStream<EdgeEvent, Swift.Error>.Continuation
    ) async throws {
        var path = "/v1/events"
        if !filter.isEmpty {
            path += "?" + filter.map { "addr=\($0)" }.joined(separator: "&")
        }
        guard let url = URL(string: baseURL.absoluteString + path) else {
            throw EdgeError.urlConstruction
        }
        var req = URLRequest(url: url)
        req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        // SSE streams have no end — disable URLSession's default
        // request timeout for the body. Connect timeout still applies.
        req.timeoutInterval = .greatestFiniteMagnitude

        let (bytes, response) = try await session.bytes(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw EdgeError.transport("non-HTTP response")
        }
        guard http.statusCode == 200 else {
            throw EdgeError.http(statusCode: http.statusCode, body: "")
        }

        continuation.yield(EdgeEvent(kind: .connected, raw: Data()))

        // Foundation's URLSession.bytes(for:).lines silently
        // collapses consecutive newlines into a single delimiter, so
        // we never see the empty-line separator that SSE uses
        // between events. We work around it by dispatching whenever
        // we encounter a line that signals the *start* of a new
        // event or a comment/heartbeat — both indicate the previous
        // event block is complete on the wire.
        var eventName = ""
        var dataBuf = Data()
        let flush: () -> Void = {
            guard !eventName.isEmpty, !dataBuf.isEmpty else { return }
            continuation.yield(EdgeEvent.parse(eventName: eventName, data: dataBuf))
            eventName = ""
            dataBuf = Data()
        }
        for try await line in bytes.lines {
            // (debug prints removed; the parser path is exercised
            // by an integration test in EdgeIntegrationTests when
            // EDGE_INTEGRATION=1 is set)
            if line.hasPrefix(":") {
                // Comment / heartbeat — also a valid event boundary.
                flush()
                continue
            }
            if line.isEmpty {
                // Real empty line (rare, but handle it correctly if
                // a future Foundation release stops collapsing them).
                flush()
                continue
            }
            if let rest = line.dropPrefixIfPresent("event: ") {
                // New event — flush any prior one before starting.
                flush()
                eventName = rest
            } else if let rest = line.dropPrefixIfPresent("data: ") {
                if !dataBuf.isEmpty {
                    dataBuf.append(0x0A) // SSE multi-line data join
                }
                dataBuf.append(Data(rest.utf8))
            }
        }
        flush() // final event on stream end
    }
}

private extension String {
    /// Returns the suffix after `prefix`, or nil if `prefix` doesn't
    /// match. Cleaner at the call site than `if hasPrefix { drop }`.
    func dropPrefixIfPresent(_ prefix: String) -> String? {
        guard hasPrefix(prefix) else { return nil }
        return String(dropFirst(prefix.count))
    }
}
