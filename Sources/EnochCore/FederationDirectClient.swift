// FederationDirectClient — the mainnet wallet's HTTP client.
//
// Replaced EdgeClient on the mainnet wallet path (enoch-edge retired
// 2026-06-21). Instead of talking to one proxy endpoint, the client
// picks K operators from the manifest, dials each operator's
// `enoch_peer` onion in parallel, and tallies the responses via
// CrossCheckResult.
//
// Trust delta vs the retired edge proxy: see spec/ios_active_spv.md
// §4.9. Net result: smaller TCB, real cross-check, no DNS/CA
// dependency.
//
// Lives above the NetworkSubstrate abstraction — uses the
// substrate's URLSession for outbound HTTP so the privacy property
// (plain HTTP / Tor SOCKS / future Sphinx-via-shim) stays
// independent of the federation-direct logic.

import Foundation

/// Errors specific to the federation-direct client's aggregation
/// layer. Per-operator HTTP errors stay typed as L2ClientError and
/// surface inside CrossCheckResult.dissents / .allFailed; this enum
/// is reserved for client-level failures.
public enum FederationDirectError: Swift.Error, Equatable {
    /// Caller asked for cross-check with K operators, but the
    /// manifest doesn't have that many. Caught at construction
    /// time so misconfiguration fails loudly.
    case insufficientOperatorsForFanOut(have: Int, requested: Int)

    /// All K operators returned errors and none produced a
    /// usable response. The caller can still inspect the
    /// CrossCheckResult.allFailed payload for per-operator
    /// errors; this enum value is for callers that want the
    /// "everyone offline" path as a typed throw.
    case allFailed
}

public final class FederationDirectClient {
    public let manifest: FederationManifest
    public let substrate: NetworkSubstrate
    /// Default fan-out width for cross-check queries. Spec §4.9.3
    /// recommends K=3 for v1; callers can override per-call when
    /// they need fewer (e.g., informational queries that don't
    /// require cross-check) or more (paranoid mode).
    public let defaultFanOut: Int

    internal let session: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    public init(
        manifest: FederationManifest,
        substrate: NetworkSubstrate = PlainHTTPSubstrate(),
        defaultFanOut: Int = 3
    ) throws {
        if manifest.operators.count < defaultFanOut {
            throw FederationDirectError.insufficientOperatorsForFanOut(
                have: manifest.operators.count,
                requested: defaultFanOut
            )
        }
        self.manifest = manifest
        self.substrate = substrate
        self.defaultFanOut = defaultFanOut
        self.session = substrate.urlSession
        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()
    }

    // MARK: - Informational queries (no cross-check)

    /// `/v1/info` is a self-describe call. We don't cross-check —
    /// every operator is the authority on its own configuration.
    /// We just pick the first operator in manifest order and ask.
    /// If that one's unreachable, we fall back to the next.
    ///
    /// Wire-shape: operators return the bare `OperatorInfo` body
    /// (no `edge`/`operator` envelope — edge-mode added that wrapping
    /// to surface its own version. Direct mode talks to operators
    /// only, so we drop the envelope).
    public func getInfo() async throws -> OperatorInfo {
        var lastError: Swift.Error?
        for op in manifest.operators {
            do {
                return try await get(operator: op, path: "/v1/info")
            } catch {
                lastError = error
                continue
            }
        }
        throw lastError ?? FederationDirectError.allFailed
    }

    // MARK: - Cross-checked queries

    /// `/v1/balance` is the canonical cross-check call. Fan out to
    /// K operators, compare their `BalanceResponse` answers, return
    /// the structured outcome so the caller can decide between
    /// "display / warn / block / retry."
    ///
    /// Equivalence is `BalanceResponse`'s `Equatable` impl. If the
    /// response type includes fields that legitimately drift across
    /// operators (server clocks, view-change view number), the
    /// type's Equatable must exclude them.
    public func getBalance(
        address: String,
        fanOut: Int? = nil
    ) async throws -> CrossCheckResult<BalanceResponse> {
        let K = fanOut ?? defaultFanOut
        return try await fanOutCrossCheck(K: K) { op in
            try await self.get(
                operator: op,
                path: "/v1/balance/\(percentEncode(address))"
            )
        }
    }

    /// `/v1/utxos` — the UTXO set the operator believes belongs to
    /// `address`. Coin selection feeds off this; equivocation here
    /// would let the federation steer the wallet into double-spends
    /// or stranded change. Cross-checked.
    public func getUTXOs(
        address: String,
        fanOut: Int? = nil
    ) async throws -> CrossCheckResult<UTXOsResponse> {
        let K = fanOut ?? defaultFanOut
        return try await fanOutCrossCheck(K: K) { op in
            try await self.get(
                operator: op,
                path: "/v1/utxos/\(percentEncode(address))"
            )
        }
    }

    /// `/v1/address_history` — per-address tx history with
    /// optional pagination (`from`, `limit`). The wallet's
    /// HistoryView renders this; equivocation would let the
    /// federation hide / fabricate user-visible entries.
    /// Cross-checked.
    public func getAddressHistory(
        address: String,
        from: UInt64? = nil,
        limit: UInt64? = nil,
        fanOut: Int? = nil
    ) async throws -> CrossCheckResult<AddressHistoryResponse> {
        let K = fanOut ?? defaultFanOut
        var query = [String]()
        if let from { query.append("from=\(from)") }
        if let limit { query.append("limit=\(limit)") }
        let suffix = query.isEmpty ? "" : "?" + query.joined(separator: "&")
        let basePath = "/v1/address_history/\(percentEncode(address))" + suffix
        return try await fanOutCrossCheck(K: K) { op in
            try await self.get(operator: op, path: basePath)
        }
    }

    /// `/v1/pending_withdrawals` — federation-internal state about
    /// burns whose L1 tx hasn't broadcast yet. Used by the wallet
    /// to render "pending bridge confirmation" badges; equivocation
    /// here would let the federation lie about withdrawal status.
    /// Cross-checked.
    public func getPendingWithdrawals(
        fanOut: Int? = nil
    ) async throws -> CrossCheckResult<PendingWithdrawalsResponse> {
        let K = fanOut ?? defaultFanOut
        return try await fanOutCrossCheck(K: K) { op in
            try await self.get(operator: op, path: "/v1/pending_withdrawals")
        }
    }

    // MARK: - Tx submission (single-operator with retry)

    /// Submit a fully-signed `Tx` to one operator. Submission is
    /// inherently single-operator: the leader (or any operator that
    /// can forward to the leader) accepts the tx and propagates it
    /// through the federation's internal gossip. Cross-check
    /// doesn't apply at submit time — it applies later when the
    /// wallet observes the tx in cross-checked balance / history
    /// responses.
    ///
    /// Retry semantics: iterate operators in manifest order. The
    /// first to return 2xx wins; subsequent operators are skipped.
    /// On 4xx (request-shape error — `insufficient funds`, etc.),
    /// the wallet must NOT retry against another operator: a 4xx
    /// is the wallet's fault and another operator will report the
    /// same. Only 5xx / transport errors trigger the next-operator
    /// fallback.
    public func submitTx(_ tx: Tx) async throws -> SubmitTxResponse {
        let body: Data
        do {
            body = try encoder.encode(tx.toWire())
        } catch {
            throw L2ClientError.decode("submit_tx encode: \(error)")
        }

        var lastError: Swift.Error?
        for op in manifest.operators {
            do {
                return try await post(
                    operator: op,
                    path: "/v1/submit_tx",
                    body: body
                )
            } catch L2ClientError.http(let code, let respBody) {
                // 4xx → request-shape error; retrying won't help.
                if (400..<500).contains(code) {
                    throw L2ClientError.http(statusCode: code, body: respBody)
                }
                lastError = L2ClientError.http(statusCode: code, body: respBody)
                continue
            } catch {
                lastError = error
                continue
            }
        }
        throw lastError ?? FederationDirectError.allFailed
    }

    // MARK: - Internal HTTP

    /// Build the per-operator URL from the manifest's `enoch_peer`
    /// string + a relative path. Accepts both schemed forms
    /// (`http://host:port`, `https://onion:port`) and bare
    /// `host:port` — the latter assumes `http://` for dev/regtest.
    /// Production manifests should always carry an explicit scheme.
    internal func url(
        operator op: FederationManifestOperator,
        path: String
    ) throws -> URL {
        let base: String
        if op.enochPeer.contains("://") {
            base = op.enochPeer
        } else {
            // Bare host:port — dev/regtest default. Production
            // manifests should declare the scheme explicitly so
            // this branch never fires in mainnet builds.
            base = "http://" + op.enochPeer
        }
        let cleanedPath = path.hasPrefix("/") ? path : "/" + path
        guard let url = URL(string: base + cleanedPath) else {
            throw L2ClientError.urlConstruction
        }
        return url
    }

    /// Issue a GET to one operator's endpoint, decode the JSON
    /// response into `T`. Per-operator failure surfaces as a typed
    /// L2ClientError so the calling cross-check tallier can categorise
    /// it as a dissent reason in CrossCheckResult.
    internal func get<T: Decodable>(
        operator op: FederationManifestOperator,
        path: String
    ) async throws -> T {
        var request = URLRequest(url: try url(operator: op, path: path))
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return try await perform(request, operatorID: op.operatorID)
    }

    /// Issue a POST with the supplied JSON body. Used by tx
    /// submission; the cross-check tallier never sees this path
    /// because submit_tx is single-operator-with-retry.
    internal func post<T: Decodable>(
        operator op: FederationManifestOperator,
        path: String,
        body: Data
    ) async throws -> T {
        var request = URLRequest(url: try url(operator: op, path: path))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = body
        return try await perform(request, operatorID: op.operatorID)
    }

    /// Common request execution: surface URLSession failures as
    /// `.transport`, non-2xx as `.http`, and JSON decode failures
    /// as `.decode` (L2ClientError) so call sites stay uniform.
    private func perform<T: Decodable>(
        _ request: URLRequest,
        operatorID: OperatorID
    ) async throws -> T {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw L2ClientError.transport(
                "operator_\(operatorID): \(error.localizedDescription)"
            )
        }
        guard let http = response as? HTTPURLResponse else {
            throw L2ClientError.transport(
                "non-HTTP response from operator_\(operatorID)"
            )
        }
        if !(200...299).contains(http.statusCode) {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw L2ClientError.http(
                statusCode: http.statusCode,
                body: body.trimmingCharacters(in: .whitespacesAndNewlines)
            )
        }
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw L2ClientError.decode(error.localizedDescription)
        }
    }

    /// Fan out a single query across K operators chosen from the
    /// front of the manifest in order, await all responses (success
    /// or failure), and tally via CrossCheckResult.
    ///
    /// Selection policy is deliberately simple in v1: first K
    /// operators in manifest order. Future versions add latency-
    /// or reputation-aware selection; the manifest ordering keeps
    /// behaviour deterministic for tests and for explaining
    /// dissents to the user.
    internal func fanOutCrossCheck<T: Equatable>(
        K: Int,
        per: @escaping (FederationManifestOperator) async throws -> T
    ) async throws -> CrossCheckResult<T> {
        if manifest.operators.count < K {
            throw FederationDirectError.insufficientOperatorsForFanOut(
                have: manifest.operators.count,
                requested: K
            )
        }
        let selected = Array(manifest.operators.prefix(K))
        let responses: [OperatorResponse<T>] =
            await withTaskGroup(of: OperatorResponse<T>.self) { group in
                for op in selected {
                    group.addTask {
                        do {
                            let value = try await per(op)
                            return (operatorID: op.operatorID, outcome: .success(value))
                        } catch {
                            return (operatorID: op.operatorID, outcome: .failure(error))
                        }
                    }
                }
                var collected: [OperatorResponse<T>] = []
                for await response in group {
                    collected.append(response)
                }
                // Stable order matters for the test assertions and
                // the dissent display. Sort by manifest order.
                let indexByID = Dictionary(
                    uniqueKeysWithValues: selected.enumerated().map { ($1.operatorID, $0) }
                )
                collected.sort { (a, b) in
                    (indexByID[a.operatorID] ?? 0) < (indexByID[b.operatorID] ?? 0)
                }
                return collected
            }
        return CrossCheckResult.tally(responses, K: K)
    }
}

/// URL-percent-encode an address (or any path segment) so callers
/// don't have to think about it. Bech32 and bech32m strings only
/// use [a-z0-9] so this is usually a no-op, but legacy P2PKH /
/// P2SH addresses can contain characters URLs care about.
private func percentEncode(_ s: String) -> String {
    s.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? s
}
