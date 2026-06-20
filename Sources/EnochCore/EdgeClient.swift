// EdgeClient — async/await wrapper around enoch-edge's /v1/* HTTP API.
//
// All wallet read traffic and tx submission goes through this class.
// SSE event subscription lives in EdgeEvents.swift; this file is HTTP
// only so the surfaces stay legible.
//
// Error model:
//   - .urlConstruction — caller passed something we couldn't build a
//     URL from; programmer bug, surface eagerly.
//   - .transport       — URLSession-level failure (DNS, network, TLS).
//   - .http            — server returned non-2xx; status + body
//                        captured so callers can render an actionable
//                        message ("insufficient funds", "tx invalid").
//   - .decode          — server returned 2xx but JSON didn't match
//                        our expected shape; almost always a server-
//                        client schema drift.

import Foundation

public enum EdgeError: Swift.Error, Equatable {
    case urlConstruction
    case transport(String)
    case http(statusCode: Int, body: String)
    case decode(String)

    public static func == (lhs: EdgeError, rhs: EdgeError) -> Bool {
        switch (lhs, rhs) {
        case (.urlConstruction, .urlConstruction):
            return true
        case (.transport(let a), .transport(let b)):
            return a == b
        case (.http(let a, let b), .http(let c, let d)):
            return a == c && b == d
        case (.decode(let a), .decode(let b)):
            return a == b
        default:
            return false
        }
    }
}

public final class EdgeClient {
    public let baseURL: URL
    public let substrate: NetworkSubstrate
    // `session` is `internal` (not `private`) so the SSE extension
    // in EdgeEvents.swift can drive it. Module-private boundary is
    // preserved either way. Derived from `substrate.urlSession` at
    // init time so EdgeClient holds a stable reference even if the
    // substrate's internal session changes.
    internal let session: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    /// `baseURL` is the wallet-facing edge endpoint, e.g.
    /// `http://localhost:8081` in the simulator or
    /// `https://edge.enoch.example` in production. `substrate`
    /// supplies the URLSession used for every request — the
    /// privacy property (plain HTTP vs Tor-routed) lives in the
    /// substrate. Defaults to PlainHTTPSubstrate (no privacy).
    public init(baseURL: URL, substrate: NetworkSubstrate = PlainHTTPSubstrate()) {
        self.baseURL = baseURL
        self.substrate = substrate
        self.session = substrate.urlSession
        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()
    }

    /// Legacy convenience initializer kept so existing call sites
    /// that pass a URLSession directly continue to compile. New
    /// callers should construct a NetworkSubstrate explicitly so
    /// the privacy substrate is visible at the wiring layer.
    public convenience init(baseURL: URL, session: URLSession) {
        self.init(baseURL: baseURL, substrate: PlainHTTPSubstrate(session: session))
    }

    // MARK: - GET endpoints

    public func getInfo() async throws -> InfoResponse {
        try await get("/v1/info")
    }

    public func getUTXOs(address: String) async throws -> UTXOsResponse {
        try await get("/v1/utxos/\(address)")
    }

    public func getBalance(address: String) async throws -> BalanceResponse {
        try await get("/v1/balance/\(address)")
    }

    public func getAddressHistory(
        address: String,
        from: UInt64? = nil,
        limit: UInt64? = nil
    ) async throws -> AddressHistoryResponse {
        var path = "/v1/address_history/\(address)"
        var query = [String]()
        if let from { query.append("from=\(from)") }
        if let limit { query.append("limit=\(limit)") }
        if !query.isEmpty {
            path += "?" + query.joined(separator: "&")
        }
        return try await get(path)
    }

    public func getFeeOracle() async throws -> FeeOracleResponse {
        try await get("/v1/fee_oracle")
    }

    /// In-flight withdrawals — burns whose L1 tx hasn't been
    /// broadcast yet. Wallet correlates against its address-history
    /// burn rows (`burnTxHash` ↔ row's `txHash`) to render a
    /// "Pending bridge confirmation" status badge until the
    /// operator emits a `withdrawal_status` SSE event with
    /// status = "broadcast".
    public func getPendingWithdrawals() async throws -> PendingWithdrawalsResponse {
        try await get("/v1/pending_withdrawals")
    }

    // MARK: - POST /v1/submit_tx

    /// Submit a fully-signed `Tx`. The wallet builds + signs via
    /// `Tx.sighashLegacyAll(...)` + `Secp256k1.PrivateKey
    /// .signDigest(...)`, then hands the result here. Operator's
    /// reject reasons surface as `.http(statusCode: 422, body:
    /// "insufficient funds")` etc.
    public func submitTx(_ tx: Tx) async throws -> SubmitTxResponse {
        let body = try encoder.encode(tx.toWire())
        return try await post("/v1/submit_tx", body: body)
    }

    // MARK: - internals

    private func get<T: Decodable>(_ path: String) async throws -> T {
        let url = try buildURL(path)
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        return try await perform(request)
    }

    private func post<T: Decodable>(_ path: String, body: Data) async throws -> T {
        let url = try buildURL(path)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body
        return try await perform(request)
    }

    private func perform<T: Decodable>(_ request: URLRequest) async throws -> T {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw EdgeError.transport(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw EdgeError.transport("non-HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw EdgeError.http(statusCode: http.statusCode, body: body.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw EdgeError.decode(error.localizedDescription)
        }
    }

    private func buildURL(_ path: String) throws -> URL {
        // baseURL.appendingPathComponent percent-encodes unsafely for
        // us — bech32 addrs are URL-safe but query strings need raw
        // joining. URLComponents would be safer for arbitrary inputs;
        // for the closed set of paths we use, string concat is fine
        // and avoids the percent-encoding gotchas entirely.
        guard let url = URL(string: baseURL.absoluteString + path) else {
            throw EdgeError.urlConstruction
        }
        return url
    }
}
