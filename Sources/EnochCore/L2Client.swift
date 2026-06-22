// L2Client — the wallet's view of the federation's L2 HTTP/SSE surface.
//
// Only one concrete conformer post-edge-deprecation (spec §4.9):
// `FederationDirectL2Client` — talks directly to each operator's
// `enoch_peer` onion, with K-of-N cross-check on read queries and
// manifest-order retry on submit_tx.
//
// WalletStore depends on this protocol (not on a concrete client) so
// tests can inject a mock and an eventual Tor-substrate variant can
// drop in without churning every call site.

import Foundation

/// The L2 surface the wallet's view layer consumes.
///
/// Cross-check semantics live INSIDE the concrete conformer, not in
/// the protocol: dissent detection, majority-with-warning, and
/// no-majority-throw are all `FederationDirectL2Client`'s job, so the
/// wallet view code stays uniform.
public protocol L2Client: AnyObject {
    func getInfo() async throws -> OperatorInfo
    func getBalance(address: String) async throws -> BalanceResponse
    func getUTXOs(address: String) async throws -> UTXOsResponse
    func getAddressHistory(
        address: String,
        from: UInt64?,
        limit: UInt64?
    ) async throws -> AddressHistoryResponse
    func getPendingWithdrawals() async throws -> PendingWithdrawalsResponse
    func submitTx(_ tx: Tx) async throws -> SubmitTxResponse
    func eventStream(filter: [String]) -> AsyncThrowingStream<EdgeEvent, Swift.Error>
}

/// Adapter from `FederationDirectClient`'s `CrossCheckResult`-returning
/// methods to the `L2Client` throw-or-value shape.
///
/// Dissent handling for v1:
///   • `.agreement(v, _)` → return v.
///   • `.majority(v, _, dissents)` → return v, log the dissent set.
///     Proper UX surface (warning banner naming dissenting operators)
///     is a Slice F follow-up.
///   • `.noMajority(_)` → throw `L2ClientError.transport` with a
///     federation-inconsistency tag. The wallet shows the
///     reconciliation UX (spec §7).
///   • `.allFailed(_)` → throw `L2ClientError.transport`. Wallet shows
///     offline UX.
public final class FederationDirectL2Client: L2Client {
    public let inner: FederationDirectClient

    /// Receives a FederationDissentRecord for every cross-checked
    /// call — including `.agreement` outcomes, which act as a
    /// clear-signal for any prior dissent on the same op. Held
    /// `weak` because the wallet store owns the L2Client and
    /// conforms to DissentSink; a strong reverse reference would
    /// cycle.
    ///
    /// Optional: when nil, dissent outcomes are silently collapsed
    /// (the previous behaviour). All FederationDirectL2Client tests
    /// that don't care about dissent surfacing leave this nil.
    public weak var dissentSink: DissentSink?

    public init(_ inner: FederationDirectClient, dissentSink: DissentSink? = nil) {
        self.inner = inner
        self.dissentSink = dissentSink
    }

    public func getInfo() async throws -> OperatorInfo {
        try await inner.getInfo()
    }

    public func getBalance(address: String) async throws -> BalanceResponse {
        try collapse(try await inner.getBalance(address: address), op: "balance")
    }

    public func getUTXOs(address: String) async throws -> UTXOsResponse {
        try collapse(try await inner.getUTXOs(address: address), op: "utxos")
    }

    public func getAddressHistory(
        address: String,
        from: UInt64?,
        limit: UInt64?
    ) async throws -> AddressHistoryResponse {
        try collapse(
            try await inner.getAddressHistory(address: address, from: from, limit: limit),
            op: "address_history"
        )
    }

    public func getPendingWithdrawals() async throws -> PendingWithdrawalsResponse {
        try collapse(try await inner.getPendingWithdrawals(), op: "pending_withdrawals")
    }

    public func submitTx(_ tx: Tx) async throws -> SubmitTxResponse {
        try await inner.submitTx(tx)
    }

    public func eventStream(filter: [String]) -> AsyncThrowingStream<EdgeEvent, Swift.Error> {
        inner.eventStream(filter: filter)
    }

    /// Collapse a CrossCheckResult to a single value or a typed
    /// error. Naming the call site (`op`) keeps the resulting error
    /// messages actionable in logs and matches the `op` field on the
    /// FederationDissentRecord the sink receives.
    ///
    /// Emits exactly one record to `dissentSink` per call — including
    /// `.agreement` outcomes, which the sink uses to clear any prior
    /// dissent it was holding for this op. This means a transient
    /// dissent (one bad refresh tick) self-clears as soon as the
    /// federation reaches agreement again.
    private func collapse<T>(
        _ result: CrossCheckResult<T>,
        op: String
    ) throws -> T {
        let now = Date()
        switch result {
        case .agreement(let value, _):
            dissentSink?.record(.init(op: op, kind: .agreement, timestamp: now))
            return value
        case .majority(let value, _, let dissents):
            let ids = dissents.map { $0.operatorID }
            dissentSink?.record(.init(op: op, kind: .majority(dissenters: ids), timestamp: now))
            return value
        case .noMajority(let responses):
            dissentSink?.record(.init(op: op, kind: .noMajority(distinctCount: responses.count), timestamp: now))
            throw L2ClientError.transport(
                "federation: no majority on \(op) (\(responses.count) distinct responses)"
            )
        case .allFailed(let errors):
            dissentSink?.record(.init(op: op, kind: .allFailed, timestamp: now))
            throw L2ClientError.transport(
                "federation: all operators failed on \(op) (\(errors.count) errors)"
            )
        }
    }
}
