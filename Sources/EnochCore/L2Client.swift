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

    public init(_ inner: FederationDirectClient) {
        self.inner = inner
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
    /// messages actionable in logs.
    private func collapse<T>(
        _ result: CrossCheckResult<T>,
        op: String
    ) throws -> T {
        switch result {
        case .agreement(let value, _):
            return value
        case .majority(let value, _, let dissents):
            // TODO(Slice F): surface to UI. For now, print so it's
            // visible in dev. Mainnet builds get a warning UX
            // before this lint flag is removed.
            print("federation: dissent on \(op) — \(dissents.count) operator(s) disagreed")
            return value
        case .noMajority(let responses):
            throw L2ClientError.transport(
                "federation: no majority on \(op) (\(responses.count) distinct responses)"
            )
        case .allFailed(let errors):
            throw L2ClientError.transport(
                "federation: all operators failed on \(op) (\(errors.count) errors)"
            )
        }
    }
}
