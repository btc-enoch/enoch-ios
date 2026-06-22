import XCTest
@testable import EnochCore

/// Verifies that FederationDirectL2Client's `collapse` step forwards
/// every cross-check outcome to its DissentSink — including the
/// `.agreement` case, which the wallet uses to clear prior dissent.
///
/// Lives in its own file because Slice F (#371) is the first time the
/// L2Client surface produced telemetry callbacks; future
/// dissent-sink contracts (auto A6, reconciliation UX) will live
/// alongside these basic plumbing tests.
final class FederationDissentTests: XCTestCase {

    /// Capture sink for tests. Conforms via main-actor hop just like
    /// WalletStore does in production.
    final class CapturingSink: DissentSink {
        private let lock = NSLock()
        private var records: [FederationDissentRecord] = []

        func record(_ event: FederationDissentRecord) {
            lock.lock()
            records.append(event)
            lock.unlock()
        }

        var snapshot: [FederationDissentRecord] {
            lock.lock()
            defer { lock.unlock() }
            return records
        }
    }

    // MARK: - WalletStore.applyDissent (in-memory bookkeeping)

    /// Slice F bookkeeping invariant: a fresh outcome wholly replaces
    /// any prior record for the same op. Two majority records for
    /// "balance" in sequence yield exactly one entry in `dissents`.
    @MainActor
    func testApplyDissentReplacesPerOp() throws {
        let store = try makeStore()
        store.applyDissent(.init(op: "balance", kind: .majority(dissenters: [1]), timestamp: Date()))
        store.applyDissent(.init(op: "balance", kind: .majority(dissenters: [2]), timestamp: Date()))
        XCTAssertEqual(store.dissents.count, 1)
        XCTAssertEqual(store.dissents[0].op, "balance")
        guard case .majority(let ids) = store.dissents[0].kind else {
            XCTFail("expected .majority kind"); return
        }
        XCTAssertEqual(ids, [2])
    }

    /// `.agreement` is the clear-signal. After a majority dissent on
    /// "balance", a subsequent agreement on "balance" must remove the
    /// record entirely.
    @MainActor
    func testAgreementClearsPriorDissent() throws {
        let store = try makeStore()
        store.applyDissent(.init(op: "balance", kind: .majority(dissenters: [1]), timestamp: Date()))
        store.applyDissent(.init(op: "balance", kind: .agreement, timestamp: Date()))
        XCTAssertTrue(store.dissents.isEmpty)
    }

    /// Per-op isolation: a dissent on "balance" stays put when
    /// "utxos" later reports agreement. Each op clears independently.
    @MainActor
    func testAgreementOnOneOpDoesNotClearAnother() throws {
        let store = try makeStore()
        store.applyDissent(.init(op: "balance", kind: .majority(dissenters: [1]), timestamp: Date()))
        store.applyDissent(.init(op: "utxos", kind: .agreement, timestamp: Date()))
        XCTAssertEqual(store.dissents.map(\.op), ["balance"])
    }

    // MARK: - spendsBlockedByDissent

    /// `.majority` is a soft warning, not a spend-blocker. Sends and
    /// withdraws stay enabled.
    @MainActor
    func testMajorityDoesNotBlockSpends() throws {
        let store = try makeStore()
        store.applyDissent(.init(op: "balance", kind: .majority(dissenters: [1]), timestamp: Date()))
        XCTAssertFalse(store.spendsBlockedByDissent)
    }

    /// `.noMajority` blocks spends — the federation can't agree on
    /// the wallet's state, so we can't trust any balance figure for
    /// the fee/availability check.
    @MainActor
    func testNoMajorityBlocksSpends() throws {
        let store = try makeStore()
        store.applyDissent(.init(op: "balance", kind: .noMajority(distinctCount: 3), timestamp: Date()))
        XCTAssertTrue(store.spendsBlockedByDissent)
    }

    /// `.allFailed` also blocks — we have no signal at all.
    @MainActor
    func testAllFailedBlocksSpends() throws {
        let store = try makeStore()
        store.applyDissent(.init(op: "pending_withdrawals", kind: .allFailed, timestamp: Date()))
        XCTAssertTrue(store.spendsBlockedByDissent)
    }

    // MARK: - FederationDirectL2Client emits on collapse

    /// The integration path: a CapturingSink wired to a real
    /// FederationDirectL2Client receives one record per
    /// cross-checked call. We exercise `.agreement` (the happy path
    /// via the URLProtocol mocks set up identically across 3 ops).
    ///
    /// FederationDirectClient internals use OperatorRoutingMockProtocol
    /// — the same harness FederationDirectClientTests use for unit
    /// coverage of cross-check outcomes. We just plug a sink in and
    /// confirm the side-effect.
    func testAgreementEmitsRecord() async throws {
        let sink = CapturingSink()
        let direct = try makeFederationDirectClient()
        let l2 = FederationDirectL2Client(direct, dissentSink: sink)

        let body = balanceJSON(address: "enoch1abc", balanceSatoshi: 0, utxoCount: 0)
        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in (200, body) }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in (200, body) }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in (200, body) }

        _ = try await l2.getBalance(address: "enoch1abc")
        XCTAssertEqual(sink.snapshot.count, 1)
        XCTAssertEqual(sink.snapshot.first?.op, "balance")
        if case .agreement = sink.snapshot.first?.kind {} else {
            XCTFail("expected .agreement kind")
        }
    }

    /// A single dissenting op produces a `.majority` record naming
    /// the wrong operator. The call still succeeds (majority wins).
    func testMajorityEmitsRecordWithDissenter() async throws {
        let sink = CapturingSink()
        let direct = try makeFederationDirectClient()
        let l2 = FederationDirectL2Client(direct, dissentSink: sink)

        let agreed = balanceJSON(address: "enoch1abc", balanceSatoshi: 100, utxoCount: 1)
        let lying  = balanceJSON(address: "enoch1abc", balanceSatoshi: 999, utxoCount: 1)
        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in (200, agreed) }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in (200, agreed) }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in (200, lying) }

        let result = try await l2.getBalance(address: "enoch1abc")
        XCTAssertEqual(result.balanceSatoshi, 100, "majority should win")
        XCTAssertEqual(sink.snapshot.count, 1)
        guard case .majority(let dissenters) = sink.snapshot.first?.kind else {
            XCTFail("expected .majority kind")
            return
        }
        XCTAssertEqual(dissenters, [2], "operator 2 was the liar")
    }

    /// `.noMajority` records the distinct-count and throws. The sink
    /// sees the record even though the call surface raised an error.
    func testNoMajorityEmitsRecordEvenWhenThrowing() async throws {
        let sink = CapturingSink()
        let direct = try makeFederationDirectClient()
        let l2 = FederationDirectL2Client(direct, dissentSink: sink)

        let b0 = balanceJSON(address: "enoch1abc", balanceSatoshi: 10, utxoCount: 1)
        let b1 = balanceJSON(address: "enoch1abc", balanceSatoshi: 20, utxoCount: 1)
        let b2 = balanceJSON(address: "enoch1abc", balanceSatoshi: 30, utxoCount: 1)
        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in (200, b0) }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in (200, b1) }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in (200, b2) }

        do {
            _ = try await l2.getBalance(address: "enoch1abc")
            XCTFail("expected throw")
        } catch L2ClientError.transport {
            // expected
        }
        XCTAssertEqual(sink.snapshot.count, 1)
        guard case .noMajority(let n) = sink.snapshot.first?.kind else {
            XCTFail("expected .noMajority kind")
            return
        }
        XCTAssertEqual(n, 3)
    }

    /// Every operator returning 5xx → `.allFailed`. Same shape: sink
    /// receives one record, call surface raises.
    func testAllFailedEmitsRecordEvenWhenThrowing() async throws {
        let sink = CapturingSink()
        let direct = try makeFederationDirectClient()
        let l2 = FederationDirectL2Client(direct, dissentSink: sink)

        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in (500, Data()) }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in (500, Data()) }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in (500, Data()) }

        do {
            _ = try await l2.getBalance(address: "enoch1abc")
            XCTFail("expected throw")
        } catch L2ClientError.transport {
            // expected
        }
        XCTAssertEqual(sink.snapshot.count, 1)
        if case .allFailed = sink.snapshot.first?.kind {} else {
            XCTFail("expected .allFailed kind")
        }
    }

    // MARK: - Helpers

    /// In-memory WalletStore for the bookkeeping tests. We use the
    /// `InMemoryWalletKeystore` and a dummy L2 client — the sink
    /// path doesn't touch the network in these cases.
    @MainActor
    private func makeStore() throws -> WalletStore {
        let direct = try makeFederationDirectClient()
        let l2 = FederationDirectL2Client(direct)
        return WalletStore(keystore: InMemoryWalletKeystore(), client: l2)
    }

    /// Build a 3-operator FederationDirectClient wired to the same
    /// URLProtocol harness FederationDirectClientTests uses. Operator
    /// hostnames match the patterns the mock dispatches on.
    private func makeFederationDirectClient() throws -> FederationDirectClient {
        let ops = [
            FederationManifestOperator(
                operatorID: 0,
                identityPub: "0001",
                bip157Peer: "bip157.op0.test:18444",
                enochPeer: "http://op0.enoch.test"
            ),
            FederationManifestOperator(
                operatorID: 1,
                identityPub: "0002",
                bip157Peer: "bip157.op1.test:18444",
                enochPeer: "http://op1.enoch.test"
            ),
            FederationManifestOperator(
                operatorID: 2,
                identityPub: "0003",
                bip157Peer: "bip157.op2.test:18444",
                enochPeer: "http://op2.enoch.test"
            ),
        ]
        let manifest = try FederationManifest(networkName: "regtest", operators: ops)
        OperatorRoutingMockProtocol.routes.removeAll()
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [OperatorRoutingMockProtocol.self]
        let substrate = PlainHTTPSubstrate(session: URLSession(configuration: config))
        return try FederationDirectClient(manifest: manifest, substrate: substrate)
    }

    private func balanceJSON(address: String, balanceSatoshi: UInt64, utxoCount: Int) -> Data {
        let s = """
        {"address":"\(address)","balance_satoshi":\(balanceSatoshi),"utxo_count":\(utxoCount)}
        """
        return Data(s.utf8)
    }
}
