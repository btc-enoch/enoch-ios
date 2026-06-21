import XCTest
@testable import EnochCore

/// Live-stack integration tests for FederationDirectClient against
/// the bundled regtest manifest (3 operators on
/// 127.0.0.1:18080/18081/18082). Auto-skipped when op-0 is
/// unreachable, so the tests run on dev machines with
/// `make federation-up` running and quietly no-op on CI / clean
/// checkouts.
///
/// The unit tests in FederationDirectClientTests cover wire-shape
/// behaviour with mocked URLProtocol; these cover the actual operator
/// `/v1/*` aliases over real loopback HTTP — the layer mocks can't
/// give us (TLS off, plain `http://`, real bech32 parsing, real
/// Codable decoding against the wire bytes the operator emits).
final class FederationDirectIntegrationTests: XCTestCase {
    override func setUp() async throws {
        // Probe op-0 once; if it can't be reached we skip rather than
        // fail. Same gate works under `swift test` (macOS) and
        // `xcodebuild test -destination iOS Simulator` — the simulator
        // shares the host's loopback so 127.0.0.1:18080 is the same
        // bitcoind compose stack in both contexts.
        let url = URL(string: "http://127.0.0.1:18080/v1/info")!
        var req = URLRequest(url: url)
        req.timeoutInterval = 2
        do {
            let (_, response) = try await URLSession.shared.data(for: req)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else {
                throw XCTSkip("op-0 at 127.0.0.1:18080 didn't return 200; run `make federation-up`")
            }
        } catch let skip as XCTSkip {
            throw skip
        } catch {
            throw XCTSkip("op-0 at 127.0.0.1:18080 unreachable (\(error)); run `make federation-up`")
        }
    }

    private func makeClient() throws -> FederationDirectClient {
        try FederationDirectClient(
            manifest: .bundledRegtest(),
            substrate: PlainHTTPSubstrate()
        )
    }

    /// First-reachable smoke: at least one operator must answer /v1/info.
    func testGetInfoLive() async throws {
        let client = try makeClient()
        let info = try await client.getInfo()
        XCTAssertEqual(info.network, "regtest")
        XCTAssertFalse(info.operatorPubkey.isEmpty)
    }

    /// K-of-N cross-check on an unfunded address — every operator MUST
    /// report 0 balance, so we expect `.agreement`. If we see
    /// `.majority` here something has drifted between ops.
    func testGetBalanceUnfundedAgreement() async throws {
        let client = try makeClient()
        let pkh = Data(repeating: 0, count: 20)
        let addr = try Address.encodeEnoch(pkh: pkh)
        let result = try await client.getBalance(address: addr)
        switch result {
        case .agreement(let agreement):
            XCTAssertEqual(agreement.value.balanceSatoshi, 0)
            XCTAssertEqual(agreement.value.utxoCount, 0)
        case .majority(_, _, let dissents):
            let labels = dissents.map { "op \($0.operatorID)" }.joined(separator: ", ")
            XCTFail("expected agreement on unfunded balance — dissents: \(labels)")
        case .noMajority(let responses):
            XCTFail("no majority on unfunded balance: \(responses.count) distinct values")
        case .allFailed(let errors):
            let labels = errors.map { resp -> String in
                if case .failure(let err) = resp.outcome { return "op \(resp.operatorID): \(err)" }
                return "op \(resp.operatorID): <no error>"
            }.joined(separator: ", ")
            XCTFail("every operator errored: \(labels)")
        }
    }

    /// Same cross-check shape for utxos — unfunded address → empty
    /// list everywhere → `.agreement`.
    func testGetUTXOsUnfundedAgreement() async throws {
        let client = try makeClient()
        let pkh = Data(repeating: 0, count: 20)
        let addr = try Address.encodeEnoch(pkh: pkh)
        let result = try await client.getUTXOs(address: addr)
        switch result {
        case .agreement(let agreement):
            XCTAssertTrue(agreement.value.utxos.isEmpty)
        case .majority(_, _, let dissents):
            let labels = dissents.map { "op \($0.operatorID)" }.joined(separator: ", ")
            XCTFail("expected agreement on unfunded utxos — dissents: \(labels)")
        case .noMajority(let responses):
            XCTFail("no majority on unfunded utxos: \(responses.count) distinct values")
        case .allFailed(let errors):
            let labels = errors.map { resp -> String in
                if case .failure(let err) = resp.outcome { return "op \(resp.operatorID): \(err)" }
                return "op \(resp.operatorID): <no error>"
            }.joined(separator: ", ")
            XCTFail("every operator errored: \(labels)")
        }
    }

    /// Address history for an unfunded address — same agreement
    /// expectation.
    func testGetAddressHistoryUnfundedAgreement() async throws {
        let client = try makeClient()
        let pkh = Data(repeating: 0, count: 20)
        let addr = try Address.encodeEnoch(pkh: pkh)
        let result = try await client.getAddressHistory(
            address: addr,
            from: nil,
            limit: nil
        )
        switch result {
        case .agreement(let agreement):
            XCTAssertTrue(agreement.value.entries.isEmpty)
        case .majority(_, _, let dissents):
            let labels = dissents.map { "op \($0.operatorID)" }.joined(separator: ", ")
            XCTFail("expected agreement on unfunded history — dissents: \(labels)")
        case .noMajority:
            XCTFail("no majority on unfunded address history")
        case .allFailed(let errors):
            let labels = errors.map { resp -> String in
                if case .failure(let err) = resp.outcome { return "op \(resp.operatorID): \(err)" }
                return "op \(resp.operatorID): <no error>"
            }.joined(separator: ", ")
            XCTFail("every operator errored: \(labels)")
        }
    }

    /// Pending withdrawals cross-check (no path parameter — different
    /// route shape; exercises the second handler class).
    func testGetPendingWithdrawalsLive() async throws {
        let client = try makeClient()
        let result = try await client.getPendingWithdrawals()
        switch result {
        case .agreement, .majority:
            return // either is acceptable; we just want to see the call land
        case .noMajority(let responses):
            XCTFail("pending withdrawals split — \(responses.count) distinct values")
        case .allFailed(let errors):
            let labels = errors.map { resp -> String in
                if case .failure(let err) = resp.outcome { return "op \(resp.operatorID): \(err)" }
                return "op \(resp.operatorID): <no error>"
            }.joined(separator: ", ")
            XCTFail("every operator errored: \(labels)")
        }
    }
}
