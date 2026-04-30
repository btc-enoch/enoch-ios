import XCTest
@testable import EnochCore

/// Live-stack integration tests. Skipped from `swift test` by default;
/// opt in by setting `EDGE_INTEGRATION=1` and pointing `EDGE_URL` at
/// a running edge (default: http://localhost:8081). The tests verify
/// our typed Codable models actually decode the bytes the running
/// edge emits — the layer of trust the URLProtocol unit tests can't
/// give us.
final class EdgeIntegrationTests: XCTestCase {
    override func setUpWithError() throws {
        guard ProcessInfo.processInfo.environment["EDGE_INTEGRATION"] != nil else {
            throw XCTSkip("set EDGE_INTEGRATION=1 to enable; requires running edge + operator")
        }
    }

    private var client: EdgeClient {
        let s = ProcessInfo.processInfo.environment["EDGE_URL"] ?? "http://localhost:8081"
        return EdgeClient(baseURL: URL(string: s)!)
    }

    func testInfoLive() async throws {
        let info = try await client.getInfo()
        XCTAssertFalse(info.edge.version.isEmpty)
        XCTAssertFalse(info.operator.network.isEmpty)
        XCTAssertFalse(info.operator.operatorPubkey.isEmpty)
    }

    func testBalanceLive_unfundedAddress() async throws {
        let pkh = Data(repeating: 0, count: 20)
        let addr = try Address.encodeEnoch(pkh: pkh)
        let bal = try await client.getBalance(address: addr)
        XCTAssertEqual(bal.balanceSatoshi, 0)
        XCTAssertEqual(bal.utxoCount, 0)
    }

    func testFeeOracleLive() async throws {
        do {
            let fee = try await client.getFeeOracle()
            XCTAssertFalse(fee.source.isEmpty)
            XCTAssertGreaterThanOrEqual(fee.ratesSatPerVB.fastest, fee.ratesSatPerVB.minimum)
        } catch EdgeError.http(502, _) {
            throw XCTSkip("fee oracle upstream unreachable — likely offline test env")
        }
    }
}
