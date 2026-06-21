// FederationDirectClientTests — proves the K-of-N cross-check
// semantics defined in spec/ios_active_spv.md §4.9.3.
//
// Strategy: stub the URL protocol so different operator URLs return
// different bodies in the same test run. The mock dispatches on the
// host portion of the request URL — that's how it tells "operator_0"
// from "operator_1" from "operator_2."

import XCTest
@testable import EnochCore

final class FederationDirectClientTests: XCTestCase {
    /// Build a substrate whose URLSession routes all traffic through
    /// the `OperatorRoutingMockProtocol` defined below.
    private func makeSubstrate() -> NetworkSubstrate {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [OperatorRoutingMockProtocol.self]
        let session = URLSession(configuration: config)
        return PlainHTTPSubstrate(session: session)
    }

    /// A 3-operator regtest manifest. The peer URLs use distinct
    /// hostnames so the mock can dispatch by operator.
    private func makeManifest() throws -> FederationManifest {
        try FederationManifest(
            networkName: "regtest",
            operators: [
                FederationManifestOperator(
                    operatorID: 0,
                    identityPub: "00" + String(repeating: "0", count: 62),
                    bip157Peer: "op0.bip157.test:8333",
                    enochPeer: "http://op0.enoch.test:8080"
                ),
                FederationManifestOperator(
                    operatorID: 1,
                    identityPub: "01" + String(repeating: "0", count: 62),
                    bip157Peer: "op1.bip157.test:8333",
                    enochPeer: "http://op1.enoch.test:8080"
                ),
                FederationManifestOperator(
                    operatorID: 2,
                    identityPub: "02" + String(repeating: "0", count: 62),
                    bip157Peer: "op2.bip157.test:8333",
                    enochPeer: "http://op2.enoch.test:8080"
                ),
            ]
        )
    }

    override func tearDown() {
        OperatorRoutingMockProtocol.routes = [:]
        super.tearDown()
    }

    // MARK: - Manifest

    func testManifestRejectsInsufficientOperators() {
        do {
            _ = try FederationManifest(
                networkName: "mainnet",
                operators: [
                    FederationManifestOperator(
                        operatorID: 0,
                        identityPub: "ab",
                        bip157Peer: "x.onion:8333",
                        enochPeer: "y.onion:8080"
                    )
                ]
            )
            XCTFail("expected insufficientOperators")
        } catch FederationManifestError.insufficientOperators(let have, let need) {
            XCTAssertEqual(have, 1)
            XCTAssertEqual(need, 3)
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testManifestRejectsMissingEnochPeer() {
        do {
            _ = try FederationManifest(
                networkName: "regtest",
                operators: [
                    FederationManifestOperator(
                        operatorID: 0, identityPub: "00",
                        bip157Peer: "x:8333", enochPeer: ""
                    ),
                    FederationManifestOperator(
                        operatorID: 1, identityPub: "01",
                        bip157Peer: "y:8333", enochPeer: "y:8080"
                    ),
                    FederationManifestOperator(
                        operatorID: 2, identityPub: "02",
                        bip157Peer: "z:8333", enochPeer: "z:8080"
                    ),
                ]
            )
            XCTFail("expected missingPeerField")
        } catch FederationManifestError.missingPeerField(let id, let field) {
            XCTAssertEqual(id, 0)
            XCTAssertEqual(field, "enoch_peer")
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testManifestRejectsDuplicateOperatorID() {
        do {
            _ = try FederationManifest(
                networkName: "regtest",
                operators: [
                    FederationManifestOperator(
                        operatorID: 0, identityPub: "00",
                        bip157Peer: "a:8333", enochPeer: "a:8080"
                    ),
                    FederationManifestOperator(
                        operatorID: 1, identityPub: "01",
                        bip157Peer: "b:8333", enochPeer: "b:8080"
                    ),
                    FederationManifestOperator(
                        operatorID: 0, identityPub: "02",
                        bip157Peer: "c:8333", enochPeer: "c:8080"
                    ),
                ]
            )
            XCTFail("expected duplicateOperatorID")
        } catch FederationManifestError.duplicateOperatorID(let id) {
            XCTAssertEqual(id, 0)
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    /// Build a balance-response JSON body for the given values. The
    /// snake_case keys mirror what the operator HTTP layer emits
    /// (BalanceResponse's CodingKeys).
    private func balanceJSON(address: String, balanceSatoshi: UInt64, utxoCount: Int) -> Data {
        let s = """
        {"address":"\(address)","balance_satoshi":\(balanceSatoshi),"utxo_count":\(utxoCount)}
        """
        return Data(s.utf8)
    }

    // MARK: - getBalance (cross-check)

    func testGetBalanceAgreement() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )

        let body = balanceJSON(address: "enoch1qexample", balanceSatoshi: 12345, utxoCount: 1)
        for host in ["op0.enoch.test", "op1.enoch.test", "op2.enoch.test"] {
            OperatorRoutingMockProtocol.routes[host] = { _ in (200, body) }
        }

        let result = try await client.getBalance(address: "enoch1qexample")
        switch result {
        case .agreement(let value, let responders):
            XCTAssertEqual(value.balanceSatoshi, 12345)
            XCTAssertEqual(value.utxoCount, 1)
            XCTAssertEqual(Set(responders), Set([0, 1, 2]))
        default:
            XCTFail("expected agreement, got \(result)")
        }
    }

    func testGetBalanceMajorityWithOneDissent() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )

        let majorityBody = balanceJSON(address: "enoch1qexample", balanceSatoshi: 100, utxoCount: 1)
        let dissentBody  = balanceJSON(address: "enoch1qexample", balanceSatoshi: 999, utxoCount: 1)
        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in (200, majorityBody) }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in (200, majorityBody) }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in (200, dissentBody) }

        let result = try await client.getBalance(address: "enoch1qexample")
        switch result {
        case .majority(let value, let agreers, let dissents):
            XCTAssertEqual(value.balanceSatoshi, 100)
            XCTAssertEqual(Set(agreers), Set([0, 1]))
            XCTAssertEqual(dissents.count, 1)
            XCTAssertEqual(dissents.first?.operatorID, 2)
        default:
            XCTFail("expected majority, got \(result)")
        }
    }

    func testGetBalanceNoMajorityWhenAllDisagree() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )

        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in
            (200, self.balanceJSON(address: "enoch1qexample", balanceSatoshi: 100, utxoCount: 1))
        }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in
            (200, self.balanceJSON(address: "enoch1qexample", balanceSatoshi: 200, utxoCount: 1))
        }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in
            (200, self.balanceJSON(address: "enoch1qexample", balanceSatoshi: 300, utxoCount: 1))
        }

        let result = try await client.getBalance(address: "enoch1qexample")
        switch result {
        case .noMajority(let responses):
            XCTAssertEqual(responses.count, 3)
        default:
            XCTFail("expected noMajority, got \(result)")
        }
    }

    func testGetBalanceAllFailedWhenEveryOperatorErrors() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )

        for host in ["op0.enoch.test", "op1.enoch.test", "op2.enoch.test"] {
            OperatorRoutingMockProtocol.routes[host] = { _ in (503, Data()) }
        }

        let result = try await client.getBalance(address: "enoch1qexample")
        switch result {
        case .allFailed(let errors):
            XCTAssertEqual(errors.count, 3)
        default:
            XCTFail("expected allFailed, got \(result)")
        }
    }

    func testGetBalanceMajorityWhenOneOperatorErrors() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )

        let body = balanceJSON(address: "enoch1qexample", balanceSatoshi: 100, utxoCount: 1)
        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in (200, body) }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in (200, body) }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in (500, Data()) }

        let result = try await client.getBalance(address: "enoch1qexample")
        switch result {
        case .majority(let value, let agreers, let dissents):
            XCTAssertEqual(value.balanceSatoshi, 100)
            XCTAssertEqual(Set(agreers), Set([0, 1]))
            XCTAssertEqual(dissents.count, 1)
            XCTAssertEqual(dissents.first?.operatorID, 2)
        default:
            XCTFail("expected majority, got \(result)")
        }
    }

    // MARK: - getUTXOs (cross-check)

    func testGetUTXOsAgreement() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )
        let body = Data(#"""
        {"address":"enoch1qexample","utxos":[
          {"tx_hash":"abcd","vout":0,"amount":1000,"script_pubkey":"5120aa","bond_info":null}
        ]}
        """#.utf8)
        for host in ["op0.enoch.test", "op1.enoch.test", "op2.enoch.test"] {
            OperatorRoutingMockProtocol.routes[host] = { _ in (200, body) }
        }
        let result = try await client.getUTXOs(address: "enoch1qexample")
        guard case .agreement(let value, _) = result else {
            XCTFail("expected agreement, got \(result)"); return
        }
        XCTAssertEqual(value.utxos.count, 1)
        XCTAssertEqual(value.utxos.first?.amount, 1000)
    }

    func testGetUTXOsDissentSurfacesAsMajority() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )
        // Two operators report the same set; one fabricates an extra
        // UTXO. Cross-check catches this as a majority + dissent.
        let truth = Data(#"""
        {"address":"enoch1q","utxos":[
          {"tx_hash":"aa","vout":0,"amount":500,"script_pubkey":"5120aa","bond_info":null}
        ]}
        """#.utf8)
        let lie = Data(#"""
        {"address":"enoch1q","utxos":[
          {"tx_hash":"aa","vout":0,"amount":500,"script_pubkey":"5120aa","bond_info":null},
          {"tx_hash":"bb","vout":0,"amount":999,"script_pubkey":"5120bb","bond_info":null}
        ]}
        """#.utf8)
        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in (200, truth) }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in (200, truth) }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in (200, lie) }

        let result = try await client.getUTXOs(address: "enoch1q")
        guard case .majority(_, let agreers, let dissents) = result else {
            XCTFail("expected majority, got \(result)"); return
        }
        XCTAssertEqual(Set(agreers), Set([0, 1]))
        XCTAssertEqual(dissents.count, 1)
        XCTAssertEqual(dissents.first?.operatorID, 2)
    }

    // MARK: - getAddressHistory (cross-check + query params)

    func testGetAddressHistoryThreadsQueryParams() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )
        let body = Data(#"""
        {"address":"enoch1x","entries":[
          {"tx_hash":"ab","height":5,"role":"self","delta_satoshi":-1001000}
        ]}
        """#.utf8)
        // Each operator asserts it saw the `from` and `limit` query
        // params we threaded in. Catches a regression where the
        // wrapper strips them.
        for host in ["op0.enoch.test", "op1.enoch.test", "op2.enoch.test"] {
            OperatorRoutingMockProtocol.routes[host] = { req in
                XCTAssertTrue(
                    req.url?.absoluteString.contains("from=10") ?? false,
                    "missing from=10 on \(host)"
                )
                XCTAssertTrue(
                    req.url?.absoluteString.contains("limit=5") ?? false,
                    "missing limit=5 on \(host)"
                )
                return (200, body)
            }
        }
        let result = try await client.getAddressHistory(
            address: "enoch1x",
            from: 10,
            limit: 5
        )
        guard case .agreement(let value, _) = result else {
            XCTFail("expected agreement, got \(result)"); return
        }
        XCTAssertEqual(value.entries.count, 1)
    }

    // MARK: - getPendingWithdrawals (cross-check)

    func testGetPendingWithdrawalsAgreement() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )
        let body = Data(#"{"withdrawals":[]}"#.utf8)
        for host in ["op0.enoch.test", "op1.enoch.test", "op2.enoch.test"] {
            OperatorRoutingMockProtocol.routes[host] = { _ in (200, body) }
        }
        let result = try await client.getPendingWithdrawals()
        guard case .agreement(let value, _) = result else {
            XCTFail("expected agreement, got \(result)"); return
        }
        XCTAssertTrue(value.withdrawals.isEmpty)
    }

    // MARK: - submitTx (single-operator with retry)

    func testSubmitTxRetriesOn5xx() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )
        let success = Data(#"""
        {"status":"accepted","tx_hash":"deadbeef","burns":0}
        """#.utf8)
        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in (503, Data("svc unavailable".utf8)) }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in (200, success) }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in (200, success) }

        let tx = sampleTx()
        let resp = try await client.submitTx(tx)
        XCTAssertEqual(resp.status, "accepted")
        XCTAssertEqual(resp.txHash, "deadbeef")
    }

    func testSubmitTxDoesNotRetryOn4xx() async throws {
        let manifest = try makeManifest()
        let substrate = makeSubstrate()
        let client = try FederationDirectClient(
            manifest: manifest,
            substrate: substrate
        )
        // op0 returns 422 (insufficient funds); the wallet must NOT
        // try op1. Retrying a request-shape error wastes operator
        // capacity and could be a fingerprint vector.
        var op1Tries = 0
        OperatorRoutingMockProtocol.routes["op0.enoch.test"] = { _ in (422, Data("insufficient funds".utf8)) }
        OperatorRoutingMockProtocol.routes["op1.enoch.test"] = { _ in
            op1Tries += 1
            return (200, Data())
        }
        OperatorRoutingMockProtocol.routes["op2.enoch.test"] = { _ in (200, Data()) }

        let tx = sampleTx()
        do {
            _ = try await client.submitTx(tx)
            XCTFail("expected L2ClientError.http")
        } catch L2ClientError.http(let code, let body) {
            XCTAssertEqual(code, 422)
            XCTAssertEqual(body, "insufficient funds")
        }
        XCTAssertEqual(op1Tries, 0, "4xx must NOT trigger next-operator retry")
    }

    private func sampleTx() -> Tx {
        // A minimal Tx the encoder can serialise. The wire payload
        // doesn't have to be a valid Enoch tx — submitTx tests only
        // exercise the HTTP wrapper, not consensus.
        Tx(
            version: 1,
            inputs: [],
            outputs: [],
            lockTime: 0
        )
    }
}

// MARK: - Mock that dispatches per operator hostname

/// URLProtocol stub that routes per request hostname so a single
/// URLSession can simulate N operator endpoints. The routes table
/// is keyed by `request.url?.host` — when a request comes in the
/// matching handler builds the response.
final class OperatorRoutingMockProtocol: URLProtocol {
    typealias Handler = (URLRequest) throws -> (Int, Data)
    static var routes: [String: Handler] = [:]

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let host = request.url?.host ?? ""
        guard let handler = OperatorRoutingMockProtocol.routes[host] else {
            client?.urlProtocol(
                self,
                didFailWithError: NSError(
                    domain: "OperatorRoutingMockProtocol",
                    code: 1,
                    userInfo: [
                        NSLocalizedDescriptionKey: "no route for host=\(host)"
                    ]
                )
            )
            return
        }
        do {
            let (status, body) = try handler(request)
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
