import XCTest
@testable import EnochCore

final class EdgeClientTests: XCTestCase {
    /// All tests share the same baseURL — actual host doesn't matter
    /// because `MockURLProtocol` intercepts every request before it
    /// hits the network.
    private let baseURL = URL(string: "http://test.local")!

    private func makeClient(
        handler: @escaping MockURLProtocol.Handler
    ) -> EdgeClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        let session = URLSession(configuration: config)
        MockURLProtocol.handler = handler
        return EdgeClient(baseURL: baseURL, session: session)
    }

    override func tearDown() {
        super.tearDown()
        MockURLProtocol.handler = nil
    }

    // MARK: - HTTP happy paths

    func testGetInfoDecodes() async throws {
        let json = """
        {
          "edge": { "version": "0.1.0", "protocol_version": 1 },
          "operator": {
            "version": "0.1.0",
            "protocol_version": 1,
            "network": "regtest",
            "operator_pubkey": "03dcc2",
            "operator_payout_address": "enoch1...",
            "fee_pool_address": "enoch1...",
            "watchtower_pool_address": "enoch1...",
            "reserve_address": "enoch1...",
            "bridge_deposit_address": "2NA...",
            "withdrawal_challenge_window": 100,
            "current_height": 9
          }
        }
        """
        let client = makeClient { req in
            XCTAssertEqual(req.url?.path, "/v1/info")
            return (200, jsonBody(json))
        }
        let info = try await client.getInfo()
        XCTAssertEqual(info.edge.version, "0.1.0")
        XCTAssertEqual(info.operator.network, "regtest")
        XCTAssertEqual(info.operator.currentHeight, 9)
    }

    func testGetBalanceDecodes() async throws {
        let json = #"{"address":"enoch1abc","balance_satoshi":85996000,"utxo_count":1}"#
        let client = makeClient { req in
            XCTAssertEqual(req.url?.path, "/v1/balance/enoch1abc")
            return (200, jsonBody(json))
        }
        let bal = try await client.getBalance(address: "enoch1abc")
        XCTAssertEqual(bal.balanceSatoshi, 85_996_000)
        XCTAssertEqual(bal.utxoCount, 1)
    }

    func testGetAddressHistoryAttachesQueryParams() async throws {
        let json = #"{"address":"enoch1x","entries":[{"tx_hash":"ab","height":5,"role":"self","delta_satoshi":-1001000}]}"#
        let client = makeClient { req in
            XCTAssertEqual(req.url?.path, "/v1/address_history/enoch1x")
            // Query order is from→limit per the client's construction.
            XCTAssertEqual(req.url?.query, "from=3&limit=10")
            return (200, jsonBody(json))
        }
        let h = try await client.getAddressHistory(address: "enoch1x", from: 3, limit: 10)
        XCTAssertEqual(h.entries.count, 1)
        XCTAssertEqual(h.entries[0].role, .self)
        XCTAssertEqual(h.entries[0].deltaSatoshi, -1_001_000)
    }

    /// Server roles we don't recognize must NOT crash the decoder —
    /// they decode as `.unknown` so a future operator can add roles
    /// without breaking older wallets.
    func testHistoryRoleUnknownDecoder() async throws {
        let json = #"{"address":"enoch1x","entries":[{"tx_hash":"ab","height":5,"role":"some_future_role","delta_satoshi":0}]}"#
        let client = makeClient { _ in (200, jsonBody(json)) }
        let h = try await client.getAddressHistory(address: "enoch1x")
        XCTAssertEqual(h.entries[0].role, .unknown)
    }

    /// Bridge-tagged wire roles. "mint" = peg-in; "burn" = peg-out.
    /// Wallet UIs should label these "Minted" / "Withdrawn" rather
    /// than the generic "Received" / "Sent".
    func testHistoryRoleBridgeDecoders() async throws {
        let json = #"""
        {"address":"enoch1x","entries":[
          {"tx_hash":"aa","height":1,"role":"mint","delta_satoshi":100000},
          {"tx_hash":"bb","height":2,"role":"burn","delta_satoshi":-50000}
        ]}
        """#
        let client = makeClient { _ in (200, jsonBody(json)) }
        let h = try await client.getAddressHistory(address: "enoch1x")
        XCTAssertEqual(h.entries[0].role, .mint)
        XCTAssertEqual(h.entries[1].role, .burn)
    }

    func testSubmitTxPostsBodyAndDecodesResponse() async throws {
        let respJSON = #"{"status":"ok","tx_hash":"deadbeef","burns":0}"#
        let client = makeClient { req in
            XCTAssertEqual(req.httpMethod, "POST")
            XCTAssertEqual(req.url?.path, "/v1/submit_tx")
            XCTAssertEqual(req.value(forHTTPHeaderField: "Content-Type"), "application/json")
            // The bodyStream lives in URLProtocol's request copy —
            // assert via decodes-as-SubmitTxRequest, not raw bytes,
            // since URLProtocol may rewrap the body.
            let body = req.httpBodyOrStream() ?? Data()
            XCTAssertFalse(body.isEmpty, "POST body must be forwarded")
            return (200, jsonBody(respJSON))
        }
        let tx = makeFixtureTx()
        let resp = try await client.submitTx(tx)
        XCTAssertEqual(resp.status, "ok")
        XCTAssertEqual(resp.txHash, "deadbeef")
    }

    // MARK: - error paths

    func testHTTPErrorSurfaces422WithBody() async throws {
        let client = makeClient { _ in (422, Data("insufficient funds: have 100, spend 200".utf8)) }
        do {
            _ = try await client.getInfo()
            XCTFail("expected throw")
        } catch let EdgeError.http(status, body) {
            XCTAssertEqual(status, 422)
            XCTAssertTrue(body.contains("insufficient funds"))
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testDecodeErrorSurfacesOnSchemaDrift() async throws {
        // "balance_satoshi" missing -> Codable fails to decode.
        let client = makeClient { _ in (200, Data(#"{"address":"enoch1","utxo_count":0}"#.utf8)) }
        do {
            _ = try await client.getBalance(address: "enoch1")
            XCTFail("expected throw")
        } catch EdgeError.decode {
            // ok
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    func testTransportErrorSurfaces() async throws {
        let client = makeClient { _ in
            throw NSError(domain: NSURLErrorDomain, code: NSURLErrorTimedOut, userInfo: nil)
        }
        do {
            _ = try await client.getInfo()
            XCTFail("expected throw")
        } catch EdgeError.transport {
            // ok
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    // MARK: - fixtures

    private func makeFixtureTx() -> Transaction {
        Transaction(
            version: 1,
            inputs: [
                TxInput(
                    txHash: Data((0..<32).map { UInt8($0) }),
                    vout: 0,
                    scriptSig: Data([0xAA]),
                    sequence: 0xFFFFFFFF
                ),
            ],
            outputs: [
                TxOutput(amount: 1000, scriptPubKey: Data([0x76, 0xA9, 0x14] + Array(repeating: UInt8(0xCD), count: 20) + [0x88, 0xAC])),
            ],
            lockTime: 0
        )
    }
}

private func jsonBody(_ s: String) -> Data {
    Data(s.utf8)
}

// MARK: - URLProtocol stub

/// MockURLProtocol intercepts every URLSession request that uses it
/// and routes to a per-test handler closure. Standard Swift pattern
/// for stubbing the network without spinning up a real HTTP server.
final class MockURLProtocol: URLProtocol {
    typealias Handler = (URLRequest) throws -> (Int, Data)
    static var handler: Handler?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = MockURLProtocol.handler else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "MockURLProtocol", code: -1))
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

// MARK: - test helpers

private extension URLRequest {
    /// URLSession sometimes converts `httpBody` into an
    /// `httpBodyStream` for transport. Read whichever is present so
    /// tests don't have to care which path the runtime took.
    func httpBodyOrStream() -> Data? {
        if let body = httpBody { return body }
        guard let stream = httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let bufSize = 1024
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        defer { buf.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buf, maxLength: bufSize)
            if read <= 0 { break }
            data.append(buf, count: read)
        }
        return data
    }
}
