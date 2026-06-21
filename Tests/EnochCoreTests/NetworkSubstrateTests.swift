import XCTest
@testable import EnochCore

final class NetworkSubstrateTests: XCTestCase {

    /// PlainHTTPSubstrate with no arguments returns URLSession.shared.
    /// EdgeClient's default-substrate path depends on this — the
    /// no-args wallet bring-up keeps using the shared session.
    func testPlainHTTPDefaultsToSharedSession() {
        let sub = PlainHTTPSubstrate()
        XCTAssertTrue(sub.urlSession === URLSession.shared)
        XCTAssertEqual(sub.description, "plainhttp")
    }

    /// PlainHTTPSubstrate honors an injected URLSession verbatim.
    /// Used by test code (MockURLProtocol) to swap in a mocked
    /// transport without going through a real network call.
    func testPlainHTTPHonorsInjectedSession() {
        let config = URLSessionConfiguration.ephemeral
        let custom = URLSession(configuration: config)
        let sub = PlainHTTPSubstrate(session: custom)
        XCTAssertTrue(sub.urlSession === custom)
    }

    /// PlainHTTPSubstrate.close() is safe on the shared session
    /// (which can't be invalidated). The substrate must not crash;
    /// the shared session must remain usable for other code.
    func testPlainHTTPCloseSafeOnSharedSession() {
        let sub = PlainHTTPSubstrate()
        sub.close()
        sub.close() // idempotent
        // URLSession.shared still usable after substrate close.
        XCTAssertNotNil(URLSession.shared.configuration)
    }

    /// #83-S7 mainnet refusal: throwing init with network:"mainnet"
    /// and no opt-in must throw .plainHTTPRefusedOnMainnet. Mirrors
    /// the Go-side ErrPlainHTTPRefusedOnMainnet sentinel — a wallet
    /// shipping with mainnet defaults must NOT silently use PlainHTTP
    /// and leak client IPs to operators.
    func testPlainHTTPRefusesMainnetWithoutOptIn() {
        do {
            _ = try PlainHTTPSubstrate(network: "mainnet")
            XCTFail("expected SubstrateError.plainHTTPRefusedOnMainnet")
        } catch SubstrateError.plainHTTPRefusedOnMainnet {
            // expected
        } catch {
            XCTFail("expected .plainHTTPRefusedOnMainnet, got \(error)")
        }
    }

    /// Honest mainnet+plainhttp deployments (self-hosted edge inside
    /// a trusted network, system-Tor where privacy comes from below
    /// the substrate) opt in with allowOnMainnet: true. Init must
    /// succeed and the description must encode the network for log
    /// inspection.
    func testPlainHTTPAllowsMainnetWithOptIn() throws {
        let sub = try PlainHTTPSubstrate(network: "mainnet", allowOnMainnet: true)
        XCTAssertEqual(sub.description, "plainhttp:mainnet")
        sub.close()
    }

    /// Mainnet refusal is mainnet-specific: regtest, signet, testnet
    /// all pass without opt-in.
    func testPlainHTTPAllowsNonMainnetWithoutOptIn() throws {
        for network in ["regtest", "signet", "testnet"] {
            let sub = try PlainHTTPSubstrate(network: network)
            XCTAssertEqual(sub.description, "plainhttp:\(network)")
            sub.close()
        }
    }

    /// TorSubstrate is intentionally not yet implemented. Construction
    /// must throw SubstrateError.notImplemented so a wallet
    /// misconfigured to use Tor fails loudly at boot rather than
    /// silently using PlainHTTP. The error message must mention the
    /// follow-up slice (#83-S6b) so the failure is actionable.
    func testTorSubstrateThrowsNotImplemented() {
        do {
            _ = try TorSubstrate(socksHost: "127.0.0.1", socksPort: 9050)
            XCTFail("expected SubstrateError.notImplemented")
        } catch let err as SubstrateError {
            guard case .notImplemented(let message) = err else {
                XCTFail("expected .notImplemented, got \(err)")
                return
            }
            XCTAssertTrue(message.contains("#83-S6b"))
            XCTAssertTrue(message.contains("9050"))
        } catch {
            XCTFail("expected SubstrateError, got \(error)")
        }
    }

}
