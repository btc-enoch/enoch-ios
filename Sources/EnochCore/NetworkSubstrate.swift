// NetworkSubstrate — Swift mirror of the Go federation/substrate
// abstraction in the enoch repo. The wallet's outbound HTTP traffic
// to each operator's onion rides on a substrate-provided URLSession;
// swapping the substrate at boot swaps the privacy property (direct
// HTTP → Tor SOCKS → eventually Sphinx) without changing any wallet
// code.
//
// Why a "provider" shape rather than a 1:1 binding of the Go
// NetworkSubstrate interface (SubmitTx/Subscribe/Query):
//
// FederationDirectClient has HTTP-application logic — status-code-
// based error surfacing (`.http(statusCode: 422, body: "insufficient
// funds")`), JSON envelope decoding, SSE framing — that doesn't fit
// cleanly above an abstract submitTx/query interface. Same impedance
// mismatch as the Go side: we keep the application logic in
// FederationDirectClient and let the substrate provide the
// *transport* (the URLSession). The privacy property lives in the
// transport.
//
// When Sphinx ships, this protocol needs a different shape — a
// Sphinx substrate can't return a URLSession because there's no
// HTTP layer. At that point we either:
//   (a) add submitTx/subscribe/query methods to this protocol that
//       only Sphinx implements; or
//   (b) ship a Sphinx-to-HTTP shim that wraps the mixnet behind a
//       synthetic URLSession.
// Both are deferred. spec/network_substrate.md §4 in the enoch repo
// documents the Go-side rationale; the Swift side follows it.
//
// Anti-rot: the wallet must NEVER import a Tor framework directly
// outside the TorSubstrate implementation. When iOS Tor lands, a
// matching lint script will enforce this — same discipline as the
// Go side's scripts/check_substrate_boundary.sh.

import Foundation

/// The wallet's pluggable network transport. Provides a configured
/// URLSession for HTTP-based substrates; future non-HTTP substrates
/// (Sphinx) will extend this protocol.
public protocol NetworkSubstrate: AnyObject {
    /// The URLSession EdgeClient should use for all outbound HTTP.
    /// For PlainHTTPSubstrate this is a default-configured session;
    /// for TorSubstrate it's a session whose transport routes
    /// through a SOCKS5 proxy.
    var urlSession: URLSession { get }

    /// Human-readable substrate identifier shown in logs / debug UI.
    /// "plainhttp", "tor:onion-via-127.0.0.1:9050", etc.
    var description: String { get }

    /// Releases substrate-held resources (Tor circuits, session
    /// state). Calling after close() returns immediately; calling
    /// urlSession after close() returns the released session (whose
    /// behavior is undefined). Idempotent.
    func close()
}

/// Default substrate — direct HTTP via URLSession. No privacy
/// property. Fine for regtest and for trusted-network deployments;
/// the production wallet on mainnet should default to a TorSubstrate
/// once that ships (#83-S6b).
///
/// Mainnet refusal: if you try to construct PlainHTTPSubstrate with
/// network: "mainnet" without allowOnMainnet: true, init throws
/// SubstrateError.plainHTTPRefusedOnMainnet. This mirrors the Go-side
/// safety gate in federation/substrate/plainhttp/plainhttp.go — a
/// wallet shipped to a real user with mainnet config defaulting to
/// PlainHTTP would silently leak the user's IP to every operator on
/// every payment, and that's worth failing loudly at boot to prevent.
public final class PlainHTTPSubstrate: NetworkSubstrate {
    public let urlSession: URLSession
    public let description: String

    /// Non-throwing convenience initializer for the dev / regtest /
    /// no-network-context path. `session` defaults to `.shared`; tests
    /// inject a mocked URLSession backed by a custom URLProtocol.
    ///
    /// Use the throwing `init(session:network:allowOnMainnet:)` when
    /// the caller knows what Bitcoin network it's running against —
    /// that's the path where mainnet refusal applies.
    public init(session: URLSession = .shared) {
        self.urlSession = session
        self.description = "plainhttp"
    }

    /// Throwing, network-aware initializer.
    ///
    /// `network` names the Bitcoin network — "regtest" / "signet" /
    /// "testnet" / "mainnet". If "mainnet" and `allowOnMainnet` is
    /// false (default), init throws `.plainHTTPRefusedOnMainnet`.
    ///
    /// `allowOnMainnet: true` opts the caller into PlainHTTP on
    /// mainnet. Required for: self-hosted edge inside a trusted
    /// network (corporate VPN), system-Tor deployments where privacy
    /// comes from below the substrate. Honest callers opt in with
    /// one parameter; misconfigured wallets fail loudly.
    public init(
        session: URLSession = .shared,
        network: String,
        allowOnMainnet: Bool = false
    ) throws {
        if network == "mainnet" && !allowOnMainnet {
            throw SubstrateError.plainHTTPRefusedOnMainnet
        }
        self.urlSession = session
        self.description = network.isEmpty ? "plainhttp" : "plainhttp:\(network)"
    }

    public func close() {
        // URLSession.shared can't be invalidated; non-shared
        // sessions get finishTasksAndInvalidate so in-flight
        // requests complete cleanly.
        if urlSession !== URLSession.shared {
            urlSession.finishTasksAndInvalidate()
        }
    }
}

/// Errors specific to substrate construction or use.
public enum SubstrateError: Swift.Error, Equatable {
    /// The requested substrate kind exists in the type system but is
    /// not yet implemented for this platform. iOS Tor returns this
    /// until the embed strategy (OnionKit / Arti / system Tor) is
    /// chosen and integrated — see #83-S6b.
    case notImplemented(String)

    /// Substrate was used after close().
    case closed

    /// PlainHTTPSubstrate construction refused because the configured
    /// network is "mainnet" and allowOnMainnet was not set. Mirrors
    /// the Go-side ErrPlainHTTPRefusedOnMainnet sentinel.
    case plainHTTPRefusedOnMainnet
}

/// Tor substrate stub. iOS Tor integration is deferred to a
/// follow-up slice (#83-S6b) because the embedding strategy is a
/// real platform-engineering decision:
///   - OnionKit: well-established but ages; bridge tor.framework
///   - Arti: pure-Rust Tor implementation, fits the FFI umbrella
///   - System Tor app: Onion Browser exposes a SOCKS5 endpoint;
///     wallet routes through it when present
///
/// Until that choice is made and integrated, construct attempts
/// throw SubstrateError.notImplemented so misconfigured wallets
/// fail loudly at boot rather than silently using PlainHTTP.
public final class TorSubstrate: NetworkSubstrate {
    public let urlSession: URLSession
    public let description: String

    public init(socksHost: String, socksPort: Int) throws {
        throw SubstrateError.notImplemented(
            "iOS Tor substrate not yet implemented — see #83-S6b in the enoch repo. " +
            "Requested SOCKS endpoint: \(socksHost):\(socksPort)."
        )
    }

    public func close() {
        if urlSession !== URLSession.shared {
            urlSession.finishTasksAndInvalidate()
        }
    }
}
