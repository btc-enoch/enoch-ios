// Typed error model for the L2 HTTP/SSE client surface.
//
// Previously named `EdgeError` and lived inside EdgeClient.swift.
// Renamed when enoch-edge was deleted (slice 5) — the type is still
// useful for FederationDirectClient + the SSE streamer, it's just no
// longer named after a now-defunct middlebox.

import Foundation

public enum L2ClientError: Swift.Error, Equatable {
    case urlConstruction
    case transport(String)
    case http(statusCode: Int, body: String)
    case decode(String)

    public static func == (lhs: L2ClientError, rhs: L2ClientError) -> Bool {
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
