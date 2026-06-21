// EnochCore is the wallet's non-custodial protocol layer for the
// Enoch L2 — the same role that Bitcoin Core's wallet code plays
// for Bitcoin, ported to Swift for first-class iOS integration.
//
// Submodules (filled out incrementally):
//   - Bech32        encode/decode for enoch1... and bc1q.../tb1q.../bcrt1q...
//   - Secp256k1     wraps swift-secp256k1 with the operator's sighash + low-s rules
//   - Tx            wire types matching submitTxRequestJSON on the operator side
//   - Sighash       double-SHA256 over the canonical-form tx (scriptSigs zeroed)
//   - FederationDirectClient
//                   K-of-N HTTP/SSE client that fans out to each
//                   operator's /v1/* directly (replaced the old
//                   EdgeClient when enoch-edge was retired)
//
// Nothing here imports UIKit or SwiftUI. The iOS app target depends
// on EnochCore but EnochCore stays platform-agnostic so it builds
// and tests on linux/macos CI without a simulator.

import Foundation

/// Library version string. Mirrors the operator's `/info.version`
/// shape so wallet logs / about-screens can show both side by side.
public enum EnochCore {
    public static let version = "0.1.0"
}
