// FederationManifest — the wallet's pinned view of the operator set.
//
// Ships with the binary at app install / App Store update. Hash-
// pinned via the binary signature; the wallet refuses to boot
// without one (mainnet) or falls back to a regtest default (dev).
//
// Schema authority: `spec/ios_active_spv.md` §4.4 + §4.9 in the
// enoch repo. Every operator entry MUST declare both `bip157_peer`
// (Bitcoin P2P onion → bitcoind) and `enoch_peer` (Enoch L2 HTTP
// onion → operator daemon). Manifest with either missing is
// rejected at construction time, mirroring the same refusal the
// `enoch-fedinit` tool enforces server-side.
//
// Onion naming convention: protocol-describing subdomain
// (`bip157.onion`, `enoch.onion`), not transport-describing
// (`http.onion`). Future endpoints follow the same pattern.

import Foundation

/// Stable identifier for an operator within a federation. Matches
/// the on-disk `operator_id` field in the Go-side manifest, and the
/// `operatorID` field in `OperatorInfo` returned by `/v1/info`.
public typealias OperatorID = Int

/// One operator entry in the federation manifest.
public struct FederationManifestOperator: Codable, Equatable, Hashable {
    /// Stable id pinned by the manifest. The wallet uses this to
    /// distinguish operator responses in cross-check + slashing UX.
    public let operatorID: OperatorID

    /// Hex-encoded ed25519/secp256k1 public key the operator uses to
    /// sign QuorumRoots + responses. Verified against this key on
    /// every signed payload the wallet receives.
    public let identityPub: String

    /// Bitcoin P2P endpoint the wallet dials for BIP-157 (§4.4).
    /// Production: `.onion:8333` form, reached via Tor SOCKS5. Dev:
    /// plain `host:port`.
    public let bip157Peer: String

    /// Enoch L2 HTTP+SSE endpoint the wallet dials for state queries
    /// + tx submission + event streams (§4.9). Production:
    /// `.onion:8080` form, reached via Tor SOCKS5. Dev: plain
    /// `host:port` or `http://...`.
    public let enochPeer: String

    public init(
        operatorID: OperatorID,
        identityPub: String,
        bip157Peer: String,
        enochPeer: String
    ) {
        self.operatorID = operatorID
        self.identityPub = identityPub
        self.bip157Peer = bip157Peer
        self.enochPeer = enochPeer
    }

    enum CodingKeys: String, CodingKey {
        case operatorID = "operator_id"
        case identityPub = "identity_pub"
        case bip157Peer = "bip157_peer"
        case enochPeer = "enoch_peer"
    }
}

/// Errors raised during manifest construction or validation.
public enum FederationManifestError: Swift.Error, Equatable {
    /// Manifest carries fewer operators than the wallet requires
    /// for K-of-N cross-check (default K=3). Without this minimum
    /// the cross-check property is degraded and v1 refuses to boot.
    case insufficientOperators(have: Int, need: Int)

    /// An operator entry is missing one of the mandatory onion
    /// fields. Catches misconfiguration at boot rather than at
    /// first-sync time when the user would feel it.
    case missingPeerField(operatorID: OperatorID, field: String)

    /// Two operator entries share the same `operatorID`. Catches
    /// hand-edited manifests + replay attacks where an attacker
    /// duplicates a real operator's entry to bias the cross-check.
    case duplicateOperatorID(OperatorID)
}

/// The wallet's pinned federation view. Constructed from a JSON
/// blob bundled with the app binary, or from a server-rotated
/// manifest delivered via the operator HTTP `/v1/manifest`
/// endpoint (signature-validated against the prior manifest's
/// rotation key — that flow lands in a separate slice).
public struct FederationManifest: Codable, Equatable {
    /// Bitcoin network name — "regtest" / "signet" / "testnet" /
    /// "mainnet". Threads down to the substrate + client mainnet
    /// refusal gates.
    public let networkName: String

    /// Ordered set of operator entries. The wallet preserves
    /// manifest order for stable cross-check fan-out + debug UX.
    public let operators: [FederationManifestOperator]

    enum CodingKeys: String, CodingKey {
        case networkName = "network_name"
        case operators
    }

    /// Throwing initializer that runs every validation gate. Use
    /// this anywhere a manifest is constructed; the
    /// `Codable`-synthesized init does NOT run these checks.
    public init(
        networkName: String,
        operators: [FederationManifestOperator],
        minimumOperators: Int = 3
    ) throws {
        if operators.count < minimumOperators {
            throw FederationManifestError.insufficientOperators(
                have: operators.count,
                need: minimumOperators
            )
        }
        var seen = Set<OperatorID>()
        for op in operators {
            if op.bip157Peer.isEmpty {
                throw FederationManifestError.missingPeerField(
                    operatorID: op.operatorID,
                    field: "bip157_peer"
                )
            }
            if op.enochPeer.isEmpty {
                throw FederationManifestError.missingPeerField(
                    operatorID: op.operatorID,
                    field: "enoch_peer"
                )
            }
            if !seen.insert(op.operatorID).inserted {
                throw FederationManifestError.duplicateOperatorID(op.operatorID)
            }
        }
        self.networkName = networkName
        self.operators = operators
    }

    /// Decode + validate from a Data payload (typically the
    /// contents of `manifest.json` bundled with the app binary).
    public static func decodeAndValidate(
        from data: Data,
        minimumOperators: Int = 3
    ) throws -> FederationManifest {
        let raw = try JSONDecoder().decode(FederationManifest.self, from: data)
        return try FederationManifest(
            networkName: raw.networkName,
            operators: raw.operators,
            minimumOperators: minimumOperators
        )
    }

    /// Hard-coded regtest manifest for dev workflows. Three
    /// operators on localhost — matches the port forwards in
    /// `docker-compose.federation.yml`:
    ///   - operator HTTP: 18080/18081/18082 (already exposed)
    ///   - bitcoind P2P:  18544/18545/18546 (op-0 is exposed today;
    ///                    op-1/op-2 will be exposed when #363 lands)
    ///
    /// `identity_pub` values are placeholder hex — the wallet's
    /// regtest signature checks will fail if it tries to verify
    /// QuorumRoot signatures against these. That's fine for v1 dev:
    /// the wallet just exercises HTTP cross-check + BIP-157 sync.
    /// Real identity keys land alongside the federation manifest
    /// generator (`enoch-fedinit`) in #363/#369-followup.
    ///
    /// MUST NOT be used on mainnet builds — the manifest's
    /// `networkName` would refuse construction of a mainnet
    /// substrate even if the caller tried.
    public static func bundledRegtest() -> FederationManifest {
        // swiftlint:disable:next force_try
        try! FederationManifest(
            networkName: "regtest",
            operators: [
                FederationManifestOperator(
                    operatorID: 0,
                    identityPub: String(repeating: "00", count: 32),
                    bip157Peer: "127.0.0.1:18544",
                    enochPeer: "http://127.0.0.1:18080"
                ),
                FederationManifestOperator(
                    operatorID: 1,
                    identityPub: String(repeating: "01", count: 32),
                    bip157Peer: "127.0.0.1:18545",
                    enochPeer: "http://127.0.0.1:18081"
                ),
                FederationManifestOperator(
                    operatorID: 2,
                    identityPub: String(repeating: "02", count: 32),
                    bip157Peer: "127.0.0.1:18546",
                    enochPeer: "http://127.0.0.1:18082"
                ),
            ]
        )
    }
}
