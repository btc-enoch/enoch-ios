// DepositAddress — per-user Bitcoin L1 deposit address derivation.
//
// Implements spec/deposit_address.md: a P2TR output with NUMS as the
// internal key and a two-leaf tap-tree.
//
//   internal      = NUMS                          (BIP-341 §3 unspendable)
//   leaf_A_script = <x_a0> CHECKSIG
//                   <x_a1> CHECKSIGADD
//                   ...
//                   <x_a{N-1}> CHECKSIGADD
//                   <M> NUMEQUAL                  (BIP-342 multisig)
//   leaf_B_script = <R> CSV OP_DROP
//                   <user_xonly> CHECKSIG          (user reclaim)
//   H_A           = TaggedHash("TapLeaf", 0xc0 || varint(|S_A|) || S_A)
//   H_B           = TaggedHash("TapLeaf", 0xc0 || varint(|S_B|) || S_B)
//   merkle_root   = TaggedHash("TapBranch", min(H_A,H_B) || max(H_A,H_B))
//   t             = TaggedHash("TapTweak", NUMS_xonly || merkle_root)
//   output_key    = x(NUMS + t·G)
//
// Per-user uniqueness comes from leaf B's `user_xonly` push: same
// federation, different user → different H_B → different merkle root
// → different output key. Leaf A is constant across users.
//
// The federation can spend via leaf A (M-of-N agent sweep). The user
// can reclaim via leaf B once the deposit UTXO has matured `R` blocks
// (BIP-68 sequence; OP_CSV enforces). Mirrors
// federation/depositaddr/depositaddr.go byte-for-byte.

import EnochCrypto
import Foundation

public enum DepositAddress {
    /// BIP-341 NUMS unspendable point (the well-known x-only key
    /// `lift_x(0x50929b...)`).
    public static let numsXOnlyHex =
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"

    /// Bitcoin network HRPs for bech32m segwit-v1 addresses.
    public enum Network: String {
        case mainnet = "bc"
        case testnet = "tb"
        case regtest = "bcrt"

        public init?(infoNetwork: String) {
            switch infoNetwork {
            case "mainnet": self = .mainnet
            case "testnet": self = .testnet
            case "regtest": self = .regtest
            default: return nil
            }
        }
    }

    public enum Error: Swift.Error, Equatable {
        case invalidL2XOnly(byteCount: Int)
        case invalidUserXOnly(byteCount: Int)
        case invalidRedeemScriptHex
        case malformedRedeemScript(String)
        case invalidReclaimR(reason: String)
        case bech32(String)
        case crypto(String)
    }

    /// Bitcoin Script opcodes used in the deposit leaves. Spelled out
    /// here so the leaf-script construction is auditable from this
    /// file alone.
    private static let opDrop: UInt8        = 0x75
    private static let opCheckSig: UInt8    = 0xac
    private static let opCheckSigAdd: UInt8 = 0xba
    private static let opNumEqual: UInt8    = 0x9c
    private static let opCSV: UInt8         = 0xb2 // OP_CHECKSEQUENCEVERIFY

    /// Encode a small integer 0..16 as the corresponding OP_N byte.
    /// OP_0 = 0x00; OP_1..OP_16 = 0x51..0x60.
    private static func opN(_ n: Int) throws -> UInt8 {
        if n == 0 { return 0x00 }
        if (1...16).contains(n) { return UInt8(0x50 + n) }
        throw Error.malformedRedeemScript("can't OP_N-encode \(n)")
    }

    /// Push a CScriptNum onto an output buffer using the most compact
    /// valid form: OP_0 / OP_1..OP_16 for small values, otherwise
    /// minimal little-endian bytes with sign-bit padding per
    /// CScriptNum encoding. Used for the OP_CSV operand.
    private static func appendScriptNum(_ n: UInt32, to out: inout Data) {
        if n == 0 {
            out.append(0x00) // OP_0
            return
        }
        if n <= 16 {
            out.append(UInt8(0x50) + UInt8(n)) // OP_1..OP_16
            return
        }
        var v = n
        var bytes: [UInt8] = []
        while v > 0 {
            bytes.append(UInt8(v & 0xFF))
            v >>= 8
        }
        if bytes.last! & 0x80 != 0 {
            bytes.append(0x00)
        }
        out.append(UInt8(bytes.count))
        out.append(contentsOf: bytes)
    }

    /// Parse a legacy `OP_M <pk1>..<pkN> OP_N OP_CHECKMULTISIG` redeem
    /// script into (compressed pubkeys, m, n).
    static func parseLegacyMultisigRedeem(
        _ redeem: Data
    ) throws -> (pubkeys: [Data], m: Int, n: Int) {
        guard redeem.count >= 3 else {
            throw Error.malformedRedeemScript("redeem too short (\(redeem.count) bytes)")
        }
        let bytes = [UInt8](redeem)
        guard bytes.last == 0xae else {
            throw Error.malformedRedeemScript("redeem must end with OP_CHECKMULTISIG (0xae)")
        }
        let mOp = bytes[0]
        let nOp = bytes[bytes.count - 2]
        guard (0x51...0x60).contains(mOp) else {
            throw Error.malformedRedeemScript("first byte must be OP_M")
        }
        guard (0x51...0x60).contains(nOp) else {
            throw Error.malformedRedeemScript("second-to-last byte must be OP_N")
        }
        let m = Int(mOp) - 0x50
        let n = Int(nOp) - 0x50

        var pubkeys: [Data] = []
        var i = 1
        let end = bytes.count - 2
        while i < end {
            let pushLen = bytes[i]
            guard pushLen == 0x21 else {
                throw Error.malformedRedeemScript(
                    "expected 0x21 push of 33-byte pubkey at offset \(i)"
                )
            }
            guard i + 1 + 33 <= end else {
                throw Error.malformedRedeemScript("redeem truncated mid-pubkey")
            }
            pubkeys.append(redeem.subdata(in: (i + 1)..<(i + 1 + 33)))
            i += 1 + 33
        }
        guard pubkeys.count == n else {
            throw Error.malformedRedeemScript(
                "redeem says OP_\(n) but contains \(pubkeys.count) pubkey(s)"
            )
        }
        guard m >= 1, m <= n else {
            throw Error.malformedRedeemScript("threshold m=\(m) out of range for n=\(n)")
        }
        return (pubkeys, m, n)
    }

    /// Strip the parity prefix from a 33-byte compressed secp256k1
    /// pubkey, returning the 32-byte x-only form.
    public static func xOnlyFromCompressed(_ compressed: Data) throws -> Data {
        guard compressed.count == 33 else {
            throw Error.malformedRedeemScript(
                "compressed pubkey must be 33 bytes, got \(compressed.count)"
            )
        }
        let prefix = compressed[compressed.startIndex]
        guard prefix == 0x02 || prefix == 0x03 else {
            throw Error.malformedRedeemScript(
                "compressed pubkey must start with 0x02 or 0x03"
            )
        }
        return compressed.subdata(in: (compressed.startIndex + 1)..<compressed.endIndex)
    }

    /// Build the M-of-N bridge sweep tap-script (leaf A):
    ///
    ///     <x_pk1> OP_CHECKSIG
    ///     <x_pk2> OP_CHECKSIGADD
    ///     ...
    ///     <x_pkN> OP_CHECKSIGADD
    ///     <M>     OP_NUMEQUAL
    ///
    /// Constant across all users — per-user uniqueness lives in leaf B.
    public static func buildBridgeLeafScript(
        agentXOnly: [Data], m: Int
    ) throws -> Data {
        guard !agentXOnly.isEmpty else {
            throw Error.malformedRedeemScript("need at least one agent pubkey")
        }
        guard m >= 1, m <= agentXOnly.count else {
            throw Error.malformedRedeemScript("threshold m=\(m) out of range")
        }
        var out = Data()
        for (i, x) in agentXOnly.enumerated() {
            guard x.count == 32 else {
                throw Error.malformedRedeemScript(
                    "agent pubkey \(i): want 32-byte x-only, got \(x.count)"
                )
            }
            out.append(0x20)
            out.append(x)
            out.append(i == 0 ? opCheckSig : opCheckSigAdd)
        }
        out.append(try opN(m))
        out.append(opNumEqual)
        return out
    }

    /// Build the user CSV-locked reclaim tap-script (leaf B):
    ///
    ///     <R> OP_CHECKSEQUENCEVERIFY OP_DROP
    ///     <user_xonly> OP_CHECKSIG
    public static func buildReclaimLeafScript(
        userXOnly: Data, reclaimR R: UInt32
    ) throws -> Data {
        guard userXOnly.count == 32 else {
            throw Error.invalidUserXOnly(byteCount: userXOnly.count)
        }
        guard R > 0 else {
            throw Error.invalidReclaimR(
                reason: "R must be > 0 (zero-block reclaim defeats the lock)"
            )
        }
        guard R & 0xFFFF_0000 == 0 else {
            throw Error.invalidReclaimR(
                reason: "R=\(R) exceeds BIP-68 16-bit block-count field"
            )
        }
        var out = Data()
        appendScriptNum(R, to: &out)
        out.append(opCSV)
        out.append(opDrop)
        out.append(0x20) // 32-byte push
        out.append(userXOnly)
        out.append(opCheckSig)
        return out
    }

    /// Compute the 32-byte tap-tree merkle root binding leaf A
    /// (federation M-of-N sweep) and leaf B (user reclaim with
    /// CSV). Both `outputKey` and `derive` need it; isolating the
    /// derivation here keeps the two callers from drifting.
    private static func merkleRoot(
        l2XOnly: Data,
        bridgeRedeemScript: Data,
        reclaimR R: UInt32
    ) throws -> Data {
        guard l2XOnly.count == 32 else {
            throw Error.invalidL2XOnly(byteCount: l2XOnly.count)
        }
        let parsed = try parseLegacyMultisigRedeem(bridgeRedeemScript)
        let agentXOnly = try parsed.pubkeys.map { try xOnlyFromCompressed($0) }

        let bridgeLeaf = try buildBridgeLeafScript(agentXOnly: agentXOnly, m: parsed.m)
        let reclaimLeaf = try buildReclaimLeafScript(userXOnly: l2XOnly, reclaimR: R)

        let hBridge = tapLeafHash(bridgeLeaf)
        let hReclaim = tapLeafHash(reclaimLeaf)
        return tapBranchHash(hBridge, hReclaim)
    }

    /// Compute the 32-byte x-only Taproot output key for a per-user
    /// deposit address. Reclaim-spend construction (control blocks
    /// with parity bits) lands in a follow-up commit alongside the
    /// reclaim signing flow.
    public static func outputKey(
        l2XOnly: Data,
        bridgeRedeemScript: Data,
        reclaimR R: UInt32
    ) throws -> Data {
        let root = try merkleRoot(
            l2XOnly: l2XOnly,
            bridgeRedeemScript: bridgeRedeemScript,
            reclaimR: R
        )
        let numsXOnly = try Data(hex: numsXOnlyHex)
        do {
            return try EnochCrypto.taprootTweakedOutputKey(
                internalXonly: numsXOnly,
                merkleRoot: root
            )
        } catch {
            throw Error.crypto(String(describing: error))
        }
    }

    /// Derive the user's L1 deposit address as a bech32m string.
    ///
    /// `l2XOnly` is the user's 32-byte x-only secp256k1 pubkey — the
    /// same bytes embedded in their `enoch1p…` Taproot address.
    /// `bridgeRedeemScriptHex` comes from `/v1/info`'s
    /// `bridge_redeem_script` field. `reclaimR` is the federation's
    /// pinned reclaim relative-timelock (also from `/v1/info`).
    ///
    /// Routes the witness-v1 + bech32m segwit encoding through Rust
    /// EnochCrypto's address_p2tr (rust-bitcoin Address::p2tr under
    /// the hood). Single source of truth for the tweak math AND the
    /// address string.
    public static func derive(
        l2XOnly: Data,
        bridgeRedeemScriptHex: String,
        reclaimR R: UInt32,
        network: Network
    ) throws -> String {
        let bridgeRedeem: Data
        do {
            bridgeRedeem = try Data(hex: bridgeRedeemScriptHex)
        } catch {
            throw Error.invalidRedeemScriptHex
        }

        let root = try merkleRoot(
            l2XOnly: l2XOnly,
            bridgeRedeemScript: bridgeRedeem,
            reclaimR: R
        )
        let numsXOnly = try Data(hex: numsXOnlyHex)
        do {
            return try EnochCrypto.addressP2tr(
                internalXonly: numsXOnly,
                merkleRoot: root,
                network: networkRustString(network)
            )
        } catch {
            throw Error.crypto(String(describing: error))
        }
    }

    // MARK: - Slice 7b: keypath-shape derivation
    //
    // FROST stage 7 changes the per-user deposit address shape:
    //   internal_key  = FROST aggregate verifying-key x-only
    //                   (was: NUMS unspendable point)
    //   tap_tree      = [reclaim_leaf]            // single leaf
    //                   (was: [bridge_multisig_leaf, reclaim_leaf])
    //   merkle_root   = TapLeaf(reclaim_leaf)
    //                   (was: TapBranch(min(H_bridge,H_reclaim) ||
    //                                    max(H_bridge,H_reclaim)))
    //
    // The federation sweep is now a P2TR keypath spend (single
    // 64B FROST signature in the witness) instead of a 7-element
    // CHECKSIGADD multisig script-path. Reclaim leaf shape is
    // unchanged — user recovery stays trustless and shape-stable.
    //
    // Cross-language parity: federation/depositaddr/keypath.go
    // produces byte-identical addresses for the same inputs;
    // pinned in DepositAddressTests + Go's keypath_test.go.

    /// Derive the keypath-shape per-user deposit address.
    ///
    /// `frostInternalXOnly` is the 32-byte x-only verifying key of
    /// the federation's FROST PKP — passed in from `/v1/info`'s
    /// `frost_internal_xonly` field (added when the operator
    /// cuts over to the keypath shape in slice 7d). `l2XOnly` is
    /// the user's 32-byte x-only L2 identity key. `R` is the
    /// reclaim relative-timelock (BIP-68 block-count).
    ///
    /// Routes the BIP-341 tap-tweak + bech32m encoding through
    /// EnochCrypto.addressP2tr — single source of truth shared
    /// with the operator/agent (Go side via keypath.go).
    public static func deriveKeypath(
        l2XOnly: Data,
        frostInternalXOnly: Data,
        reclaimR R: UInt32,
        network: Network
    ) throws -> String {
        guard frostInternalXOnly.count == 32 else {
            throw Error.invalidL2XOnly(byteCount: frostInternalXOnly.count)
        }
        let reclaimLeaf = try buildReclaimLeafScript(userXOnly: l2XOnly, reclaimR: R)
        let merkleRoot = tapLeafHash(reclaimLeaf)
        do {
            return try EnochCrypto.addressP2tr(
                internalXonly: frostInternalXOnly,
                merkleRoot: merkleRoot,
                network: networkRustString(network)
            )
        } catch {
            throw Error.crypto(String(describing: error))
        }
    }

    /// Compute the 32-byte x-only Taproot output key for the
    /// keypath-shape per-user deposit address. Used by callers
    /// that need just the witness-program bytes (e.g., recipient
    /// scriptPubKey construction) without the bech32m wrapping.
    public static func outputKeyKeypath(
        l2XOnly: Data,
        frostInternalXOnly: Data,
        reclaimR R: UInt32
    ) throws -> Data {
        guard frostInternalXOnly.count == 32 else {
            throw Error.invalidL2XOnly(byteCount: frostInternalXOnly.count)
        }
        let reclaimLeaf = try buildReclaimLeafScript(userXOnly: l2XOnly, reclaimR: R)
        let merkleRoot = tapLeafHash(reclaimLeaf)
        do {
            return try EnochCrypto.taprootTweakedOutputKey(
                internalXonly: frostInternalXOnly,
                merkleRoot: merkleRoot
            )
        } catch {
            throw Error.crypto(String(describing: error))
        }
    }

    /// Map our Network enum (which carries the bech32m HRP for
    /// presentation) to the network-name strings Rust's
    /// EnochCrypto.address* functions accept.
    private static func networkRustString(_ n: Network) -> String {
        switch n {
        case .mainnet: return "mainnet"
        case .testnet: return "testnet"
        case .regtest: return "regtest"
        }
    }

    // MARK: - Hashing primitives

    /// Compute BIP-341 TapLeaf hash:
    ///   TaggedHash("TapLeaf", 0xc0 || varint(|script|) || script)
    private static func tapLeafHash(_ script: Data) -> Data {
        var blob = Data()
        blob.append(0xc0)
        blob.append(contentsOf: encodeVarInt(UInt64(script.count)))
        blob.append(script)
        return Secp256k1.taggedHash(tag: "TapLeaf", data: blob)
    }

    /// Compute BIP-341 TapBranch hash:
    ///   TaggedHash("TapBranch", min(a,b) || max(a,b))
    private static func tapBranchHash(_ a: Data, _ b: Data) -> Data {
        let (left, right): (Data, Data) = a.lexicographicallyPrecedes(b) ? (a, b) : (b, a)
        var combined = Data()
        combined.append(left)
        combined.append(right)
        return Secp256k1.taggedHash(tag: "TapBranch", data: combined)
    }

    /// Bitcoin varint encoding. Used by the tap-leaf prologue.
    private static func encodeVarInt(_ n: UInt64) -> [UInt8] {
        if n < 0xFD {
            return [UInt8(n)]
        }
        if n <= 0xFFFF {
            return [0xFD, UInt8(n & 0xFF), UInt8((n >> 8) & 0xFF)]
        }
        if n <= 0xFFFFFFFF {
            var out: [UInt8] = [0xFE]
            for i in 0..<4 {
                out.append(UInt8((n >> (8 * i)) & 0xFF))
            }
            return out
        }
        var out: [UInt8] = [0xFF]
        for i in 0..<8 {
            out.append(UInt8((n >> (8 * i)) & 0xFF))
        }
        return out
    }
}

private extension Data {
    /// Lexicographic byte-string comparison. Used for BIP-341
    /// TapBranch ordering (sort children by raw 32-byte hash).
    func lexicographicallyPrecedes(_ other: Data) -> Bool {
        let n = Swift.min(count, other.count)
        for i in 0..<n {
            let l = self[self.index(self.startIndex, offsetBy: i)]
            let r = other[other.index(other.startIndex, offsetBy: i)]
            if l != r { return l < r }
        }
        return count < other.count
    }
}
