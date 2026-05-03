// DepositAddress — per-user Bitcoin L1 deposit address derivation (#108).
//
// Each L2 user has a unique L1 deposit address derived deterministically
// from their 32-byte x-only L2 pubkey + the bridge's existing 3-of-5
// agent set. The wallet learns the agent set via the legacy P2SH
// multisig redeem script published in `/v1/info`; we parse out the
// agent pubkeys and threshold and *rebuild* a BIP-342-compatible
// tap-leaf using OP_CHECKSIGADD. The legacy redeem script ends in
// OP_CHECKMULTISIG, which BIP-342 disables in tapscript — wrapping
// it directly in a tap-leaf would produce funds-locked outputs.
//
// Construction:
//
//   internal_pubkey = NUMS                 (well-known unspendable point)
//   user_salt   = tagged_hash("EnochUserDeposit", L2_XONLY)
//   inner       = <x_pk1> OP_CHECKSIG
//                 <x_pk2> OP_CHECKSIGADD
//                 ...
//                 <x_pkN> OP_CHECKSIGADD
//                 OP_M OP_NUMEQUAL
//   leaf_script = <push 32> <user_salt> OP_DROP <inner>
//   leaf_hash   = tagged_hash("TapLeaf", 0xc0 || varint(|leaf_script|) || leaf_script)
//   merkle_root = leaf_hash                (single-leaf tree)
//   t           = tagged_hash("TapTweak", NUMS_xonly || merkle_root)
//   output_key  = NUMS + t·G               (x-only)
//   address     = bech32m(witver=1, output_key) under the L1 HRP
//
// Spending the resulting UTXO requires 3 BIP-340 Schnorr signatures
// over the leaf — same agents, same threshold as today's bridge,
// just signing with Schnorr instead of ECDSA for the deposit-sweep
// path. Cross-language parity vector pinned against the Python
// reference implementation in bridge/enoch/shared/enoch_address.py;
// the spend round-trip in bridge/tests/test_deposit_spend_roundtrip.py
// proves the construction is actually spendable on regtest. See
// spec/deposit_flow.md.

import Foundation

public enum DepositAddress {
    /// BIP-341 NUMS unspendable point (the well-known x-only key
    /// `lift_x(0x50929b...)` from BIP-341 §3). Provably has no
    /// privkey, so the keypath spend is unusable; only the
    /// tap-script path works.
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
        case invalidRedeemScriptHex
        case malformedRedeemScript(String)
        case bech32(String)
        case crypto(String)
    }

    /// Bitcoin Script opcodes used in the deposit leaf. Spelled out
    /// here so the leaf-script construction is auditable from this
    /// file alone.
    private static let opDrop: UInt8        = 0x75
    private static let opCheckSig: UInt8    = 0xac
    private static let opCheckSigAdd: UInt8 = 0xba
    private static let opNumEqual: UInt8    = 0x9c

    /// Encode a small integer 0..16 as the corresponding OP_N byte.
    /// OP_0 = 0x00; OP_1..OP_16 = 0x51..0x60.
    private static func opN(_ n: Int) throws -> UInt8 {
        if n == 0 { return 0x00 }
        if (1...16).contains(n) { return UInt8(0x50 + n) }
        throw Error.malformedRedeemScript("can't OP_N-encode \(n)")
    }

    /// Parse a legacy `OP_M <pk1>..<pkN> OP_N OP_CHECKMULTISIG` redeem
    /// script into (compressed pubkeys, m, n). Used as the input shape
    /// to the per-user deposit derivation: `/v1/info` ships this
    /// legacy form, and we rebuild a BIP-342-compatible tap-leaf
    /// from it on the wallet side.
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

    /// Build the m-of-n tapscript-compatible bridge inner leaf:
    ///
    ///     <x_pk1> OP_CHECKSIG
    ///     <x_pk2> OP_CHECKSIGADD
    ///     ...
    ///     <x_pkN> OP_CHECKSIGADD
    ///     OP_M OP_NUMEQUAL
    ///
    /// Each pubkey is 32-byte x-only (drop parity prefix from the
    /// legacy 33-byte compressed form). BIP-342 replacement for the
    /// disabled `OP_CHECKMULTISIG`.
    static func buildBridgeLeafInner(agentXOnly: [Data], m: Int) throws -> Data {
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

    /// Derive the user's L1 deposit address.
    ///
    /// `l2XOnly` is the user's 32-byte BIP-340 x-only secp256k1
    /// pubkey — the same bytes embedded in the user's `enoch1p...`
    /// Taproot address.
    /// `bridgeRedeemScriptHex` comes from `/v1/info`'s
    /// `bridge_redeem_script` field.
    /// `network` selects the bech32m HRP.
    public static func derive(
        l2XOnly: Data,
        bridgeRedeemScriptHex: String,
        network: Network
    ) throws -> String {
        let bridgeRedeem: Data
        do {
            bridgeRedeem = try Data(hex: bridgeRedeemScriptHex)
        } catch {
            throw Error.invalidRedeemScriptHex
        }

        let outputKey = try outputKey(
            l2XOnly: l2XOnly,
            bridgeRedeemScript: bridgeRedeem
        )

        // bech32m segwit encoding: witver=1 byte + 32-byte program in
        // 5-bit groups. Same shape as the wallet's own enoch1p... but
        // under a Bitcoin HRP.
        do {
            let prog = try Bech32.convertBits(
                [UInt8](outputKey), from: 8, to: 5, pad: true
            )
            let payload: [UInt8] = [1] + prog
            return try Bech32.encode(
                hrp: network.rawValue,
                data: payload,
                variant: .bech32m
            )
        } catch let e as Bech32.Error {
            throw Error.bech32(String(describing: e))
        }
    }

    /// Lower-level: just compute the 32-byte x-only Taproot output
    /// key. Useful for cross-language parity tests + for callers that
    /// want the raw scriptPubkey bytes (`OP_1 <push 32> <output_key>`).
    public static func outputKey(
        l2XOnly: Data,
        bridgeRedeemScript: Data
    ) throws -> Data {
        guard l2XOnly.count == 32 else {
            throw Error.invalidL2XOnly(byteCount: l2XOnly.count)
        }

        // Parse the legacy P2SH 3-of-5 multisig and rebuild as a
        // BIP-342-compatible inner leaf using OP_CHECKSIGADD.
        let parsed = try parseLegacyMultisigRedeem(bridgeRedeemScript)
        let agentXOnly = parsed.pubkeys.map { $0.subdata(in: 1..<33) }
        let inner = try buildBridgeLeafInner(agentXOnly: agentXOnly, m: parsed.m)

        // Per-user salt + tap-leaf:
        //   leaf_script = <push 32> <salt> OP_DROP <inner>
        let salt = Secp256k1.taggedHash(tag: "EnochUserDeposit", data: l2XOnly)
        var leafScript = Data()
        leafScript.append(0x20)
        leafScript.append(salt)
        leafScript.append(opDrop)
        leafScript.append(inner)

        // tap-leaf hash: SHA256_TapLeaf(0xc0 || varint(|leaf|) || leaf).
        // 0xc0 is the BIP-342 leaf version (top 6 bits 0xc0, bottom 2
        // are the parity bits set later by the tweak — for hashing
        // purposes the canonical leaf-version constant is 0xc0).
        var leafBlob = Data()
        leafBlob.append(0xc0)
        leafBlob.append(contentsOf: encodeVarInt(UInt64(leafScript.count)))
        leafBlob.append(leafScript)
        let leafHash = Secp256k1.taggedHash(tag: "TapLeaf", data: leafBlob)

        // Single-leaf tree → merkle_root == leaf_hash.
        let merkleRoot = leafHash

        // BIP-341 keypath tweak with non-empty merkle root:
        // t = tagged_hash("TapTweak", internal_xonly || merkle_root)
        let numsXOnly = try Data(hex: numsXOnlyHex)
        var tweakInput = Data()
        tweakInput.append(numsXOnly)
        tweakInput.append(merkleRoot)
        let tweak = Secp256k1.taggedHash(tag: "TapTweak", data: tweakInput)

        // output_key = NUMS + t·G (x-only). Same primitive used for
        // the wallet's own keypath output key, just with a non-empty
        // merkle root in the tweak.
        do {
            let outputKey = try Secp256k1.applyTaprootTweak(
                internalXOnly: numsXOnly,
                tweak: tweak
            )
            return outputKey.bytes
        } catch {
            throw Error.crypto(String(describing: error))
        }
    }

    /// Bitcoin varint encoding. Used only by the tap-leaf prologue;
    /// we don't need a general tx-serialization codec.
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
