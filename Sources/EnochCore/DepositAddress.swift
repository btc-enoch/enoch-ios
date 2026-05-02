// DepositAddress — per-user Bitcoin L1 deposit address derivation (#108).
//
// Each L2 user has a unique L1 deposit address derived deterministically
// from their L2 pubkey + the bridge's existing 3-of-5 multisig redeem
// script. Construction (BIP-341 script-path Taproot, no keypath spend):
//
//   internal_pubkey = NUMS                 (well-known unspendable point)
//   user_salt   = tagged_hash("EnochUserDeposit", L2_PUBKEY)
//   leaf_script = <user_salt> OP_DROP <BRIDGE_REDEEM_SCRIPT>
//   leaf_hash   = tagged_hash("TapLeaf", 0xc0 || varint(|leaf_script|) || leaf_script)
//   merkle_root = leaf_hash                (single-leaf tree)
//   t           = tagged_hash("TapTweak", NUMS_xonly || merkle_root)
//   output_key  = NUMS + t·G               (x-only)
//   address     = bech32m(witver=1, output_key) under the L1 HRP
//
// The salt-then-OP_DROP prologue makes each user's tap-tree merkle
// root unique without changing execution semantics. Spending the
// resulting UTXO requires 3-of-5 sigs over the leaf_script via the
// tap-script path — same agents, same threshold as today's bridge,
// no protocol upgrade needed. See spec/deposit_flow.md.

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
        case invalidL2Pubkey(byteCount: Int)
        case invalidRedeemScriptHex
        case bech32(String)
        case crypto(String)
    }

    /// Derive the user's L1 deposit address.
    ///
    /// `l2Pubkey` is the user's 33-byte compressed secp256k1 pubkey
    /// — the same key the wallet uses for its L2 P2TR receive
    /// address.
    /// `bridgeRedeemScriptHex` comes from `/v1/info`'s
    /// `bridge_redeem_script` field.
    /// `network` selects the bech32m HRP.
    public static func derive(
        l2Pubkey: Data,
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
            l2Pubkey: l2Pubkey,
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
        l2Pubkey: Data,
        bridgeRedeemScript: Data
    ) throws -> Data {
        guard l2Pubkey.count == 33 else {
            throw Error.invalidL2Pubkey(byteCount: l2Pubkey.count)
        }
        let salt = Secp256k1.taggedHash(tag: "EnochUserDeposit", data: l2Pubkey)

        // tap-leaf script = <push 32> <salt> OP_DROP <varint-prefixed
        // redeem script>. The leaf is encoded as a normal Bitcoin
        // script — `<push N> data` for the salt, `OP_DROP` (0x75)
        // to discard it, then the bridge redeem script verbatim.
        var leafScript = Data()
        leafScript.append(0x20)                 // push 32 bytes
        leafScript.append(salt)
        leafScript.append(0x75)                 // OP_DROP
        leafScript.append(bridgeRedeemScript)

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
