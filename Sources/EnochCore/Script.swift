// Script — minimal Bitcoin Script builders the wallet needs to
// construct user-money outputs and inputs.
//
// Pre-#109 (legacy): P2PKH everywhere — `p2pkhScriptPubKey` for
// outputs, `p2pkhScriptSig` for inputs. Mirrors the operator's
// `BuildP2PKHScript`.
//
// Post-#109: P2TR keypath spends — `taprootScriptPubKey` for
// outputs, witness construction handled in TxBuilder (Schnorr sig
// in a single-element witness, no scriptSig). The two paths
// coexist during the migration window; once #109 + B6 ship, the
// P2PKH builders are dead code and can be removed.

import Foundation

public enum ScriptError: Swift.Error, Equatable {
    case wrongPKHLength(Int)
    case wrongCompressedPubKeyLength(Int)
    case sigPushTooLong(Int)
    case burnPayloadTooLong(Int)
    case wrongOutputKeyLength(Int)
}

public enum Script {
    /// P2PKH scriptPubKey:
    ///
    ///   OP_DUP OP_HASH160 <push 20> <pkh> OP_EQUALVERIFY OP_CHECKSIG
    ///   76     a9         14         ...        88            ac
    ///
    /// Always exactly 25 bytes. This is what we put in tx outputs;
    /// the operator's storage-side scanner uses the same opcode
    /// pattern to decide which UTXOs are P2PKH-and-therefore-
    /// spendable-by-pkh.
    public static func p2pkhScriptPubKey(pkh: Data) throws -> Data {
        guard pkh.count == 20 else {
            throw ScriptError.wrongPKHLength(pkh.count)
        }
        var out = Data(capacity: 25)
        out.append(contentsOf: [0x76, 0xA9, 0x14])
        out.append(pkh)
        out.append(contentsOf: [0x88, 0xAC])
        return out
    }

    /// OP_RETURN withdrawal-burn output:
    ///
    ///   OP_RETURN <push N> "ENOCH:WD:<btc_addr>"
    ///   0x6A     N        ...payload...
    ///
    /// The payload tags an L2-side burn for the bridge agents to
    /// pick up; they 3-of-5-sign an L1 tx paying `bitcoinAddress`
    /// from the bridge's P2SH multisig. Single-byte push form only
    /// (matches the operator's parser) — payload must fit in ≤ 75
    /// bytes, which leaves up to 66 chars for the address. Every
    /// real Bitcoin address format fits comfortably (taproot at 62
    /// chars is the longest).
    public static func opReturnBurn(bitcoinAddress: String) throws -> Data {
        let prefix = "ENOCH:WD:"
        let payload = prefix + bitcoinAddress
        let payloadBytes = Data(payload.utf8)
        guard payloadBytes.count <= 75 else {
            throw ScriptError.burnPayloadTooLong(payloadBytes.count)
        }
        var out = Data(capacity: 2 + payloadBytes.count)
        out.append(0x6A) // OP_RETURN
        out.append(UInt8(payloadBytes.count))
        out.append(payloadBytes)
        return out
    }

    /// P2PKH scriptSig:
    ///
    ///   <push N> <DER+sighash> <push 33> <compressed pubkey>
    ///
    /// The sigPushBytes already has the SIGHASH_ALL byte appended (use
    /// `Secp256k1.Signature.derWithSighashAll`). We use direct-push
    /// length bytes (1..75) rather than OP_PUSHDATA1+; valid DER
    /// signatures are at most 73 bytes including the sighash byte,
    /// well below the 75-byte direct-push ceiling.
    public static func p2pkhScriptSig(sigWithSighashType: Data, compressedPubKey: Data) throws -> Data {
        guard compressedPubKey.count == 33 else {
            throw ScriptError.wrongCompressedPubKeyLength(compressedPubKey.count)
        }
        guard sigWithSighashType.count >= 1, sigWithSighashType.count <= 75 else {
            throw ScriptError.sigPushTooLong(sigWithSighashType.count)
        }
        var out = Data(capacity: 1 + sigWithSighashType.count + 1 + 33)
        out.append(UInt8(sigWithSighashType.count))
        out.append(sigWithSighashType)
        out.append(0x21) // direct-push 33 bytes
        out.append(compressedPubKey)
        return out
    }

    /// P2TR scriptPubKey (witness version 1, BIP-341):
    ///
    ///   OP_1 <push 32> <x-only output key>
    ///   0x51 0x20      ...32 bytes...
    ///
    /// Always exactly 34 bytes. The 32-byte output key is the
    /// BIP-341 tweaked public key — for keypath-only spends this is
    /// `internal_key + H_TapTweak(internal_key) · G`. For Enoch L2
    /// post-#109, keypath-only is the standard form (no script
    /// trees on user-money UTXOs).
    public static func taprootScriptPubKey(outputKey: Data) throws -> Data {
        guard outputKey.count == 32 else {
            throw ScriptError.wrongOutputKeyLength(outputKey.count)
        }
        var out = Data(capacity: 34)
        out.append(0x51) // OP_1 (witness version)
        out.append(0x20) // direct-push 32 bytes
        out.append(outputKey)
        return out
    }
}
