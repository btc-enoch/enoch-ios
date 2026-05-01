// Script — minimal Bitcoin Script builders the wallet needs to
// construct P2PKH outputs and inputs. Mirrors the operator's
// `BuildP2PKHScript` (output side) and is paired with
// `Secp256k1.Signature.derWithSighashAll` for the input side.
//
// We don't ship a general Bitcoin Script encoder because Enoch
// transactions are uniformly P2PKH on both sides — no multisig,
// no segwit, no Taproot. If those land later, this file grows; for
// now keeping the surface tight makes correctness obvious at a
// glance.

import Foundation

public enum ScriptError: Swift.Error, Equatable {
    case wrongPKHLength(Int)
    case wrongCompressedPubKeyLength(Int)
    case sigPushTooLong(Int)
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
}
