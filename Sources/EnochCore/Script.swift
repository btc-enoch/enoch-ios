// Script — Bitcoin Script builders the wallet needs to construct
// withdrawal-burn outputs and P2TR script-pubkeys.
//
// Post-#109 + #197 (rust-bitcoin migration Phase 5):
//   - taprootScriptPubKey routes through EnochCrypto's
//     scriptpubkeyP2tr FFI (rust-bitcoin source of truth)
//   - opReturnBurn stays Swift-side (mechanical OP_RETURN +
//     length-prefixed UTF-8 payload, settled spec)
//
// Pre-#109 P2PKH builders (p2pkhScriptPubKey / p2pkhScriptSig)
// were removed in Phase 8 of #191 — fully unused after the
// L2-wallet P2TR migration landed.

import Foundation
import EnochCrypto

public enum ScriptError: Swift.Error, Equatable {
    case burnPayloadTooLong(Int)
    case wrongOutputKeyLength(Int)
}

public enum Script {
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
    ///
    /// Routes through EnochCrypto's scriptpubkeyP2tr (rust-bitcoin
    /// source of truth per #191 Phase 4). Length validation stays
    /// Swift-side so callers preserve the
    /// `ScriptError.wrongOutputKeyLength` contract.
    public static func taprootScriptPubKey(outputKey: Data) throws -> Data {
        guard outputKey.count == 32 else {
            throw ScriptError.wrongOutputKeyLength(outputKey.count)
        }
        return try scriptpubkeyP2tr(outputXonly: outputKey)
    }
}
