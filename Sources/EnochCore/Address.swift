// Address — wallet-level encode/decode for the formats the
// Enoch wallet accepts as input:
//
//   Legacy (pre-#109, P2PKH-equivalent):
//     - enoch1...                       (Enoch L2, no witness version)
//     - bc1q... / tb1q... / bcrt1q...   (Bitcoin segwit v0, P2WPKH)
//   Post-#109 (Taproot, x-only output keys):
//     - enoch1p...                      (Enoch L2 P2TR, witness version 1)
//     - bc1p... / tb1p... / bcrt1p...   (Bitcoin segwit v1, P2TR)
//
// The legacy path reduces to a 20-byte HASH160(pubkey). The Taproot
// path reduces to a 32-byte x-only output key (BIP-340/341).
// Mirrors the operator's Go address impl.

import Foundation

public enum Address {
    public enum Error: Swift.Error, Equatable {
        case wrongHRP(String)
        case wrongPayloadLength(Int)
        case unsupportedWitnessVersion(UInt8)
        case bech32(Bech32.Error)
    }

    /// HRP for Enoch L2 addresses (both legacy bech32 and Taproot bech32m).
    public static let enochHRP = "enoch"

    /// Discriminated union of the wallet's recognized address formats.
    /// Returned by `decode(_:)` so callers can dispatch by script type.
    public enum Decoded: Equatable {
        /// Legacy P2PKH-equivalent: 20-byte hash160(pubkey).
        case p2pkh(pkh: Data)
        /// Bitcoin segwit v0: 20-byte hash160(pubkey).
        case p2wpkh(pkh: Data)
        /// Taproot (Enoch L2 enoch1p... or Bitcoin bc1p.../tb1p.../bcrt1p...):
        /// 32-byte x-only output key (BIP-341 tweaked).
        case p2tr(outputKey: Data)
    }

    /// Derive the wallet's `enoch1...` address from its public key —
    /// HASH160(compressed-pubkey) → bech32(HRP=enoch). Same shape the
    /// operator uses internally to key UTXOs by pkh.
    public static func encodeEnoch(publicKey: Secp256k1.PublicKey) throws -> String {
        let pkh = Hashing.hash160(publicKey.compressedBytes)
        return try encodeEnoch(pkh: pkh)
    }

    /// Encode a 20-byte pkh as `enoch1...`.
    public static func encodeEnoch(pkh: Data) throws -> String {
        guard pkh.count == 20 else {
            throw Error.wrongPayloadLength(pkh.count)
        }
        do {
            let data5 = try Bech32.convertBits([UInt8](pkh), from: 8, to: 5, pad: true)
            return try Bech32.encode(hrp: enochHRP, data: data5)
        } catch let e as Bech32.Error {
            throw Error.bech32(e)
        }
    }

    /// Decode any of enoch1.../bc1q.../tb1q.../bcrt1q... into the
    /// 20-byte pkh both formats share. Convenience for legacy call
    /// sites; rejects Taproot inputs. New code should call
    /// `decode(_:)` and pattern-match on the returned Decoded enum.
    public static func decodeToPKH(_ s: String) throws -> Data {
        switch try decode(s) {
        case .p2pkh(let pkh):  return pkh
        case .p2wpkh(let pkh): return pkh
        case .p2tr:            throw Error.unsupportedWitnessVersion(1)
        }
    }

    /// Decode any of the wallet's recognized address formats —
    /// legacy enoch1..., segwit-v0 P2WPKH, segwit-v1 / Enoch
    /// Taproot — into a discriminated payload.
    ///
    /// Variant validation is enforced per BIP-350: witness-version-0
    /// payloads MUST use BIP173 (bech32); witness-version-1+ payloads
    /// MUST use BIP350 (bech32m). Mismatches are rejected as invalid
    /// checksum.
    public static func decode(_ s: String) throws -> Decoded {
        let decoded: (hrp: String, data: [UInt8], variant: Bech32.Variant)
        do {
            decoded = try Bech32.decodeAny(s)
        } catch let e as Bech32.Error {
            throw Error.bech32(e)
        }

        switch decoded.hrp {
        case enochHRP:
            return try unpackEnoch(decoded.data, variant: decoded.variant)
        case "bc", "tb", "bcrt":
            return try unpackSegwit(decoded.data, variant: decoded.variant)
        default:
            throw Error.wrongHRP(decoded.hrp)
        }
    }

    /// Encode a 32-byte x-only Taproot output key as `enoch1p...`
    /// (witness version 1, bech32m). Used post-#109 for L2 receive
    /// addresses; same shape as Bitcoin's bc1p... addresses but with
    /// HRP=enoch.
    public static func encodeTaproot(outputKey: Data) throws -> String {
        guard outputKey.count == 32 else {
            throw Error.wrongPayloadLength(outputKey.count)
        }
        do {
            // Witness-version byte (1 for Taproot) is the first 5-bit
            // symbol; the 32-byte program follows in 8→5-bit groups.
            let program5 = try Bech32.convertBits([UInt8](outputKey), from: 8, to: 5, pad: true)
            let payload: [UInt8] = [1] + program5
            return try Bech32.encode(hrp: enochHRP, data: payload, variant: .bech32m)
        } catch let e as Bech32.Error {
            throw Error.bech32(e)
        }
    }

    // MARK: - Internals

    private static func unpackEnoch(_ data5: [UInt8], variant: Bech32.Variant) throws -> Decoded {
        // Two coexisting formats under HRP=enoch:
        //   bech32  + 20-byte payload, no version byte → legacy P2PKH-equivalent
        //   bech32m + version-byte=1 + 32-byte payload → P2TR (#109)
        switch variant {
        case .bech32:
            do {
                let bytes = try Bech32.convertBits(data5, from: 5, to: 8, pad: false)
                guard bytes.count == 20 else {
                    throw Error.wrongPayloadLength(bytes.count)
                }
                return .p2pkh(pkh: Data(bytes))
            } catch let e as Bech32.Error {
                throw Error.bech32(e)
            }
        case .bech32m:
            guard let witver = data5.first, witver == 1 else {
                throw Error.unsupportedWitnessVersion(data5.first ?? 0)
            }
            do {
                let program = try Bech32.convertBits(Array(data5.dropFirst()), from: 5, to: 8, pad: false)
                guard program.count == 32 else {
                    throw Error.wrongPayloadLength(program.count)
                }
                return .p2tr(outputKey: Data(program))
            } catch let e as Bech32.Error {
                throw Error.bech32(e)
            }
        }
    }

    private static func unpackSegwit(_ data5: [UInt8], variant: Bech32.Variant) throws -> Decoded {
        // BIP-350 rules: witness version 0 → bech32; witness version 1+ → bech32m.
        guard let witver = data5.first else {
            throw Error.wrongPayloadLength(0)
        }
        do {
            let program = try Bech32.convertBits(Array(data5.dropFirst()), from: 5, to: 8, pad: false)
            switch (witver, variant, program.count) {
            case (0, .bech32, 20):
                return .p2wpkh(pkh: Data(program))
            case (1, .bech32m, 32):
                return .p2tr(outputKey: Data(program))
            default:
                throw Error.unsupportedWitnessVersion(witver)
            }
        } catch let e as Bech32.Error {
            throw Error.bech32(e)
        }
    }
}
