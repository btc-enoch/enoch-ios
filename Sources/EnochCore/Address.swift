// Address — wallet-level encode/decode for the four formats the
// Enoch wallet accepts as input:
//
//   - enoch1...                       (Enoch L2, no witness version)
//   - bc1q... / tb1q... / bcrt1q...   (Bitcoin segwit v0, P2WPKH)
//
// Internally everything reduces to a 20-byte HASH160(pubkey). The
// operator only speaks `enoch1`; the wallet decodes any input
// format to pkh and re-encodes as enoch1 before calling the
// edge API, mirroring enoch-edge/internal/address (Go).

import Foundation

public enum Address {
    public enum Error: Swift.Error, Equatable {
        case wrongHRP(String)
        case wrongPayloadLength(Int)
        case unsupportedWitnessVersion(UInt8)
        case bech32(Bech32.Error)
    }

    /// HRP for Enoch L2 bech32 addresses.
    public static let enochHRP = "enoch"

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
    /// 20-byte pkh both formats share. Taproot (segwit v1, bech32m)
    /// is rejected — different curve, different mapping, no shared
    /// pkh — and surfaces as `bech32(.invalidChecksum)` since BIP173
    /// won't validate a BIP350 string.
    public static func decodeToPKH(_ s: String) throws -> Data {
        let decoded: (hrp: String, data: [UInt8])
        do {
            decoded = try Bech32.decode(s)
        } catch let e as Bech32.Error {
            throw Error.bech32(e)
        }

        switch decoded.hrp {
        case enochHRP:
            return try unpackEnoch(decoded.data)
        case "bc", "tb", "bcrt":
            return try unpackSegwitV0(decoded.data)
        default:
            throw Error.wrongHRP(decoded.hrp)
        }
    }

    // MARK: - Internals

    private static func unpackEnoch(_ data5: [UInt8]) throws -> Data {
        do {
            let bytes = try Bech32.convertBits(data5, from: 5, to: 8, pad: false)
            guard bytes.count == 20 else {
                throw Error.wrongPayloadLength(bytes.count)
            }
            return Data(bytes)
        } catch let e as Bech32.Error {
            throw Error.bech32(e)
        }
    }

    private static func unpackSegwitV0(_ data5: [UInt8]) throws -> Data {
        // First 5-bit symbol is the witness version; the rest is the
        // program. v0 with a 20-byte program is P2WPKH — exactly the
        // shape we need.
        guard let witver = data5.first else {
            throw Error.wrongPayloadLength(0)
        }
        if witver != 0 {
            throw Error.unsupportedWitnessVersion(witver)
        }
        do {
            let program = try Bech32.convertBits(Array(data5.dropFirst()), from: 5, to: 8, pad: false)
            guard program.count == 20 else {
                throw Error.wrongPayloadLength(program.count)
            }
            return Data(program)
        } catch let e as Bech32.Error {
            throw Error.bech32(e)
        }
    }
}
