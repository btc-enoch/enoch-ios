// Bech32 (BIP173) — pure Swift implementation.
//
// We deliberately do NOT cover bech32m (BIP350, segwit v1 / Taproot).
// Enoch L2 addresses use BIP173 with HRP="enoch" and no witness
// version byte. Bitcoin segwit-v0 addresses (bc1q.../tb1q.../bcrt1q...)
// also use BIP173 and we accept those for cross-format wallet input.
//
// Mirrors enoch-edge/internal/address (Go) so a single set of
// BIP173 vectors covers both implementations. Spec:
// https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki

import Foundation

public enum Bech32 {
    public enum Error: Swift.Error, Equatable {
        case invalidLength
        case invalidCharacter(Character)
        case mixedCase
        case missingSeparator
        case invalidChecksum
        case invalidPadding
        case bitConversion
    }

    // BIP173 charset; index = 5-bit value.
    private static let charset: [Character] = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

    // Reverse lookup: ASCII char -> 5-bit value, or -1 if not in charset.
    private static let charsetReverse: [Int8] = {
        var t = [Int8](repeating: -1, count: 128)
        for (i, c) in charset.enumerated() {
            t[Int(c.asciiValue!)] = Int8(i)
        }
        return t
    }()

    // Generator polynomial coefficients (BIP173).
    private static let gen: [UInt32] = [
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
    ]

    // BIP173 checksum constant. (BIP350 / bech32m uses 0x2bc830a3;
    // intentionally omitted — Enoch + segwit-v0 are both BIP173.)
    private static let checksumConst: UInt32 = 1

    /// Encode an HRP + 5-bit data array as a bech32 string.
    /// `data` MUST already be in 5-bit-per-symbol form (call
    /// `convertBits(_:from:to:pad:)` to translate from raw bytes).
    public static func encode(hrp: String, data: [UInt8]) throws -> String {
        let lowerHRP = hrp.lowercased()
        try validateHRPChars(lowerHRP)
        let checksum = createChecksum(hrp: lowerHRP, data: data)
        var result = lowerHRP + "1"
        for v in data + checksum {
            result.append(charset[Int(v)])
        }
        return result
    }

    /// Decode a bech32 string into (hrp, 5-bit data). Caller is
    /// responsible for converting back to bytes via convertBits.
    public static func decode(_ s: String) throws -> (hrp: String, data: [UInt8]) {
        // BIP173 forbids mixed-case strings.
        let hasLower = s.contains(where: { $0.isLowercase })
        let hasUpper = s.contains(where: { $0.isUppercase })
        if hasLower && hasUpper {
            throw Error.mixedCase
        }
        let lower = s.lowercased()

        guard let sepRange = lower.range(of: "1", options: .backwards) else {
            throw Error.missingSeparator
        }
        let sepIdx = lower.distance(from: lower.startIndex, to: sepRange.lowerBound)

        // BIP173: HRP is 1..83 chars, data section >= 6 (the checksum), total <= 90.
        if sepIdx < 1 || sepIdx + 7 > lower.count || lower.count > 90 {
            throw Error.invalidLength
        }

        let hrp = String(lower.prefix(sepIdx))
        try validateHRPChars(hrp)

        var data = [UInt8]()
        data.reserveCapacity(lower.count - sepIdx - 1)
        for ch in lower.suffix(lower.count - sepIdx - 1) {
            guard let ascii = ch.asciiValue, ascii < 128 else {
                throw Error.invalidCharacter(ch)
            }
            let v = charsetReverse[Int(ascii)]
            if v < 0 {
                throw Error.invalidCharacter(ch)
            }
            data.append(UInt8(v))
        }

        if !verifyChecksum(hrp: hrp, data: data) {
            throw Error.invalidChecksum
        }
        // Strip the 6-symbol checksum tail from the returned data.
        return (hrp, Array(data.dropLast(6)))
    }

    /// Re-pack a byte array between bit widths (e.g. 8→5 for encoding,
    /// 5→8 for decoding). `pad=true` zero-extends a partial final group;
    /// `pad=false` requires the input to be exact and rejects leftover
    /// bits, which is the correct behavior on the decode path.
    public static func convertBits(_ data: [UInt8], from: Int, to: Int, pad: Bool) throws -> [UInt8] {
        var acc: UInt32 = 0
        var bits = 0
        var out = [UInt8]()
        let maxv: UInt32 = (1 << to) - 1
        let maxAcc: UInt32 = (1 << (from + to - 1)) - 1
        for v in data {
            let value = UInt32(v)
            if value >> from != 0 {
                throw Error.bitConversion
            }
            acc = ((acc << from) | value) & maxAcc
            bits += from
            while bits >= to {
                bits -= to
                out.append(UInt8((acc >> bits) & maxv))
            }
        }
        if pad {
            if bits > 0 {
                out.append(UInt8((acc << (to - bits)) & maxv))
            }
        } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
            throw Error.invalidPadding
        }
        return out
    }

    // MARK: - Internals

    private static func validateHRPChars(_ hrp: String) throws {
        if hrp.isEmpty || hrp.count > 83 { throw Error.invalidLength }
        for ch in hrp {
            guard let a = ch.asciiValue, (33...126).contains(a) else {
                throw Error.invalidCharacter(ch)
            }
        }
    }

    private static func polymod(_ values: [UInt8]) -> UInt32 {
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ UInt32(v)
            for i in 0..<5 {
                if ((top >> i) & 1) != 0 {
                    chk ^= gen[i]
                }
            }
        }
        return chk
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(hrp.count * 2 + 1)
        for ch in hrp {
            out.append(UInt8(ch.asciiValue! >> 5))
        }
        out.append(0)
        for ch in hrp {
            out.append(UInt8(ch.asciiValue! & 31))
        }
        return out
    }

    private static func verifyChecksum(hrp: String, data: [UInt8]) -> Bool {
        return polymod(hrpExpand(hrp) + data) == checksumConst
    }

    private static func createChecksum(hrp: String, data: [UInt8]) -> [UInt8] {
        let values = hrpExpand(hrp) + data + [0, 0, 0, 0, 0, 0]
        let mod = polymod(values) ^ checksumConst
        var out = [UInt8](repeating: 0, count: 6)
        for i in 0..<6 {
            out[i] = UInt8((mod >> (5 * (5 - i))) & 31)
        }
        return out
    }
}
