// Bech32 (BIP173) + Bech32m (BIP350) — pure Swift implementation.
//
// The two variants are byte-for-byte identical except for the
// checksum constant. BIP173 governs witness version 0 + Enoch's
// pre-Taproot legacy `enoch1...` addresses; BIP350 governs witness
// version 1+ (Taproot) + Enoch's post-#109 `enoch1p...` addresses.
//
// Mirrors enoch-edge/internal/address (Go) so a single set of test
// vectors covers both implementations.
//   BIP173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//   BIP350: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

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

    /// Which checksum scheme to use. BIP173 (`bech32`) for witness
    /// version 0 + legacy Enoch addresses; BIP350 (`bech32m`) for
    /// witness version 1+ (Taproot) + post-#109 Enoch P2TR addresses.
    public enum Variant {
        case bech32   // BIP173, constant = 1
        case bech32m  // BIP350, constant = 0x2bc830a3

        var checksumConstant: UInt32 {
            switch self {
            case .bech32:  return 1
            case .bech32m: return 0x2bc830a3
            }
        }
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

    // Generator polynomial coefficients (shared by BIP173 + BIP350).
    private static let gen: [UInt32] = [
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3,
    ]

    /// Encode an HRP + 5-bit data array as a bech32(m) string. Default
    /// variant is BIP173 to preserve the existing call sites; pass
    /// `.bech32m` for Taproot-era addresses.
    /// `data` MUST already be in 5-bit-per-symbol form (call
    /// `convertBits(_:from:to:pad:)` to translate from raw bytes).
    public static func encode(hrp: String, data: [UInt8], variant: Variant = .bech32) throws -> String {
        let lowerHRP = hrp.lowercased()
        try validateHRPChars(lowerHRP)
        let checksum = createChecksum(hrp: lowerHRP, data: data, variant: variant)
        var result = lowerHRP + "1"
        for v in data + checksum {
            result.append(charset[Int(v)])
        }
        return result
    }

    /// Decode a bech32(m) string into (hrp, 5-bit data, variant). The
    /// caller learns from the returned variant whether the input was
    /// BIP173 (witness v0 / legacy) or BIP350 (witness v1 / Taproot).
    /// Caller is responsible for converting back to bytes via
    /// `convertBits` and for validating that the variant matches the
    /// witness version of the encoded payload (BIP350 requires v1+,
    /// BIP173 requires v0).
    public static func decodeAny(_ s: String) throws -> (hrp: String, data: [UInt8], variant: Variant) {
        let (hrp, dataWithChecksum) = try decodeRaw(s)
        if polymod(hrpExpand(hrp) + dataWithChecksum) == Variant.bech32.checksumConstant {
            return (hrp, Array(dataWithChecksum.dropLast(6)), .bech32)
        }
        if polymod(hrpExpand(hrp) + dataWithChecksum) == Variant.bech32m.checksumConstant {
            return (hrp, Array(dataWithChecksum.dropLast(6)), .bech32m)
        }
        throw Error.invalidChecksum
    }

    /// Backward-compat: decode strictly as BIP173 (the original behavior).
    /// Existing call sites in Address.swift continue to use this.
    public static func decode(_ s: String) throws -> (hrp: String, data: [UInt8]) {
        let (hrp, dataWithChecksum) = try decodeRaw(s)
        if !verifyChecksum(hrp: hrp, data: dataWithChecksum, variant: .bech32) {
            throw Error.invalidChecksum
        }
        // Strip the 6-symbol checksum tail from the returned data.
        return (hrp, Array(dataWithChecksum.dropLast(6)))
    }

    /// Shared parsing for BIP173 + BIP350: validates structure, returns
    /// (hrp, data-including-checksum). Callers verify the checksum
    /// against the expected variant.
    private static func decodeRaw(_ s: String) throws -> (hrp: String, data: [UInt8]) {
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

        // HRP is 1..83 chars, data section >= 6 (the checksum), total <= 90.
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
        return (hrp, data)
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

    private static func verifyChecksum(hrp: String, data: [UInt8], variant: Variant) -> Bool {
        return polymod(hrpExpand(hrp) + data) == variant.checksumConstant
    }

    private static func createChecksum(hrp: String, data: [UInt8], variant: Variant) -> [UInt8] {
        let values = hrpExpand(hrp) + data + [0, 0, 0, 0, 0, 0]
        let mod = polymod(values) ^ variant.checksumConstant
        var out = [UInt8](repeating: 0, count: 6)
        for i in 0..<6 {
            out[i] = UInt8((mod >> (5 * (5 - i))) & 31)
        }
        return out
    }
}
