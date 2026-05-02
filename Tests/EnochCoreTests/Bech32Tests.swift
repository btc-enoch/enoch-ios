import XCTest
@testable import EnochCore

final class Bech32Tests: XCTestCase {
    // BIP173 test vectors known to be valid bech32 with their HRPs.
    // We don't decode-then-redecode here because BIP173 strings are
    // case-insensitive but encode emits lowercase — equality on the
    // raw string would be misleading. We only assert decode succeeds.
    private let bip173Valid = [
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    ]

    func testBIP173ValidVectorsDecode() throws {
        for s in bip173Valid {
            XCTAssertNoThrow(try Bech32.decode(s), "should decode \(s)")
        }
    }

    func testRoundTripPreservesData() throws {
        let raw: [UInt8] = (0..<20).map { UInt8($0) }
        let data5 = try Bech32.convertBits(raw, from: 8, to: 5, pad: true)
        let encoded = try Bech32.encode(hrp: "test", data: data5)
        let (hrp, decoded5) = try Bech32.decode(encoded)
        XCTAssertEqual(hrp, "test")
        let roundTripped = try Bech32.convertBits(decoded5, from: 5, to: 8, pad: false)
        XCTAssertEqual(roundTripped, raw)
    }

    /// BIP-350 round trip via the new variant-aware encoder/decoder.
    /// A bech32m string MUST decode with `variant == .bech32m`; a
    /// bech32m-encoded string MUST NOT validate under BIP-173.
    func testBech32mRoundTrip() throws {
        let raw: [UInt8] = (0..<32).map { UInt8($0) }
        let data5 = try Bech32.convertBits(raw, from: 8, to: 5, pad: true)
        let encoded = try Bech32.encode(hrp: "test", data: data5, variant: .bech32m)

        let (hrp, decoded5, variant) = try Bech32.decodeAny(encoded)
        XCTAssertEqual(hrp, "test")
        XCTAssertEqual(variant, .bech32m)
        let roundTripped = try Bech32.convertBits(decoded5, from: 5, to: 8, pad: false)
        XCTAssertEqual(roundTripped, raw)

        // Strict BIP-173 decoder must reject a bech32m string.
        XCTAssertThrowsError(try Bech32.decode(encoded)) { err in
            XCTAssertEqual(err as? Bech32.Error, .invalidChecksum)
        }
    }

    /// Cross-variant: a bech32 string MUST decode as `.bech32` via
    /// the variant-aware decoder. Used as the contract for
    /// Address.decode's variant dispatch.
    func testDecodeAnyDistinguishesVariants() throws {
        let data5 = try Bech32.convertBits([UInt8](repeating: 0, count: 20), from: 8, to: 5, pad: true)
        let asBech32  = try Bech32.encode(hrp: "test", data: data5, variant: .bech32)
        let asBech32m = try Bech32.encode(hrp: "test", data: data5, variant: .bech32m)

        XCTAssertEqual(try Bech32.decodeAny(asBech32).variant, .bech32)
        XCTAssertEqual(try Bech32.decodeAny(asBech32m).variant, .bech32m)
        XCTAssertNotEqual(asBech32, asBech32m, "the two checksums must produce different strings")
    }

    func testMixedCaseRejected() {
        XCTAssertThrowsError(try Bech32.decode("Bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")) { err in
            XCTAssertEqual(err as? Bech32.Error, .mixedCase)
        }
    }

    func testMissingSeparatorRejected() {
        XCTAssertThrowsError(try Bech32.decode("noseparatorhere")) { err in
            // Either missingSeparator or invalidLength is acceptable;
            // the string lacks a final '1' so the HRP/data split fails.
            switch err as? Bech32.Error {
            case .missingSeparator, .invalidLength: break
            default: XCTFail("unexpected error: \(err)")
            }
        }
    }

    func testInvalidChecksumRejected() {
        // Flip one character of a known-good vector.
        XCTAssertThrowsError(try Bech32.decode("a12uel5x")) { err in
            XCTAssertEqual(err as? Bech32.Error, .invalidChecksum)
        }
    }

    func testConvertBits8To5RoundTrip() throws {
        let raw: [UInt8] = [0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
                            0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6]
        let five = try Bech32.convertBits(raw, from: 8, to: 5, pad: true)
        let back = try Bech32.convertBits(five, from: 5, to: 8, pad: false)
        XCTAssertEqual(back, raw)
    }
}
