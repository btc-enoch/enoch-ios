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
