import XCTest
@testable import EnochCore

final class AddressTests: XCTestCase {
    /// Round-trip the full pkh space we can hit on the wallet's
    /// happy path: arbitrary 20-byte hash → enoch1 → back to bytes.
    func testEnochRoundTrip() throws {
        let pkh = Data((1...20).map { UInt8($0) })
        let addr = try Address.encodeEnoch(pkh: pkh)
        XCTAssertTrue(addr.hasPrefix("enoch1"))
        let recovered = try Address.decodeToPKH(addr)
        XCTAssertEqual(recovered, pkh)
    }

    /// BIP173 canonical mainnet P2WPKH vector. Same vector our Go-side
    /// decoder uses, so wallet ↔ edge address handling is bit-for-bit
    /// identical for this case.
    func testBitcoinMainnetP2WPKH() throws {
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        let expected = Data([
            0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
            0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ])
        let pkh = try Address.decodeToPKH(addr)
        XCTAssertEqual(pkh, expected)
    }

    /// Taproot is bech32m, not bech32 — BIP173 decoder rejects it
    /// at checksum validation. Caller-visible: `bech32(.invalidChecksum)`.
    func testTaprootRejected() {
        let taproot = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx"
        XCTAssertThrowsError(try Address.decodeToPKH(taproot))
    }

    /// HRP-policed: a syntactically valid bech32 string with an HRP
    /// the wallet doesn't accept (`doge`) must fail before any
    /// payload decoding work.
    func testUnknownHRPRejected() throws {
        let pkh = Data(repeating: 0, count: 20)
        let data5 = try Bech32.convertBits([UInt8](pkh), from: 8, to: 5, pad: true)
        let dogeAddr = try Bech32.encode(hrp: "doge", data: data5)
        XCTAssertThrowsError(try Address.decodeToPKH(dogeAddr)) { err in
            guard case Address.Error.wrongHRP(let hrp) = err else {
                return XCTFail("unexpected error: \(err)")
            }
            XCTAssertEqual(hrp, "doge")
        }
    }

    func testGarbageRejected() {
        XCTAssertThrowsError(try Address.decodeToPKH("not-an-address"))
    }

    /// Wrong pkh length on encode is a programmer error — surface it
    /// with the real length, not a generic "invalid" error.
    func testEncodeWrongLengthRejected() {
        XCTAssertThrowsError(try Address.encodeEnoch(pkh: Data(repeating: 0, count: 19))) { err in
            guard case Address.Error.wrongPayloadLength(let n) = err else {
                return XCTFail("unexpected error: \(err)")
            }
            XCTAssertEqual(n, 19)
        }
    }
}
