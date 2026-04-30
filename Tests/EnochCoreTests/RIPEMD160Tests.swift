import XCTest
@testable import EnochCore

final class RIPEMD160Tests: XCTestCase {
    /// The canonical RIPEMD160 test vectors from the original
    /// Bosselaers/Preneel reference (https://homes.esat.kuleuven.be/
    /// ~bosselae/ripemd160.html). Any deviation here means the round
    /// tables, padding, or compression function is wrong — and any
    /// such bug would silently corrupt every wallet address derived
    /// from a pubkey.
    private let vectors: [(message: String, expected: String)] = [
        ("",                              "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        ("a",                             "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        ("abc",                           "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        ("message digest",                "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        ("abcdefghijklmnopqrstuvwxyz",    "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                                          "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                                          "b0e20b6e3116640286ed3a87a5713079b21f5189"),
    ]

    func testCanonicalVectors() throws {
        for (msg, expected) in vectors {
            let got = RIPEMD160.hash(Data(msg.utf8)).hexString
            XCTAssertEqual(got, expected, "RIPEMD160(\"\(msg)\") = \(got), want \(expected)")
        }
    }

    /// A 64-byte input crosses a single block boundary cleanly (the
    /// pad pushes us into a second block). Catches off-by-one bugs
    /// in `pad()` that the short vectors above wouldn't expose.
    func testEightCopiesOf1234567890() {
        let msg = String(repeating: "1234567890", count: 8) // 80 bytes
        let got = RIPEMD160.hash(Data(msg.utf8)).hexString
        XCTAssertEqual(got, "9b752e45573d4b39f4dbd3323cab82bf63326bfb")
    }

    /// Output is always 20 bytes regardless of input.
    func testOutputLength() {
        XCTAssertEqual(RIPEMD160.hash(Data()).count, 20)
        XCTAssertEqual(RIPEMD160.hash(Data(repeating: 0, count: 1)).count, 20)
        XCTAssertEqual(RIPEMD160.hash(Data(repeating: 0, count: 1000)).count, 20)
    }
}
