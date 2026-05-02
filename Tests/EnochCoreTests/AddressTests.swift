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

    /// Taproot can't be reduced to a 20-byte pkh, so the legacy
    /// `decodeToPKH` rejects it. Same input goes through the new
    /// `decode` API in the dedicated test below.
    func testTaprootRejectedByDecodeToPKH() {
        let taproot = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx"
        XCTAssertThrowsError(try Address.decodeToPKH(taproot)) { err in
            guard case Address.Error.unsupportedWitnessVersion(let v) = err else {
                return XCTFail("unexpected error: \(err)")
            }
            XCTAssertEqual(v, 1)
        }
    }

    /// BIP-86 canonical mainnet Taproot vector — the first receive
    /// address derived from the BIP-86 test seed (a real 32-byte
    /// x-only output key, not the 40-byte BIP-350 encoding-test
    /// vector). The new `decode` API recognizes it as `.p2tr`.
    func testBitcoinMainnetP2TR() throws {
        let addr = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        let decoded = try Address.decode(addr)
        guard case .p2tr(let outputKey) = decoded else {
            return XCTFail("expected .p2tr, got \(decoded)")
        }
        XCTAssertEqual(outputKey.count, 32)
        // BIP-86 test vector: output key of m/86'/0'/0'/0/0
        XCTAssertEqual(
            outputKey.map { String(format: "%02x", $0) }.joined(),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        )
    }

    /// Round-trip a 32-byte x-only output key through the `enoch1p...`
    /// encoding and back. This is the post-#109 L2 receive address.
    func testEnochTaprootRoundTrip() throws {
        let outputKey = Data((1...32).map { UInt8($0) })
        let addr = try Address.encodeTaproot(outputKey: outputKey)
        XCTAssertTrue(addr.hasPrefix("enoch1p"), "got \(addr)")
        guard case .p2tr(let recovered) = try Address.decode(addr) else {
            return XCTFail("expected .p2tr after round-trip")
        }
        XCTAssertEqual(recovered, outputKey)
    }

    /// Wrong-variant cross-checking: a bech32-encoded enoch1... must
    /// resolve to .p2pkh; a bech32m-encoded enoch1p... must resolve
    /// to .p2tr. The new variant-aware decoder distinguishes them.
    func testVariantSplitsLegacyVsTaproot(){
        let pkh = Data(repeating: 0xab, count: 20)
        let legacy = try? Address.encodeEnoch(pkh: pkh)
        XCTAssertNotNil(legacy)
        if case .p2pkh(let recovered) = try? Address.decode(legacy!) {
            XCTAssertEqual(recovered, pkh)
        } else {
            XCTFail("legacy enoch1 should decode as .p2pkh")
        }

        let outputKey = Data(repeating: 0xcd, count: 32)
        let taproot = try? Address.encodeTaproot(outputKey: outputKey)
        XCTAssertNotNil(taproot)
        if case .p2tr(let recovered) = try? Address.decode(taproot!) {
            XCTAssertEqual(recovered, outputKey)
        } else {
            XCTFail("enoch1p should decode as .p2tr")
        }
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

    /// Gold-standard cross-check: alice's actual pubkey from a real
    /// regtest tx (extracted from her scriptSig) hashes through
    /// HASH160 + bech32 to her actual stored enoch1 address. Proves
    /// RIPEMD160, SHA256 composition, bech32, and the encoder all
    /// agree with the operator side end-to-end.
    func testEnochAddressDerivationMatchesOperator() throws {
        let pubBytes = try Data(hex: "03716d4b4281cd60ad2e3a8cb36cc92dcc870ac5355bce04abb80cbb135a3d063f")
        let pub = try Secp256k1.PublicKey(compressed: pubBytes)
        let addr = try Address.encodeEnoch(publicKey: pub)
        XCTAssertEqual(addr, "enoch12hgh7g39q5w6rwdhmvn6lxk30m8jwce2rq6w36")
    }

    /// Sanity round-trip via the new pubkey overload: derive an
    /// address, decode it back to a pkh, confirm it equals
    /// HASH160(pubkey).
    func testDerivedAddressRoundTripsToHash160() throws {
        let key = try Secp256k1.PrivateKey()
        let addr = try Address.encodeEnoch(publicKey: key.publicKey)
        let pkh = try Address.decodeToPKH(addr)
        XCTAssertEqual(pkh, Hashing.hash160(key.publicKey.compressedBytes))
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
