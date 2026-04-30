import XCTest
@testable import EnochCore

final class Secp256k1Tests: XCTestCase {
    /// Round-trip: generate, export raw bytes, restore — should
    /// produce a key that signs/verifies identically.
    func testRoundTripRestore() throws {
        let original = try Secp256k1.PrivateKey()
        let restored = try Secp256k1.PrivateKey(rawBytes: original.rawBytes)
        XCTAssertEqual(original.rawBytes, restored.rawBytes)
        XCTAssertEqual(original.publicKey.compressedBytes, restored.publicKey.compressedBytes)
    }

    /// Compressed SEC1 pubkeys are exactly 33 bytes with leading
    /// 0x02 or 0x03 — the wire format Bitcoin scriptSigs push.
    func testPublicKeyCompressedLength() throws {
        let key = try Secp256k1.PrivateKey()
        let pub = key.publicKey.compressedBytes
        XCTAssertEqual(pub.count, 33)
        XCTAssertTrue(pub[0] == 0x02 || pub[0] == 0x03)
    }

    /// Fundamental sanity: a signature over a digest verifies
    /// against the same digest with the same key. This exercises
    /// both the `Digest`-overload sign path and the `Digest`-
    /// overload verify path — re-hashing bugs would surface as a
    /// false negative here.
    func testSignThenVerify() throws {
        let key = try Secp256k1.PrivateKey()
        let digest = Data(repeating: 0xAB, count: 32)
        let sig = try key.signDigest(digest)
        XCTAssertTrue(key.publicKey.verifyDigest(digest, signature: sig))
    }

    /// A signature over digest A must NOT verify against digest B.
    /// Catches the "we accidentally re-hashed and got the same
    /// degenerate result twice" failure mode.
    func testVerifyRejectsDifferentDigest() throws {
        let key = try Secp256k1.PrivateKey()
        let digest = Data(repeating: 0xAB, count: 32)
        let sig = try key.signDigest(digest)
        let other = Data(repeating: 0xCD, count: 32)
        XCTAssertFalse(key.publicKey.verifyDigest(other, signature: sig))
    }

    /// A signature must NOT verify under a different key.
    func testVerifyRejectsWrongKey() throws {
        let signer = try Secp256k1.PrivateKey()
        let other = try Secp256k1.PrivateKey()
        let digest = Data(repeating: 0xAB, count: 32)
        let sig = try signer.signDigest(digest)
        XCTAssertFalse(other.publicKey.verifyDigest(digest, signature: sig))
    }

    /// RFC 6979 deterministic-k means signing the same message
    /// twice with the same key produces the same signature. The
    /// operator's verifier doesn't require this, but it's a strong
    /// signal that nonces aren't leaking entropy across sigs.
    func testDeterministicSignature() throws {
        let key = try Secp256k1.PrivateKey()
        let digest = Data(repeating: 0xAB, count: 32)
        let s1 = try key.signDigest(digest)
        let s2 = try key.signDigest(digest)
        XCTAssertEqual(s1, s2)
    }

    /// `derWithSighashAll` is what gets pushed in scriptSig. The
    /// shape is "DER || 0x01" — verify the byte boundary so a
    /// future refactor doesn't accidentally insert padding.
    func testSighashAllAppendedAtEnd() throws {
        let key = try Secp256k1.PrivateKey()
        let digest = Data(repeating: 0xAB, count: 32)
        let sig = try key.signDigest(digest)
        let withFlag = sig.derWithSighashAll
        XCTAssertEqual(withFlag.count, sig.der.count + 1)
        XCTAssertEqual(withFlag.last, Secp256k1.sighashAllByte)
        XCTAssertEqual(withFlag.prefix(sig.der.count), sig.der)
    }

    /// Wrong-sized digest input — the API is precise about taking
    /// 32 bytes, surface a clear error rather than silently
    /// signing a malformed input.
    func testWrongDigestLengthRejected() throws {
        let key = try Secp256k1.PrivateKey()
        XCTAssertThrowsError(try key.signDigest(Data(repeating: 0, count: 31))) { err in
            guard case Secp256k1.Error.invalidDigestLength(let n) = err else {
                return XCTFail("unexpected error: \(err)")
            }
            XCTAssertEqual(n, 31)
        }
    }

    func testWrongPrivateKeyLengthRejected() {
        XCTAssertThrowsError(try Secp256k1.PrivateKey(rawBytes: Data(repeating: 0, count: 31))) { err in
            guard case Secp256k1.Error.invalidPrivateKeyLength(let n) = err else {
                return XCTFail("unexpected error: \(err)")
            }
            XCTAssertEqual(n, 31)
        }
    }
}
