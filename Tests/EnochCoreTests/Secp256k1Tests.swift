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

    // MARK: - Schnorr (BIP-340) — used by L2 P2TR keypath spends post-#109

    /// Round-trip: sign a 32-byte digest with the wallet's privkey,
    /// verify the resulting 64-byte Schnorr signature against the
    /// derived x-only pubkey.
    func testSchnorrSignVerifyRoundTrip() throws {
        let priv = try Secp256k1.PrivateKey()
        let xonly = try Secp256k1.XOnlyPublicKey.from(compressed: priv.publicKey.compressedBytes)

        let digest = Data((1...32).map { UInt8($0) })
        let sig = try Secp256k1.schnorrSign(digest: digest, privKey: priv)

        XCTAssertEqual(sig.bytes.count, 64)
        XCTAssertTrue(Secp256k1.schnorrVerify(signature: sig, digest: digest, publicKey: xonly))
    }

    /// Verification under a DIFFERENT digest must fail. Catches
    /// "verifier ignores its inputs" regressions.
    func testSchnorrVerifyRejectsTamperedDigest() throws {
        let priv = try Secp256k1.PrivateKey()
        let xonly = try Secp256k1.XOnlyPublicKey.from(compressed: priv.publicKey.compressedBytes)

        let digest = Data(repeating: 0xAB, count: 32)
        let sig = try Secp256k1.schnorrSign(digest: digest, privKey: priv)

        var tampered = digest
        tampered[0] ^= 0xFF
        XCTAssertFalse(Secp256k1.schnorrVerify(signature: sig, digest: tampered, publicKey: xonly))
    }

    /// Verification with the WRONG pubkey must fail. Catches
    /// "verifier doesn't actually look at the pubkey" regressions.
    func testSchnorrVerifyRejectsWrongKey() throws {
        let alice = try Secp256k1.PrivateKey()
        let bob   = try Secp256k1.PrivateKey()
        let bobXonly = try Secp256k1.XOnlyPublicKey.from(compressed: bob.publicKey.compressedBytes)

        let digest = Data(repeating: 0xCD, count: 32)
        let sig = try Secp256k1.schnorrSign(digest: digest, privKey: alice)

        XCTAssertFalse(Secp256k1.schnorrVerify(signature: sig, digest: digest, publicKey: bobXonly))
    }

    /// Schnorr signatures are deterministic per BIP-340 with zero
    /// auxiliary randomness, but the swift-secp256k1 default mixes
    /// in fresh randomness — so two signatures of the same digest
    /// SHOULD differ. (If this ever flips to deterministic, the
    /// signature is still valid; this test just documents the
    /// current property.)
    func testSchnorrAuxRandomnessProducesDifferentSigs() throws {
        let priv = try Secp256k1.PrivateKey()
        let digest = Data(repeating: 0x01, count: 32)
        let sig1 = try Secp256k1.schnorrSign(digest: digest, privKey: priv)
        let sig2 = try Secp256k1.schnorrSign(digest: digest, privKey: priv)
        XCTAssertNotEqual(sig1.bytes, sig2.bytes,
                          "default signing path mixes in aux randomness; sigs must differ")
    }

    /// X-only key has the right shape: 32 bytes, derived from the
    /// 33-byte compressed form by dropping the parity prefix.
    func testXOnlyFromCompressed() throws {
        let priv = try Secp256k1.PrivateKey()
        let compressed = priv.publicKey.compressedBytes
        let xonly = try Secp256k1.XOnlyPublicKey.from(compressed: compressed)
        XCTAssertEqual(xonly.bytes.count, 32)
        XCTAssertEqual(xonly.bytes, compressed.subdata(in: 1..<33))
    }

    func testXOnlyRejectsWrongLength() {
        XCTAssertThrowsError(try Secp256k1.XOnlyPublicKey(bytes: Data(repeating: 0, count: 31)))
        XCTAssertThrowsError(try Secp256k1.XOnlyPublicKey(bytes: Data(repeating: 0, count: 33)))
    }

    func testSchnorrSignatureRejectsWrongLength() {
        XCTAssertThrowsError(try Secp256k1.SchnorrSignature(bytes: Data(repeating: 0, count: 63)))
        XCTAssertThrowsError(try Secp256k1.SchnorrSignature(bytes: Data(repeating: 0, count: 65)))
    }
}
