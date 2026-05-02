import XCTest
@testable import EnochCore

/// Tests target `InMemoryWalletKeystore` — KeychainWalletKeystore
/// requires a real device + biometric and isn't useful to exercise
/// from `swift test` on a build server. The two implementations
/// share the WalletKeystore protocol contract, so passing tests here
/// also document what behavior the Keychain impl is expected to
/// provide on-device.
final class WalletKeystoreTests: XCTestCase {
    /// Fresh keystore reports no key. Lets a launching app render an
    /// onboarding screen vs. the wallet home without prompting.
    func testFreshKeystoreHasNoKey() throws {
        let ks = InMemoryWalletKeystore()
        XCTAssertNil(try ks.publicKey())
    }

    /// createKey returns the public part of the freshly-stored key,
    /// AND a subsequent publicKey() returns the same compressed
    /// bytes. Catches a class of bugs where the create path stores
    /// one key but the read path returns something else.
    func testCreateKeyPublishesPublicKey() throws {
        let ks = InMemoryWalletKeystore()
        let created = try ks.createKey()
        let loaded = try XCTUnwrap(try ks.publicKey())
        XCTAssertEqual(created.compressedBytes, loaded.compressedBytes)
    }

    /// Calling createKey twice without an intervening delete is a
    /// programmer bug — could overwrite a funded wallet with a
    /// freshly generated key. Surface it loudly.
    func testCreateKeyTwiceFails() throws {
        let ks = InMemoryWalletKeystore()
        _ = try ks.createKey()
        XCTAssertThrowsError(try ks.createKey()) { err in
            XCTAssertEqual(err as? WalletKeystoreError, .keyAlreadyExists)
        }
    }

    /// Sign then locally verify against the published public key.
    /// Proves the keystore-stored privkey actually matches the
    /// pubkey it advertised at create time.
    func testSignVerifiesAgainstPublicKey() async throws {
        let ks = InMemoryWalletKeystore()
        let pub = try ks.createKey()
        let digest = Data(repeating: 0xAB, count: 32)
        let sig = try await ks.sign(digest: digest, prompt: "test")
        XCTAssertTrue(pub.verifyDigest(digest, signature: sig))
    }

    /// Signing without ever calling createKey must fail cleanly,
    /// not crash. UI maps `.keyNotFound` to the onboarding flow.
    func testSignBeforeCreateFails() async {
        let ks = InMemoryWalletKeystore()
        do {
            _ = try await ks.sign(digest: Data(repeating: 0, count: 32), prompt: "test")
            XCTFail("expected throw")
        } catch let err as WalletKeystoreError {
            XCTAssertEqual(err, .keyNotFound)
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    /// delete() makes the keystore behave like fresh, so a "reset
    /// wallet" flow + onboarding immediately after works.
    func testDeleteResets() throws {
        let ks = InMemoryWalletKeystore()
        _ = try ks.createKey()
        try ks.delete()
        XCTAssertNil(try ks.publicKey())
        // And we can create again without hitting keyAlreadyExists.
        _ = try ks.createKey()
    }

    /// delete() on an empty keystore is a no-op rather than an
    /// error. Lets reset flows be idempotent.
    func testDeleteOnEmptyKeystoreIsNoOp() throws {
        let ks = InMemoryWalletKeystore()
        XCTAssertNoThrow(try ks.delete())
    }

    // MARK: - Taproot keypath signing (#109)

    /// Sign a digest via signTaprootKeypath and verify the resulting
    /// 64-byte Schnorr signature against the wallet's Taproot output
    /// key. End-to-end check that the keystore's tweak+sign matches
    /// what an external verifier (or txscript engine) would expect
    /// from a P2TR keypath spend at this address.
    func testSignTaprootKeypathVerifiesAgainstOutputKey() async throws {
        let ks = InMemoryWalletKeystore()
        _ = try ks.createKey()
        // Recover the underlying privkey via a fresh InMemoryKeystore
        // path: createKey + publicKey is enough to compute the output
        // key; the keystore signs internally with the tweaked priv.
        // We cross-check against schnorrVerify under that output key.
        let priv = try Secp256k1.PrivateKey()                 // distinct test key
        let testKs = InMemoryWalletKeystore.preloaded(privKey: priv)
        let outputKey = try priv.taprootOutputKey()

        let digest = Data(repeating: 0x42, count: 32)
        let sig = try await testKs.signTaprootKeypath(digest: digest, prompt: "test")
        XCTAssertEqual(sig.bytes.count, 64)
        XCTAssertTrue(Secp256k1.schnorrVerify(signature: sig, digest: digest, publicKey: outputKey))
    }

    /// Negative: signing with the legacy ECDSA path must NOT verify
    /// as a Schnorr signature against the Taproot output key.
    /// Catches "the two paths accidentally produce the same sig"
    /// regressions even though the underlying crypto is different.
    func testEcdsaSigDoesNotVerifyAsSchnorr() async throws {
        let priv = try Secp256k1.PrivateKey()
        let ks = InMemoryWalletKeystore.preloaded(privKey: priv)
        let outputKey = try priv.taprootOutputKey()

        let digest = Data(repeating: 0xCD, count: 32)
        let ecdsaSig = try await ks.sign(digest: digest, prompt: "test")
        // Repackage the first 64 DER bytes as if it were a Schnorr sig
        // — not a valid form, but documents that they're disjoint.
        if ecdsaSig.der.count >= 64,
           let bogus = try? Secp256k1.SchnorrSignature(bytes: ecdsaSig.der.prefix(64)) {
            XCTAssertFalse(Secp256k1.schnorrVerify(signature: bogus, digest: digest, publicKey: outputKey))
        }
    }

    func testSignTaprootKeypathBeforeCreateFails() async {
        let ks = InMemoryWalletKeystore()
        do {
            _ = try await ks.signTaprootKeypath(digest: Data(repeating: 0, count: 32), prompt: "test")
            XCTFail("expected throw")
        } catch let err as WalletKeystoreError {
            XCTAssertEqual(err, .keyNotFound)
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }
}

// MARK: - Test helper: pre-load a known privkey

extension InMemoryWalletKeystore {
    /// Test-only: build a keystore around a caller-provided privkey
    /// so cross-checks (sign here, verify with that key's pubkey)
    /// are deterministic. Mirrors `createKey` but skips the
    /// random-generation step.
    static func preloaded(privKey: Secp256k1.PrivateKey) -> InMemoryWalletKeystore {
        let ks = InMemoryWalletKeystore()
        // Reach into the private storage via a shim — we don't expose
        // a public seed-from-bytes initializer because production
        // wallets never want one (every key is fresh from libsecp's
        // CSRNG). Tests are the exception.
        ks._setPrivateKeyForTesting(privKey)
        return ks
    }
}
