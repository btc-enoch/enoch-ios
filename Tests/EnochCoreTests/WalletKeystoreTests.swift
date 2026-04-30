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
}
