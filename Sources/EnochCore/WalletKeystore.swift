// WalletKeystore — abstraction over "where the wallet's secp256k1
// private key lives." Production deployments back this with the iOS
// Keychain (KeychainWalletKeystore) so signing requires Face ID;
// tests and SwiftUI previews back it with InMemoryWalletKeystore.
//
// The protocol is small on purpose: create-once, read pubkey freely,
// sign with biometric gate, wipe on reset. HD-wallet derivation and
// multi-key support are deliberately out of scope (see
// memory/feedback_no_bdk_swift — single-key for the PoC).

import Foundation

public enum WalletKeystoreError: Swift.Error, Equatable {
    case keyAlreadyExists
    case keyNotFound
    case userCancelled
    case authenticationFailed
    case unhandledStatus(Int32)        // OSStatus from Security framework
    case malformedStoredKey            // bytes returned by Keychain weren't 32

    public static func == (lhs: WalletKeystoreError, rhs: WalletKeystoreError) -> Bool {
        switch (lhs, rhs) {
        case (.keyAlreadyExists, .keyAlreadyExists),
             (.keyNotFound, .keyNotFound),
             (.userCancelled, .userCancelled),
             (.authenticationFailed, .authenticationFailed),
             (.malformedStoredKey, .malformedStoredKey):
            return true
        case (.unhandledStatus(let a), .unhandledStatus(let b)):
            return a == b
        default:
            return false
        }
    }
}

public protocol WalletKeystore {
    /// Generate a fresh Secp256k1 key and store it. Throws
    /// `.keyAlreadyExists` if the keystore already holds a key —
    /// callers that want to overwrite must `delete()` first, so a
    /// programmer bug can't accidentally rotate funds away.
    func createKey() throws -> Secp256k1.PublicKey

    /// Import an externally-supplied Secp256k1 key and store it.
    /// Same overwrite-safety contract as `createKey`: throws
    /// `.keyAlreadyExists` if a key is already present.
    ///
    /// Used by the "I already have a wallet" / restore flows — the
    /// caller has the raw 32-byte secret from somewhere external
    /// (typed hex, BIP-39 derivation, claim-link, etc.) and asks the
    /// keystore to take ownership. Same biometric ACL as createKey.
    func importKey(_ priv: Secp256k1.PrivateKey) throws -> Secp256k1.PublicKey

    /// Return the public key without prompting biometric. Pubkey is
    /// not biometrically gated — only the *signing* operation is.
    /// Returns nil if no key has been created.
    func publicKey() throws -> Secp256k1.PublicKey?

    /// Sign a precomputed 32-byte digest. On Keychain-backed
    /// implementations this triggers the system biometric prompt;
    /// `prompt` is the user-facing string ("Authorize send", etc.).
    func sign(digest: Data, prompt: String) async throws -> Secp256k1.Signature

    /// Sign a BIP-341 keypath sighash with the **Taproot-tweaked**
    /// private key, returning a 64-byte BIP-340 Schnorr signature.
    /// Used by L2 P2TR keypath spends post-#109.
    ///
    /// The keystore loads the raw privkey, applies the BIP-341
    /// keypath tweak, and signs in one operation — the raw privkey
    /// doesn't leave the keystore boundary, only the (already
    /// tweak-derived) signature does. Same biometric-prompt UX as
    /// `sign(digest:prompt:)`.
    func signTaprootKeypath(digest: Data, prompt: String) async throws -> Secp256k1.SchnorrSignature

    /// Wipe the stored key. Used for "reset wallet" flows; on a
    /// freshly-installed app the keystore is already empty so this
    /// is a no-op.
    func delete() throws
}

// MARK: - In-memory implementation

/// Test / preview keystore. Stores the privkey in process memory only
/// — never persisted, no biometric gate, instant signs. Use this in
/// SwiftUI #Preview, in `swift test`, and in any context where the
/// real Keychain prompt would be a UX blocker.
public final class InMemoryWalletKeystore: WalletKeystore {
    private var key: Secp256k1.PrivateKey?

    public init() {}

    public func createKey() throws -> Secp256k1.PublicKey {
        if key != nil { throw WalletKeystoreError.keyAlreadyExists }
        let k = try Secp256k1.PrivateKey()
        key = k
        return k.publicKey
    }

    public func importKey(_ priv: Secp256k1.PrivateKey) throws -> Secp256k1.PublicKey {
        if key != nil { throw WalletKeystoreError.keyAlreadyExists }
        key = priv
        return priv.publicKey
    }

    public func publicKey() throws -> Secp256k1.PublicKey? {
        return key?.publicKey
    }

    public func sign(digest: Data, prompt _: String) async throws -> Secp256k1.Signature {
        guard let k = key else { throw WalletKeystoreError.keyNotFound }
        return try k.signDigest(digest)
    }

    public func signTaprootKeypath(digest: Data, prompt _: String) async throws -> Secp256k1.SchnorrSignature {
        guard let k = key else { throw WalletKeystoreError.keyNotFound }
        let tweaked = try k.taprootKeypathTweaked()
        return try Secp256k1.schnorrSign(digest: digest, privKey: tweaked)
    }

    public func delete() throws {
        key = nil
    }

    /// Test-only seam: pre-load a known privkey. Lets test code
    /// cross-check signatures against the corresponding pubkey
    /// without going through random generation. NOT exposed via
    /// the protocol — production wallets always generate fresh.
    internal func _setPrivateKeyForTesting(_ priv: Secp256k1.PrivateKey) {
        self.key = priv
    }
}
