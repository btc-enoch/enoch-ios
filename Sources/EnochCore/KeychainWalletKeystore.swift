// KeychainWalletKeystore — production WalletKeystore backed by the
// iOS Keychain with a biometric ACL.
//
// Storage shape:
//   - Service:     "enoch-ios.wallet"
//   - Account:     "primary" (single-key wallet for the PoC)
//   - Class:       kSecClassGenericPassword (raw 32 bytes)
//   - Accessible:  WhenUnlockedThisDeviceOnly (no iCloud sync)
//   - Access ctrl: .biometryCurrentSet — Face ID required for signing,
//                  invalidated automatically if the user adds or
//                  removes a fingerprint/face. Pubkey lookups are NOT
//                  gated (Keychain returns the metadata without
//                  biometric prompt; only the secret value is gated).
//
// Why Keychain rather than Secure Enclave: Apple's SE only supports
// the NIST P-256 curve, not secp256k1. We instead keep the raw 32
// bytes in Keychain with a strong ACL. A future hardening phase can
// add SE-wrapping (encrypt the secp256k1 privkey with an SE-owned
// P-256 key) so the Bitcoin key never touches disk in plaintext;
// out of scope for the PoC.
//
// TESTING NOTE: this implementation only works on a real device or
// the iOS Simulator with a configured biometric. `swift test` on
// macOS will hit Keychain ACL prompts that block CI, which is why
// EnochCore tests use InMemoryWalletKeystore.

import Foundation
import Security

#if canImport(LocalAuthentication)
import LocalAuthentication
#endif

public final class KeychainWalletKeystore: WalletKeystore {
    private let service: String
    private let account: String

    public init(service: String = "enoch-ios.wallet", account: String = "primary") {
        self.service = service
        self.account = account
    }

    // MARK: - createKey / importKey

    public func createKey() throws -> Secp256k1.PublicKey {
        let priv = try Secp256k1.PrivateKey()
        return try storeFreshKey(priv)
    }

    public func importKey(_ priv: Secp256k1.PrivateKey) throws -> Secp256k1.PublicKey {
        return try storeFreshKey(priv)
    }

    /// Shared body for createKey + importKey. Both paths refuse to
    /// overwrite an existing key (callers that want to rotate must
    /// `delete()` first), set the same biometric ACL, and store the
    /// pubkey alongside in the generic-attribute slot so reads don't
    /// need to crack the biometric gate.
    private func storeFreshKey(_ priv: Secp256k1.PrivateKey) throws -> Secp256k1.PublicKey {
        // Existence check — querying for the *attribute* (not the
        // secret) doesn't trigger a biometric prompt, so this is
        // cheap to call on every launch.
        if try storedSecretAttributesExist() {
            throw WalletKeystoreError.keyAlreadyExists
        }

        let pub = priv.publicKey
        let secret = priv.rawBytes

        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &error
        ) else {
            // Construction failure means the platform doesn't
            // support biometric ACL at all — extremely unusual on
            // a real device.
            throw WalletKeystoreError.unhandledStatus(Int32(error?.takeRetainedValue().hashValue ?? 0))
        }

        let attrs: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     service,
            kSecAttrAccount as String:     account,
            kSecAttrAccessControl as String: access,
            kSecValueData as String:       secret,
            // Storing the pubkey alongside lets `publicKey()` answer
            // without needing to crack open the biometric-gated
            // secret. Generic attribute slot is meant for exactly
            // this — small, non-secret metadata about the item.
            kSecAttrGeneric as String:     pub.compressedBytes,
        ]

        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw mapStatus(status)
        }
        return pub
    }

    // MARK: - publicKey

    public func publicKey() throws -> Secp256k1.PublicKey? {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     service,
            kSecAttrAccount as String:     account,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String:      kSecMatchLimitOne,
            // Crucial: do NOT request kSecReturnData. Returning the
            // attribute dictionary keeps this call out of the
            // biometric-gated path so a wallet can render its receive
            // address without prompting Face ID.
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard
                let dict = item as? [String: Any],
                let pubBytes = dict[kSecAttrGeneric as String] as? Data
            else {
                throw WalletKeystoreError.malformedStoredKey
            }
            do {
                return try Secp256k1.PublicKey(compressed: pubBytes)
            } catch {
                throw WalletKeystoreError.malformedStoredKey
            }
        case errSecItemNotFound:
            return nil
        default:
            throw mapStatus(status)
        }
    }

    // MARK: - sign

    public func sign(digest: Data, prompt: String) async throws -> Secp256k1.Signature {
        // Run the (synchronous, possibly blocking) Keychain lookup
        // off the calling thread so the UI doesn't freeze while the
        // biometric sheet is up.
        try await Task.detached(priority: .userInitiated) {
            try self.signSync(digest: digest, prompt: prompt)
        }.value
    }

    public func signTaprootKeypath(digest: Data, prompt: String) async throws -> Secp256k1.SchnorrSignature {
        try await Task.detached(priority: .userInitiated) {
            try self.signTaprootKeypathSync(digest: digest, prompt: prompt)
        }.value
    }

    private func signTaprootKeypathSync(digest: Data, prompt: String) throws -> Secp256k1.SchnorrSignature {
        let key = try loadPrivateKeyWithBiometric(prompt: prompt)
        let tweaked = try key.taprootKeypathTweaked()
        return try Secp256k1.schnorrSign(digest: digest, privKey: tweaked)
    }

    private func signSync(digest: Data, prompt: String) throws -> Secp256k1.Signature {
        let key = try loadPrivateKeyWithBiometric(prompt: prompt)
        return try key.signDigest(digest)
    }

    /// Shared Keychain fetch path used by both ECDSA `sign` and
    /// Schnorr `signTaprootKeypath`. Issues the biometric prompt,
    /// returns the freshly-loaded `Secp256k1.PrivateKey`. Caller
    /// performs whatever signing operation (ECDSA, Schnorr, or
    /// Schnorr-with-tweak) the spend type requires.
    private func loadPrivateKeyWithBiometric(prompt: String) throws -> Secp256k1.PrivateKey {
        var query: [String: Any] = [
            kSecClass as String:        kSecClassGenericPassword,
            kSecAttrService as String:  service,
            kSecAttrAccount as String:  account,
            kSecReturnData as String:   true,
            kSecMatchLimit as String:   kSecMatchLimitOne,
        ]
        #if canImport(LocalAuthentication)
        // Modern (macOS 11+ / iOS 14+) replacement for the deprecated
        // kSecUseOperationPrompt: attach an LAContext with the prompt
        // string set as localizedReason. Same UX, with the option
        // later to cache an authenticated session across multiple
        // signs (e.g. when signing each input of a multi-input tx
        // without re-prompting).
        let ctx = LAContext()
        ctx.localizedReason = prompt
        query[kSecUseAuthenticationContext as String] = ctx
        #endif

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw mapStatus(status)
        }
        guard let bytes = result as? Data, bytes.count == 32 else {
            throw WalletKeystoreError.malformedStoredKey
        }
        return try Secp256k1.PrivateKey(rawBytes: bytes)
    }

    // MARK: - delete

    public func delete() throws {
        let query: [String: Any] = [
            kSecClass as String:        kSecClassGenericPassword,
            kSecAttrService as String:  service,
            kSecAttrAccount as String:  account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        default:
            throw mapStatus(status)
        }
    }

    // MARK: - internals

    /// Checks whether a Keychain item exists at our (service, account)
    /// without fetching the secret — this avoids triggering the
    /// biometric prompt during an existence check.
    private func storedSecretAttributesExist() throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     service,
            kSecAttrAccount as String:     account,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String:      kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:      return true
        case errSecItemNotFound: return false
        default:                 throw mapStatus(status)
        }
    }

    private func mapStatus(_ status: OSStatus) -> WalletKeystoreError {
        switch status {
        case errSecUserCanceled:     return .userCancelled
        case errSecAuthFailed:       return .authenticationFailed
        case errSecItemNotFound:     return .keyNotFound
        case errSecDuplicateItem:    return .keyAlreadyExists
        default:                     return .unhandledStatus(Int32(status))
        }
    }
}

