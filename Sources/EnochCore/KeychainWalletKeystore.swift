// KeychainWalletKeystore — production WalletKeystore backed by the
// iOS Keychain with a biometric ACL.
//
// Multi-wallet model: each wallet is its own Keychain item, keyed by
// `(service, account=wallet_id)`. The user-visible name lives in the
// kSecAttrLabel attribute; the public key in kSecAttrGeneric (so it
// can be read without prompting biometric); the raw 32-byte privkey
// in kSecValueData (biometric-gated). The active wallet id lives in
// UserDefaults.
//
// Storage shape (per wallet):
//   - Service:     "enoch-ios.wallet"
//   - Account:     <wallet_id> — UUID for new wallets, "primary" for legacy
//   - Class:       kSecClassGenericPassword (raw 32 bytes in kSecValueData)
//   - Label:       wallet display name
//   - Generic:     compressed pubkey (33 bytes) — non-secret, for fast reads
//   - Accessible:  WhenUnlockedThisDeviceOnly (no iCloud sync)
//   - Access ctrl: .biometryCurrentSet — Face ID required for signing,
//                  invalidated automatically if the user adds or
//                  removes a fingerprint/face.
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
    private let activeKeyDefault: String

    public init(service: String = "enoch-ios.wallet") {
        self.service = service
        self.activeKeyDefault = "enoch-ios.wallet.activeID"
    }

    // MARK: - listWallets / activeWalletID / selectWallet

    public func listWallets() throws -> [WalletDescriptor] {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     service,
            kSecMatchLimit as String:      kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            // Crucial: do NOT request kSecReturnData — keeps this
            // call out of the biometric-gated path.
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let items = result as? [[String: Any]] else { return [] }
            var out: [WalletDescriptor] = []
            for item in items {
                guard
                    let id = item[kSecAttrAccount as String] as? String
                else { continue }
                let name = (item[kSecAttrLabel as String] as? String) ?? id
                let createdAt = (item[kSecAttrCreationDate as String] as? Date) ?? Date.distantPast
                out.append(WalletDescriptor(id: id, name: name, createdAt: createdAt))
            }
            return out.sorted { $0.createdAt < $1.createdAt }
        case errSecItemNotFound:
            return []
        default:
            throw mapStatus(status)
        }
    }

    public func activeWalletID() -> String? {
        let raw = UserDefaults.standard.string(forKey: activeKeyDefault)
        // Defensive: validate the stored id is still in the keychain;
        // a deleted-from-elsewhere wallet could leave a stale pointer.
        guard let id = raw else { return nil }
        let descriptors = (try? listWallets()) ?? []
        if descriptors.contains(where: { $0.id == id }) {
            return id
        }
        // Stale pointer — repair to the most recent remaining wallet.
        let fallback = descriptors.sorted { $0.createdAt > $1.createdAt }.first?.id
        UserDefaults.standard.setValue(fallback, forKey: activeKeyDefault)
        return fallback
    }

    public func selectWallet(id: String) throws {
        let descriptors = try listWallets()
        guard descriptors.contains(where: { $0.id == id }) else {
            throw WalletKeystoreError.unknownWallet(id)
        }
        UserDefaults.standard.setValue(id, forKey: activeKeyDefault)
    }

    // MARK: - createWallet / importWallet

    public func createWallet(name: String) throws -> WalletDescriptor {
        let priv = try Secp256k1.PrivateKey()
        return try insert(name: name, priv: priv)
    }

    public func importWallet(name: String, priv: Secp256k1.PrivateKey) throws -> WalletDescriptor {
        try insert(name: name, priv: priv)
    }

    private func insert(name: String, priv: Secp256k1.PrivateKey) throws -> WalletDescriptor {
        let id = UUID().uuidString
        let pub = priv.publicKey
        let secret = priv.rawBytes

        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &error
        ) else {
            throw WalletKeystoreError.unhandledStatus(Int32(error?.takeRetainedValue().hashValue ?? 0))
        }

        let attrs: [String: Any] = [
            kSecClass as String:             kSecClassGenericPassword,
            kSecAttrService as String:       service,
            kSecAttrAccount as String:       id,
            kSecAttrLabel as String:         name,
            kSecAttrAccessControl as String: access,
            kSecValueData as String:         secret,
            // Storing the pubkey in the generic-attribute slot lets
            // publicKey() / publicKey(walletID:) answer without
            // cracking the biometric gate.
            kSecAttrGeneric as String:       pub.compressedBytes,
        ]
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw mapStatus(status)
        }
        UserDefaults.standard.setValue(id, forKey: activeKeyDefault)
        return WalletDescriptor(id: id, name: name, createdAt: Date())
    }

    // MARK: - deleteWallet

    public func deleteWallet(id: String) throws {
        let query: [String: Any] = [
            kSecClass as String:        kSecClassGenericPassword,
            kSecAttrService as String:  service,
            kSecAttrAccount as String:  id,
        ]
        let status = SecItemDelete(query as CFDictionary)
        switch status {
        case errSecSuccess, errSecItemNotFound:
            break
        default:
            throw mapStatus(status)
        }
        // Reactivate-the-most-recent-remaining if we deleted the active.
        if UserDefaults.standard.string(forKey: activeKeyDefault) == id {
            let remaining = (try? listWallets()) ?? []
            let fallback = remaining.sorted { $0.createdAt > $1.createdAt }.first?.id
            UserDefaults.standard.setValue(fallback, forKey: activeKeyDefault)
        }
    }

    // MARK: - publicKey

    public func publicKey() throws -> Secp256k1.PublicKey? {
        guard let id = activeWalletID() else { return nil }
        return try publicKey(walletID: id)
    }

    public func publicKey(walletID: String) throws -> Secp256k1.PublicKey? {
        let query: [String: Any] = [
            kSecClass as String:           kSecClassGenericPassword,
            kSecAttrService as String:     service,
            kSecAttrAccount as String:     walletID,
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
        let key = try loadActivePrivateKeyWithBiometric(prompt: prompt)
        return try Secp256k1.signTaprootKeypath(digest: digest, privKey: key)
    }

    private func signSync(digest: Data, prompt: String) throws -> Secp256k1.Signature {
        let key = try loadActivePrivateKeyWithBiometric(prompt: prompt)
        return try key.signDigest(digest)
    }

    /// Shared Keychain fetch path used by both ECDSA `sign` and
    /// Schnorr `signTaprootKeypath`. Issues the biometric prompt for
    /// the active wallet's keychain item, returns the freshly-loaded
    /// `Secp256k1.PrivateKey`.
    private func loadActivePrivateKeyWithBiometric(prompt: String) throws -> Secp256k1.PrivateKey {
        guard let id = activeWalletID() else {
            throw WalletKeystoreError.keyNotFound
        }
        var query: [String: Any] = [
            kSecClass as String:        kSecClassGenericPassword,
            kSecAttrService as String:  service,
            kSecAttrAccount as String:  id,
            kSecReturnData as String:   true,
            kSecMatchLimit as String:   kSecMatchLimitOne,
        ]
        #if canImport(LocalAuthentication)
        // Modern (macOS 11+ / iOS 14+) replacement for the deprecated
        // kSecUseOperationPrompt: attach an LAContext with the prompt
        // string set as localizedReason.
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
