// WalletKeystore — abstraction over "where the wallet's secp256k1
// private key(s) live." Production deployments back this with the iOS
// Keychain (KeychainWalletKeystore) so signing requires Face ID;
// tests and SwiftUI previews back it with InMemoryWalletKeystore.
//
// Multi-wallet model: each wallet is a single secp256k1 keypair plus
// metadata (id, display name, creation date). The keystore tracks an
// "active wallet" id; sign / publicKey() operate on the active wallet.
// Switching wallets is `selectWallet(id:)`. HD-derived multi-account
// (BIP-39) is a separate follow-on; this is independent-keys.

import Foundation

public enum WalletKeystoreError: Swift.Error, Equatable {
    case keyAlreadyExists
    case keyNotFound
    case userCancelled
    case authenticationFailed
    case unhandledStatus(Int32)        // OSStatus from Security framework
    case malformedStoredKey            // bytes returned by Keychain weren't 32
    case unknownWallet(String)         // wallet id not present

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
        case (.unknownWallet(let a), .unknownWallet(let b)):
            return a == b
        default:
            return false
        }
    }
}

/// Public-facing metadata for a single wallet. Returned by
/// `listWallets()` so UIs can render a switcher without prompting
/// biometric. The privkey lives behind `sign(...)` only.
public struct WalletDescriptor: Equatable, Identifiable, Codable, Sendable {
    public let id: String          // stable identity (UUID for new; "primary" for legacy)
    public var name: String
    public let createdAt: Date

    public init(id: String, name: String, createdAt: Date) {
        self.id = id
        self.name = name
        self.createdAt = createdAt
    }
}

public protocol WalletKeystore {
    /// All wallets currently stored, ordered by createdAt ascending.
    /// Pubkey lookups don't trigger biometric — only signing does —
    /// so this is cheap to call on every render.
    func listWallets() throws -> [WalletDescriptor]

    /// id of the currently-active wallet, or nil if there are none.
    /// `sign`, `publicKey()`, etc. operate on the active wallet.
    func activeWalletID() -> String?

    /// Switch the active wallet. Throws `.unknownWallet` if id isn't
    /// in `listWallets()`.
    func selectWallet(id: String) throws

    /// Generate a fresh Secp256k1 key, store it as a new wallet, and
    /// make it active. Returns the new wallet's descriptor.
    func createWallet(name: String) throws -> WalletDescriptor

    /// Import an externally-supplied Secp256k1 key as a new wallet
    /// and make it active. Used by the "I already have a wallet" /
    /// claim-link / BIP-39-restore flows.
    func importWallet(name: String, priv: Secp256k1.PrivateKey) throws -> WalletDescriptor

    /// Delete a specific wallet by id. If the active wallet is
    /// deleted and there are others, the most recent remaining one
    /// becomes active; otherwise activeWalletID becomes nil.
    /// Idempotent on an unknown id.
    func deleteWallet(id: String) throws

    /// Return the public key of the active wallet without prompting
    /// biometric. Returns nil if there are no wallets.
    func publicKey() throws -> Secp256k1.PublicKey?

    /// Public key of a specific wallet by id, no biometric prompt.
    /// Useful for UIs rendering a wallet picker that shows each
    /// wallet's address. Returns nil if the id is unknown.
    func publicKey(walletID: String) throws -> Secp256k1.PublicKey?

    /// Sign a precomputed 32-byte digest with the active wallet.
    /// Triggers the system biometric prompt on Keychain-backed
    /// implementations; `prompt` is the user-facing string.
    func sign(digest: Data, prompt: String) async throws -> Secp256k1.Signature

    /// Sign a BIP-341 keypath sighash with the active wallet's
    /// Taproot-tweaked private key, returning a 64-byte BIP-340
    /// Schnorr signature. Used by L2 P2TR keypath spends post-#109.
    func signTaprootKeypath(digest: Data, prompt: String) async throws -> Secp256k1.SchnorrSignature
}

// MARK: - Convenience back-compat shims (single-wallet callers)

public extension WalletKeystore {
    /// Pre-multi-wallet shim: createKey == createWallet with a
    /// default name. Existing callers / tests using createKey keep
    /// working unchanged.
    @discardableResult
    func createKey() throws -> Secp256k1.PublicKey {
        let descriptor = try createWallet(name: "Wallet")
        return try publicKey(walletID: descriptor.id) ?? { throw WalletKeystoreError.keyNotFound }()
    }

    /// Pre-multi-wallet shim: importKey == importWallet with a
    /// default name.
    @discardableResult
    func importKey(_ priv: Secp256k1.PrivateKey) throws -> Secp256k1.PublicKey {
        let descriptor = try importWallet(name: "Imported", priv: priv)
        return try publicKey(walletID: descriptor.id) ?? { throw WalletKeystoreError.keyNotFound }()
    }

    /// Pre-multi-wallet shim: delete the active wallet. Equivalent
    /// to "reset wallet" when there's only one.
    func delete() throws {
        guard let id = activeWalletID() else { return }
        try deleteWallet(id: id)
    }
}

// MARK: - In-memory implementation

/// Test / preview keystore. Stores wallets in process memory only —
/// never persisted, no biometric gate, instant signs. Use this in
/// SwiftUI #Preview, in `swift test`, and in any context where the
/// real Keychain prompt would be a UX blocker.
public final class InMemoryWalletKeystore: WalletKeystore {
    private struct Entry {
        let descriptor: WalletDescriptor
        let priv: Secp256k1.PrivateKey
    }
    private var entries: [String: Entry] = [:]
    private var activeID: String?

    public init() {}

    public func listWallets() throws -> [WalletDescriptor] {
        entries.values.map { $0.descriptor }.sorted { $0.createdAt < $1.createdAt }
    }

    public func activeWalletID() -> String? { activeID }

    public func selectWallet(id: String) throws {
        guard entries[id] != nil else { throw WalletKeystoreError.unknownWallet(id) }
        activeID = id
    }

    public func createWallet(name: String) throws -> WalletDescriptor {
        let priv = try Secp256k1.PrivateKey()
        return try insert(name: name, priv: priv)
    }

    public func importWallet(name: String, priv: Secp256k1.PrivateKey) throws -> WalletDescriptor {
        try insert(name: name, priv: priv)
    }

    public func deleteWallet(id: String) throws {
        guard entries.removeValue(forKey: id) != nil else { return }
        if activeID == id {
            activeID = entries.values
                .map { $0.descriptor }
                .sorted { $0.createdAt > $1.createdAt }
                .first?.id
        }
    }

    public func publicKey() throws -> Secp256k1.PublicKey? {
        guard let id = activeID, let e = entries[id] else { return nil }
        return e.priv.publicKey
    }

    public func publicKey(walletID: String) throws -> Secp256k1.PublicKey? {
        entries[walletID]?.priv.publicKey
    }

    public func sign(digest: Data, prompt _: String) async throws -> Secp256k1.Signature {
        guard let id = activeID, let e = entries[id] else {
            throw WalletKeystoreError.keyNotFound
        }
        return try e.priv.signDigest(digest)
    }

    public func signTaprootKeypath(digest: Data, prompt _: String) async throws -> Secp256k1.SchnorrSignature {
        guard let id = activeID, let e = entries[id] else {
            throw WalletKeystoreError.keyNotFound
        }
        return try Secp256k1.signTaprootKeypath(digest: digest, privKey: e.priv)
    }

    private func insert(name: String, priv: Secp256k1.PrivateKey) throws -> WalletDescriptor {
        let descriptor = WalletDescriptor(
            id: UUID().uuidString,
            name: name,
            createdAt: Date()
        )
        entries[descriptor.id] = Entry(descriptor: descriptor, priv: priv)
        activeID = descriptor.id
        return descriptor
    }

    /// Test-only seam: pre-load a known privkey under a deterministic
    /// id. Lets test code cross-check signatures against a known pub
    /// without going through random generation.
    internal func _insertForTesting(id: String, name: String, priv: Secp256k1.PrivateKey) {
        let descriptor = WalletDescriptor(id: id, name: name, createdAt: Date())
        entries[id] = Entry(descriptor: descriptor, priv: priv)
        activeID = id
    }
}
