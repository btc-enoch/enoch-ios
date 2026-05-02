// Hashing — small helpers around CryptoKit's SHA256. Centralized here
// so other modules don't each open `import CryptoKit` and re-implement
// the hash256 (= SHA256 of SHA256) idiom that Bitcoin uses everywhere.

import CryptoKit
import Foundation

public enum Hashing {
    /// Single SHA256. Used by BIP-341 sighash sub-hashes
    /// (sha_prevouts, sha_amounts, sha_outputs) — those are plain
    /// SHA256, not the double-SHA256 that legacy Bitcoin sighash uses.
    public static func sha256(_ data: Data) -> Data {
        return Data(SHA256.hash(data: data))
    }

    /// Double-SHA256, the standard "hash256" used for Bitcoin txids,
    /// merkle nodes, and legacy sighash. Output is 32 bytes in
    /// natural order (not reversed). Display order — what explorers
    /// show — is `Data(hash256(x).reversed())`.
    public static func hash256(_ data: Data) -> Data {
        let first = SHA256.hash(data: data)
        let second = SHA256.hash(data: Data(first))
        return Data(second)
    }

    /// HASH160 = RIPEMD160(SHA256(x)). The 20-byte pubkey-hash that
    /// P2PKH scripts (and Enoch L2 addresses) use as their identity.
    /// Apple's CryptoKit doesn't ship RIPEMD160 — we compose with
    /// our local pure-Swift implementation.
    public static func hash160(_ data: Data) -> Data {
        let sha = SHA256.hash(data: data)
        return RIPEMD160.hash(Data(sha))
    }
}
