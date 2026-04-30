// Hashing — small helpers around CryptoKit's SHA256. Centralized here
// so other modules don't each open `import CryptoKit` and re-implement
// the hash256 (= SHA256 of SHA256) idiom that Bitcoin uses everywhere.

import CryptoKit
import Foundation

public enum Hashing {
    /// Double-SHA256, the standard "hash256" used for Bitcoin txids,
    /// merkle nodes, and legacy sighash. Output is 32 bytes in
    /// natural order (not reversed). Display order — what explorers
    /// show — is `Data(hash256(x).reversed())`.
    public static func hash256(_ data: Data) -> Data {
        let first = SHA256.hash(data: data)
        let second = SHA256.hash(data: Data(first))
        return Data(second)
    }
}
