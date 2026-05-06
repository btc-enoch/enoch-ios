// Hashing — thin Swift facade over EnochCrypto's Rust hash
// primitives. The actual hashing now lives in
// federation/ffi/enoch-crypto-core/src/hashes.rs, shared with
// the operator/agent (Go via cgo, future) so a single
// implementation produces identical bytes everywhere — see
// #161.
//
// The function shapes are unchanged from the prior pure-Swift
// version so call sites in Address.swift / Tx.swift didn't
// have to adapt: still `Data → Data`, no thrown errors, no
// async. Behavior is byte-identical: validated by the parity
// vectors pinned in both Rust (hashes::tests) and the iOS
// XCFramework consumer (federation/ffi/ios-test).

import EnochCrypto
import Foundation

public enum Hashing {
    /// Single SHA256. Used by BIP-341 sighash sub-hashes
    /// (sha_prevouts, sha_amounts, sha_outputs) — those are plain
    /// SHA256, not the double-SHA256 that legacy Bitcoin sighash uses.
    public static func sha256(_ data: Data) -> Data {
        sha256Ffi(msg: data)
    }

    /// Double-SHA256, the standard "hash256" used for Bitcoin txids,
    /// merkle nodes, and legacy sighash. Output is 32 bytes in
    /// natural order (not reversed). Display order — what explorers
    /// show — is `Data(hash256(x).reversed())`.
    ///
    /// Composed from two Rust SHA-256 calls rather than exporting
    /// a separate `hash256_ffi`: cheaper to keep the FFI surface
    /// small + the cost of the extra FFI hop is negligible vs the
    /// SHA-256 itself.
    public static func hash256(_ data: Data) -> Data {
        sha256Ffi(msg: sha256Ffi(msg: data))
    }

    /// HASH160 = RIPEMD160(SHA256(x)). The 20-byte pubkey-hash that
    /// P2PKH scripts (and Enoch L2 addresses) use as their identity.
    public static func hash160(_ data: Data) -> Data {
        hash160Ffi(msg: data)
    }
}
