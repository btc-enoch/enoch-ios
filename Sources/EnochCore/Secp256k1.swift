// Secp256k1 — thin wrapper around 21-DOT-DEV/swift-secp256k1 (P256K).
//
// Why a wrapper rather than direct P256K use throughout the codebase:
//  - The P256K name is misleading (P-256 is the NIST curve; this lib
//    actually exposes secp256k1). Renaming it at the boundary keeps
//    call sites honest about which curve they're using.
//  - We want a stable signing surface even if P256K's pre-1.0 API
//    shifts. The wrapper is small enough that pinning is cheap.
//  - Critical: we MUST sign Bitcoin sighashes (already-hashed 32-byte
//    digests) directly, not by passing them through P256K's
//    `signature(for: Data)` overload — that overload re-hashes with
//    SHA-256, which would produce a non-Bitcoin signature. Wrapping
//    the digest in `HashDigest` routes to the `Digest` overload that
//    signs the bytes as-is.
//
// Low-s normalization is automatic per BIP-146 — the operator's
// verifier (btcsuite/btcd/txscript) requires it, so this is
// load-bearing for tx acceptance.

import Foundation
import P256K

public enum Secp256k1 {
    public enum Error: Swift.Error {
        case invalidPrivateKeyLength(Int)
        case invalidDigestLength(Int)
        case invalidSignature(Swift.Error)
        case keyGen(Swift.Error)
    }

    /// Bitcoin's standard sighash type byte appended to scriptSig
    /// signatures. We only support SIGHASH_ALL (0x01) for now —
    /// every wallet-built tx signs every input/output.
    public static let sighashAllByte: UInt8 = 0x01

    // MARK: - PrivateKey

    public struct PrivateKey {
        fileprivate let inner: P256K.Signing.PrivateKey

        /// Generate a fresh keypair using libsecp256k1's CSRNG. Throws
        /// on the vanishingly rare case (<2⁻¹²⁸) of a generated scalar
        /// failing `secp256k1_ec_seckey_verify` — surface it rather
        /// than crashing so callers can retry.
        public init() throws {
            do {
                self.inner = try P256K.Signing.PrivateKey()
            } catch {
                throw Error.keyGen(error)
            }
        }

        /// Restore from 32 raw bytes — the path the Keychain layer
        /// uses on app launch.
        public init(rawBytes: Data) throws {
            guard rawBytes.count == 32 else {
                throw Error.invalidPrivateKeyLength(rawBytes.count)
            }
            do {
                self.inner = try P256K.Signing.PrivateKey(dataRepresentation: rawBytes)
            } catch {
                throw Error.keyGen(error)
            }
        }

        /// Raw 32-byte privkey scalar. Caller is responsible for
        /// putting this in Keychain; copies escape the library's
        /// zeroization scope.
        public var rawBytes: Data { inner.dataRepresentation }

        /// Derived public key.
        public var publicKey: PublicKey { PublicKey(inner: inner.publicKey) }

        /// Sign a precomputed 32-byte digest (Bitcoin sighash).
        /// The returned signature is DER-encoded with low-s already
        /// normalized by libsecp256k1.
        ///
        /// CRITICAL: pass the sighash directly. Do NOT pre-hash it
        /// again, and do NOT route through `signature(for: Data)` on
        /// the P256K type — that variant SHA-256s its input and would
        /// produce a signature over the wrong digest.
        public func signDigest(_ digest: Data) throws -> Signature {
            guard digest.count == 32 else {
                throw Error.invalidDigestLength(digest.count)
            }
            let hd = HashDigest([UInt8](digest))
            let sig = inner.signature(for: hd)
            return Signature(der: sig.derRepresentation)
        }
    }

    // MARK: - PublicKey

    public struct PublicKey {
        fileprivate let inner: P256K.Signing.PublicKey

        /// Compressed (33-byte) SEC1 encoding — what Bitcoin Script
        /// scriptSigs push after the signature.
        public var compressedBytes: Data { inner.dataRepresentation }

        /// Verify a DER signature against the given precomputed
        /// digest. Same digest-vs-data caveat as `signDigest`: we
        /// route through the `HashDigest` overload so the bytes are
        /// verified as-is, not re-hashed.
        public func verifyDigest(_ digest: Data, signature: Signature) -> Bool {
            guard digest.count == 32 else { return false }
            do {
                let sig = try P256K.Signing.ECDSASignature(derRepresentation: signature.der)
                let hd = HashDigest([UInt8](digest))
                return inner.isValidSignature(sig, for: hd)
            } catch {
                return false
            }
        }
    }

    // MARK: - Signature

    public struct Signature: Equatable {
        public let der: Data

        public init(der: Data) {
            self.der = der
        }

        /// DER bytes followed by a 1-byte sighash type — the form
        /// pushed onto scriptSig before the pubkey. We only use
        /// SIGHASH_ALL today, so a fixed 0x01 suffix is correct.
        public var derWithSighashAll: Data {
            var out = der
            out.append(Secp256k1.sighashAllByte)
            return out
        }
    }
}
