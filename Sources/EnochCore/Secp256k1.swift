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
        case invalidPublicKey(Swift.Error)
        case keyGen(Swift.Error)
        case invalidSchnorrSignatureLength(Int)
        case invalidXOnlyPublicKeyLength(Int)
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

        fileprivate init(inner: P256K.Signing.PublicKey) {
            self.inner = inner
        }

        /// Reconstruct from a 33-byte compressed (SEC1) pubkey — the
        /// form stashed alongside privkey-bearing Keychain items so
        /// receive-address rendering doesn't need a biometric prompt.
        public init(compressed: Data) throws {
            do {
                self.inner = try P256K.Signing.PublicKey(dataRepresentation: compressed, format: .compressed)
            } catch {
                throw Error.invalidPublicKey(error)
            }
        }

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

    // MARK: - Schnorr (BIP-340) — used by L2 P2TR keypath spends post-#109

    /// 64-byte BIP-340 Schnorr signature: `R.x || s`. Wire-stable;
    /// matches the witness layout for P2TR keypath spends (single
    /// element, no sighash byte under SIGHASH_DEFAULT).
    public struct SchnorrSignature: Equatable {
        public let bytes: Data

        public init(bytes: Data) throws {
            guard bytes.count == 64 else {
                throw Error.invalidSchnorrSignatureLength(bytes.count)
            }
            self.bytes = bytes
        }
    }

    /// 32-byte x-only public key (BIP-340). The Y coordinate is
    /// implicitly the even one. Schnorr signatures verify against
    /// this form, not against the 33-byte compressed form.
    public struct XOnlyPublicKey: Equatable {
        public let bytes: Data

        public init(bytes: Data) throws {
            guard bytes.count == 32 else {
                throw Error.invalidXOnlyPublicKeyLength(bytes.count)
            }
            self.bytes = bytes
        }

        /// Derive an x-only key from a compressed (33-byte) pubkey by
        /// dropping the parity prefix. Note the resulting x-only key
        /// has a "natural" parity that's lost in the encoding;
        /// callers that need that parity (BIP-341 tweak applied to
        /// the private key) should track it separately via the full
        /// `Secp256k1.PublicKey`.
        public static func from(compressed: Data) throws -> XOnlyPublicKey {
            guard compressed.count == 33 else {
                throw Error.invalidXOnlyPublicKeyLength(compressed.count)
            }
            return try XOnlyPublicKey(bytes: compressed.subdata(in: 1..<33))
        }
    }

    /// Sign a precomputed 32-byte digest (BIP-341 tap-script or
    /// keypath sighash) using BIP-340 Schnorr. The returned 64-byte
    /// signature is what gets pushed as the single-element witness
    /// for a P2TR keypath spend under SIGHASH_DEFAULT.
    ///
    /// CRITICAL: pass the sighash directly. Same digest-vs-data
    /// caveat as `signDigest` — we route through the `Digest`
    /// overload so the bytes are signed as-is, not re-hashed.
    ///
    /// `privKey` is signed *as-is* — for BIP-341 keypath spends the
    /// caller is responsible for producing the **tweaked** private
    /// key (priv + H_TapTweak(pubkey) mod n, with parity-flip if the
    /// internal pubkey has odd Y). The tweaking helper lives in a
    /// separate file (Schnorr+Tweak from swift-secp256k1) and will
    /// be wrapped in a follow-up commit.
    public static func schnorrSign(digest: Data, privKey: PrivateKey) throws -> SchnorrSignature {
        guard digest.count == 32 else {
            throw Error.invalidDigestLength(digest.count)
        }
        do {
            // P256K's Schnorr.PrivateKey takes raw 32-byte private
            // scalar. Reuse our existing PrivateKey's rawBytes.
            let schnorrKey = try P256K.Schnorr.PrivateKey(dataRepresentation: privKey.rawBytes)
            let hd = HashDigest([UInt8](digest))
            let sig = try schnorrKey.signature(for: hd)
            return try SchnorrSignature(bytes: sig.dataRepresentation)
        } catch let e as secp256k1Error {
            throw Error.invalidSignature(e)
        } catch {
            throw Error.invalidSignature(error)
        }
    }

    /// Verify a 64-byte Schnorr signature against an x-only pubkey
    /// over a precomputed 32-byte digest. Returns false on any
    /// malformed input (no thrown error — verifiers want a single
    /// boolean).
    public static func schnorrVerify(
        signature: SchnorrSignature,
        digest: Data,
        publicKey: XOnlyPublicKey
    ) -> Bool {
        guard digest.count == 32 else { return false }
        do {
            let xonly = P256K.Schnorr.XonlyKey(dataRepresentation: publicKey.bytes, keyParity: 0)
            let sig = try P256K.Schnorr.SchnorrSignature(dataRepresentation: signature.bytes)
            let hd = HashDigest([UInt8](digest))
            return xonly.isValidSignature(sig, for: hd)
        } catch {
            return false
        }
    }
}

