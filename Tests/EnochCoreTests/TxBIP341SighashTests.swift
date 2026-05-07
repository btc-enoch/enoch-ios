import XCTest
@testable import EnochCore

/// BIP-341 keypath sighash: end-to-end correctness via "sign +
/// verify" against the Taproot output key. If the sighash bytes
/// drift from BIP-341, the Schnorr signature won't verify against
/// the tweaked output key the address commits to.
final class TxBIP341SighashTests: XCTestCase {
    /// Happy path: build a single-input single-output tx, compute
    /// BIP-341 keypath sighash, sign with the tweaked privkey,
    /// verify under the Taproot output key. This is exactly what
    /// a P2TR keypath spend will do at runtime.
    func testKeypathSighashRoundTripsThroughSchnorr() throws {
        let priv = try Secp256k1.PrivateKey()
        let outputKey = try priv.taprootOutputKey()
        let prevScript = try Script.taprootScriptPubKey(outputKey: outputKey.bytes)
        let bondAmount: UInt64 = 1_000_000

        let txHash = Data(repeating: 0x11, count: 32)
        let inputs = [TxInput(txHash: txHash, vout: 0, scriptSig: Data(), sequence: 0xFFFFFFFE)]
        let outputs = [TxOutput(amount: 990_000, scriptPubKey: Data(repeating: 0xAB, count: 25))]
        let tx = Tx(version: 2, inputs: inputs, outputs: outputs, lockTime: 0)
        let prevouts = [Tx.Prevout(amountSatoshi: bondAmount, scriptPubKey: prevScript)]

        let sighash = try tx.sighashBIP341Keypath(inputIndex: 0, prevouts: prevouts)
        XCTAssertEqual(sighash.count, 32)

        let sig = try Secp256k1.signTaprootKeypath(digest: sighash, privKey: priv)
        XCTAssertTrue(Secp256k1.schnorrVerify(signature: sig, digest: sighash, publicKey: outputKey),
                      "P2TR keypath sig must verify against tweaked output key")
    }

    /// Multi-input multi-output: BIP-341 commits to ALL inputs'
    /// amounts + scripts, not just the one being signed. If the
    /// sub-hashes (sha_amounts, sha_scripts) skip any input, signing
    /// the same tx with both inputs produces sighashes that would
    /// trivially be equal — this test fails under any such regression.
    func testKeypathSighashCommitsToAllInputs() throws {
        let alice = try Secp256k1.PrivateKey()
        let bob   = try Secp256k1.PrivateKey()
        let aliceOut = try alice.taprootOutputKey()
        let bobOut   = try bob.taprootOutputKey()
        let aliceScript = try Script.taprootScriptPubKey(outputKey: aliceOut.bytes)
        let bobScript   = try Script.taprootScriptPubKey(outputKey: bobOut.bytes)

        let inputs = [
            TxInput(txHash: Data(repeating: 0x01, count: 32), vout: 0, scriptSig: Data(), sequence: 0xFFFFFFFE),
            TxInput(txHash: Data(repeating: 0x02, count: 32), vout: 1, scriptSig: Data(), sequence: 0xFFFFFFFE),
        ]
        let outputs = [TxOutput(amount: 1_500_000, scriptPubKey: Data(repeating: 0xCD, count: 25))]
        let tx = Tx(version: 2, inputs: inputs, outputs: outputs, lockTime: 0)
        let prevouts = [
            Tx.Prevout(amountSatoshi: 1_000_000, scriptPubKey: aliceScript),
            Tx.Prevout(amountSatoshi:   600_000, scriptPubKey: bobScript),
        ]

        let sighashIn0 = try tx.sighashBIP341Keypath(inputIndex: 0, prevouts: prevouts)
        let sighashIn1 = try tx.sighashBIP341Keypath(inputIndex: 1, prevouts: prevouts)
        XCTAssertNotEqual(sighashIn0, sighashIn1,
                          "different input_index → different sighash (BIP-341 commits to it)")

        // Sign each input with its internal privkey; the unified
        // signTaprootKeypath does the tap-tweak inside Rust, so the
        // resulting signatures verify under the tweaked output keys.
        let sig0 = try Secp256k1.signTaprootKeypath(digest: sighashIn0, privKey: alice)
        let sig1 = try Secp256k1.signTaprootKeypath(digest: sighashIn1, privKey: bob)
        XCTAssertTrue(Secp256k1.schnorrVerify(signature: sig0, digest: sighashIn0, publicKey: aliceOut))
        XCTAssertTrue(Secp256k1.schnorrVerify(signature: sig1, digest: sighashIn1, publicKey: bobOut))

        // Cross-mix should fail: sig0 is over sighashIn0; verifying it
        // under bob's output key (and at sighashIn1) must reject. This
        // catches "sighash ignores input index" regressions even with
        // the cleaner double-check above.
        XCTAssertFalse(Secp256k1.schnorrVerify(signature: sig0, digest: sighashIn1, publicKey: bobOut))
    }

    /// Determinism: same tx, same prevouts → same sighash on
    /// repeated calls. (Tagged hashes are deterministic; the only
    /// non-determinism in BIP-341 keypath signing is the auxiliary
    /// randomness on the *signature*, not the sighash itself.)
    func testKeypathSighashDeterministic() throws {
        let priv = try Secp256k1.PrivateKey()
        let outputKey = try priv.taprootOutputKey()
        let script = try Script.taprootScriptPubKey(outputKey: outputKey.bytes)

        let inputs = [TxInput(txHash: Data(repeating: 0xAA, count: 32), vout: 0, scriptSig: Data(), sequence: 0xFFFFFFFE)]
        let outputs = [TxOutput(amount: 100_000, scriptPubKey: Data([0x6A, 0x00]))]
        let tx = Tx(version: 2, inputs: inputs, outputs: outputs, lockTime: 0)
        let prevouts = [Tx.Prevout(amountSatoshi: 110_000, scriptPubKey: script)]

        let h1 = try tx.sighashBIP341Keypath(inputIndex: 0, prevouts: prevouts)
        let h2 = try tx.sighashBIP341Keypath(inputIndex: 0, prevouts: prevouts)
        XCTAssertEqual(h1, h2)
    }

    func testKeypathSighashRejectsMismatchedPrevouts() throws {
        let inputs = [
            TxInput(txHash: Data(repeating: 0x01, count: 32), vout: 0, scriptSig: Data(), sequence: 0xFFFFFFFF),
            TxInput(txHash: Data(repeating: 0x02, count: 32), vout: 0, scriptSig: Data(), sequence: 0xFFFFFFFF),
        ]
        let tx = Tx(version: 2, inputs: inputs, outputs: [], lockTime: 0)
        // Only one prevout for two inputs.
        let prevouts = [Tx.Prevout(amountSatoshi: 1_000, scriptPubKey: Data())]
        XCTAssertThrowsError(try tx.sighashBIP341Keypath(inputIndex: 0, prevouts: prevouts)) { err in
            guard case TxError.prevoutCountMismatch = err else {
                return XCTFail("unexpected: \(err)")
            }
        }
    }

    func testKeypathSighashRejectsBadInputIndex() throws {
        let inputs = [TxInput(txHash: Data(repeating: 0x01, count: 32), vout: 0, scriptSig: Data(), sequence: 0xFFFFFFFF)]
        let tx = Tx(version: 2, inputs: inputs, outputs: [], lockTime: 0)
        let prevouts = [Tx.Prevout(amountSatoshi: 1_000, scriptPubKey: Data())]
        XCTAssertThrowsError(try tx.sighashBIP341Keypath(inputIndex: 5, prevouts: prevouts)) { err in
            guard case TxError.inputIndexOutOfRange = err else {
                return XCTFail("unexpected: \(err)")
            }
        }
    }

    /// Cross-language parity vector. The expected sighash is what
    /// btcsuite's `txscript.CalcTaprootSignatureHash` (operator side)
    /// emits for this exact tx, so this pin guards the iOS sighash
    /// against drifting from what the operator's verifier will accept.
    ///
    /// Vector: 1 input at txid 0x11..×32 vout 0 sequence 0xFFFFFFFE,
    /// previous P2TR scriptPubKey at 32-byte output key 0x42..×32 with
    /// 1_000_000 sat. 1 output of 990_000 sat at P2TR scriptPubKey for
    /// 32-byte recipient key 0xCD..×32. Version 2, locktime 0.
    func testKeypathSighashParityWithOperatorVector() throws {
        let prevScript = Data([0x51, 0x20]) + Data(repeating: 0x42, count: 32)
        let recvScript = Data([0x51, 0x20]) + Data(repeating: 0xCD, count: 32)
        let inputs = [
            TxInput(
                txHash: Data(repeating: 0x11, count: 32),
                vout: 0,
                scriptSig: Data(),
                sequence: 0xFFFFFFFE
            ),
        ]
        let outputs = [TxOutput(amount: 990_000, scriptPubKey: recvScript)]
        let tx = Tx(version: 2, inputs: inputs, outputs: outputs, lockTime: 0)
        let prevouts = [Tx.Prevout(amountSatoshi: 1_000_000, scriptPubKey: prevScript)]

        let got = try tx.sighashBIP341Keypath(inputIndex: 0, prevouts: prevouts)
        // Expected: btcsuite txscript.CalcTaprootSignatureHash on the
        // same tx (regenerated via a small Go probe; see #109 commit).
        let expected = try Data(hex: "a886e6d4f2902e7a4bf6202906209efe3d0d8d18e99b6d4793bbdfcb4d34bb45")
        XCTAssertEqual(got, expected)
    }
}
