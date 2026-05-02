import XCTest
@testable import EnochCore

final class TxTests: XCTestCase {
    // MARK: - varint encoding

    /// Boundary values for Bitcoin's compact-int encoding. A bug here
    /// would silently corrupt every wire serialization — the operator
    /// would read the wrong input/output count and reject the tx.
    func testVarIntBoundaries() {
        var d = Data(); d.appendVarInt(0)
        XCTAssertEqual([UInt8](d), [0x00])

        d = Data(); d.appendVarInt(0xFC)
        XCTAssertEqual([UInt8](d), [0xFC])

        d = Data(); d.appendVarInt(0xFD)
        XCTAssertEqual([UInt8](d), [0xFD, 0xFD, 0x00])

        d = Data(); d.appendVarInt(0xFFFF)
        XCTAssertEqual([UInt8](d), [0xFD, 0xFF, 0xFF])

        d = Data(); d.appendVarInt(0x10000)
        XCTAssertEqual([UInt8](d), [0xFE, 0x00, 0x00, 0x01, 0x00])

        d = Data(); d.appendVarInt(0xFFFFFFFF)
        XCTAssertEqual([UInt8](d), [0xFE, 0xFF, 0xFF, 0xFF, 0xFF])

        d = Data(); d.appendVarInt(0x100000000)
        XCTAssertEqual([UInt8](d), [0xFF, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])
    }

    func testUInt32LE() {
        var d = Data(); d.appendUInt32LE(0x01020304)
        XCTAssertEqual([UInt8](d), [0x04, 0x03, 0x02, 0x01])
    }

    func testUInt64LE() {
        var d = Data(); d.appendUInt64LE(0x0102030405060708)
        XCTAssertEqual([UInt8](d), [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
    }

    // MARK: - hex round-trip

    func testHexRoundTrip() throws {
        let raw = Data([0x00, 0x01, 0xAB, 0xCD, 0xFF])
        let s = raw.hexString
        XCTAssertEqual(s, "0001abcdff")
        let back = try Data(hex: s)
        XCTAssertEqual(back, raw)
    }

    func testHexEmpty() throws {
        XCTAssertEqual(Data().hexString, "")
        XCTAssertEqual(try Data(hex: ""), Data())
    }

    func testHexRejectsOddLength() {
        XCTAssertThrowsError(try Data(hex: "abc")) { err in
            XCTAssertEqual(err as? HexError, .oddLength)
        }
    }

    func testHexRejectsNonHex() {
        XCTAssertThrowsError(try Data(hex: "zz"))
    }

    // MARK: - tx serialization

    /// Exact byte-level fixture: a minimal 1-in/1-out tx serialized
    /// per the canonical Bitcoin wire format. Verified against the
    /// known structure (version + varint + reversed-txid + vout + ...
    /// + locktime). A drift here = wrong txHash = wrong sighash.
    func testWireBytesMinimalTx() throws {
        let txHashDisplay = Data((0..<32).map { UInt8($0) }) // 0x00..0x1f, display order
        let scriptSig = Data([0xAA, 0xBB])
        let scriptPubKey = Data([0xCC, 0xDD, 0xEE])

        let tx = Tx(
            version: 1,
            inputs: [TxInput(txHash: txHashDisplay, vout: 0, scriptSig: scriptSig, sequence: 0xFFFFFFFF)],
            outputs: [TxOutput(amount: 1000, scriptPubKey: scriptPubKey)],
            lockTime: 0
        )

        let bytes = try tx.wireBytes()
        var expected = Data()
        expected.append(contentsOf: [0x01, 0x00, 0x00, 0x00])             // version
        expected.append(0x01)                                              // 1 input
        expected.append(contentsOf: txHashDisplay.reversed())              // wire-order txid
        expected.append(contentsOf: [0x00, 0x00, 0x00, 0x00])             // vout 0
        expected.append(0x02)                                              // scriptSig len
        expected.append(scriptSig)                                          // scriptSig
        expected.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF])             // sequence
        expected.append(0x01)                                              // 1 output
        expected.append(contentsOf: [0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) // 1000 LE
        expected.append(0x03)                                              // scriptPubKey len
        expected.append(scriptPubKey)
        expected.append(contentsOf: [0x00, 0x00, 0x00, 0x00])             // locktime

        XCTAssertEqual(bytes, expected)
    }

    func testWireBytesRejectsWrongTxHashLength() {
        let tx = Tx(
            version: 1,
            inputs: [TxInput(txHash: Data(repeating: 0, count: 31), vout: 0)],
            outputs: [TxOutput(amount: 1, scriptPubKey: Data([0x00]))],
            lockTime: 0
        )
        XCTAssertThrowsError(try tx.wireBytes()) { err in
            guard case TxError.wrongTxHashLength(let i, let n) = err else {
                return XCTFail("unexpected error: \(err)")
            }
            XCTAssertEqual(i, 0)
            XCTAssertEqual(n, 31)
        }
    }

    // MARK: - txHash

    /// Idempotency: same tx → same hash, every time.
    func testTxHashDeterministic() throws {
        let tx = makeFixtureTx()
        let h1 = try tx.txHash()
        let h2 = try tx.txHash()
        XCTAssertEqual(h1, h2)
        XCTAssertEqual(h1.count, 32)
    }

    /// scriptSigs are zeroed before hashing — that's the malleability-
    /// resistance property. Two txs differing ONLY in scriptSigs must
    /// share a txHash.
    func testTxHashIgnoresScriptSig() throws {
        var a = makeFixtureTx()
        var b = a
        b.inputs[0].scriptSig = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let ha = try a.txHash()
        let hb = try b.txHash()
        XCTAssertEqual(ha, hb)
        XCTAssertNotEqual(a.inputs[0].scriptSig, b.inputs[0].scriptSig) // sanity
        _ = a // silence "var unused"
    }

    /// Any structural change DOES affect txHash — output amount as
    /// the simplest non-scriptSig perturbation.
    func testTxHashChangesWithOutputAmount() throws {
        var a = makeFixtureTx()
        var b = a
        b.outputs[0].amount += 1
        let ha = try a.txHash()
        let hb = try b.txHash()
        XCTAssertNotEqual(ha, hb)
        _ = a
    }

    // MARK: - sighash

    /// Per-input sighash: two inputs of the same tx have DIFFERENT
    /// sighashes (since the substituted scriptSig differs by index).
    func testSighashDiffersByInputIndex() throws {
        let tx = makeTwoInputTx()
        let prevPK = Data([0x76, 0xA9, 0x14] + Array(repeating: UInt8(0xAA), count: 20) + [0x88, 0xAC])
        let h0 = try tx.sighashLegacyAll(inputIndex: 0, prevScriptPubKey: prevPK)
        let h1 = try tx.sighashLegacyAll(inputIndex: 1, prevScriptPubKey: prevPK)
        XCTAssertNotEqual(h0, h1)
    }

    /// Different prevScriptPubKey → different sighash for the same
    /// input. Catches the "we forgot to splice in the prev script"
    /// failure mode (which would yield identical sighashes).
    func testSighashDiffersByPrevScript() throws {
        let tx = makeFixtureTx()
        let pkA = Data([0x76, 0xA9, 0x14] + Array(repeating: UInt8(0xAA), count: 20) + [0x88, 0xAC])
        let pkB = Data([0x76, 0xA9, 0x14] + Array(repeating: UInt8(0xBB), count: 20) + [0x88, 0xAC])
        let hA = try tx.sighashLegacyAll(inputIndex: 0, prevScriptPubKey: pkA)
        let hB = try tx.sighashLegacyAll(inputIndex: 0, prevScriptPubKey: pkB)
        XCTAssertNotEqual(hA, hB)
    }

    func testSighashOutOfRangeInputRejected() {
        let tx = makeFixtureTx()
        XCTAssertThrowsError(try tx.sighashLegacyAll(inputIndex: 99, prevScriptPubKey: Data())) { err in
            guard case TxError.inputIndexOutOfRange(let i) = err else {
                return XCTFail("unexpected error: \(err)")
            }
            XCTAssertEqual(i, 99)
        }
    }

    // MARK: - JSON wire round-trip

    /// Submit a tx → JSON → submit object back to a domain Tx.
    /// Must be byte-stable: txHash before and after a round-trip equal.
    func testJSONRoundTrip() throws {
        let original = makeFixtureTx()
        let wire = original.toWire()
        let encoded = try JSONEncoder().encode(wire)
        let decoded = try JSONDecoder().decode(SubmitTxRequest.self, from: encoded)
        let recovered = try Tx(wire: decoded)
        XCTAssertEqual(try original.txHash(), try recovered.txHash())
    }

    /// The on-the-wire JSON keys are snake_case, matching the
    /// operator's `submitTxRequestJSON`. A drift here means the
    /// operator silently treats fields as missing (default values)
    /// and our tx becomes nonsensical.
    func testJSONKeysAreSnakeCase() throws {
        let wire = makeFixtureTx().toWire()
        let encoded = try JSONEncoder().encode(wire)
        let s = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(s.contains("\"tx_hash\""))
        XCTAssertTrue(s.contains("\"script_sig\""))
        XCTAssertTrue(s.contains("\"script_pubkey\""))
        XCTAssertTrue(s.contains("\"lock_time\""))
    }

    // MARK: - Witness wire format (#109)

    /// Empty witness: a legacy tx (P2PKH) emits NO `witness` key at
    /// all in the JSON. The operator's existing tx-history will keep
    /// parsing untouched. This is the backward-compat property —
    /// without it, every operator deserializer would need a
    /// pre-#109 / post-#109 schema split.
    func testWitnessOmittedFromLegacyTxJSON() throws {
        let legacyTx = makeFixtureTx()  // built without setting witness
        let encoded = try JSONEncoder().encode(legacyTx.toWire())
        let s = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertFalse(s.contains("\"witness\""), "legacy tx must not emit witness key:\n\(s)")
    }

    /// Non-empty witness: a Taproot keypath input has a single 64-byte
    /// Schnorr sig in its witness stack. JSON includes the witness
    /// field as an array of hex strings; Tx(wire:) decodes it back to
    /// the original bytes.
    func testWitnessRoundTripsThroughJSON() throws {
        let schnorrSig = Data((0..<64).map { UInt8($0) })
        let inputs = [
            TxInput(
                txHash: Data((0..<32).map { UInt8($0) }),
                vout: 0,
                scriptSig: Data(),                       // empty for P2TR
                sequence: 0xFFFFFFFE,
                witness: [schnorrSig]
            )
        ]
        let outputs = [TxOutput(amount: 100_000, scriptPubKey: Data([0x51, 0x20] + Array(repeating: UInt8(0xAB), count: 32)))]
        let original = Tx(version: 2, inputs: inputs, outputs: outputs, lockTime: 0)

        let encoded = try JSONEncoder().encode(original.toWire())
        let s = String(data: encoded, encoding: .utf8) ?? ""
        XCTAssertTrue(s.contains("\"witness\""), "P2TR tx must emit witness key:\n\(s)")

        let decoded = try JSONDecoder().decode(SubmitTxRequest.self, from: encoded)
        let recovered = try Tx(wire: decoded)
        XCTAssertEqual(recovered.inputs.count, 1)
        XCTAssertEqual(recovered.inputs[0].witness, [schnorrSig])
        XCTAssertEqual(recovered.inputs[0].scriptSig.count, 0)
    }

    /// txHash() must NOT change when witness data is added/altered.
    /// This is BIP-141's load-bearing property: txid commits to
    /// scriptSig-zeroed legacy bytes, never to witness data, so
    /// Taproot txs are non-malleable by witness tweaking.
    func testTxHashIgnoresWitness() throws {
        let baseInput = TxInput(txHash: Data(repeating: 0xAA, count: 32), vout: 0)
        let outputs = [TxOutput(amount: 50_000, scriptPubKey: Data([0x6A]))]
        let txNoWitness = Tx(version: 1, inputs: [baseInput], outputs: outputs, lockTime: 0)

        var withWitness = baseInput
        withWitness.witness = [Data(repeating: 0xBB, count: 64)]
        let txWithWitness = Tx(version: 1, inputs: [withWitness], outputs: outputs, lockTime: 0)

        XCTAssertEqual(try txNoWitness.txHash(), try txWithWitness.txHash())
    }

    /// Multi-element witness round-trip — covers e.g. tap-script
    /// spends ([sig, leaf_script, control_block]) which we don't
    /// emit from the wallet today but the wire format must support
    /// (the bond's slash + reclaim spends use this shape).
    func testWitnessMultiElementRoundTrip() throws {
        let elem1 = Data((0..<64).map { UInt8($0) })
        let elem2 = Data([0x20] + Array(repeating: UInt8(0x42), count: 32) + [0xAC])
        let elem3 = Data([0xC0] + Array(repeating: UInt8(0x77), count: 32) + Array(repeating: UInt8(0x88), count: 32))
        let inputs = [
            TxInput(
                txHash: Data(repeating: 0x01, count: 32),
                vout: 0,
                scriptSig: Data(),
                sequence: 0xFFFFFFFE,
                witness: [elem1, elem2, elem3]
            )
        ]
        let original = Tx(version: 2, inputs: inputs, outputs: [], lockTime: 0)

        let encoded = try JSONEncoder().encode(original.toWire())
        let recovered = try Tx(wire: try JSONDecoder().decode(SubmitTxRequest.self, from: encoded))
        XCTAssertEqual(recovered.inputs[0].witness, [elem1, elem2, elem3])
    }

    // MARK: - operator gold-standard cross-check

    /// Real tx body pulled from a running regtest operator (alice→bob
    /// at height 8). The operator computed and stored tx_hash =
    /// f3e52ffbfd442383fd266e126d4678aae60c2c2cfa9d903323c5a60fecb7f569.
    /// Our Swift port is correct iff txHash() over the same body
    /// yields the same 32 bytes — i.e. wire serialization +
    /// double-SHA256 + scriptSig-zeroing all match the Go side.
    func testTxHashMatchesOperatorGoldStandard() throws {
        let json = """
        {
          "version": 1,
          "inputs": [
            {
              "tx_hash": "ea0f1134383e8a55948839c96ba8f8d4fc6caf1d27dafce7ee7f7784d2fa5f25",
              "vout": 2,
              "script_sig": "483045022100a48f6be9f7e03fc1f84b8aecc8ca84725d50b0344b828c5c9a5345e5b0b0d064022025f22a48cf91369d0ef8e71a0c1bc90511e4e648abbf3fccf3e6687392dedc07012103716d4b4281cd60ad2e3a8cb36cc92dcc870ac5355bce04abb80cbb135a3d063f",
              "sequence": 4294967295
            }
          ],
          "outputs": [
            { "amount": 250000,   "script_pubkey": "76a914488b2dc940180c6e332578fe78fc8694bfac8f1e88ac" },
            { "amount": 1000,     "script_pubkey": "76a914227d8f735443f4a4a85a9c0629ba26e8cf0f368388ac" },
            { "amount": 84243000, "script_pubkey": "76a91455d17f2225051da1b9b7db27af9ad17ecf27632a88ac" }
          ],
          "lock_time": 0
        }
        """.data(using: .utf8)!

        let wire = try JSONDecoder().decode(SubmitTxRequest.self, from: json)
        let tx = try Tx(wire: wire)
        let computed = try tx.txHash().hexString
        XCTAssertEqual(computed, "f3e52ffbfd442383fd266e126d4678aae60c2c2cfa9d903323c5a60fecb7f569")
    }

    // MARK: - fixtures

    private func makeFixtureTx() -> Tx {
        Tx(
            version: 1,
            inputs: [
                TxInput(
                    txHash: Data((0..<32).map { UInt8($0) }),
                    vout: 0,
                    scriptSig: Data(),
                    sequence: 0xFFFFFFFF
                ),
            ],
            outputs: [
                TxOutput(
                    amount: 100_000,
                    scriptPubKey: Data([0x76, 0xA9, 0x14] + Array(repeating: UInt8(0xCD), count: 20) + [0x88, 0xAC])
                ),
            ],
            lockTime: 0
        )
    }

    private func makeTwoInputTx() -> Tx {
        Tx(
            version: 1,
            inputs: [
                TxInput(txHash: Data((0..<32).map { UInt8($0) }), vout: 0),
                TxInput(txHash: Data((0x40..<0x60).map { UInt8($0) }), vout: 1),
            ],
            outputs: [
                TxOutput(amount: 50_000, scriptPubKey: Data([0x6A])), // OP_RETURN-ish
            ],
            lockTime: 0
        )
    }
}
