import XCTest
@testable import EnochCore

/// Tests TxBuilder end-to-end with stubbed edge responses + an
/// InMemoryWalletKeystore. Output is a fully-signed P2TR keypath
/// tx — we verify its shape (inputs / outputs / amounts / witness)
/// AND that each input's witness sig actually verifies as Schnorr
/// against the wallet's Taproot output key over the BIP-341 keypath
/// sighash.
///
/// Post-#109 Enoch L2 is uniformly P2TR; the wallet's UTXOs sit at
/// `enoch1p...` Taproot addresses, inputs sign via Schnorr + BIP-341
/// keypath sighash, and the witness carries the 64-byte sig (no
/// scriptSig, no pubkey push). These tests pin every link in that
/// chain so a regression that breaks signing surfaces in `swift test`
/// rather than as a "tx rejected" message at submit time.
final class TxBuilderTests: XCTestCase {
    private let edgeURL = URL(string: "http://test.local")!

    /// Compute the Taproot address + scriptPubKey for a freshly-
    /// created wallet keystore. Mirrors what the production wallet
    /// does on first launch.
    private func walletIdentity(
        from keystore: InMemoryWalletKeystore
    ) throws -> (address: String, scriptPubKey: Data, outputKey: Secp256k1.XOnlyPublicKey, pubkey: Secp256k1.PublicKey) {
        let pub = try keystore.publicKey() ?? (try keystore.createKey())
        let outputKey = try pub.taprootOutputKey()
        let address = try Address.encodeTaproot(outputKey: outputKey.bytes)
        let scriptPubKey = try Script.taprootScriptPubKey(outputKey: outputKey.bytes)
        return (address, scriptPubKey, outputKey, pub)
    }

    private func makeStubbedEdge(
        feePerTx: UInt64 = 1_000,
        feePoolOutputKey: Data = Data(repeating: 0x11, count: 32),
        utxos: [(amount: UInt64, scriptPubKey: Data)],
        myAddress: String
    ) -> StubL2Client {
        // The fee pool address is now P2TR — same shape as the
        // wallet's own. (Pre-#109 it was P2PKH; post-cutover both
        // sides are uniformly Taproot.)
        let feePoolAddr = (try? Address.encodeTaproot(outputKey: feePoolOutputKey)) ?? "enoch1p"
        let utxoWires = utxos.enumerated().map { (i, u) -> UTXOWire in
            let txHashHex = String(format: "%064x", i + 1)
            return UTXOWire(
                txHash: txHashHex,
                vout: 0,
                amount: u.amount,
                scriptPubKey: u.scriptPubKey.hexString,
                bondInfo: nil
            )
        }
        return StubL2Client(
            feePerTx: feePerTx,
            feePoolAddress: feePoolAddr,
            myAddress: myAddress,
            utxos: utxoWires
        )
    }

    /// Happy path: 1 input fully covers target + fee + change. The
    /// resulting Tx has exactly 3 outputs (recipient, fee, change),
    /// the recipient amount matches, scriptSig is empty, and the
    /// witness's single Schnorr sig verifies against the wallet's
    /// Taproot output key over the BIP-341 keypath sighash.
    func testBuildsSignedTxWithChange() async throws {
        let keystore = InMemoryWalletKeystore()
        _ = try keystore.createKey()
        let me = try walletIdentity(from: keystore)

        let edge = makeStubbedEdge(
            feePerTx: 1_000,
            utxos: [(amount: 100_000, scriptPubKey: me.scriptPubKey)],
            myAddress: me.address
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        // Recipient is itself a Taproot address — post-#109 L2 is
        // P2TR-only on both ends.
        let recipientOutputKey = Data(repeating: 0xAA, count: 32)
        let recipient = try Address.encodeTaproot(outputKey: recipientOutputKey)

        let tx = try await builder.buildSendTx(recipient: recipient,
                                               amountSatoshi: 50_000,
                                               biometricPrompt: "test")

        XCTAssertEqual(tx.inputs.count, 1)
        XCTAssertEqual(tx.outputs.count, 3, "recipient + fee + change")
        XCTAssertEqual(tx.outputs[0].amount, 50_000)
        XCTAssertEqual(tx.outputs[1].amount, 1_000)
        XCTAssertEqual(tx.outputs[2].amount, 49_000)

        // P2TR keypath spend: scriptSig empty, witness has exactly
        // one 64-byte Schnorr signature.
        XCTAssertEqual(tx.inputs[0].scriptSig.count, 0)
        XCTAssertEqual(tx.inputs[0].witness.count, 1)
        XCTAssertEqual(tx.inputs[0].witness[0].count, 64)

        // The sig actually validates over the BIP-341 keypath sighash
        // against the wallet's Taproot output key — the load-bearing
        // assertion that proves Address derivation + sighash + Schnorr
        // signing all line up.
        let prevouts = [Tx.Prevout(amountSatoshi: 100_000, scriptPubKey: me.scriptPubKey)]
        let digest = try tx.sighashBIP341Keypath(inputIndex: 0, prevouts: prevouts)
        let sig = try Secp256k1.SchnorrSignature(bytes: tx.inputs[0].witness[0])
        XCTAssertTrue(Secp256k1.schnorrVerify(signature: sig, digest: digest, publicKey: me.outputKey),
                      "witness Schnorr sig must verify under wallet's Taproot output key over BIP-341 keypath sighash")
    }

    /// Multi-input: sum of two UTXOs covers target. Both inputs get
    /// signed; both signatures verify over their distinct sighashes.
    /// BIP-341 commits to input_index in the spend_type/index field,
    /// so two inputs of the same tx have different sighashes — a
    /// wrong implementation that signed both inputs over the same
    /// digest would silently work as long as both prevouts match,
    /// but the sighashes themselves would be equal, which this test
    /// asserts is NOT the case.
    func testBuildsMultiInputTx() async throws {
        let keystore = InMemoryWalletKeystore()
        _ = try keystore.createKey()
        let me = try walletIdentity(from: keystore)

        let edge = makeStubbedEdge(
            feePerTx: 1_000,
            utxos: [
                (amount: 30_000, scriptPubKey: me.scriptPubKey),
                (amount: 25_000, scriptPubKey: me.scriptPubKey),
            ],
            myAddress: me.address
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        let recipient = try Address.encodeTaproot(outputKey: Data(repeating: 0xAA, count: 32))
        let tx = try await builder.buildSendTx(recipient: recipient,
                                               amountSatoshi: 40_000,
                                               biometricPrompt: "test")
        XCTAssertEqual(tx.inputs.count, 2)

        let prevouts = [
            Tx.Prevout(amountSatoshi: 30_000, scriptPubKey: me.scriptPubKey),
            Tx.Prevout(amountSatoshi: 25_000, scriptPubKey: me.scriptPubKey),
        ]
        for i in 0..<tx.inputs.count {
            let digest = try tx.sighashBIP341Keypath(inputIndex: i, prevouts: prevouts)
            let sig = try Secp256k1.SchnorrSignature(bytes: tx.inputs[i].witness[0])
            XCTAssertTrue(Secp256k1.schnorrVerify(signature: sig, digest: digest, publicKey: me.outputKey),
                          "input \(i) witness sig must verify over its own BIP-341 sighash")
        }

        // Two inputs MUST have different sighashes (BIP-341 commits
        // to input_index).
        let d0 = try tx.sighashBIP341Keypath(inputIndex: 0, prevouts: prevouts)
        let d1 = try tx.sighashBIP341Keypath(inputIndex: 1, prevouts: prevouts)
        XCTAssertNotEqual(d0, d1)
    }

    /// Surplus is sub-dust → no change output, change rolls into fee.
    /// 2 outputs only (recipient + fee).
    func testDustChangeIsAbsorbedIntoFee() async throws {
        let keystore = InMemoryWalletKeystore()
        _ = try keystore.createKey()
        let me = try walletIdentity(from: keystore)

        // 50_000 - 49_500 - 100 = 400 sat surplus → below 546 dust → folded into fee.
        let edge = makeStubbedEdge(
            feePerTx: 100,
            utxos: [(amount: 50_000, scriptPubKey: me.scriptPubKey)],
            myAddress: me.address
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        let recipient = try Address.encodeTaproot(outputKey: Data(repeating: 0xAA, count: 32))
        let tx = try await builder.buildSendTx(recipient: recipient,
                                               amountSatoshi: 49_500,
                                               biometricPrompt: "test")
        XCTAssertEqual(tx.outputs.count, 2)
        XCTAssertEqual(tx.outputs[0].amount, 49_500)
        XCTAssertEqual(tx.outputs[1].amount, 500) // 100 + 400 dust absorbed
    }

    /// Caller hasn't created a wallet → clear error rather than a
    /// nil-deref or empty-input crash. Recipient address must parse
    /// successfully so the failure reaches the noWalletKey check
    /// rather than tripping on decodeRecipient.
    func testNoWalletKeyFails() async throws {
        let keystore = InMemoryWalletKeystore()
        let recipient = try Address.encodeTaproot(outputKey: Data(repeating: 0xAA, count: 32))
        // We never reach the UTXOs path so myAddress can be anything
        // syntactically valid.
        let dummyAddr = try Address.encodeTaproot(outputKey: Data(repeating: 0, count: 32))
        let edge = makeStubbedEdge(utxos: [], myAddress: dummyAddr)
        let builder = TxBuilder(edge: edge, keystore: keystore)

        do {
            _ = try await builder.buildSendTx(recipient: recipient,
                                              amountSatoshi: 1,
                                              biometricPrompt: "test")
            XCTFail("expected throw")
        } catch TxBuilderError.noWalletKey {
            // ok
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    /// Insufficient funds surfaces a structured error with the
    /// actual numbers, so wallet UIs can render "you have X, need Y".
    func testInsufficientFundsSurfacesNumbers() async throws {
        let keystore = InMemoryWalletKeystore()
        _ = try keystore.createKey()
        let me = try walletIdentity(from: keystore)

        let edge = makeStubbedEdge(
            feePerTx: 100,
            utxos: [(amount: 1_000, scriptPubKey: me.scriptPubKey)],
            myAddress: me.address
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        do {
            _ = try await builder.buildSendTx(
                recipient: try Address.encodeTaproot(outputKey: Data(repeating: 0, count: 32)),
                amountSatoshi: 5_000,
                biometricPrompt: "test")
            XCTFail("expected throw")
        } catch TxBuilderError.selectInputs(.insufficientFunds(let have, let need)) {
            XCTAssertEqual(have, 1_000)
            XCTAssertEqual(need, 5_100)
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }

    /// Withdraw path: recipient output is OP_RETURN with the burn
    /// payload, NOT a P2TR scriptPubKey. The fee output and (optional)
    /// change output stay P2TR, and every input is signed correctly.
    func testBuildsWithdrawTxWithBurnOutput() async throws {
        let keystore = InMemoryWalletKeystore()
        _ = try keystore.createKey()
        let me = try walletIdentity(from: keystore)

        let edge = makeStubbedEdge(
            feePerTx: 250,
            utxos: [(amount: 100_000, scriptPubKey: me.scriptPubKey)],
            myAddress: me.address
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        let bitcoinAddr = "bcrt1qabcdefghijklmnopqrstuvwxyz0123456789"
        let tx = try await builder.buildWithdrawTx(bitcoinAddress: bitcoinAddr,
                                                   amountSatoshi: 50_000,
                                                   biometricPrompt: "test")

        XCTAssertEqual(tx.outputs.count, 3, "burn + fee + change")

        // Output 0 must be the OP_RETURN burn — first byte 0x6a, the
        // payload after the push length must equal "ENOCH:WD:<addr>".
        let burn = tx.outputs[0].scriptPubKey
        XCTAssertEqual(burn.first, 0x6A, "first byte of burn output is OP_RETURN")
        let pushLen = Int(burn[1])
        let payload = String(data: burn.subdata(in: 2..<(2 + pushLen)), encoding: .utf8)
        XCTAssertEqual(payload, "ENOCH:WD:" + bitcoinAddr)
        XCTAssertEqual(tx.outputs[0].amount, 50_000)

        // Output 1 = fee pool P2TR — first byte 0x51 (OP_1), 34 bytes total.
        XCTAssertEqual(tx.outputs[1].amount, 250)
        XCTAssertEqual(tx.outputs[1].scriptPubKey.first, 0x51,
                       "post-#109 fee output is P2TR (OP_1 push 32)")
        XCTAssertEqual(tx.outputs[1].scriptPubKey.count, 34)

        // Witness Schnorr sig verifies over the BIP-341 sighash
        // — proves we sign over a tx whose first output is the burn
        // (the operator's verifier will be hashing the same bytes).
        let prevouts = [Tx.Prevout(amountSatoshi: 100_000, scriptPubKey: me.scriptPubKey)]
        let digest = try tx.sighashBIP341Keypath(inputIndex: 0, prevouts: prevouts)
        let sig = try Secp256k1.SchnorrSignature(bytes: tx.inputs[0].witness[0])
        XCTAssertTrue(Secp256k1.schnorrVerify(signature: sig, digest: digest, publicKey: me.outputKey))
    }

    /// Legacy `enoch1q...` (P2PKH) recipients still need to work
    /// because the federation emits protocol-controlled addresses
    /// (fee_pool, agent_payouts, operator_payout) as P2PKH —
    /// every L2 send pays a fee output into one of those, so the
    /// scriptPubKey builder must handle both shapes.
    func testCanSendToLegacyAddress() async throws {
        let keystore = InMemoryWalletKeystore()
        _ = try keystore.createKey()
        let me = try walletIdentity(from: keystore)

        let edge = makeStubbedEdge(
            feePerTx: 1_000,
            utxos: [(amount: 100_000, scriptPubKey: me.scriptPubKey)],
            myAddress: me.address
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        let legacyRecipient = try Address.encodeEnoch(pkh: Data(repeating: 0xCD, count: 20))
        let tx = try await builder.buildSendTx(recipient: legacyRecipient,
                                               amountSatoshi: 50_000,
                                               biometricPrompt: "test")

        XCTAssertEqual(tx.outputs.count, 3)
        // Recipient output is a P2PKH (25 bytes, prefix 0x76 0xa9 0x14).
        XCTAssertEqual(tx.outputs[0].scriptPubKey.count, 25)
        XCTAssertEqual(tx.outputs[0].scriptPubKey.prefix(3), Data([0x76, 0xa9, 0x14]))
    }

    /// Bitcoin segwit-v0 P2WPKH (`bc1q...`) is a valid Bitcoin
    /// address but has no place on L2. The wallet must reject it
    /// with a clear error so the UI can say "use an enoch address."
    func testSendToBitcoinP2WPKHIsRejected() async throws {
        let keystore = InMemoryWalletKeystore()
        _ = try keystore.createKey()
        let me = try walletIdentity(from: keystore)
        let edge = makeStubbedEdge(
            utxos: [(amount: 100_000, scriptPubKey: me.scriptPubKey)],
            myAddress: me.address
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        let p2wpkh = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        do {
            _ = try await builder.buildSendTx(recipient: p2wpkh,
                                              amountSatoshi: 1_000,
                                              biometricPrompt: "test")
            XCTFail("expected throw")
        } catch TxBuilderError.unsupportedRecipient {
            // ok
        } catch {
            XCTFail("wrong error: \(error)")
        }
    }
}

/// In-package L2Client stub for TxBuilder tests. TxBuilder only
/// touches `getInfo` (for fee + feePool address) and `getUTXOs` (for
/// coin selection); everything else fatalErrors so a future TxBuilder
/// change that reaches outside this surface fails the test loudly
/// rather than returning a silent empty value.
final class StubL2Client: L2Client {
    let feePerTx: UInt64
    let feePoolAddress: String
    let myAddress: String
    let utxos: [UTXOWire]

    init(
        feePerTx: UInt64,
        feePoolAddress: String,
        myAddress: String,
        utxos: [UTXOWire]
    ) {
        self.feePerTx = feePerTx
        self.feePoolAddress = feePoolAddress
        self.myAddress = myAddress
        self.utxos = utxos
    }

    func getInfo() async throws -> OperatorInfo {
        // Synthesize the minimum OperatorInfo TxBuilder reads.
        let json = """
        {
          "version": "test",
          "protocol_version": 1,
          "network": "regtest",
          "operator_pubkey": "00",
          "operator_payout_address": "\(feePoolAddress)",
          "fee_pool_address": "\(feePoolAddress)",
          "watchtower_pool_address": "\(feePoolAddress)",
          "reserve_address": "\(feePoolAddress)",
          "bridge_deposit_address": "2N",
          "withdrawal_challenge_window_l1_blocks": 100,
          "current_height": 1,
          "fee_schedule": { "per_tx_fee": \(feePerTx) }
        }
        """
        return try JSONDecoder().decode(OperatorInfo.self, from: Data(json.utf8))
    }

    func getUTXOs(address: String) async throws -> UTXOsResponse {
        XCTAssertEqual(address, myAddress, "TxBuilder queried unexpected address")
        return UTXOsResponse(address: address, utxos: utxos)
    }

    func getBalance(address: String) async throws -> BalanceResponse {
        fatalError("StubL2Client.getBalance unused by TxBuilder")
    }
    func getAddressHistory(address: String, from: UInt64?, limit: UInt64?) async throws -> AddressHistoryResponse {
        fatalError("StubL2Client.getAddressHistory unused by TxBuilder")
    }
    func getPendingWithdrawals() async throws -> PendingWithdrawalsResponse {
        fatalError("StubL2Client.getPendingWithdrawals unused by TxBuilder")
    }
    func submitTx(_ tx: Tx) async throws -> SubmitTxResponse {
        fatalError("StubL2Client.submitTx unused by TxBuilder")
    }
    func eventStream(filter: [String]) -> AsyncThrowingStream<EdgeEvent, Swift.Error> {
        fatalError("StubL2Client.eventStream unused by TxBuilder")
    }
}
