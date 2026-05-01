import XCTest
@testable import EnochCore

/// Tests TxBuilder end-to-end with stubbed edge responses + an
/// InMemoryWalletKeystore. The output is a fully-signed Tx — we
/// verify its shape (inputs / outputs / amounts) AND that each
/// input's signature actually verifies against the wallet's public
/// key over the correct sighash. That second check is what makes
/// these tests load-bearing: a broken sighash or scriptSig assembly
/// would still produce a "valid-looking" Tx but fail real-world
/// signature verification on the operator.
final class TxBuilderTests: XCTestCase {
    private let edgeURL = URL(string: "http://test.local")!

    private func makeStubbedEdge(
        feePerTx: UInt64 = 1_000,
        feePoolPKH: Data = Data(repeating: 0x11, count: 20),
        utxos: [(amount: UInt64, scriptPubKey: Data)],
        myAddress: String
    ) -> EdgeClient {
        let feePoolAddr = (try? Address.encodeEnoch(pkh: feePoolPKH)) ?? "enoch1"

        // Build a single canned set of responses. URLProtocol routes
        // by path, so we encode the dispatch logic here.
        MockURLProtocol.handler = { req in
            let path = req.url?.path ?? ""
            if path == "/v1/info" {
                let body = """
                {
                  "edge": { "version": "test", "protocol_version": 1 },
                  "operator": {
                    "version": "test", "protocol_version": 1, "network": "regtest",
                    "operator_pubkey": "00", "operator_payout_address": "enoch1",
                    "fee_pool_address": "\(feePoolAddr)",
                    "watchtower_pool_address": "enoch1",
                    "reserve_address": "enoch1", "bridge_deposit_address": "2N",
                    "withdrawal_challenge_window_l1_blocks": 100, "current_height": 1,
                    "fee_schedule": { "per_tx_fee": \(feePerTx) }
                  }
                }
                """
                return (200, Data(body.utf8))
            }
            if path == "/v1/utxos/\(myAddress)" {
                let entries = utxos.enumerated().map { (i, u) in
                    let txHash = String(format: "%064x", i + 1)
                    return """
                    {
                      "tx_hash": "\(txHash)",
                      "vout": 0,
                      "amount": \(u.amount),
                      "script_pubkey": "\(u.scriptPubKey.hexString)"
                    }
                    """
                }.joined(separator: ",")
                let body = #"{"address":"\#(myAddress)","utxos":[\#(entries)]}"#
                return (200, Data(body.utf8))
            }
            return (404, Data())
        }

        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [MockURLProtocol.self]
        return EdgeClient(baseURL: edgeURL, session: URLSession(configuration: config))
    }

    override func tearDown() {
        super.tearDown()
        MockURLProtocol.handler = nil
    }

    /// Happy path: 1 input fully covers target + fee + change. The
    /// resulting Tx has exactly 3 outputs (recipient, fee, change),
    /// the recipient amount matches, and the input's signature
    /// verifies against the wallet's public key over the correct
    /// per-input sighash.
    func testBuildsSignedTxWithChange() async throws {
        let keystore = InMemoryWalletKeystore()
        let pub = try keystore.createKey()
        let myAddress = try Address.encodeEnoch(publicKey: pub)
        let myPKH = Hashing.hash160(pub.compressedBytes)
        let myScriptPubKey = try Script.p2pkhScriptPubKey(pkh: myPKH)

        let edge = makeStubbedEdge(
            feePerTx: 1_000,
            utxos: [(amount: 100_000, scriptPubKey: myScriptPubKey)],
            myAddress: myAddress
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        let recipient = try Address.encodeEnoch(pkh: Data(repeating: 0xAA, count: 20))
        let tx = try await builder.buildSendTx(recipient: recipient,
                                               amountSatoshi: 50_000,
                                               biometricPrompt: "test")

        XCTAssertEqual(tx.inputs.count, 1)
        XCTAssertEqual(tx.outputs.count, 3, "recipient + fee + change")
        XCTAssertEqual(tx.outputs[0].amount, 50_000)              // recipient
        XCTAssertEqual(tx.outputs[1].amount, 1_000)               // fee
        XCTAssertEqual(tx.outputs[2].amount, 49_000)              // 100_000 - 50_000 - 1_000

        // The signature in scriptSig actually validates against the
        // wallet's pubkey over the correct sighash — the load-bearing
        // assertion that proves Script + sighash + signing all line up.
        let prevScriptPubKey = myScriptPubKey
        let digest = try tx.sighashLegacyAll(inputIndex: 0, prevScriptPubKey: prevScriptPubKey)
        let (sigBytes, _) = try parseScriptSig(tx.inputs[0].scriptSig)
        // Strip the trailing SIGHASH_ALL byte before passing to verify.
        let derOnly = sigBytes.dropLast()
        let sig = Secp256k1.Signature(der: Data(derOnly))
        XCTAssertTrue(pub.verifyDigest(digest, signature: sig),
                      "scriptSig signature must verify under wallet pubkey + per-input sighash")
    }

    /// Multi-input: sum of two UTXOs covers target. Both inputs get
    /// signed; both signatures verify over their distinct sighashes
    /// (per-input sighash is what makes this load-bearing — a wrong
    /// implementation could sign all inputs over the same digest).
    func testBuildsMultiInputTx() async throws {
        let keystore = InMemoryWalletKeystore()
        let pub = try keystore.createKey()
        let myAddress = try Address.encodeEnoch(publicKey: pub)
        let myPKH = Hashing.hash160(pub.compressedBytes)
        let myScriptPubKey = try Script.p2pkhScriptPubKey(pkh: myPKH)

        let edge = makeStubbedEdge(
            feePerTx: 1_000,
            utxos: [
                (amount: 30_000, scriptPubKey: myScriptPubKey),
                (amount: 25_000, scriptPubKey: myScriptPubKey),
            ],
            myAddress: myAddress
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        let recipient = try Address.encodeEnoch(pkh: Data(repeating: 0xAA, count: 20))
        let tx = try await builder.buildSendTx(recipient: recipient,
                                               amountSatoshi: 40_000,
                                               biometricPrompt: "test")
        XCTAssertEqual(tx.inputs.count, 2)

        for i in 0..<tx.inputs.count {
            let digest = try tx.sighashLegacyAll(inputIndex: i, prevScriptPubKey: myScriptPubKey)
            let (sigBytes, _) = try parseScriptSig(tx.inputs[i].scriptSig)
            let sig = Secp256k1.Signature(der: Data(sigBytes.dropLast()))
            XCTAssertTrue(pub.verifyDigest(digest, signature: sig),
                          "input \(i) signature must verify over its own sighash")
        }

        // The two inputs MUST have different sighashes, otherwise
        // we've made the classic "signed every input with the same
        // digest" mistake.
        let d0 = try tx.sighashLegacyAll(inputIndex: 0, prevScriptPubKey: myScriptPubKey)
        let d1 = try tx.sighashLegacyAll(inputIndex: 1, prevScriptPubKey: myScriptPubKey)
        XCTAssertNotEqual(d0, d1)
    }

    /// Surplus is sub-dust → no change output, change rolls into fee.
    /// 2 outputs only (recipient + fee).
    func testDustChangeIsAbsorbedIntoFee() async throws {
        let keystore = InMemoryWalletKeystore()
        let pub = try keystore.createKey()
        let myAddress = try Address.encodeEnoch(publicKey: pub)
        let myScriptPubKey = try Script.p2pkhScriptPubKey(pkh: Hashing.hash160(pub.compressedBytes))

        // 50_000 - 49_500 - 100 = 400 sat surplus → below 546 dust → folded into fee.
        let edge = makeStubbedEdge(
            feePerTx: 100,
            utxos: [(amount: 50_000, scriptPubKey: myScriptPubKey)],
            myAddress: myAddress
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        let recipient = try Address.encodeEnoch(pkh: Data(repeating: 0xAA, count: 20))
        let tx = try await builder.buildSendTx(recipient: recipient,
                                               amountSatoshi: 49_500,
                                               biometricPrompt: "test")
        XCTAssertEqual(tx.outputs.count, 2)
        XCTAssertEqual(tx.outputs[0].amount, 49_500)
        XCTAssertEqual(tx.outputs[1].amount, 500) // 100 + 400 dust absorbed
    }

    /// Caller hasn't created a wallet → clear error rather than a
    /// nil-deref or empty-input crash.
    func testNoWalletKeyFails() async throws {
        let keystore = InMemoryWalletKeystore()
        // Valid syntactic recipient + edge stub so we get past
        // address-decode and into the actual key check. Passing
        // "enoch1" used to land here pre-refactor; post-refactor
        // (recipient decoded before key lookup) we need a parseable
        // address to make sure the key-missing path is what fires.
        let recipient = try Address.encodeEnoch(pkh: Data(repeating: 0xAA, count: 20))
        let edge = makeStubbedEdge(
            utxos: [],
            myAddress: "enoch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqljsyzs"
        )
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
        let pub = try keystore.createKey()
        let myAddress = try Address.encodeEnoch(publicKey: pub)
        let myScriptPubKey = try Script.p2pkhScriptPubKey(pkh: Hashing.hash160(pub.compressedBytes))

        let edge = makeStubbedEdge(
            feePerTx: 100,
            utxos: [(amount: 1_000, scriptPubKey: myScriptPubKey)],
            myAddress: myAddress
        )
        let builder = TxBuilder(edge: edge, keystore: keystore)

        do {
            _ = try await builder.buildSendTx(recipient: try Address.encodeEnoch(pkh: Data(repeating: 0, count: 20)),
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
    /// payload, NOT a P2PKH script. The fee output and (optional)
    /// change output stay P2PKH, and every input is signed
    /// correctly. Catches a regression where the helper might use
    /// the wrong output script construction.
    func testBuildsWithdrawTxWithBurnOutput() async throws {
        let keystore = InMemoryWalletKeystore()
        let pub = try keystore.createKey()
        let myAddress = try Address.encodeEnoch(publicKey: pub)
        let myScriptPubKey = try Script.p2pkhScriptPubKey(pkh: Hashing.hash160(pub.compressedBytes))

        let edge = makeStubbedEdge(
            feePerTx: 250,
            utxos: [(amount: 100_000, scriptPubKey: myScriptPubKey)],
            myAddress: myAddress
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

        // Output 1 = fee pool P2PKH.
        XCTAssertEqual(tx.outputs[1].amount, 250)
        XCTAssertEqual(tx.outputs[1].scriptPubKey.first, 0x76,
                       "fee output is still standard P2PKH")

        // Signature on the input verifies — proves we sign over a
        // tx whose first output is the burn (the operator's verifier
        // will be hashing the same bytes).
        let digest = try tx.sighashLegacyAll(inputIndex: 0, prevScriptPubKey: myScriptPubKey)
        let (sigBytes, _) = try parseScriptSig(tx.inputs[0].scriptSig)
        let sig = Secp256k1.Signature(der: Data(sigBytes.dropLast()))
        XCTAssertTrue(pub.verifyDigest(digest, signature: sig))
    }
}

// MARK: - helpers

/// Parse a P2PKH scriptSig back into its (sig+sighash, pubkey)
/// components. Mirror of Script.p2pkhScriptSig in reverse — used by
/// tests to validate that the script we built can be round-tripped
/// + verified.
private func parseScriptSig(_ data: Data) throws -> (sig: Data, pubkey: Data) {
    guard data.count >= 2 else {
        throw NSError(domain: "parseScriptSig", code: 1)
    }
    let sigLen = Int(data[0])
    guard data.count >= 1 + sigLen + 1 else {
        throw NSError(domain: "parseScriptSig", code: 2)
    }
    let sig = data.subdata(in: 1..<(1 + sigLen))
    let pubLen = Int(data[1 + sigLen])
    let pubStart = 1 + sigLen + 1
    guard data.count >= pubStart + pubLen else {
        throw NSError(domain: "parseScriptSig", code: 3)
    }
    let pub = data.subdata(in: pubStart..<(pubStart + pubLen))
    return (sig, pub)
}
