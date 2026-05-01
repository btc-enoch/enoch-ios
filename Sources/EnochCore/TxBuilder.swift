// TxBuilder — orchestrate "send N sats to address X" into a fully
// signed Tx ready for EdgeClient.submitTx.
//
// The build path:
//   1. Fetch operator info (fee schedule, fee-pool address).
//   2. Fetch the wallet's UTXOs.
//   3. Decode recipient + fee-pool addresses to pkh.
//   4. Run CoinSelection over the UTXOs.
//   5. Construct the unsigned Tx (inputs + recipient/change/fee outputs).
//   6. For each input: compute sighashLegacyAll, sign via the keystore,
//      splice DER+sighash + compressed pubkey into scriptSig.
//   7. Return the signed Tx.
//
// The keystore biometric prompt fires once per input today. A future
// optimization is a batch-sign API that authenticates one LAContext
// and reuses it across N digests — out of scope for the PoC.

import Foundation

public enum TxBuilderError: Swift.Error {
    case missingFeeSchedule
    case feeOutputBuildFailed
    case noWalletKey
    case selectInputs(CoinSelectionError)
    case decodeRecipient(Swift.Error)
    case decodeFeePool(Swift.Error)
    case invalidPrevScriptPubKey(input: Int)
    case sign(input: Int, underlying: Swift.Error)
    case scriptSigBuild(input: Int, underlying: Swift.Error)
    case fetchInfo(Swift.Error)
    case fetchUTXOs(Swift.Error)
}

public final class TxBuilder {
    private let edge: EdgeClient
    private let keystore: WalletKeystore

    public init(edge: EdgeClient, keystore: WalletKeystore) {
        self.edge = edge
        self.keystore = keystore
    }

    /// Build, sign, and return a `Tx` that sends `amountSatoshi` to
    /// `recipient` (any address format) from the wallet's address.
    /// The returned tx is ready for `EdgeClient.submitTx`.
    ///
    /// Operator fee accounting: we read the per-tx fee from
    /// `/v1/info` and emit a third output paying the fee pool. If
    /// the surplus over recipient + fee is non-dust, a change output
    /// returns to the wallet's own address; otherwise the dust is
    /// rolled into the fee.
    public func buildSendTx(
        recipient: String,
        amountSatoshi: UInt64,
        biometricPrompt: String
    ) async throws -> Tx {
        guard let publicKey = try keystore.publicKey() else {
            throw TxBuilderError.noWalletKey
        }
        let myAddress = try Address.encodeEnoch(publicKey: publicKey)

        // Step 1 + 2: parallel fetch of operator info + UTXOs.
        async let infoTask = wrap(TxBuilderError.fetchInfo) {
            try await self.edge.getInfo()
        }
        async let utxosTask = wrap(TxBuilderError.fetchUTXOs) {
            try await self.edge.getUTXOs(address: myAddress)
        }
        let info = try await infoTask
        let utxos = try await utxosTask

        guard let feePerTx = info.operator.feeSchedule?.perTxFeeSatoshi else {
            throw TxBuilderError.missingFeeSchedule
        }

        // Step 3: addresses → pkhs.
        let recipientPKH: Data
        do {
            recipientPKH = try Address.decodeToPKH(recipient)
        } catch {
            throw TxBuilderError.decodeRecipient(error)
        }
        let feePoolPKH: Data
        do {
            feePoolPKH = try Address.decodeToPKH(info.operator.feePoolAddress)
        } catch {
            throw TxBuilderError.decodeFeePool(error)
        }

        // Step 4: coin selection.
        let selection: CoinSelection.Selection
        do {
            selection = try CoinSelection.select(
                utxos: utxos.utxos,
                target: amountSatoshi,
                feePerTx: feePerTx
            )
        } catch let e as CoinSelectionError {
            throw TxBuilderError.selectInputs(e)
        }

        // Step 5: build unsigned tx.
        var outputs: [TxOutput] = [
            TxOutput(amount: amountSatoshi, scriptPubKey: try Script.p2pkhScriptPubKey(pkh: recipientPKH)),
            TxOutput(amount: selection.feeSatoshi, scriptPubKey: try Script.p2pkhScriptPubKey(pkh: feePoolPKH)),
        ]
        if selection.changeSatoshi > 0 {
            let myPKH = Hashing.hash160(publicKey.compressedBytes)
            outputs.append(TxOutput(
                amount: selection.changeSatoshi,
                scriptPubKey: try Script.p2pkhScriptPubKey(pkh: myPKH)
            ))
        }

        let inputs: [TxInput] = try selection.inputs.map { utxo in
            TxInput(
                txHash: try Data(hex: utxo.txHash),
                vout: utxo.vout,
                scriptSig: Data(),
                sequence: 0xFFFFFFFF
            )
        }
        var tx = Tx(version: 1, inputs: inputs, outputs: outputs, lockTime: 0)

        // Step 6: sign each input. Each sighash uses the *prevScriptPubKey*
        // of the spent UTXO — recovered from the UTXOWire we already have.
        for i in 0..<tx.inputs.count {
            let prevScriptPubKey: Data
            do {
                prevScriptPubKey = try Data(hex: selection.inputs[i].scriptPubKey)
            } catch {
                throw TxBuilderError.invalidPrevScriptPubKey(input: i)
            }
            let digest = try tx.sighashLegacyAll(inputIndex: i, prevScriptPubKey: prevScriptPubKey)
            let sig: Secp256k1.Signature
            do {
                sig = try await keystore.sign(digest: digest, prompt: biometricPrompt)
            } catch {
                throw TxBuilderError.sign(input: i, underlying: error)
            }
            do {
                tx.inputs[i].scriptSig = try Script.p2pkhScriptSig(
                    sigWithSighashType: sig.derWithSighashAll,
                    compressedPubKey: publicKey.compressedBytes
                )
            } catch {
                throw TxBuilderError.scriptSigBuild(input: i, underlying: error)
            }
        }

        return tx
    }
}

/// Run an async throwing closure and remap any error into a
/// caller-supplied wrapper case. Keeps the call sites in
/// buildSendTx readable.
private func wrap<T>(_ wrapper: (Swift.Error) -> TxBuilderError, _ body: () async throws -> T) async throws -> T {
    do {
        return try await body()
    } catch {
        throw wrapper(error)
    }
}
