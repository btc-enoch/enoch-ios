// TxBuilder — orchestrate "send N sats to address X" into a fully
// signed Tx ready for EdgeClient.submitTx.
//
// Post-#109 the wallet is uniformly P2TR keypath:
//   - Wallet's own UTXOs are at `enoch1p...` (Taproot output key)
//   - Inputs sign via BIP-341 keypath sighash + BIP-340 Schnorr
//   - The sig goes into TxInput.witness (single 64-byte element);
//     scriptSig stays empty
//   - Recipients can be either P2TR (preferred) or P2PKH (legacy
//     enoch1...) — the wallet decodes via Address.decode and emits
//     the matching scriptPubKey
//
// Build path:
//   1. Derive wallet's Taproot address from pubkey (no biometric).
//   2. Fetch operator info + UTXOs in parallel.
//   3. Decode recipient + fee-pool addresses; build scriptPubKeys.
//   4. Run CoinSelection over the UTXOs.
//   5. Construct unsigned Tx: recipient + fee + change outputs;
//      empty inputs (no scriptSig, no witness yet).
//   6. For each input: compute BIP-341 keypath sighash + biometric-
//      gated Schnorr sign + populate input.witness = [sig].
//   7. Return the signed Tx.
//
// One biometric prompt per input today. Batch-sign across N inputs
// in a single Face ID prompt is a future ergonomic improvement.

import Foundation

public enum TxBuilderError: Swift.Error {
    case missingFeeSchedule
    case feeOutputBuildFailed
    case noWalletKey
    case selectInputs(CoinSelectionError)
    case decodeRecipient(Swift.Error)
    case decodeFeePool(Swift.Error)
    case unsupportedRecipient(String)  // e.g. P2WPKH (segwit v0) — L2 doesn't speak it
    case invalidPrevScriptPubKey(input: Int)
    case sign(input: Int, underlying: Swift.Error)
    case scriptBuild(input: Int, underlying: Swift.Error)
    case fetchInfo(Swift.Error)
    case fetchUTXOs(Swift.Error)
    case buildBurnOutput(Swift.Error)
}

public final class TxBuilder {
    private let edge: EdgeClient
    private let keystore: WalletKeystore

    public init(edge: EdgeClient, keystore: WalletKeystore) {
        self.edge = edge
        self.keystore = keystore
    }

    /// Build, sign, and return a Tx that sends `amountSatoshi` to
    /// `recipient` (any address format the operator recognizes — L2
    /// P2TR `enoch1p...` and legacy P2PKH `enoch1...` both supported)
    /// from the wallet's address.
    public func buildSendTx(
        recipient: String,
        amountSatoshi: UInt64,
        biometricPrompt: String
    ) async throws -> Tx {
        let recipientScript: Data
        do {
            recipientScript = try Self.scriptForRecipient(recipient)
        } catch let e as TxBuilderError {
            throw e
        } catch {
            throw TxBuilderError.decodeRecipient(error)
        }
        let recipientOutput = TxOutput(amount: amountSatoshi, scriptPubKey: recipientScript)
        return try await buildOutgoing(
            recipientOutput: recipientOutput,
            biometricPrompt: biometricPrompt
        )
    }

    /// Build, sign, and return a Tx initiating an L2 → L1 peg-out:
    /// the "recipient" output is an `OP_RETURN ENOCH:WD:<bitcoinAddress>`
    /// burn marker. Bridge agents pick it up after the L2 challenge
    /// window, 3-of-5 sign a Bitcoin tx paying the L1 address from
    /// the bridge multisig, and broadcast it.
    public func buildWithdrawTx(
        bitcoinAddress: String,
        amountSatoshi: UInt64,
        biometricPrompt: String
    ) async throws -> Tx {
        let burnScript: Data
        do {
            burnScript = try Script.opReturnBurn(bitcoinAddress: bitcoinAddress)
        } catch {
            throw TxBuilderError.buildBurnOutput(error)
        }
        let recipientOutput = TxOutput(amount: amountSatoshi, scriptPubKey: burnScript)
        return try await buildOutgoing(
            recipientOutput: recipientOutput,
            biometricPrompt: biometricPrompt
        )
    }

    /// Shared core. Caller provides the pre-built recipient output
    /// (a P2TR or P2PKH spend for L2 sends, OP_RETURN burn for L2 →
    /// L1 withdrawals); we handle fetch + selection + fee + change +
    /// per-input Schnorr signing.
    private func buildOutgoing(
        recipientOutput: TxOutput,
        biometricPrompt: String
    ) async throws -> Tx {
        guard let publicKey = try keystore.publicKey() else {
            throw TxBuilderError.noWalletKey
        }
        // Pubkey-side Taproot output key + address (no biometric).
        let myOutputKey = try publicKey.taprootOutputKey()
        let myAddress = try Address.encodeTaproot(outputKey: myOutputKey.bytes)
        let myChangeScript = try Script.taprootScriptPubKey(outputKey: myOutputKey.bytes)

        // Parallel fetch: operator info + UTXOs.
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

        // Fee pool address may be either format during the migration;
        // post-#109 + B6 it's uniformly P2TR.
        let feePoolScript: Data
        do {
            feePoolScript = try Self.scriptForRecipient(info.operator.feePoolAddress)
        } catch {
            throw TxBuilderError.decodeFeePool(error)
        }

        let selection: CoinSelection.Selection
        do {
            selection = try CoinSelection.select(
                utxos: utxos.utxos,
                target: recipientOutput.amount,
                feePerTx: feePerTx
            )
        } catch let e as CoinSelectionError {
            throw TxBuilderError.selectInputs(e)
        }

        // Outputs: recipient + fee + (optional) change.
        var outputs: [TxOutput] = [
            recipientOutput,
            TxOutput(amount: selection.feeSatoshi, scriptPubKey: feePoolScript),
        ]
        if selection.changeSatoshi > 0 {
            outputs.append(TxOutput(amount: selection.changeSatoshi, scriptPubKey: myChangeScript))
        }

        // Inputs: empty scriptSig + empty witness; we'll fill witness below.
        // Sequence is non-final to keep the tx RBF-eligible at L1
        // (irrelevant for L2 acceptance but mirrors the Bitcoin shape).
        let inputs: [TxInput] = try selection.inputs.map { utxo in
            TxInput(
                txHash: try Data(hex: utxo.txHash),
                vout: utxo.vout,
                scriptSig: Data(),
                sequence: 0xFFFFFFFE,
                witness: []
            )
        }
        var tx = Tx(version: 2, inputs: inputs, outputs: outputs, lockTime: 0)

        // BIP-341 sighash commits to ALL inputs' amounts + scripts,
        // not just the one being signed — so we hand the full
        // prevouts list to every per-input call. Both pieces come
        // from the UTXOWire the operator returned.
        let prevouts: [Tx.Prevout]
        do {
            prevouts = try selection.inputs.map { utxo in
                Tx.Prevout(
                    amountSatoshi: utxo.amount,
                    scriptPubKey: try Data(hex: utxo.scriptPubKey)
                )
            }
        } catch {
            throw TxBuilderError.invalidPrevScriptPubKey(input: 0)
        }

        // Sign each input.
        for i in 0..<tx.inputs.count {
            let digest: Data
            do {
                digest = try tx.sighashBIP341Keypath(inputIndex: i, prevouts: prevouts)
            } catch {
                throw TxBuilderError.sign(input: i, underlying: error)
            }
            let sig: Secp256k1.SchnorrSignature
            do {
                sig = try await keystore.signTaprootKeypath(digest: digest, prompt: biometricPrompt)
            } catch {
                throw TxBuilderError.sign(input: i, underlying: error)
            }
            // P2TR keypath spend: witness is a single element — the
            // 64-byte Schnorr signature. SIGHASH_DEFAULT, no sighash
            // byte appended.
            tx.inputs[i].witness = [sig.bytes]
            // scriptSig stays empty.
        }

        return tx
    }

    /// Decode an address and emit the matching scriptPubKey. Supports
    /// the two L2-receive formats; rejects anything else with a clear
    /// error so the caller can surface a "wrong address type" message.
    static func scriptForRecipient(_ address: String) throws -> Data {
        let decoded = try Address.decode(address)
        switch decoded {
        case .p2tr(let outputKey):
            return try Script.taprootScriptPubKey(outputKey: outputKey)
        case .p2pkh(let pkh):
            // Legacy enoch1... — still valid as a recipient during
            // the migration window. Both shapes coexist on L2.
            return try Script.p2pkhScriptPubKey(pkh: pkh)
        case .p2wpkh:
            // Bitcoin segwit v0 P2WPKH (`bc1q.../tb1q...`) — not an
            // L2 address, can't be a recipient on this rail.
            throw TxBuilderError.unsupportedRecipient("P2WPKH (Bitcoin segwit v0) — not an L2 address")
        }
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
