// CoinSelection — pick which UTXOs the wallet should spend to cover
// a target amount + the operator's flat per-tx fee.
//
// Phase 4 of #191: this Swift module is now a thin wrapper over
// EnochCrypto's `coinselectSelect` — same algorithm (greedy
// largest-first with bond filtering and dust-into-fee), single
// Rust source of truth shared with the operator's Go cgo binding.
// Public Swift API + error type preserved so existing callers
// (TxBuilder, SendView) don't change.
//
// Algorithm choice (unchanged from the pre-migration impl):
// the operator charges a flat per-tx fee, so input count
// doesn't materially affect cost — greedy largest-first is
// fine, no need for branch-and-bound or knapsack.
//
// Bond UTXOs are filtered out. Watchtowers can also have
// bond-like UTXOs; the same rule applies.

import Foundation
import EnochCrypto

public enum CoinSelectionError: Swift.Error, Equatable {
    case noSpendableUTXOs
    case insufficientFunds(have: UInt64, need: UInt64)
}

public enum CoinSelection {
    /// Result of a successful selection. Caller constructs the
    /// final tx outputs from this:
    ///   - one to the recipient (target sats)
    ///   - one to the fee pool (fee sats)
    ///   - if changeSatoshi > 0 → one back to self
    /// Sum of those equals `selectedTotal`.
    public struct Selection: Equatable {
        public let inputs: [UTXOWire]
        public let selectedTotal: UInt64
        public let changeSatoshi: UInt64
        public let feeSatoshi: UInt64
    }

    /// Greedy largest-first selection.
    ///
    /// - Parameter utxos: every UTXO at the wallet's address. Must
    ///   be the full set; bond-UTXO filtering is done by the
    ///   underlying Rust impl.
    /// - Parameter target: amount to send to the recipient (sats).
    /// - Parameter feePerTx: operator's flat per-tx fee (sats).
    /// - Parameter dustThreshold: change below this (sats) is
    ///   rolled into the fee rather than emitted as an output.
    ///   546 matches Bitcoin's standardness rule.
    public static func select(
        utxos: [UTXOWire],
        target: UInt64,
        feePerTx: UInt64,
        dustThreshold: UInt64 = 546
    ) throws -> Selection {
        // Convert UTXOWire → CoinUtxo for the FFI call. Use a
        // (txHash, vout) → UTXOWire dictionary so we can map the
        // selected CoinUtxos back to the original wire structs
        // (preserving scriptPubKey + bondInfo etc. that the FFI
        // doesn't carry).
        var byKey: [String: UTXOWire] = [:]
        var coinUtxos: [CoinUtxo] = []
        coinUtxos.reserveCapacity(utxos.count)
        for w in utxos {
            let key = "\(w.txHash):\(w.vout)"
            byKey[key] = w
            // The FFI takes txid as raw bytes; UTXOWire ships hex.
            // Failed decode means the operator handed us garbage,
            // which the existing impl would also have failed on
            // downstream — so swap in placeholder bytes here and
            // let the algorithmic outcome match (selection is on
            // amount + bond flag; txid is opaque to it).
            let txidBytes = (try? Data(hex: w.txHash)) ?? Data(count: 32)
            coinUtxos.append(CoinUtxo(
                txid: txidBytes,
                vout: w.vout,
                amountSat: w.amount,
                isBond: w.bondInfo != nil
            ))
        }

        let result: EnochCrypto.CoinSelection
        do {
            result = try coinselectSelect(
                utxos: coinUtxos,
                targetSat: target,
                feePerTxSat: feePerTx,
                dustThresholdSat: dustThreshold
            )
        } catch let e as CoinSelectError {
            switch e {
            case .NoSpendableUtxos:
                throw CoinSelectionError.noSpendableUTXOs
            case .InsufficientFunds(let have, let need):
                throw CoinSelectionError.insufficientFunds(have: have, need: need)
            }
        }

        // Map selected CoinUtxos back to the original UTXOWire
        // entries by (txHash, vout). Preserves scriptPubKey +
        // bondInfo for the rest of the tx-builder pipeline.
        var picked: [UTXOWire] = []
        picked.reserveCapacity(result.inputs.count)
        for c in result.inputs {
            let key = "\(c.txid.hexString):\(c.vout)"
            if let w = byKey[key] {
                picked.append(w)
            }
        }
        return Selection(
            inputs: picked,
            selectedTotal: result.selectedTotalSat,
            changeSatoshi: result.changeSat,
            feeSatoshi: result.feeSat
        )
    }
}

