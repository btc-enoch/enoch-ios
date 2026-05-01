// CoinSelection — pick which UTXOs the wallet should spend to cover
// a target amount + the operator's flat per-tx fee.
//
// The operator charges a flat fee per tx (governance-set, not size-
// driven), so input count matters less than on Bitcoin L1 — we
// don't need branch-and-bound or bytes-aware optimization. Greedy
// largest-first is fine and easy to test.
//
// Bond UTXOs (slashing collateral) are filtered out: a regular
// "send" must never accidentally consume a bond. Watchtowers can
// also have bond-like UTXOs by Kind="agent"; same rule.
//
// Future: replace the algorithm behind the same select(...) entry
// point if we ever want randomization for privacy or knapsack-
// style change minimization. The rest of TxBuilder doesn't care.

import Foundation

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
    /// - Parameter utxos: every UTXO at the wallet's address. Must be
    ///   the full set; filtering is done internally (bond UTXOs etc.).
    /// - Parameter target: amount to send to the recipient (sats).
    /// - Parameter feePerTx: operator's flat per-tx fee (sats).
    /// - Parameter dustThreshold: change below this (sats) is rolled
    ///   into the fee rather than emitted as an output. 546 matches
    ///   Bitcoin's standardness rule for non-OP_RETURN outputs.
    public static func select(
        utxos: [UTXOWire],
        target: UInt64,
        feePerTx: UInt64,
        dustThreshold: UInt64 = 546
    ) throws -> Selection {
        // Filter spendable: ignore bond UTXOs. A wallet that wants
        // to actually claim a bond does it through a separate path.
        let spendable = utxos.filter { $0.bondInfo == nil }
        if spendable.isEmpty {
            throw CoinSelectionError.noSpendableUTXOs
        }

        let needed = target + feePerTx
        // Sort largest first — minimizes input count for typical sends.
        let sorted = spendable.sorted { $0.amount > $1.amount }

        var picked: [UTXOWire] = []
        var total: UInt64 = 0
        for u in sorted {
            picked.append(u)
            total = total &+ u.amount
            if total >= needed { break }
        }
        if total < needed {
            throw CoinSelectionError.insufficientFunds(have: total, need: needed)
        }

        let surplus = total - needed
        // Sub-dust change → roll into fee. Otherwise emit a change
        // output and let the operator's accounting balance.
        let (change, fee) = surplus < dustThreshold
            ? (UInt64(0), feePerTx + surplus)
            : (surplus, feePerTx)

        return Selection(inputs: picked, selectedTotal: total, changeSatoshi: change, feeSatoshi: fee)
    }
}
