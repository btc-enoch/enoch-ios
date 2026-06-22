// FederationDissent — value model for cross-check outcomes that the
// wallet view layer needs to surface (Slice F of #369).
//
// Every cross-checked read on FederationDirectL2Client emits exactly
// one FederationDissentRecord through its DissentSink:
//
//   .agreement     — wipes any prior dissent for this op
//   .majority      — kept; wallet shows warning banner
//   .noMajority    — kept; wallet shows blocker + blocks sends
//   .allFailed     — kept; wallet shows offline banner
//
// The kind enum is deliberately flat (no associated values for
// "still-trusted operators") because the v1 banner only needs:
// which op, what went wrong, and which operator IDs to name.

import Foundation

public struct FederationDissentRecord: Equatable, Sendable {
    /// Logical operation name: "balance", "utxos", "address_history",
    /// "pending_withdrawals". Matches the `op` label
    /// FederationDirectL2Client passes to `collapse`.
    public let op: String

    public let kind: Kind

    /// When this outcome was observed by the L2 client. The wallet
    /// uses the latest record per op, so timestamps mostly matter for
    /// debug / dissent log display.
    public let timestamp: Date

    public enum Kind: Equatable, Sendable {
        /// Every queried operator returned the same value. The sink
        /// uses this as a clear-signal for any prior dissent on this
        /// op.
        case agreement

        /// Majority value won, but at least one operator returned a
        /// different value. The `dissenters` list names the operator
        /// IDs whose answer was rejected.
        case majority(dissenters: [OperatorID])

        /// No value commanded majority — K distinct answers (or close
        /// to it). `distinctCount` is the number of distinct response
        /// values + failures observed.
        case noMajority(distinctCount: Int)

        /// Every queried operator returned an error.
        case allFailed
    }

    public init(op: String, kind: Kind, timestamp: Date) {
        self.op = op
        self.kind = kind
        self.timestamp = timestamp
    }

    /// True when this record represents an actively-dissenting
    /// outcome the UI should surface. `.agreement` records are
    /// emitted as clear signals — they should never persist in the
    /// wallet's `dissents` list.
    public var isActiveDissent: Bool {
        if case .agreement = kind { return false }
        return true
    }

    /// True when this dissent must hard-block spends. `.majority`
    /// degrades gracefully (display warning, allow spend). The two
    /// fatal classes — no agreement at all, or every operator down —
    /// block.
    public var blocksSpends: Bool {
        switch kind {
        case .agreement, .majority:
            return false
        case .noMajority, .allFailed:
            return true
        }
    }
}

/// Sink for cross-check outcomes. FederationDirectL2Client forwards
/// every record here; WalletStore conforms to surface them to the UI.
///
/// `AnyObject` so concrete conformers can be referenced weakly from
/// the L2 client (it's owned by the WalletStore, so a strong reverse
/// reference would cycle).
public protocol DissentSink: AnyObject {
    func record(_ event: FederationDissentRecord)
}
