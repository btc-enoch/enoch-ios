// HistoryView — full activity list. Reuses the row layout from
// HomeView's RecentActivity but shows every entry, sorted newest-
// first. Pull-to-refresh re-pulls /v1/address_history; the SSE
// loop also pushes new rows in as they arrive.
//
// No pagination yet — the wallet's typical user is going to have
// dozens of entries, not thousands. Add a `from=<height>&limit=`
// loading-more flow when there's a real performance reason.

import SwiftUI
import EnochCore

struct HistoryView: View {
    @Environment(\.wallet) private var wallet

    var body: some View {
        Group {
            if wallet.history.isEmpty {
                ContentUnavailableView(
                    "No activity yet",
                    systemImage: "clock.arrow.circlepath",
                    description: Text("Once you receive or send, transactions will appear here.")
                )
            } else {
                List(wallet.history, id: \.txHash) { entry in
                    HistoryRow(entry: entry,
                               withdrawalStatus: wallet.withdrawalStatuses[entry.txHash])
                }
            }
        }
        .navigationTitle("Activity")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .refreshable { await wallet.refresh() }
    }
}

/// Same layout as the home row but lifted into its own type so
/// HomeView and HistoryView can share it. The optional
/// `withdrawalStatus` is only meaningful for `.burn` rows — when
/// present, the row gains a status badge under the height line.
struct HistoryRow: View {
    let entry: AddressHistoryEntry
    var withdrawalStatus: WalletStore.WithdrawalUIStatus? = nil

    var body: some View {
        HStack {
            Image(systemName: roleIcon(entry.role, delta: entry.deltaSatoshi))
                .foregroundStyle(roleTint(entry.role, delta: entry.deltaSatoshi))
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(roleLabel(entry.role, delta: entry.deltaSatoshi))
                    .font(.callout.weight(.medium))
                Text("Height \(entry.height)")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
                if entry.role == .burn, let status = withdrawalStatus {
                    WithdrawalStatusBadge(status: status)
                }
            }
            Spacer()
            Text(formatDelta(entry.deltaSatoshi))
                .font(.callout.monospacedDigit())
                .foregroundStyle(entry.deltaSatoshi >= 0 ? .green : .primary)
        }
        .padding(.vertical, 6)
    }
}

/// Small inline label rendering the lifecycle state of a peg-out.
/// Three concrete states (pending / broadcast / unknown) keep the
/// vocabulary tight; the unknown bucket is forward-compat for
/// future server states (e.g. confirmed once an L1 watcher lands).
private struct WithdrawalStatusBadge: View {
    let status: WalletStore.WithdrawalUIStatus

    var body: some View {
        switch status {
        case .pending:
            Label("Bridge processing…", systemImage: "hourglass")
                .font(.caption2)
                .foregroundStyle(.orange)
        case .broadcast(let btcTxID):
            Label("Bitcoin: \(btcTxID.prefix(10))…",
                  systemImage: "bitcoinsign.circle")
                .font(.caption2)
                .foregroundStyle(.green)
        case .unknownState(let s):
            Label(s, systemImage: "questionmark.circle")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - Role rendering (shared with HomeView)
//
// Bridge tags (mint/burn) take absolute priority. Otherwise the
// delta sign drives the user-facing label: a UTXO tx where your
// pkh appears as both input and change output is mechanically a
// "self" role on the wire, but the user's intent maps to whether
// their net balance went up or down.

func roleIcon(_ role: HistoryRole, delta: Int64) -> String {
    switch role {
    case .mint:    return "arrow.down.to.line.circle.fill"
    case .burn:    return "arrow.up.to.line.circle.fill"
    case .unknown: return "questionmark.circle.fill"
    case .incoming, .outgoing, .self:
        if delta > 0 { return "arrow.down.left.circle.fill" }
        if delta < 0 { return "arrow.up.right.circle.fill" }
        return "arrow.triangle.2.circlepath.circle.fill"
    }
}

func roleTint(_ role: HistoryRole, delta: Int64) -> Color {
    switch role {
    case .mint, .burn: return .purple
    case .unknown:     return .gray
    case .incoming, .outgoing, .self:
        if delta > 0 { return .green }
        if delta < 0 { return .orange }
        return .blue
    }
}

func roleLabel(_ role: HistoryRole, delta: Int64) -> String {
    switch role {
    case .mint:    return "Minted"
    case .burn:    return "Withdrawn"
    case .unknown: return "Unknown"
    case .incoming, .outgoing, .self:
        if delta > 0 { return "Received" }
        if delta < 0 { return "Sent" }
        return "Self-send"
    }
}

func formatDelta(_ delta: Int64) -> String {
    let formatter = NumberFormatter()
    formatter.numberStyle = .decimal
    formatter.groupingSeparator = ","
    formatter.positivePrefix = "+"
    let n = formatter.string(from: NSNumber(value: delta)) ?? "\(delta)"
    return n
}

#Preview {
    NavigationStack { HistoryView() }
}
