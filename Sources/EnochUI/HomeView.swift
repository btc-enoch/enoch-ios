// HomeView — wallet home. Shows the current balance prominently,
// the most recent transactions, and Send/Receive buttons. The
// connection pill in the top-right reflects SSE state so the user
// can tell whether the live feed is healthy.
//
// History list is intentionally short here (last few rows + a "see
// all" link); full history view comes in Phase 5b.

import SwiftUI
import EnochCore

struct HomeView: View {
    @Environment(\.wallet) private var wallet

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                BalanceCard(balance: wallet.balance, utxoCount: wallet.utxoCount)
                ActionRow()
                RecentActivity(history: Array(wallet.history.prefix(5)))
            }
            .padding()
        }
        .navigationTitle("Wallet")
        .toolbar {
            // .topBarTrailing is iOS-only; .primaryAction is the
            // cross-platform equivalent that maps to top-right on
            // iOS and the toolbar on macOS.
            ToolbarItem(placement: .primaryAction) {
                ConnectionPill(state: wallet.connectionState)
            }
        }
        .refreshable { await wallet.refresh() }
    }
}

private struct BalanceCard: View {
    let balance: UInt64
    let utxoCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Balance")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text(formatSatoshis(balance))
                .font(.system(size: 36, weight: .semibold, design: .rounded))
                .monospacedDigit()
            Text("\(utxoCount) UTXO\(utxoCount == 1 ? "" : "s")")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 16))
    }
}

private struct ActionRow: View {
    var body: some View {
        HStack(spacing: 12) {
            NavigationLink {
                ReceiveView()
            } label: {
                ActionButtonLabel(title: "Receive", systemImage: "arrow.down.left")
            }
            // Send screen lands in Phase 5b; placeholder for layout.
            Button {
                // no-op
            } label: {
                ActionButtonLabel(title: "Send", systemImage: "arrow.up.right")
            }
            .disabled(true)
        }
    }
}

private struct ActionButtonLabel: View {
    let title: String
    let systemImage: String

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: systemImage)
                .font(.title2)
            Text(title)
                .font(.subheadline.weight(.medium))
        }
        .frame(maxWidth: .infinity, minHeight: 80)
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }
}

private struct RecentActivity: View {
    let history: [AddressHistoryEntry]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Recent activity")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
            if history.isEmpty {
                Text("No transactions yet.")
                    .font(.callout)
                    .foregroundStyle(.tertiary)
            } else {
                ForEach(history, id: \.txHash) { entry in
                    HistoryRow(entry: entry)
                }
            }
        }
    }
}

private struct HistoryRow: View {
    let entry: AddressHistoryEntry

    var body: some View {
        HStack {
            Image(systemName: roleIcon(entry.role))
                .foregroundStyle(roleTint(entry.role))
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(roleLabel(entry.role))
                    .font(.callout.weight(.medium))
                Text("Height \(entry.height)")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            Spacer()
            Text(formatDelta(entry.deltaSatoshi))
                .font(.callout.monospacedDigit())
                .foregroundStyle(entry.deltaSatoshi >= 0 ? .green : .primary)
        }
        .padding(.vertical, 6)
    }
}

private struct ConnectionPill: View {
    let state: WalletStore.ConnectionState

    var body: some View {
        HStack(spacing: 4) {
            Circle()
                .fill(color)
                .frame(width: 8, height: 8)
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var color: Color {
        switch state {
        case .connected: return .green
        case .connecting, .idle: return .yellow
        case .disconnected: return .red
        }
    }

    private var label: String {
        switch state {
        case .connected: return "live"
        case .connecting: return "syncing"
        case .idle: return ""
        case .disconnected: return "offline"
        }
    }
}

// MARK: - Formatters

private func formatSatoshis(_ sats: UInt64) -> String {
    // Show as N sat for now; Phase 5b can add BTC/fiat toggles. The
    // monospacedDigit on the label keeps wide numbers stable.
    let formatter = NumberFormatter()
    formatter.numberStyle = .decimal
    formatter.groupingSeparator = ","
    let n = formatter.string(from: NSNumber(value: sats)) ?? "\(sats)"
    return "\(n) sat"
}

private func formatDelta(_ delta: Int64) -> String {
    let formatter = NumberFormatter()
    formatter.numberStyle = .decimal
    formatter.groupingSeparator = ","
    formatter.positivePrefix = "+"
    let n = formatter.string(from: NSNumber(value: delta)) ?? "\(delta)"
    return n
}

private func roleIcon(_ role: HistoryRole) -> String {
    switch role {
    case .incoming: return "arrow.down.left.circle.fill"
    case .outgoing: return "arrow.up.right.circle.fill"
    case .self:     return "arrow.triangle.2.circlepath.circle.fill"
    case .unknown:  return "questionmark.circle.fill"
    }
}

private func roleTint(_ role: HistoryRole) -> Color {
    switch role {
    case .incoming: return .green
    case .outgoing: return .orange
    case .self:     return .blue
    case .unknown:  return .gray
    }
}

private func roleLabel(_ role: HistoryRole) -> String {
    switch role {
    case .incoming: return "Received"
    case .outgoing: return "Sent"
    case .self:     return "Self-send"
    case .unknown:  return "Unknown"
    }
}

#Preview {
    NavigationStack { HomeView() }
}
