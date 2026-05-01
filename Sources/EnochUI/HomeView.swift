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
                RecentActivity(history: Array(wallet.history.prefix(5)),
                               totalCount: wallet.history.count)
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
            NavigationLink {
                SendView()
            } label: {
                ActionButtonLabel(title: "Send", systemImage: "arrow.up.right")
            }
            NavigationLink {
                WithdrawView()
            } label: {
                ActionButtonLabel(title: "Withdraw",
                                  systemImage: "arrow.up.right.diamond")
            }
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
    let totalCount: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Recent activity")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                if totalCount > history.count {
                    NavigationLink("See all (\(totalCount))") {
                        HistoryView()
                    }
                    .font(.caption)
                }
            }
            if history.isEmpty {
                Text("No transactions yet.")
                    .font(.callout)
                    .foregroundStyle(.tertiary)
            } else {
                ForEach(history, id: \.txHash) { entry in
                    HistoryRow(entry: entry)
                }
                if totalCount > history.count {
                    NavigationLink {
                        HistoryView()
                    } label: {
                        Text("See all activity")
                            .font(.callout)
                    }
                    .padding(.top, 4)
                }
            }
        }
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
//
// roleIcon / roleTint / roleLabel / formatDelta live in
// HistoryView.swift — shared with the full activity list. Only
// formatSatoshis stays here because BalanceCard is the only caller
// (the activity row uses formatDelta which has its own +/- logic).

private func formatSatoshis(_ sats: UInt64) -> String {
    let formatter = NumberFormatter()
    formatter.numberStyle = .decimal
    formatter.groupingSeparator = ","
    let n = formatter.string(from: NSNumber(value: sats)) ?? "\(sats)"
    return "\(n) sat"
}

#Preview {
    NavigationStack { HomeView() }
}
