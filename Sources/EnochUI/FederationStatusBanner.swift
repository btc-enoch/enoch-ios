// FederationStatusBanner — Slice F (#371) UI surface for cross-check
// dissent from #369's K-of-N FederationDirectClient.
//
// Renders nothing in the happy path (empty `wallet.dissents`). When
// one or more operators disagree, shows a coloured banner naming the
// dissenting operator IDs + the operations affected. Tapping the
// banner expands a per-op detail list.
//
// Three severity tiers mirror FederationDissentKind:
//   - .majority      → yellow ("warn but allow")
//   - .noMajority    → red    ("block sends — federation disagrees")
//   - .allFailed     → red    ("federation unreachable")
//
// The banner is a Slice F.2 component. The Send/Withdraw button
// guards consume `wallet.spendsBlockedByDissent` directly — they
// don't render their own banner; this one lives one level up so
// HomeView, SendView, WithdrawView all show the same surface.

import SwiftUI
import EnochCore

public struct FederationStatusBanner: View {
    let dissents: [FederationDissentRecord]
    @State private var expanded = false

    public init(dissents: [FederationDissentRecord]) {
        self.dissents = dissents
    }

    public var body: some View {
        if dissents.isEmpty {
            EmptyView()
        } else {
            VStack(alignment: .leading, spacing: 8) {
                summaryRow
                if expanded {
                    Divider().opacity(0.4)
                    ForEach(dissents.indices, id: \.self) { idx in
                        detailRow(dissents[idx])
                    }
                }
            }
            .padding(12)
            .background(severity.background)
            .foregroundStyle(severity.foreground)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .contentShape(Rectangle())
            .onTapGesture {
                withAnimation(.easeInOut(duration: 0.18)) {
                    expanded.toggle()
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(accessibilitySummary)
            .accessibilityHint("Tap to \(expanded ? "collapse" : "expand") operator details")
        }
    }

    // MARK: - Sub-views

    private var summaryRow: some View {
        HStack(spacing: 10) {
            Image(systemName: severity.iconName)
                .font(.system(size: 16, weight: .semibold))
            VStack(alignment: .leading, spacing: 2) {
                Text(severity.title)
                    .font(.callout.weight(.semibold))
                Text(summarySubtitle)
                    .font(.caption)
                    .opacity(0.85)
            }
            Spacer(minLength: 8)
            Image(systemName: expanded ? "chevron.up" : "chevron.down")
                .font(.caption2)
                .opacity(0.7)
        }
    }

    private func detailRow(_ rec: FederationDissentRecord) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(rec.op)
                .font(.caption.monospaced())
                .fontWeight(.medium)
            Text(rec.kind.shortDescription)
                .font(.caption)
                .opacity(0.9)
            Spacer()
        }
    }

    // MARK: - Severity classification

    /// Highest-severity outcome in the current dissent set drives the
    /// banner colour. A single noMajority among five majorities still
    /// makes the banner red, because the underlying spend block is in
    /// effect.
    private var severity: Severity {
        if dissents.contains(where: { $0.blocksSpends }) {
            return .blocker
        }
        return .warning
    }

    private enum Severity {
        case warning, blocker

        var background: Color {
            switch self {
            case .warning: return Color.yellow.opacity(0.18)
            case .blocker: return Color.red.opacity(0.20)
            }
        }
        var foreground: Color {
            switch self {
            case .warning: return Color.primary
            case .blocker: return Color.primary
            }
        }
        var iconName: String {
            switch self {
            case .warning: return "exclamationmark.triangle.fill"
            case .blocker: return "xmark.octagon.fill"
            }
        }
        var title: String {
            switch self {
            case .warning: return "Federation operators disagree"
            case .blocker: return "Federation consensus failure"
            }
        }
    }

    /// Single-line summary under the title — picks the most informative
    /// pivot to surface. Tier order: blocker first (it's what the user
    /// most needs to know), then warning, then ops affected.
    private var summarySubtitle: String {
        if let hard = dissents.first(where: { $0.blocksSpends }) {
            return "Sends blocked. \(hard.kind.shortDescription) on \(hard.op)."
        }
        // Pure-majority case: name the operators that dissented across
        // any of the ops, deduped + sorted for stable display.
        let dissenters = Set(
            dissents.flatMap { rec -> [OperatorID] in
                if case .majority(let ids) = rec.kind { return ids }
                return []
            }
        ).sorted()
        let opNames = dissents.map(\.op).sorted()
        let dissenterStr = dissenters.map { "op \($0)" }.joined(separator: ", ")
        return "Majority view shown. \(dissenterStr) disagreed on \(opNames.joined(separator: ", "))."
    }

    /// Spoken / VoiceOver summary — same content as the visible
    /// title+subtitle but flattened to a single phrase.
    private var accessibilitySummary: String {
        "\(severity.title). \(summarySubtitle)"
    }
}

private extension FederationDissentRecord.Kind {
    /// Short user-facing label for one record. Lives here rather than
    /// on the core type because the phrasing is UI-shaped, not
    /// protocol-shaped.
    var shortDescription: String {
        switch self {
        case .agreement:
            return "agreement"
        case .majority(let dissenters):
            let names = dissenters.map { "op \($0)" }.joined(separator: ", ")
            return "majority — \(names) dissented"
        case .noMajority(let count):
            return "no majority (\(count) distinct responses)"
        case .allFailed:
            return "every operator unreachable"
        }
    }
}

#Preview("Empty (healthy)") {
    FederationStatusBanner(dissents: [])
        .padding()
}

#Preview("Single majority dissent") {
    FederationStatusBanner(dissents: [
        .init(op: "balance", kind: .majority(dissenters: [2]), timestamp: .distantPast)
    ])
    .padding()
}

#Preview("Multiple majority dissents") {
    FederationStatusBanner(dissents: [
        .init(op: "balance", kind: .majority(dissenters: [2]), timestamp: .distantPast),
        .init(op: "utxos",   kind: .majority(dissenters: [2]), timestamp: .distantPast),
    ])
    .padding()
}

#Preview("No-majority blocker") {
    FederationStatusBanner(dissents: [
        .init(op: "balance", kind: .noMajority(distinctCount: 3), timestamp: .distantPast)
    ])
    .padding()
}

#Preview("All failed") {
    FederationStatusBanner(dissents: [
        .init(op: "pending_withdrawals", kind: .allFailed, timestamp: .distantPast)
    ])
    .padding()
}
