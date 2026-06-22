// WithdrawView — peg-out (L2 → L1) screen.
//
// Distinct from SendView because the user-visible behavior is
// fundamentally different: a Send is instant + L2-only; a Withdraw
// is a Bitcoin-side payout that takes minutes (L2 challenge window
// + agent 3-of-5 sign + L1 confirmations). The screen calls that
// out clearly so the user understands the timing trade-off.
//
// The wallet just constructs and submits the burn tx; the bridge
// agents do all the L1 work autonomously.

import SwiftUI
import EnochCore

struct WithdrawView: View {
    @Environment(\.wallet) private var wallet
    @Environment(\.dismiss) private var dismiss

    @State private var bitcoinAddress: String = ""
    @State private var amountText: String = ""
    @State private var sending: Bool = false
    @State private var error: String?

    var body: some View {
        Form {
            if !wallet.dissents.isEmpty {
                Section {
                    FederationStatusBanner(dissents: wallet.dissents)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                }
            }
            Section {
                Label("Withdraw to Bitcoin",
                      systemImage: "arrow.up.right.diamond.fill")
                    .font(.headline)
                    .foregroundStyle(.purple)
                Text("Send your sats to a regular Bitcoin address. Settlement takes a few minutes — bridge operators sign and broadcast the L1 transaction after a brief challenge window.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Section("Bitcoin address") {
                TextField("bc1q… / tb1q… / bcrt1q… / 1… / 3…",
                          text: $bitcoinAddress, axis: .vertical)
                    .autocorrectionDisabled()
                    .font(.callout.monospaced())
                    .lineLimit(2...4)
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                if let err = addressError {
                    Text(err)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }

            Section("Amount") {
                TextField("sats", text: $amountText)
                    .font(.title3.monospacedDigit())
                    #if os(iOS)
                    .keyboardType(.numberPad)
                    #endif
                if let err = amountError {
                    Text(err)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            }

            Section("Fees") {
                if let fee = wallet.feePerTxSatoshi {
                    LabeledContent("L2 transaction fee") {
                        Text("\(formatSats(fee)) sat")
                            .monospacedDigit()
                    }
                    LabeledContent("Bitcoin mining fee") {
                        Text("paid by bridge")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    if let amount = parsedAmount {
                        LabeledContent("L2 cost") {
                            Text("\(formatSats(amount + fee)) sat")
                                .monospacedDigit()
                                .fontWeight(.semibold)
                        }
                        LabeledContent("Bitcoin payout") {
                            Text("\(formatSats(amount)) sat")
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                    }
                } else {
                    Text("Fee unknown — pull to refresh on Wallet to load operator info.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if let error {
                Section {
                    Text(error)
                        .font(.callout)
                        .foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Withdraw")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(sending ? "Sending…" : "Withdraw") {
                    Task { await submit() }
                }
                .disabled(!canSubmit || sending)
            }
        }
    }

    // MARK: - Validation

    private var parsedAmount: UInt64? {
        guard !amountText.isEmpty else { return nil }
        return UInt64(amountText)
    }

    /// We don't pre-decode the Bitcoin address (the bridge agents
    /// do that authoritatively) — but we DO enforce the OP_RETURN
    /// payload length cap (66 chars after the "ENOCH:WD:" prefix)
    /// so the wallet can fail fast on inputs the operator would
    /// reject anyway.
    private var addressError: String? {
        let trimmed = bitcoinAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.utf8.count > 66 {
            return "Address too long for the burn output (max 66 chars)."
        }
        // Rough format hint — accept anything plausibly Bitcoin-ish;
        // bridge agents validate authoritatively.
        let lower = trimmed.lowercased()
        let looksLikeBech32 = lower.hasPrefix("bc1") || lower.hasPrefix("tb1") || lower.hasPrefix("bcrt1")
        let looksLikeBase58 = trimmed.first == "1" || trimmed.first == "3" || trimmed.first == "m" || trimmed.first == "n" || trimmed.first == "2"
        if !(looksLikeBech32 || looksLikeBase58) {
            return "Doesn't look like a Bitcoin address."
        }
        return nil
    }

    private var amountError: String? {
        guard !amountText.isEmpty else { return nil }
        guard let amount = parsedAmount else {
            return "Enter a whole number of sats."
        }
        if amount == 0 {
            return "Amount must be greater than zero."
        }
        if let fee = wallet.feePerTxSatoshi, amount + fee > wallet.balance {
            return "Insufficient funds — you have \(formatSats(wallet.balance)) sat."
        }
        return nil
    }

    private var canSubmit: Bool {
        addressError == nil
            && amountError == nil
            && !bitcoinAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && parsedAmount != nil
            && wallet.feePerTxSatoshi != nil
            // Slice F.3 (#371): block withdraws while federation
            // disagrees on the wallet's state. The banner above
            // explains why.
            && !wallet.spendsBlockedByDissent
    }

    // MARK: - Submit

    private func submit() async {
        guard let amount = parsedAmount else { return }
        let trimmedAddress = bitcoinAddress.trimmingCharacters(in: .whitespacesAndNewlines)

        sending = true
        error = nil
        defer { sending = false }

        do {
            try await wallet.withdraw(
                to: trimmedAddress,
                amount: amount,
                biometricPrompt: "Authorize withdrawal of \(formatSats(amount)) sat"
            )
            dismiss()
        } catch let e as TxBuilderError {
            self.error = render(e)
        } catch let e as L2ClientError {
            self.error = render(e)
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func render(_ e: TxBuilderError) -> String {
        switch e {
        case .selectInputs(.insufficientFunds(let have, let need)):
            return "Insufficient funds — you have \(formatSats(have)) sat, need \(formatSats(need))."
        case .selectInputs(.noSpendableUTXOs):
            return "No spendable UTXOs at this address."
        case .buildBurnOutput(let underlying):
            return "Burn output failed: \(underlying)"
        case .missingFeeSchedule:
            return "Operator fee schedule unavailable."
        case .noWalletKey:
            return "Wallet has no key — try resetting."
        default:
            return "Withdraw failed: \(e)"
        }
    }

    private func render(_ e: L2ClientError) -> String {
        switch e {
        case .http(let status, let body):
            return body.isEmpty ? "Server returned \(status)." : body
        case .transport(let msg):
            return "Network error: \(msg)"
        case .decode(let msg):
            return "Couldn't decode server reply: \(msg)"
        case .urlConstruction:
            return "Internal error: URL construction failed."
        }
    }
}

// MARK: - Local formatter (mirrors SendView's helper)

private func formatSats(_ n: UInt64) -> String {
    let f = NumberFormatter()
    f.numberStyle = .decimal
    f.groupingSeparator = ","
    return f.string(from: NSNumber(value: n)) ?? "\(n)"
}

#Preview {
    NavigationStack { WithdrawView() }
}
