// SendView — the wallet's L2 send screen.
//
// Form layout: recipient (any address format), amount in sats, a
// previewed flat fee, and a confirm button. On confirm we kick the
// keystore + biometric prompt and submit the signed tx via the edge.
//
// Validation surfaces inline as the user types so the Confirm
// button accurately reflects "is this submittable right now"
// rather than only erroring out on submit. Failure paths get
// rendered as red footer text — operator rejections, network
// errors, biometric cancellation are all distinguishable from the
// underlying EdgeError / TxBuilderError types.

import SwiftUI
import EnochCore

struct SendView: View {
    @Environment(\.wallet) private var wallet
    @Environment(\.dismiss) private var dismiss

    @State private var recipient: String = ""
    @State private var amountText: String = ""
    @State private var sending: Bool = false
    @State private var error: String?

    var body: some View {
        Form {
            Section("Recipient") {
                TextField("enoch1… or bc1q…", text: $recipient, axis: .vertical)
                    .autocorrectionDisabled()
                    .font(.callout.monospaced())
                    .lineLimit(2...4)
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    #endif
                if let err = recipientError {
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

            Section("Fee") {
                if let fee = wallet.feePerTxSatoshi {
                    LabeledContent("Network fee") {
                        Text("\(formatSats(fee)) sat")
                            .monospacedDigit()
                    }
                    if let amount = parsedAmount {
                        LabeledContent("Total") {
                            Text("\(formatSats(amount + fee)) sat")
                                .monospacedDigit()
                                .fontWeight(.semibold)
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
        .navigationTitle("Send")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button(sending ? "Sending…" : "Send") {
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

    private var recipientError: String? {
        let trimmed = recipient.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        do {
            switch try Address.decode(trimmed) {
            case .p2pkh, .p2tr:
                // Both L2 forms — legacy enoch1... and post-#109
                // enoch1p... — are valid Send recipients.
                return nil
            case .p2wpkh:
                // Bitcoin segwit v0 isn't an L2 address. The wallet's
                // Withdraw flow (peg-out) takes Bitcoin addresses; tell
                // the user where to go instead of just rejecting.
                return "That's a Bitcoin address. Use Withdraw to peg out to L1."
            }
        } catch {
            return "Not a valid Enoch address."
        }
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
        recipientError == nil
            && amountError == nil
            && !recipient.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && parsedAmount != nil
            && wallet.feePerTxSatoshi != nil
    }

    // MARK: - Submit

    private func submit() async {
        guard let amount = parsedAmount else { return }
        let trimmedRecipient = recipient.trimmingCharacters(in: .whitespacesAndNewlines)

        sending = true
        error = nil
        defer { sending = false }

        do {
            try await wallet.send(
                to: trimmedRecipient,
                amount: amount,
                biometricPrompt: "Authorize send of \(formatSats(amount)) sat"
            )
            dismiss()
        } catch let e as TxBuilderError {
            self.error = render(e)
        } catch let e as EdgeError {
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
        case .decodeRecipient:
            return "Recipient address couldn't be decoded."
        case .missingFeeSchedule:
            return "Operator fee schedule unavailable."
        case .noWalletKey:
            return "Wallet has no key — try resetting."
        default:
            return "Send failed: \(e)"
        }
    }

    private func render(_ e: EdgeError) -> String {
        switch e {
        case .http(let status, let body):
            // The operator's reject reasons (e.g. "insufficient
            // funds", "script verification failed") come back in
            // the body verbatim — surface them.
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

// MARK: - Formatting

private func formatSats(_ n: UInt64) -> String {
    let f = NumberFormatter()
    f.numberStyle = .decimal
    f.groupingSeparator = ","
    return f.string(from: NSNumber(value: n)) ?? "\(n)"
}

#Preview {
    NavigationStack { SendView() }
}
