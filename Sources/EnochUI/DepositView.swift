// DepositView — show the wallet's per-user L1 Bitcoin deposit
// address (#108), with a QR + copy + a brief explainer of what
// happens when someone sends BTC to it.
//
// The address is fully derived client-side from the wallet's L2
// x-only pubkey + the bridge redeem script published in
// /v1/info — see WalletStore.bridgeDepositAddress. Same address
// every time; safe to share, screenshot, paper-print.
//
// In-flight deposits surface on the Home screen via the
// pendingDeposits card (driven by the deposit_pending /
// deposit_minted SSE events). This screen is the "show me my
// address so I can give it out" view; lifecycle UX stays on Home.

import SwiftUI
import EnochCore

#if canImport(UIKit)
import UIKit
#endif

#if canImport(CoreImage)
import CoreImage
import CoreImage.CIFilterBuiltins
#endif

struct DepositView: View {
    @Environment(\.wallet) private var wallet
    @State private var copied = false

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                if let address = wallet.bridgeDepositAddress {
                    DepositQRSection(address: address, copied: $copied) {
                        copyToPasteboard(address)
                    }

                    InfoBlock(
                        symbol: "info.circle",
                        title: "How it works",
                        text: "Anyone can send Bitcoin to this address — they don't need an Enoch wallet. After L1 confirmation, the bridge mints the equivalent on Enoch and credits your balance."
                    )

                    InfoBlock(
                        symbol: "clock",
                        title: "Confirmation time",
                        text: confirmationCopy(for: wallet.minConfirmationsForDeposit)
                    )

                    InfoBlock(
                        symbol: "lock.shield",
                        title: "Same address every time",
                        text: "This address is unique to your wallet and stays the same. Reusing it across multiple deposits is fine."
                    )

                    InfoBlock(
                        symbol: "exclamationmark.triangle.fill",
                        title: "Bitcoin only",
                        text: "Send Bitcoin to this address — never an Enoch transaction. An Enoch send to this address would be permanently unrecoverable. Use the Receive screen for Enoch transfers.",
                        tint: .orange
                    )
                } else if wallet.address == nil {
                    ProgressView("Loading wallet…")
                        .padding(.vertical, 60)
                } else {
                    ProgressView("Loading deposit address…")
                        .padding(.vertical, 60)
                }
            }
            .padding(.vertical)
        }
        .navigationTitle("Deposit Bitcoin")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }

    private func confirmationCopy(for target: Int) -> String {
        switch target {
        case 1: return "1 Bitcoin block (≈10 min). Regtest / development network."
        case 6: return "6 Bitcoin blocks (≈1 hour) — Bitcoin's standard finality threshold for large amounts."
        default: return "\(target) Bitcoin blocks before the funds are credited on Enoch."
        }
    }

    private func copyToPasteboard(_ s: String) {
        #if canImport(UIKit)
        UIPasteboard.general.string = s
        #endif
        copied = true
        Task {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            copied = false
        }
    }
}

private struct DepositQRSection: View {
    let address: String
    @Binding var copied: Bool
    let onCopy: () -> Void

    var body: some View {
        VStack(spacing: 14) {
            QRCode(text: address)
                .frame(width: 220, height: 220)

            Text("Your Bitcoin deposit address")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Text(address)
                .font(.callout.monospaced())
                .multilineTextAlignment(.center)
                .padding(.horizontal)
                .textSelection(.enabled)

            Button {
                onCopy()
            } label: {
                Label(copied ? "Copied" : "Copy address",
                      systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.bordered)
        }
    }
}

private struct InfoBlock: View {
    let symbol: String
    let title: String
    let text: String
    var tint: Color? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol)
                .font(.title3)
                .foregroundStyle(tint ?? .secondary)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(tint ?? .primary)
                Text(text)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
        .padding(.horizontal)
    }
}

private struct QRCode: View {
    let text: String

    var body: some View {
        if let img = makeQRImage(text) {
            Image(img, scale: 1, label: Text("QR code"))
                .interpolation(.none)
                .resizable()
                .aspectRatio(contentMode: .fit)
        } else {
            Text(text)
                .font(.callout.monospaced())
                .multilineTextAlignment(.center)
        }
    }

    private func makeQRImage(_ text: String) -> CGImage? {
        #if canImport(CoreImage)
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard
            let output = filter.outputImage,
            let cg = context.createCGImage(output, from: output.extent)
        else { return nil }
        return cg
        #else
        return nil
        #endif
    }
}

#Preview {
    NavigationStack { DepositView() }
}
