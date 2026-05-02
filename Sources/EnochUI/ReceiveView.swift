// ReceiveView — show the wallet's enoch1... address as text and a
// QR code, with a copy button. The address is non-secret; rendering
// it does NOT trigger Face ID (the Keychain pubkey lookup uses
// kSecReturnAttributes only).
//
// Two sections coexist (#108):
//   - "Receive on Enoch" — the wallet's L2 enoch1p... address, used
//     by other Enoch users for instant transfers.
//   - "Receive on Bitcoin" — the user's per-user-derived L1 deposit
//     address (bech32m P2TR). Anyone can send BTC here; it arrives
//     on Enoch after L1 confirmation + bridge mint. Only present
//     when /v1/info exposes `bridge_redeem_script` and the active
//     wallet is P2TR.
//
// QR generation uses CoreImage's CIQRCodeGenerator — no third-party
// dependency, works offline.

import SwiftUI
import EnochCore

#if canImport(UIKit)
import UIKit
#endif

#if canImport(CoreImage)
import CoreImage
import CoreImage.CIFilterBuiltins
#endif

struct ReceiveView: View {
    @Environment(\.wallet) private var wallet

    var body: some View {
        ScrollView {
            VStack(spacing: 32) {
                if let address = wallet.address {
                    AddressSection(
                        title: "Receive on Enoch",
                        subtitle: "Instant — sender pays the L2 fee",
                        address: address
                    )

                    if let depositAddress = wallet.bridgeDepositAddress {
                        Divider().padding(.horizontal, 40)
                        AddressSection(
                            title: "Receive on Bitcoin",
                            subtitle: "Bitcoin sent here arrives on Enoch after L1 confirmation",
                            address: depositAddress
                        )
                    }
                } else {
                    ProgressView("Loading address…")
                }
            }
            .padding(.vertical)
        }
        .navigationTitle("Receive")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
    }
}

private struct AddressSection: View {
    let title: String
    let subtitle: String
    let address: String

    @State private var copied = false

    var body: some View {
        VStack(spacing: 16) {
            VStack(spacing: 4) {
                Text(title)
                    .font(.headline)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            QRCode(text: address)
                .frame(width: 200, height: 200)

            Text(address)
                .font(.callout.monospaced())
                .multilineTextAlignment(.center)
                .padding(.horizontal)
                .textSelection(.enabled)

            Button {
                copyToPasteboard(address)
            } label: {
                Label(copied ? "Copied" : "Copy address",
                      systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.bordered)
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

private struct QRCode: View {
    let text: String

    var body: some View {
        if let img = makeQRImage(text) {
            Image(img, scale: 1, label: Text("QR code"))
                .interpolation(.none)
                .resizable()
                .aspectRatio(contentMode: .fit)
        } else {
            // Fallback if CoreImage isn't available (e.g., test
            // environments without an image pipeline). Shows the
            // text without a QR — still usable.
            Text(text)
                .font(.callout.monospaced())
                .multilineTextAlignment(.center)
        }
    }

    /// Render a black-on-white QR for `text`. We deliberately produce
    /// a `CGImage` (not `UIImage`) so the same code works for both
    /// iOS and macOS without platform splits at the call site.
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
    NavigationStack { ReceiveView() }
}
