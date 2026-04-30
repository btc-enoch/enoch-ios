// ReceiveView — show the wallet's enoch1... address as text and a
// QR code, with a copy button. The address is non-secret; rendering
// it does NOT trigger Face ID (the Keychain pubkey lookup uses
// kSecReturnAttributes only).
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
    @State private var copied = false

    var body: some View {
        VStack(spacing: 24) {
            if let address = wallet.address {
                QRCode(text: address)
                    .frame(width: 220, height: 220)

                Text("Your Enoch address")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

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
            } else {
                ProgressView("Loading address…")
            }
        }
        .padding()
        .navigationTitle("Receive")
        #if os(iOS)
        .navigationBarTitleDisplayMode(.inline)
        #endif
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
