// OnboardingView — first-launch screen. Single big "Create wallet"
// button generates the secp256k1 keypair, stores it in the Keychain
// (Face ID required from this point forward), and lands us on Home.
//
// Restore-from-seed and HD derivation are out of scope for the PoC;
// this is the simplest path that gets a user transacting on Enoch.

import SwiftUI
import EnochCore

struct OnboardingView: View {
    @Environment(\.wallet) private var wallet
    @State private var creating = false
    @State private var error: String?

    var body: some View {
        VStack(spacing: 32) {
            Spacer()
            VStack(spacing: 12) {
                Text("Enoch")
                    .font(.largeTitle.weight(.semibold))
                Text("Bitcoin's current account")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            VStack(alignment: .leading, spacing: 8) {
                Label("Non-custodial", systemImage: "key.fill")
                Label("Face ID required to send", systemImage: "faceid")
                Label("Withdraw to Bitcoin anytime", systemImage: "arrow.up.right")
            }
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .padding(.horizontal, 32)

            Spacer()

            Button {
                Task { await create() }
            } label: {
                Text(creating ? "Creating…" : "Create wallet")
                    .font(.headline)
                    .frame(maxWidth: .infinity, minHeight: 44)
            }
            .buttonStyle(.borderedProminent)
            .disabled(creating)
            .padding(.horizontal)

            if let error {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }
        }
        .padding(.bottom, 32)
    }

    private func create() async {
        creating = true
        defer { creating = false }
        error = nil
        do {
            try await wallet.createWallet()
        } catch {
            self.error = "couldn't create wallet: \(error.localizedDescription)"
        }
    }
}

#Preview {
    OnboardingView()
}
