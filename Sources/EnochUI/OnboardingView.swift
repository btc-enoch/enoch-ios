// OnboardingView — first-launch screen. Two paths:
//   - "Create wallet" generates a fresh secp256k1 keypair and stores
//     it Keychain-backed.
//   - "I have an existing key" opens an import sheet that takes a
//     64-character hex private key and adopts it as the wallet's key.
//
// Both land on Home. Restore-from-seed (BIP-39) is a follow-on and
// will live alongside import-by-hex.

import SwiftUI
import EnochCore

struct OnboardingView: View {
    @Environment(\.wallet) private var wallet
    @State private var creating = false
    @State private var error: String?
    @State private var showingImport = false

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

            VStack(spacing: 12) {
                Button {
                    Task { await create() }
                } label: {
                    Text(creating ? "Creating…" : "Create wallet")
                        .font(.headline)
                        .frame(maxWidth: .infinity, minHeight: 44)
                }
                .buttonStyle(.borderedProminent)
                .disabled(creating)

                Button("I have an existing key") {
                    showingImport = true
                }
                .font(.subheadline)
                .disabled(creating)
            }
            .padding(.horizontal)

            if let error {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
            }
        }
        .padding(.bottom, 32)
        .sheet(isPresented: $showingImport) {
            ImportKeyView()
        }
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

/// ImportKeyView — paste a 64-char hex private key and adopt it.
///
/// Intentionally minimal: a monospaced text field, a one-line warning
/// about clipboard exposure, and a single import button. Hex import
/// is a power-user feature; the eventual mainstream restore path is
/// BIP-39 mnemonic and will live in a separate sheet with its own UX.
/// ImportKeyView — paste a 64-char hex private key, name the wallet,
/// and adopt it. Internally this calls
/// `WalletStore.importWallet(name:privateKeyHex:)`, which adds the
/// imported key as a NEW wallet alongside any existing ones (no
/// overwrite — multi-wallet keystore).
struct ImportKeyView: View {
    @Environment(\.wallet) private var wallet
    @Environment(\.dismiss) private var dismiss

    @State private var hex: String = ""
    @State private var name: String = "Imported"
    @State private var importing = false
    @State private var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Wallet name") {
                    TextField("e.g. Gift wallet", text: $name)
                        #if os(iOS)
                        .textInputAutocapitalization(.words)
                        #endif
                }

                Section("Private key (64 hex characters)") {
                    TextField("d47e4d8a…", text: $hex, axis: .vertical)
                        .autocorrectionDisabled()
                        .font(.callout.monospaced())
                        .lineLimit(2...4)
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                }

                Section {
                    Text("This is the raw 32-byte secret. Keys typed or pasted here may briefly live on your clipboard — paste from a trusted source only.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                if let error {
                    Section {
                        Text(error)
                            .font(.callout)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Import wallet")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(importing)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(importing ? "Importing…" : "Import") {
                        Task { await runImport() }
                    }
                    .disabled(!canSubmit)
                }
            }
        }
    }

    private var canSubmit: Bool {
        !importing && !name.trimmingCharacters(in: .whitespaces).isEmpty && isValidHex
    }

    private var isValidHex: Bool {
        let trimmed = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count == 64 else { return false }
        return trimmed.allSatisfy { $0.isHexDigit }
    }

    private func runImport() async {
        importing = true
        defer { importing = false }
        error = nil
        do {
            try await wallet.importWallet(
                name: name.trimmingCharacters(in: .whitespaces),
                privateKeyHex: hex
            )
            dismiss()
        } catch {
            self.error = "import failed: \(error.localizedDescription)"
        }
    }
}

#Preview {
    OnboardingView()
}
