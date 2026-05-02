// WalletPickerView — switch between wallets, add new ones (create or
// import), and delete existing ones.
//
// Each wallet is an independent secp256k1 keypair stored in the
// keystore. Switching is instant (no biometric — only signing is
// gated); deleting prompts a confirmation since it permanently
// removes the privkey from Keychain (funds remain recoverable only
// if you backed up the privkey elsewhere).

import SwiftUI
import EnochCore

struct WalletPickerView: View {
    @Environment(\.wallet) private var wallet
    @Environment(\.dismiss) private var dismiss

    @State private var addingWallet = false
    @State private var pendingDelete: WalletDescriptor?
    @State private var error: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(wallet.wallets) { descriptor in
                        WalletRow(
                            descriptor: descriptor,
                            isActive: descriptor.id == wallet.activeWalletID,
                            onSelect: { Task { await select(descriptor) } }
                        )
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button(role: .destructive) {
                                pendingDelete = descriptor
                            } label: {
                                Label("Delete", systemImage: "trash")
                            }
                        }
                    }
                }

                Section {
                    Button {
                        addingWallet = true
                    } label: {
                        Label("Add wallet", systemImage: "plus")
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
            .navigationTitle("Wallets")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .sheet(isPresented: $addingWallet) {
                AddWalletSheet()
            }
            .alert(
                "Delete wallet?",
                isPresented: Binding(
                    get: { pendingDelete != nil },
                    set: { if !$0 { pendingDelete = nil } }
                ),
                presenting: pendingDelete
            ) { descriptor in
                Button("Delete", role: .destructive) {
                    Task { await delete(descriptor) }
                }
                Button("Cancel", role: .cancel) {}
            } message: { descriptor in
                Text("\"\(descriptor.name)\" will be removed from this device. Funds at its address can only be recovered if you've backed up the private key elsewhere.")
            }
        }
    }

    private func select(_ d: WalletDescriptor) async {
        guard d.id != wallet.activeWalletID else {
            dismiss()
            return
        }
        do {
            try await wallet.selectWallet(id: d.id)
            dismiss()
        } catch {
            self.error = "couldn't switch: \(error.localizedDescription)"
        }
    }

    private func delete(_ d: WalletDescriptor) async {
        do {
            try await wallet.deleteWallet(id: d.id)
        } catch {
            self.error = "couldn't delete: \(error.localizedDescription)"
        }
    }
}

private struct WalletRow: View {
    let descriptor: WalletDescriptor
    let isActive: Bool
    let onSelect: () -> Void

    var body: some View {
        Button(action: onSelect) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(descriptor.name)
                        .font(.body)
                        .foregroundStyle(.primary)
                    Text(descriptor.id.prefix(8) + "…")
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                }
                Spacer()
                if isActive {
                    Image(systemName: "checkmark")
                        .foregroundStyle(.tint)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// AddWalletSheet — fork between "Create new" and "Import from key".
/// BIP-39 mnemonic restore is the third option once it lands; same
/// shell.
private struct AddWalletSheet: View {
    @Environment(\.wallet) private var wallet
    @Environment(\.dismiss) private var dismiss

    @State private var mode: Mode = .create
    @State private var newName: String = "Wallet"
    @State private var creating = false
    @State private var error: String?

    enum Mode: String, CaseIterable {
        case create = "Create new"
        case importKey = "Import key"
    }

    var body: some View {
        NavigationStack {
            Form {
                Picker("Source", selection: $mode) {
                    ForEach(Mode.allCases, id: \.self) { m in
                        Text(m.rawValue).tag(m)
                    }
                }
                .pickerStyle(.segmented)

                switch mode {
                case .create:
                    Section("Name") {
                        TextField("Wallet", text: $newName)
                            #if os(iOS)
                            .textInputAutocapitalization(.words)
                            #endif
                    }
                    if let error {
                        Section { Text(error).foregroundStyle(.red).font(.callout) }
                    }
                case .importKey:
                    EmptyView()
                }
            }
            .navigationTitle("Add wallet")
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(creating)
                }
                if mode == .create {
                    ToolbarItem(placement: .confirmationAction) {
                        Button(creating ? "Creating…" : "Create") {
                            Task { await runCreate() }
                        }
                        .disabled(creating || newName.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                }
            }
            .sheet(isPresented: Binding(
                get: { mode == .importKey },
                set: { if !$0 { mode = .create } }
            )) {
                ImportKeyView()
                    .onDisappear { dismiss() }
            }
        }
    }

    private func runCreate() async {
        creating = true
        defer { creating = false }
        error = nil
        do {
            try await wallet.createWallet(name: newName.trimmingCharacters(in: .whitespaces))
            dismiss()
        } catch {
            self.error = "couldn't create wallet: \(error.localizedDescription)"
        }
    }
}
