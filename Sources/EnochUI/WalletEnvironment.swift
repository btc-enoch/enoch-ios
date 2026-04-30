// WalletEnvironment — SwiftUI environment plumbing for WalletStore.
//
// Views read the store via `@Environment(\.wallet)`. The app's @main
// entry constructs the real store (KeychainWalletKeystore + real
// EdgeClient) and injects it; previews can inject a store backed by
// InMemoryWalletKeystore + a mocked EdgeClient so the design canvas
// runs offline and never prompts Face ID.

import SwiftUI
import EnochCore

public extension EnvironmentValues {
    /// `@Entry` (iOS 17+) generates the EnvironmentKey machinery
    /// internally — cleaner than the old `EnvironmentKey` boilerplate
    /// and plays nicely with @MainActor isolation on `WalletStore`,
    /// which the legacy pattern complained about.
    @Entry var wallet: WalletStore = WalletStore(
        keystore: InMemoryWalletKeystore(),
        client: EdgeClient(baseURL: URL(string: "http://localhost:8081")!)
    )
}
