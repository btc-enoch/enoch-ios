// ContentView — root chooser. If the keystore has no key we land on
// onboarding; otherwise we show the wallet home wrapped in a
// NavigationStack so child screens (Receive, Send, History) push.

import SwiftUI
import EnochCore

public struct ContentView: View {
    @Environment(\.wallet) private var wallet

    public init() {}

    public var body: some View {
        Group {
            if wallet.hasWallet {
                NavigationStack {
                    HomeView()
                }
            } else {
                OnboardingView()
            }
        }
        .task {
            // First-launch bootstrap: load the keystore, refresh
            // state, start SSE. Cheap to call even if already
            // bootstrapped — bootstrap() is idempotent.
            await wallet.bootstrap()
        }
    }
}

#Preview("No wallet (onboarding)") {
    ContentView()
}

#Preview("With wallet (home)") {
    let store = WalletStore(
        keystore: InMemoryWalletKeystore(),
        client: FederationDirectL2Client(
            try! FederationDirectClient(
                manifest: .bundledRegtest(),
                substrate: PlainHTTPSubstrate()
            )
        )
    )
    return ContentView()
        .environment(\.wallet, store)
        .task {
            try? await store.createWallet()
        }
}
