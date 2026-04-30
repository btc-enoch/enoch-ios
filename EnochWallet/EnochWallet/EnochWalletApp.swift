//
//  EnochWalletApp.swift
//  EnochWallet
//
//  Thin @main shell. All real wallet code lives in the EnochCore +
//  EnochUI Swift packages (see ../../Package.swift). This file's
//  only job is to construct the WalletStore with the production
//  dependencies (Keychain-backed key storage, real edge URL) and
//  inject it into the environment so SwiftUI views downstream see
//  it via @Environment(\.wallet).
//

import SwiftUI
import EnochCore
import EnochUI

@main
struct EnochWalletApp: App {
    /// App-lifetime store. `@State` ownership keeps SwiftUI from
    /// dropping it on view rebuilds; the store itself is
    /// `@MainActor @Observable` so SwiftUI re-renders track its
    /// state automatically.
    @State private var wallet = WalletStore(
        keystore: KeychainWalletKeystore(),
        // Localhost edge — works in the iOS Simulator (ATS allows
        // plaintext to localhost). When testing on a physical
        // iPhone, swap this for the LAN/HTTPS URL once Caddy is
        // wired up (Phase 6).
        client: EdgeClient(baseURL: URL(string: "http://localhost:8081")!)
    )

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(\.wallet, wallet)
        }
    }
}
