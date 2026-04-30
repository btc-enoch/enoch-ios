# enoch-ios

Native iOS wallet for [Enoch](../enoch) — Bitcoin's current account.
Non-custodial: keys live in the iOS Secure Enclave / Keychain, gated
by Face ID. Talks to the [`enoch-edge`](../enoch-edge) `/v1/*` API
for read state, transaction submit, and the SSE event stream.

## Layout

```
enoch-ios/
├── Package.swift              # SPM manifest — declares EnochCore
├── Sources/EnochCore/         # protocol primitives (bech32, secp256k1,
│                              # tx serialization, sighash, edge client)
├── Tests/EnochCoreTests/      # `swift test` — runs without Xcode
└── EnochWallet.xcodeproj/     # iOS app target — added when UI work begins
```

`EnochCore` is platform-agnostic and has no UIKit / SwiftUI deps. The
SwiftUI app target depends on it as a local SPM package.

## Build / test

Host toolchain (Xcode + system Swift). No Docker path for iOS.

```bash
swift build
swift test
```

## Status

Phase 2 (SPM scaffold) — in progress. Module-by-module port follows:
bech32, secp256k1, transaction wire format, sighash, then the
edge HTTP / SSE client.
