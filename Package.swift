// swift-tools-version:5.9
//
// EnochCore — non-custodial wallet primitives for the Enoch L2.
//
// Target compatibility: iOS 17+ / macOS 14+. The library has no UI
// dependency so it builds and tests on any Swift platform; the
// SwiftUI app target (added later in this repo as EnochWallet.xcodeproj)
// imports EnochCore as a local package dependency.
//
// All wire-format work (bech32, secp256k1 sigs, tx serialization,
// sighash) lives here. Operator-facing HTTP/SSE clients live here
// too, against the enoch-edge `/v1/*` API.
import PackageDescription

let package = Package(
    name: "EnochCore",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "EnochCore",
            targets: ["EnochCore"]
        ),
    ],
    dependencies: [
        // ECDSA over secp256k1. Apple's CryptoKit doesn't include the
        // secp256k1 curve (P256K is intentionally omitted; it has
        // P-256 / NIST curves only), so this is the canonical Swift
        // wrapper around libsecp256k1. The library's `.signature(for:)`
        // produces low-s-normalized DER as Bitcoin Script requires.
        .package(url: "https://github.com/21-DOT-DEV/swift-secp256k1", from: "0.23.0"),
    ],
    targets: [
        .target(
            name: "EnochCore",
            dependencies: [
                .product(name: "P256K", package: "swift-secp256k1"),
            ]
        ),
        .testTarget(
            name: "EnochCoreTests",
            dependencies: ["EnochCore"]
        ),
    ]
)
