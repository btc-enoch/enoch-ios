import XCTest
@testable import EnochCore

/// Lock the wire shape of `deposit_pending` + the wallet's
/// `DepositLifecycleStage` decoding (#158 Phase 4). The wallet
/// renders distinct UX for each operator-side state, so the contract
/// at this boundary needs to stay stable across both sides of the
/// wire — operator/events.DepositPendingData ↔ DepositPendingPayload.
final class DepositLifecycleTests: XCTestCase {

    // MARK: - DepositLifecycleStage.parse

    /// Each known wire string maps to its expected stage. Drift here
    /// (e.g. operator renames "sweeping" to "consolidating") would
    /// silently break the wallet UI without this test.
    func testStageParseKnownValues() {
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse("detected"), .detected)
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse("confirming"), .confirming)
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse("signature_pending"), .signaturePending)
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse("sweeping"), .sweeping)
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse("swept"), .swept)
    }

    /// Forward-compat: an operator emitting a future stage we haven't
    /// added yet must NOT crash the wallet. We degrade to `.detected`
    /// (the safest visible state).
    func testStageParseUnknownDegradesToDetected() {
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse("future_state"), .detected)
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse(""), .detected)
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse(nil), .detected)
    }

    /// Stage rank is monotonic and load-bearing — the wallet event
    /// handler ignores out-of-order events by comparing rank, so an
    /// off-by-one here would cause stages to skip or regress.
    func testStageRankIsMonotonic() {
        let stages: [WalletStore.DepositLifecycleStage] = [
            .detected, .confirming, .signaturePending, .sweeping, .swept,
        ]
        for (i, stage) in stages.enumerated() {
            XCTAssertEqual(stage.rank, i, "stage \(stage) rank")
        }
    }

    // MARK: - DepositPendingPayload wire decode

    /// Backward-compat: an older operator that doesn't yet emit the
    /// `state` field must still decode successfully. Wallet shows
    /// the row with stage = .detected (the safe fallback).
    func testPayloadDecodesWithoutStateField() throws {
        let json = """
        {
          "recipient": "enoch1ptest",
          "btc_txid": "aa00",
          "vout": 0,
          "amount_satoshi": 100000,
          "confirmations": 2,
          "bitcoin_height": 850000,
          "per_user": true
        }
        """.data(using: .utf8)!
        let payload = try JSONDecoder().decode(DepositPendingPayload.self, from: json)
        XCTAssertEqual(payload.btcTxID, "aa00")
        XCTAssertEqual(payload.confirmations, 2)
        XCTAssertNil(payload.state)
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse(payload.state), .detected)
    }

    /// New operator emits the `state` field; payload carries it
    /// through to the wallet's stage decode.
    func testPayloadDecodesWithStateField() throws {
        let json = """
        {
          "recipient": "enoch1ptest",
          "btc_txid": "bb01",
          "vout": 1,
          "amount_satoshi": 250000,
          "confirmations": 6,
          "bitcoin_height": 850100,
          "per_user": true,
          "state": "sweeping"
        }
        """.data(using: .utf8)!
        let payload = try JSONDecoder().decode(DepositPendingPayload.self, from: json)
        XCTAssertEqual(payload.state, "sweeping")
        XCTAssertEqual(WalletStore.DepositLifecycleStage.parse(payload.state), .sweeping)
    }
}
