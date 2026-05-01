import XCTest
@testable import EnochCore

final class CoinSelectionTests: XCTestCase {
    private func u(_ amount: UInt64, txIdx: Int = 0, vout: UInt32 = 0, bonded: Bool = false) -> UTXOWire {
        UTXOWire(
            txHash: String(repeating: "0", count: 62) + String(format: "%02x", txIdx),
            vout: vout,
            amount: amount,
            scriptPubKey: "76a914" + String(repeating: "ab", count: 20) + "88ac",
            bondInfo: bonded ? BondInfo(operatorPubkey: "deadbeef", timeoutHeight: 100, kind: nil) : nil
        )
    }

    /// Empty set + target>0 → noSpendableUTXOs (not insufficientFunds —
    /// the latter is for "you have UTXOs but not enough"; here you
    /// have nothing at all, which is a different failure mode).
    func testEmptySetFailsCleanly() {
        XCTAssertThrowsError(try CoinSelection.select(utxos: [], target: 100, feePerTx: 1)) { err in
            XCTAssertEqual(err as? CoinSelectionError, .noSpendableUTXOs)
        }
    }

    /// All UTXOs bonded → same result as empty: there's nothing
    /// regular sends can spend.
    func testAllBondedFailsCleanly() {
        let utxos = [u(1_000_000, bonded: true), u(500_000, bonded: true)]
        XCTAssertThrowsError(try CoinSelection.select(utxos: utxos, target: 100, feePerTx: 1)) { err in
            XCTAssertEqual(err as? CoinSelectionError, .noSpendableUTXOs)
        }
    }

    /// Underfunded: clear, structured error so wallet UIs can render
    /// "you have X, need Y" rather than a generic failure.
    func testInsufficientFundsReportsExactNumbers() {
        let utxos = [u(500), u(300)]
        XCTAssertThrowsError(try CoinSelection.select(utxos: utxos, target: 1000, feePerTx: 100)) { err in
            XCTAssertEqual(err as? CoinSelectionError,
                           .insufficientFunds(have: 800, need: 1100))
        }
    }

    /// Single sufficient UTXO: pick exactly that one, change is the
    /// surplus minus fee. Sanity check — nothing fancy.
    func testSingleUTXOWithChange() throws {
        let utxos = [u(10_000)]
        let s = try CoinSelection.select(utxos: utxos, target: 1_000, feePerTx: 100)
        XCTAssertEqual(s.inputs.count, 1)
        XCTAssertEqual(s.selectedTotal, 10_000)
        XCTAssertEqual(s.feeSatoshi, 100)
        XCTAssertEqual(s.changeSatoshi, 8_900)
    }

    /// Largest-first ordering. With UTXOs of [1_000, 50_000, 10_000]
    /// and a target that fits in the largest, we pick exactly one —
    /// not two of the smaller ones. Catches a sort-direction bug.
    func testPicksLargestFirstWhenSufficient() throws {
        let utxos = [u(1_000, txIdx: 1), u(50_000, txIdx: 2), u(10_000, txIdx: 3)]
        let s = try CoinSelection.select(utxos: utxos, target: 5_000, feePerTx: 100)
        XCTAssertEqual(s.inputs.count, 1)
        XCTAssertEqual(s.inputs[0].amount, 50_000)
    }

    /// Multi-input accumulation when the largest single isn't enough.
    func testAccumulatesMultipleUTXOs() throws {
        let utxos = [u(2_000, txIdx: 1), u(3_000, txIdx: 2), u(1_500, txIdx: 3)]
        let s = try CoinSelection.select(utxos: utxos, target: 4_000, feePerTx: 100)
        // Largest-first: 3_000 picked. Still need 4_100 - 3_000 = 1_100.
        // Next largest: 2_000. 3_000 + 2_000 = 5_000 ≥ 4_100. Done.
        XCTAssertEqual(s.inputs.count, 2)
        XCTAssertEqual(Set(s.inputs.map(\.amount)), [3_000, 2_000])
        XCTAssertEqual(s.selectedTotal, 5_000)
        XCTAssertEqual(s.changeSatoshi, 900) // 5000 - 4000 - 100
    }

    /// Dust-into-fee absorption. With UTXO = 1_700, target = 1_000,
    /// fee = 100, surplus = 600 — below the default 546 threshold?
    /// Let's pick numbers where the surplus IS dust: surplus 100.
    /// UTXO 1200, target 1000, fee 100 → surplus 100 → change rolled
    /// into fee, no change output, fee becomes 200.
    func testDustChangeRolledIntoFee() throws {
        let utxos = [u(1_200)]
        let s = try CoinSelection.select(utxos: utxos, target: 1_000, feePerTx: 100, dustThreshold: 546)
        XCTAssertEqual(s.changeSatoshi, 0)
        XCTAssertEqual(s.feeSatoshi, 200) // 100 base + 100 absorbed dust
    }

    /// Bond UTXOs are silently skipped — the wallet must never
    /// accidentally spend slashing collateral on a regular send.
    func testBondUTXOsAreSkipped() throws {
        let utxos = [u(50_000, txIdx: 1, bonded: true), u(2_000, txIdx: 2)]
        let s = try CoinSelection.select(utxos: utxos, target: 1_000, feePerTx: 100)
        XCTAssertEqual(s.inputs.count, 1)
        XCTAssertEqual(s.inputs[0].amount, 2_000) // spendable one only
    }
}
