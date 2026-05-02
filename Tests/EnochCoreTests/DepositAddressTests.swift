import XCTest
@testable import EnochCore

/// Per-user Taproot deposit-address derivation (#108).
///
/// Cross-language parity with the Python derivation in
/// bridge/enoch/shared/enoch_address.py::deposit_address. Same vector
/// pinned on both sides — drift on either side fails one of the two
/// test suites loud.
final class DepositAddressTests: XCTestCase {
    /// Synthetic 3-of-5 multisig redeem script with deterministic
    /// pubkeys (0x02 || 0x11..0x15 repeating). Lets the test pin
    /// exact bytes without depending on init.py-generated keys.
    private static let bridgeRedeemHex =
        "53" +
        "2102" + String(repeating: "11", count: 32) +
        "2102" + String(repeating: "12", count: 32) +
        "2102" + String(repeating: "13", count: 32) +
        "2102" + String(repeating: "14", count: 32) +
        "2102" + String(repeating: "15", count: 32) +
        "55ae"

    /// Synthetic L2 pubkey: 0x02 || 0x55×32. Even-Y, deterministic.
    private static let l2Pubkey: Data = {
        var d = Data([0x02])
        d.append(Data(repeating: 0x55, count: 32))
        return d
    }()

    /// PARITY VECTOR — bytes computed by the Python derivation
    /// (deposit_output_key) on the inputs above. Must match exactly;
    /// any drift here means the operator's view of "where the user
    /// said to send funds" differs from the wallet's view, which is
    /// silently fund-losing.
    private static let expectedOutputKeyHex =
        "9e1aa512595a8dccec8d25c99c7c48a839a6b3248bc59a1f1800ab93397d8601"
    private static let expectedRegtestAddr =
        "bcrt1pncd22yjet2xuemydyhyeclzg4qu6dvey30ze58ccqz4exwtascqsklpte2"
    private static let expectedMainnetAddr =
        "bc1pncd22yjet2xuemydyhyeclzg4qu6dvey30ze58ccqz4exwtascqsvwazkl"

    func testOutputKeyMatchesPythonVector() throws {
        let redeem = try Data(hex: Self.bridgeRedeemHex)
        let outputKey = try DepositAddress.outputKey(
            l2Pubkey: Self.l2Pubkey,
            bridgeRedeemScript: redeem
        )
        XCTAssertEqual(outputKey.count, 32)
        XCTAssertEqual(
            outputKey.map { String(format: "%02x", $0) }.joined(),
            Self.expectedOutputKeyHex,
            "Swift output_key must match Python's bytes-for-bytes — drift here means the wallet would compute a different deposit address than the operator's registry"
        )
    }

    func testRegtestAddressMatchesPythonVector() throws {
        let addr = try DepositAddress.derive(
            l2Pubkey: Self.l2Pubkey,
            bridgeRedeemScriptHex: Self.bridgeRedeemHex,
            network: .regtest
        )
        XCTAssertEqual(addr, Self.expectedRegtestAddr)
        XCTAssertTrue(addr.hasPrefix("bcrt1p"), "regtest Taproot addresses start with bcrt1p")
    }

    func testMainnetAddressMatchesPythonVector() throws {
        let addr = try DepositAddress.derive(
            l2Pubkey: Self.l2Pubkey,
            bridgeRedeemScriptHex: Self.bridgeRedeemHex,
            network: .mainnet
        )
        XCTAssertEqual(addr, Self.expectedMainnetAddr)
        XCTAssertTrue(addr.hasPrefix("bc1p"), "mainnet Taproot addresses start with bc1p")
    }

    /// Different L2 pubkeys must produce different deposit addresses.
    /// Catches a regression where the per-user salt isn't actually
    /// being mixed into the merkle root.
    func testDifferentPubkeysProduceDifferentAddresses() throws {
        let redeem = try Data(hex: Self.bridgeRedeemHex)
        let pubA = Self.l2Pubkey
        var pubB = Data([0x02])
        pubB.append(Data(repeating: 0x66, count: 32))

        let keyA = try DepositAddress.outputKey(l2Pubkey: pubA, bridgeRedeemScript: redeem)
        let keyB = try DepositAddress.outputKey(l2Pubkey: pubB, bridgeRedeemScript: redeem)
        XCTAssertNotEqual(keyA, keyB, "per-user salt must affect the merkle root")
    }

    /// Wrong-length pubkey is rejected with a typed error rather than
    /// silently producing an address from truncated bytes.
    func testRejectsInvalidPubkeyLength() throws {
        let redeem = try Data(hex: Self.bridgeRedeemHex)
        XCTAssertThrowsError(
            try DepositAddress.outputKey(l2Pubkey: Data(repeating: 0x02, count: 32), bridgeRedeemScript: redeem)
        ) { err in
            guard case DepositAddress.Error.invalidL2Pubkey = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }
}
