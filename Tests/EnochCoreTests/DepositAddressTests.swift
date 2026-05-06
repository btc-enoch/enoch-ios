import XCTest
@testable import EnochCore

/// Per-user Taproot deposit-address derivation.
///
/// Cross-language parity with the Go derivation in
/// federation/depositaddr (and the Python derivation in
/// bridge/enoch/shared/enoch_address.py). Same vector pinned on all
/// sides — drift on any side fails one of the test suites loud.
///
/// These vectors track the two-leaf tap-tree from
/// spec/deposit_address.md: leaf A = bridge multisig (constant),
/// leaf B = `<R> CSV DROP <user_xonly> CHECKSIG`. Per-user
/// uniqueness now lives in leaf B's `user_xonly` push, so the salt-
/// and-OP_DROP prologue from the previous shape is gone.
final class DepositAddressTests: XCTestCase {
    /// Synthetic 3-of-5 multisig redeem script with deterministic
    /// pubkeys (0x02 || 0x11..0x15 repeating). Same bytes
    /// federation/depositaddr/parity.go uses.
    private static let bridgeRedeemHex =
        "53" +
        "2102" + String(repeating: "11", count: 32) +
        "2102" + String(repeating: "12", count: 32) +
        "2102" + String(repeating: "13", count: 32) +
        "2102" + String(repeating: "14", count: 32) +
        "2102" + String(repeating: "15", count: 32) +
        "55ae"

    /// Synthetic 32-byte x-only L2 pubkey. Same bytes a real wallet
    /// would expose via its `enoch1p...` Taproot address.
    private static let l2XOnly = Data(repeating: 0x55, count: 32)

    /// Reclaim relative-timelock for the parity fixture (regtest-
    /// style — small enough to test reclaim spends quickly). Mainnet
    /// uses 1008 (~1 week).
    private static let reclaimR: UInt32 = 10

    /// PARITY VECTOR — bytes computed by the Go derivation
    /// (federation/depositaddr) on the inputs above. Must match
    /// exactly; drift here means the wallet would compute a different
    /// deposit address than the operator's registry, which is silently
    /// fund-losing.
    private static let expectedOutputKeyHex =
        "9b32e7bc412374bb085e1cdca711213a7d81c35a3946533ed09193f602f4d68b"
    private static let expectedRegtestAddr =
        "bcrt1pnvew00zpyd6tkzz7rnw2wyfp8f7crs6689r9x0ksjxflvqh5669sm45ete"
    private static let expectedMainnetAddr =
        "bc1pnvew00zpyd6tkzz7rnw2wyfp8f7crs6689r9x0ksjxflvqh5669spygsyv"

    func testOutputKeyMatchesParityVector() throws {
        let redeem = try Data(hex: Self.bridgeRedeemHex)
        let outputKey = try DepositAddress.outputKey(
            l2XOnly: Self.l2XOnly,
            bridgeRedeemScript: redeem,
            reclaimR: Self.reclaimR
        )
        XCTAssertEqual(outputKey.count, 32)
        XCTAssertEqual(
            outputKey.map { String(format: "%02x", $0) }.joined(),
            Self.expectedOutputKeyHex,
            "Swift output_key must match Go's bytes-for-bytes — drift here means the wallet would compute a different deposit address than the operator's registry"
        )
    }

    func testRegtestAddressMatchesParityVector() throws {
        let addr = try DepositAddress.derive(
            l2XOnly: Self.l2XOnly,
            bridgeRedeemScriptHex: Self.bridgeRedeemHex,
            reclaimR: Self.reclaimR,
            network: .regtest
        )
        XCTAssertEqual(addr, Self.expectedRegtestAddr)
        XCTAssertTrue(addr.hasPrefix("bcrt1p"), "regtest Taproot addresses start with bcrt1p")
    }

    func testMainnetAddressMatchesParityVector() throws {
        let addr = try DepositAddress.derive(
            l2XOnly: Self.l2XOnly,
            bridgeRedeemScriptHex: Self.bridgeRedeemHex,
            reclaimR: Self.reclaimR,
            network: .mainnet
        )
        XCTAssertEqual(addr, Self.expectedMainnetAddr)
        XCTAssertTrue(addr.hasPrefix("bc1p"), "mainnet Taproot addresses start with bc1p")
    }

    /// Different L2 pubkeys must produce different deposit addresses.
    /// Catches a regression where the user_xonly inside leaf B isn't
    /// being mixed into the merkle root.
    func testDifferentPubkeysProduceDifferentAddresses() throws {
        let redeem = try Data(hex: Self.bridgeRedeemHex)
        let keyA = try DepositAddress.outputKey(
            l2XOnly: Self.l2XOnly,
            bridgeRedeemScript: redeem,
            reclaimR: Self.reclaimR
        )
        let keyB = try DepositAddress.outputKey(
            l2XOnly: Data(repeating: 0x66, count: 32),
            bridgeRedeemScript: redeem,
            reclaimR: Self.reclaimR
        )
        XCTAssertNotEqual(keyA, keyB, "user_xonly inside leaf B must affect the merkle root")
    }

    /// Sanity: changing R changes the reclaim leaf bytes and therefore
    /// the output key. A misconfigured wallet that uses a different R
    /// from the operator must fail loudly (i.e. produce a different
    /// address than what the operator scans for) rather than silently
    /// route funds to an unscanned address.
    func testDifferentRProduceDifferentAddresses() throws {
        let redeem = try Data(hex: Self.bridgeRedeemHex)
        let keyA = try DepositAddress.outputKey(
            l2XOnly: Self.l2XOnly,
            bridgeRedeemScript: redeem,
            reclaimR: Self.reclaimR
        )
        let keyB = try DepositAddress.outputKey(
            l2XOnly: Self.l2XOnly,
            bridgeRedeemScript: redeem,
            reclaimR: Self.reclaimR + 1
        )
        XCTAssertNotEqual(keyA, keyB, "changing R must change the deposit address")
    }

    /// Wrong-length pubkey is rejected with a typed error rather than
    /// silently producing an address from truncated bytes.
    func testRejectsInvalidPubkeyLength() throws {
        let redeem = try Data(hex: Self.bridgeRedeemHex)
        var compressed = Data([0x02])
        compressed.append(Data(repeating: 0x55, count: 32))
        XCTAssertThrowsError(
            try DepositAddress.outputKey(
                l2XOnly: compressed,
                bridgeRedeemScript: redeem,
                reclaimR: Self.reclaimR
            )
        ) { err in
            guard case DepositAddress.Error.invalidL2XOnly = err else {
                return XCTFail("wrong error: \(err)")
            }
        }
    }
}
