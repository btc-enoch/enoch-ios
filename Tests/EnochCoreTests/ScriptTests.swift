import XCTest
@testable import EnochCore

final class ScriptTests: XCTestCase {
    /// OP_RETURN burn output exact bytes. The operator parses
    /// `0x6a <push N> "ENOCH:WD:<addr>"` with the strict single-byte
    /// push form — so the assembled bytes have to match that
    /// pattern character-for-character.
    func testOpReturnBurnShape() throws {
        let addr = "bcrt1qabc"
        let script = try Script.opReturnBurn(bitcoinAddress: addr)
        let payload = "ENOCH:WD:" + addr
        var expected = Data()
        expected.append(0x6A)
        expected.append(UInt8(payload.utf8.count))
        expected.append(Data(payload.utf8))
        XCTAssertEqual(script, expected)
    }

    /// Round-trip through the operator's parse rule (mirrored
    /// inline): prefix matches, push length matches, payload after
    /// "ENOCH:WD:" equals the address we passed in.
    func testOpReturnBurnRoundTrip() throws {
        let addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        let script = try Script.opReturnBurn(bitcoinAddress: addr)
        XCTAssertEqual(script[0], 0x6A)
        let pushLen = Int(script[1])
        XCTAssertEqual(pushLen, 9 + addr.utf8.count)
        let payload = String(data: script.subdata(in: 2..<(2 + pushLen)), encoding: .utf8)
        XCTAssertEqual(payload, "ENOCH:WD:" + addr)
    }

    /// 67-char address → 76-byte payload, just over the 75-byte
    /// single-push ceiling the operator enforces.
    func testOpReturnBurnRejectsOversizedAddress() {
        let tooLong = String(repeating: "a", count: 67)
        XCTAssertThrowsError(try Script.opReturnBurn(bitcoinAddress: tooLong)) { err in
            XCTAssertEqual(err as? ScriptError, .burnPayloadTooLong(76))
        }
    }

    /// P2TR scriptPubKey shape: OP_1 (0x51) + push 32 bytes (0x20)
    /// + 32-byte x-only output key. Always exactly 34 bytes.
    /// Routes through EnochCrypto's scriptpubkeyP2tr (rust-bitcoin
    /// source of truth per #191 Phase 4); same bytes the bondscript
    /// + operator-side BuildP2TRScript emit.
    func testTaprootScriptPubKeyShape() throws {
        let outputKey = Data((1...32).map { UInt8($0) })
        let script = try Script.taprootScriptPubKey(outputKey: outputKey)

        var expected = Data()
        expected.append(0x51)
        expected.append(0x20)
        expected.append(outputKey)

        XCTAssertEqual(script, expected)
        XCTAssertEqual(script.count, 34)
    }

    func testTaprootScriptPubKeyRejectsWrongLength() {
        XCTAssertThrowsError(try Script.taprootScriptPubKey(outputKey: Data(repeating: 0, count: 31))) { err in
            XCTAssertEqual(err as? ScriptError, .wrongOutputKeyLength(31))
        }
        XCTAssertThrowsError(try Script.taprootScriptPubKey(outputKey: Data(repeating: 0, count: 33))) { err in
            XCTAssertEqual(err as? ScriptError, .wrongOutputKeyLength(33))
        }
    }
}
