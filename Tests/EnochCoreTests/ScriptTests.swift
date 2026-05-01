import XCTest
@testable import EnochCore

final class ScriptTests: XCTestCase {
    /// Byte-level fixture for the P2PKH scriptPubKey shape. Any
    /// drift here = wallet emits non-standard outputs the operator
    /// will reject (or worse, accept and burn at withdrawal time).
    func testP2PKHScriptPubKeyShape() throws {
        let pkh = Data((1...20).map { UInt8($0) })
        let script = try Script.p2pkhScriptPubKey(pkh: pkh)

        var expected = Data()
        expected.append(contentsOf: [0x76, 0xA9, 0x14])
        expected.append(pkh)
        expected.append(contentsOf: [0x88, 0xAC])

        XCTAssertEqual(script, expected)
        XCTAssertEqual(script.count, 25)
    }

    /// Round-trips through the operator's own P2PKH extractor (we
    /// share the byte format) — proves the wallet's output and the
    /// operator's pkh lookup will agree on identity.
    func testP2PKHScriptPubKeyRoundTrip() throws {
        let pkh = Data(repeating: 0xAB, count: 20)
        let script = try Script.p2pkhScriptPubKey(pkh: pkh)
        // Operator-side extractor logic (mirrored here):
        // 25 bytes, prefix 76 a9 14, suffix 88 ac, payload at [3..23).
        XCTAssertEqual(script.prefix(3), Data([0x76, 0xA9, 0x14]))
        XCTAssertEqual(script.suffix(2), Data([0x88, 0xAC]))
        XCTAssertEqual(script.subdata(in: 3..<23), pkh)
    }

    func testP2PKHScriptPubKeyRejectsWrongLength() {
        XCTAssertThrowsError(try Script.p2pkhScriptPubKey(pkh: Data(repeating: 0, count: 19))) { err in
            XCTAssertEqual(err as? ScriptError, .wrongPKHLength(19))
        }
        XCTAssertThrowsError(try Script.p2pkhScriptPubKey(pkh: Data(repeating: 0, count: 21))) { err in
            XCTAssertEqual(err as? ScriptError, .wrongPKHLength(21))
        }
    }

    /// scriptSig shape: <push N><sig+sighash><push 33><pubkey>.
    /// Total = 1 + N + 1 + 33 = N + 35. For a typical 71-byte DER
    /// + 1 sighash byte signature, that's 107 bytes — the canonical
    /// Bitcoin P2PKH spend size.
    func testP2PKHScriptSigShape() throws {
        let sig = Data(repeating: 0xCD, count: 72) // 71-byte DER + 1 sighash byte
        let pub = Data([0x02] + Array(repeating: UInt8(0xEE), count: 32))
        let script = try Script.p2pkhScriptSig(sigWithSighashType: sig, compressedPubKey: pub)

        XCTAssertEqual(script[0], 72)                 // push 72 bytes (sig+sighash)
        XCTAssertEqual(script.subdata(in: 1..<73), sig)
        XCTAssertEqual(script[73], 0x21)              // push 33 bytes (pubkey)
        XCTAssertEqual(script.subdata(in: 74..<107), pub)
        XCTAssertEqual(script.count, 107)
    }

    func testP2PKHScriptSigRejectsWrongPubKeyLength() {
        let sig = Data(repeating: 0, count: 72)
        XCTAssertThrowsError(try Script.p2pkhScriptSig(sigWithSighashType: sig,
                                                       compressedPubKey: Data(repeating: 0, count: 32))) { err in
            XCTAssertEqual(err as? ScriptError, .wrongCompressedPubKeyLength(32))
        }
    }

    func testP2PKHScriptSigRejectsOversizedSigPush() {
        let pub = Data([0x02] + Array(repeating: UInt8(0), count: 32))
        XCTAssertThrowsError(try Script.p2pkhScriptSig(sigWithSighashType: Data(repeating: 0, count: 76),
                                                       compressedPubKey: pub)) { err in
            XCTAssertEqual(err as? ScriptError, .sigPushTooLong(76))
        }
    }
}
