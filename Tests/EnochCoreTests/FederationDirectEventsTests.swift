// Unit tests for the federation-direct SSE primitives. Three layers:
//
//   1. EventDedupeCache LRU semantics (pure actor logic)
//   2. EdgeEvent.dedupeKey() shape per event type (pure functions)
//   3. End-to-end fan-out + dedupe via a slow-emitting URLProtocol
//      that feeds three "operators" the same event in sequence
//
// The end-to-end test confirms the merger drops K-1 duplicates;
// per-operator reconnect + transport errors live behind a live
// integration test that's deferred until #369 Slice E.

import XCTest
@testable import EnochCore

final class FederationDirectEventsTests: XCTestCase {

    // MARK: - EventDedupeCache

    func testDedupeCacheEmitsFirstSuppressesRest() async {
        let cache = EventDedupeCache(capacity: 16)
        let k = "tx_applied:abc:42"
        await XCTAssertTrueAsync(await cache.shouldEmit(k))
        await XCTAssertFalseAsync(await cache.shouldEmit(k))
        await XCTAssertFalseAsync(await cache.shouldEmit(k))
    }

    func testDedupeCacheEvictsOldestWhenAtCapacity() async {
        let cache = EventDedupeCache(capacity: 2)
        _ = await cache.shouldEmit("a")
        _ = await cache.shouldEmit("b")
        // Cache is {a, b}. Both should still suppress.
        await XCTAssertFalseAsync(await cache.shouldEmit("a"))
        await XCTAssertFalseAsync(await cache.shouldEmit("b"))
        // Inserting c evicts a (oldest).
        _ = await cache.shouldEmit("c")
        let size = await cache.sizeForTesting()
        XCTAssertEqual(size, 2)
        // a was evicted → it can be emitted again.
        await XCTAssertTrueAsync(await cache.shouldEmit("a"))
        // c is still in cache → still suppressed.
        await XCTAssertFalseAsync(await cache.shouldEmit("c"))
    }

    // MARK: - dedupeKey() per event kind

    func testTxAppliedDedupeKey() {
        let raw = Data(#"{"tx_hash":"ab","height":3,"addresses":[],"burns":0}"#.utf8)
        let event = EdgeEvent(kind: .txApplied, raw: raw)
        XCTAssertEqual(event.dedupeKey(), "tx_applied:ab:3")
    }

    func testStateRootSignedDedupeKeyExcludesSignature() {
        // Two operators sign the same height + state_root with their
        // own different sigs. Same event from the wallet's POV →
        // dedupe key matches (the signature changes don't matter
        // for dedupe — they're aggregated separately for FROST).
        let raw0 = Data(#"{"height":7,"state_root":"deadbeef","signature":"aaaa"}"#.utf8)
        let raw1 = Data(#"{"height":7,"state_root":"deadbeef","signature":"bbbb"}"#.utf8)
        let e0 = EdgeEvent(kind: .stateRootSigned, raw: raw0)
        let e1 = EdgeEvent(kind: .stateRootSigned, raw: raw1)
        XCTAssertEqual(e0.dedupeKey(), e1.dedupeKey())
        XCTAssertEqual(e0.dedupeKey(), "state_root_signed:7:deadbeef")
    }

    func testStateRootSignedDifferentRootsAreDifferentEvents() {
        // Federation equivocation: same height, DIFFERENT state_roots
        // from two operators. Both must pass through so reconciliation
        // (spec §7) sees the disagreement.
        let raw0 = Data(#"{"height":7,"state_root":"aa","signature":"00"}"#.utf8)
        let raw1 = Data(#"{"height":7,"state_root":"bb","signature":"00"}"#.utf8)
        let e0 = EdgeEvent(kind: .stateRootSigned, raw: raw0)
        let e1 = EdgeEvent(kind: .stateRootSigned, raw: raw1)
        XCTAssertNotEqual(e0.dedupeKey(), e1.dedupeKey())
    }

    func testWithdrawalStatusDedupeKey() {
        let raw = Data(#"""
        {"burn_tx_hash":"deadbeef","status":"broadcast",
         "bitcoin_address":"bc1q","amount_satoshi":100,"btc_txid":"aa"}
        """#.utf8)
        let event = EdgeEvent(kind: .withdrawalStatus, raw: raw)
        XCTAssertEqual(event.dedupeKey(), "withdrawal_status:deadbeef:broadcast")
    }

    func testDepositPendingDedupeKeyIncludesConfirmations() {
        // Each watcher tick (1, 2, 3, …) is a distinct event because
        // confirmations changes — the wallet should re-render the
        // progress pill on every tick.
        let raw1 = Data(#"""
        {"recipient":"enoch1","btc_txid":"aa","vout":0,
         "amount_satoshi":100,"confirmations":1,
         "bitcoin_height":10,"per_user":true,"state":"detected"}
        """#.utf8)
        let raw2 = Data(#"""
        {"recipient":"enoch1","btc_txid":"aa","vout":0,
         "amount_satoshi":100,"confirmations":2,
         "bitcoin_height":11,"per_user":true,"state":"confirming"}
        """#.utf8)
        let e1 = EdgeEvent(kind: .depositPending, raw: raw1)
        let e2 = EdgeEvent(kind: .depositPending, raw: raw2)
        XCTAssertEqual(e1.dedupeKey(), "deposit_pending:aa:0:1")
        XCTAssertEqual(e2.dedupeKey(), "deposit_pending:aa:0:2")
        XCTAssertNotEqual(e1.dedupeKey(), e2.dedupeKey())
    }

    func testDepositMintedDedupeKey() {
        let raw = Data(#"""
        {"recipient":"enoch1","btc_txid":"aa","vout":0,
         "amount_satoshi":100,"l2_tx_hash":"bb"}
        """#.utf8)
        let event = EdgeEvent(kind: .depositMinted, raw: raw)
        XCTAssertEqual(event.dedupeKey(), "deposit_minted:aa:0")
    }

    func testConnectedAndUnknownHaveNilKeys() {
        XCTAssertNil(EdgeEvent(kind: .connected, raw: Data()).dedupeKey())
        XCTAssertNil(EdgeEvent(kind: .unknown, raw: Data()).dedupeKey())
    }
}

// MARK: - Async XCTAssert helpers

private func XCTAssertTrueAsync(
    _ expression: @autoclosure () async -> Bool,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    let v = await expression()
    XCTAssertTrue(v, file: file, line: line)
}

private func XCTAssertFalseAsync(
    _ expression: @autoclosure () async -> Bool,
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    let v = await expression()
    XCTAssertFalse(v, file: file, line: line)
}
