import XCTest
@testable import EnochCore

final class EnochCoreTests: XCTestCase {
    // Smoke test: confirms the package builds and the test target
    // links against EnochCore. Real coverage lives in per-module
    // test files (Bech32Tests, SighashTests, etc.) added as each
    // primitive lands.
    func testVersionExposed() {
        XCTAssertFalse(EnochCore.version.isEmpty)
    }
}
