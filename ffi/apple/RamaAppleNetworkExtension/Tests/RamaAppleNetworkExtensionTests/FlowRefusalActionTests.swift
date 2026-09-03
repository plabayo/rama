import XCTest

@testable import RamaAppleNetworkExtension

/// The provider-side fail-open/closed decision for flows it declines for its own
/// reasons (start cap / breaker, or a missing session over FFI). The full
/// admission-cap integration runs through `TcpFlowSession.start()`, which needs
/// a real engine session and so is only reachable in the FFI e2e suite; this
/// pins the decision logic + the `defaultFlowRefusalPassthrough` wiring.
final class FlowRefusalActionTests: XCTestCase {
    private var saved = false

    override func setUp() {
        super.setUp()
        saved = defaultFlowRefusalPassthrough
    }

    override func tearDown() {
        defaultFlowRefusalPassthrough = saved
        super.tearDown()
    }

    /// Rust's `TransparentProxyConfig` is authoritative at runtime; the Swift
    /// global is the fallback for tests and startup-failure paths, and must
    /// agree with the Rust default so the two can never disagree on a path
    /// that skipped `applyRuntimeConfig`.
    func testSwiftFallbackDefaultIsFailOpenLikeRust() {
        XCTAssertTrue(saved, "Swift fallback must mirror FlowRefusalAction's Passthrough default")
    }

    func testFailsOpenWhenPassthrough() {
        defaultFlowRefusalPassthrough = true
        XCTAssertTrue(failOpenOnFlowRefusal("unit reason"), "Passthrough fails open")
    }

    func testBlocksWhenConfiguredClosed() {
        defaultFlowRefusalPassthrough = false
        XCTAssertFalse(failOpenOnFlowRefusal("unit reason"), "Block opts into fail closed")
    }
}
