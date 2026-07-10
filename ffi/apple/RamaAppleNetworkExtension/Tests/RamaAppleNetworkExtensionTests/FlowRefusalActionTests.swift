import XCTest

@testable import RamaAppleNetworkExtension

/// The provider-side fail-open/closed decision for flows it declines for its own
/// reasons (unknown action / missing session over FFI). The full admission-cap
/// integration runs through `TcpFlowSession.start()`, which needs a real engine
/// session and so is only reachable in the FFI e2e suite; this pins the decision
/// logic + the `defaultFlowRefusalPassthrough` wiring.
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

    func testDefaultsToFailClosed() {
        defaultFlowRefusalPassthrough = false
        XCTAssertFalse(failOpenOnFlowRefusal("unit reason"), "default is Block (fail closed)")
    }

    func testFailsOpenWhenConfigured() {
        defaultFlowRefusalPassthrough = true
        XCTAssertTrue(failOpenOnFlowRefusal("unit reason"), "Passthrough opts into fail open")
    }
}
