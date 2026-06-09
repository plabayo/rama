import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Contract tests for `NwConnectionLike.cancelAndDetach`.
///
/// Production NWConnection's `stateUpdateHandler` retains a closure
/// graph that transitively pins the kernel `NEAppProxyTCPFlow`, the
/// per-flow `DispatchQueue`, and the post-ready teardown closure.
/// Apple's framework does NOT release that graph promptly on `cancel()`
/// — the kernel NECP slot is destroyed but the userland `NWConnection`
/// object keeps polling for path updates because *we* still hold a
/// strong reference via the attached handler. The leak surfaces in
/// production as `Endpoint.addressStorage` / `__NWPath` /
/// `MutableParametersStorage` growing without bound under churn and
/// `nw_path_necp_check_for_updates Failed (22 EINVAL)` storms in the
/// system log.
///
/// `cancelAndDetach` nulls the handler before calling `cancel()` so
/// the closure graph is dropped immediately. These tests pin the
/// contract: handler observably nil, cancel observably called, in
/// that order.
final class NwConnectionExtensionTests: XCTestCase {
    /// `cancelAndDetach` MUST null out BOTH `stateUpdateHandler` and
    /// `viabilityUpdateHandler` AND invoke `cancel()` exactly once. Order
    /// matters: dropping the handlers must precede the cancel call so the
    /// framework's final `.cancelled` notification has no recipient (and
    /// can't perpetuate the retain chain). Both handlers capture the same
    /// per-flow graph, so leaving EITHER attached re-leaks it.
    func testCancelAndDetachNullsHandlersAndCancelsOnce() {
        let conn = MockNwConnection()
        conn.stateUpdateHandler = { _ in XCTFail("state handler must not fire after detach") }
        conn.viabilityUpdateHandler = { _ in XCTFail("viability handler must not fire after detach") }
        XCTAssertNotNil(conn.stateUpdateHandler, "precondition: state handler attached")
        XCTAssertNotNil(conn.viabilityUpdateHandler, "precondition: viability handler attached")
        XCTAssertEqual(conn.cancelCount, 0, "precondition: not yet cancelled")

        conn.cancelAndDetach()

        XCTAssertNil(conn.stateUpdateHandler, "state handler must be nil after detach")
        XCTAssertNil(conn.viabilityUpdateHandler, "viability handler must be nil after detach")
        XCTAssertEqual(conn.cancelCount, 1, "cancel must be invoked exactly once")
    }

    /// Calling `cancelAndDetach` twice MUST be observably idempotent
    /// from the caller's POV — yes, the underlying mock counts two
    /// cancels (we don't add an "already-cancelled" gate in this
    /// helper; the underlying NWConnection contract says `cancel()` is
    /// idempotent), but the handler stays nil and no exception is
    /// thrown. Important: the production "is already cancelled,
    /// ignoring cancel" log noise comes from racing teardown PATHS,
    /// not from the same path running twice — that's a separate fix
    /// (a sticky `cancelled` flag at the teardown-orchestration
    /// layer). This test exists so a future refactor that adds
    /// guarding here doesn't silently break the (acceptable) "called
    /// twice" path.
    func testCancelAndDetachIsSafeToCallTwice() {
        let conn = MockNwConnection()
        conn.stateUpdateHandler = { _ in }

        conn.cancelAndDetach()
        conn.cancelAndDetach()

        XCTAssertNil(conn.stateUpdateHandler)
        XCTAssertEqual(
            conn.cancelCount, 2,
            "underlying cancel() is documented idempotent; this test pins the helper does not swallow the second call",
        )
    }

    /// `cancelAndDetach` must not require a handler to have been set
    /// — it's the default state of every fresh NWConnection until the
    /// engine attaches one. Catches a regression where the helper
    /// adds e.g. a precondition or force-unwrap on the handler.
    func testCancelAndDetachWorksWithNoHandlerAttached() {
        let conn = MockNwConnection()
        XCTAssertNil(conn.stateUpdateHandler)

        conn.cancelAndDetach()

        XCTAssertNil(conn.stateUpdateHandler)
        XCTAssertEqual(conn.cancelCount, 1)
    }
}
