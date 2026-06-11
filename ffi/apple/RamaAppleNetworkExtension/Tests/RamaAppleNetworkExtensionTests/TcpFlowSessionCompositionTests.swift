import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Layer-2 scenarios for `TcpFlowSession`: chain multiple
/// state-machine transitions and assert end-state. These are
/// where the cross-closure interaction bugs would manifest
/// (write-after-close, double-cancel, stale-callback-after-
/// teardown) — they need to be cheap to run so they live next
/// to the phase tests instead of in the engine integration suite.
final class TcpFlowSessionCompositionTests: XCTestCase {

    private final class Fixture {
        let core: TransparentProxyCore
        let flow: MockTcpFlow
        let conn: MockNwConnection
        let session: TcpFlowSession<MockTcpFlow>

        init() {
            self.core = TransparentProxyCore()
            self.flow = MockTcpFlow()
            self.conn = MockNwConnection()
            let meta = RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 1, remoteHost: "example.com", remotePort: 443,
                localHost: nil, localPort: 0,
                sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: nil,
                sourceAppAuditToken: nil, sourceAppPid: 4242)
            self.session = TcpFlowSession(core: core, flow: flow, meta: meta)
            self.session.ctx.connection = self.conn
        }
    }

    /// Connect-timeout-then-late-`.ready`: timeout wins, the late
    /// `.ready` callback must be a no-op (the connection is already
    /// cancelled and the session torn down).
    func testConnectTimeoutThenLateReadyIsIdempotent() {
        let fx = Fixture()
        // Simulate the timeout fire path directly.
        fx.session.ctx.applyConnectTimeout()
        XCTAssertEqual(fx.conn.cancelCount, 1)
        XCTAssertTrue(fx.session.ctx.isDone)

        // Now a stale .ready lands.
        fx.session.handleEgressReady(connection: fx.conn)

        // `egressReady` flips locally (the session has no idea the
        // teardown ran), but the stale .ready adds no extra cancel and no
        // extra flow close: the connect-timeout already rejected the
        // claimed flow (closeReadCallCount == 1), and the late .ready is a
        // no-op because the session lacks a sessionHandle.
        XCTAssertTrue(fx.session.egressReady)
        XCTAssertEqual(fx.conn.cancelCount, 1, "no double-cancel from stale .ready")
        XCTAssertEqual(
            fx.flow.closeReadCallCount, 1, "connect timeout rejected the flow; stale .ready adds nothing")
    }

    /// `.ready` → `.waiting` → `.ready` recovery clears the
    /// tolerance timer; flow stays untouched.
    func testWaitingThenReadyRecoveryClearsTolerance() {
        let fx = Fixture()
        fx.session.egressReady = true

        // .waiting arms tolerance.
        fx.session.handleEgressWaiting(nil)
        XCTAssertNotNil(fx.session.waitingWork)
        let tolerance = fx.session.waitingWork

        // Recovery .ready cancels tolerance.
        fx.session.handleEgressReady(connection: fx.conn)
        XCTAssertNil(fx.session.waitingWork, "recovery clears tolerance")
        XCTAssertTrue(tolerance?.isCancelled ?? false, "tolerance timer was invalidated")
        XCTAssertEqual(fx.flow.closeReadCallCount, 0, "flow untouched by recovery")
        XCTAssertEqual(fx.conn.cancelCount, 0)
    }

    /// `.ready` → `.waiting` → `.failed` (post-ready) triggers the
    /// full teardown exactly once; the tolerance timer is cancelled
    /// before it fires.
    func testWaitingThenFailedRunsFullTeardownOnce() {
        let fx = Fixture()
        fx.session.egressReady = true
        fx.session.handleEgressWaiting(nil)
        let tolerance = fx.session.waitingWork
        XCTAssertNotNil(tolerance)

        fx.session.handleEgressFailed(nil)

        XCTAssertTrue(fx.session.ctx.isDone)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1, "post-ready failure closed the flow")
        XCTAssertEqual(fx.conn.cancelCount, 1)
        XCTAssertTrue(tolerance?.isCancelled ?? false, "tolerance timer cancelled by failure")
    }

    /// Two `.failed` state callbacks in a row — only the first
    /// runs teardown; the second is a no-op via the sticky `done`
    /// flag on `TcpFlowContext`.
    func testTwoFailedCallbacksOnlyFirstRunsTeardown() {
        let fx = Fixture()
        fx.session.egressReady = true
        fx.session.handleEgressFailed(nil)
        XCTAssertEqual(fx.conn.cancelCount, 1)

        fx.session.handleEgressFailed(nil)
        XCTAssertEqual(fx.conn.cancelCount, 1, "second failure must be a no-op")
        XCTAssertEqual(fx.flow.closeReadCallCount, 1)
    }

    /// `.cancelled` after a tolerance timer was armed (e.g. due to
    /// `.waiting`) invalidates the timer.
    func testCancelledClearsArmedTolerance() {
        let fx = Fixture()
        fx.session.egressReady = true
        fx.session.handleEgressWaiting(nil)
        XCTAssertNotNil(fx.session.waitingWork)
        let tolerance = fx.session.waitingWork

        fx.session.handleEgressCancelled()

        XCTAssertNil(fx.session.waitingWork)
        XCTAssertTrue(tolerance?.isCancelled ?? false)
    }

    /// Apply two different teardown variants in sequence — only
    /// the first effective; idempotency holds across variants.
    func testTwoTeardownVariantsAreIdempotent() {
        let fx = Fixture()
        fx.session.ctx.applyConnectTimeout()
        XCTAssertEqual(fx.conn.cancelCount, 1)

        // Pretending a post-ready failure raced in.
        fx.session.egressReady = true
        fx.session.handleEgressFailed(nil)

        XCTAssertEqual(fx.conn.cancelCount, 1, "second teardown variant is a no-op")
        XCTAssertEqual(
            fx.flow.closeReadCallCount, 1,
            "first teardown (pre-open) rejected the flow once; the second variant is a no-op")
    }
}
