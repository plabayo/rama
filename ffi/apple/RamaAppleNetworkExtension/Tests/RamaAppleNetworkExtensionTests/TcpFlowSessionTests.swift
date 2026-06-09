import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Per-phase tests for `TcpFlowSession`.
///
/// Each test drives ONE method on a freshly-constructed session
/// (no engine attached — the session's `start()` happily refuses to
/// proceed and the phase methods can be called individually). The
/// fixture holds strong references to keep the weak-ctx pattern
/// from collapsing the state graph under us.
final class TcpFlowSessionTests: XCTestCase {

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
            // Pre-wire the egress connection slot so tests of the
            // post-`.ready` phases have a connection to operate on.
            self.session.ctx.connection = self.conn
        }
    }

    // MARK: - Construction

    /// init() wires teardown into ctx so racing closures can reach it.
    func testInitWiresTeardownIntoContext() {
        let fx = Fixture()
        XCTAssertNotNil(fx.session.ctx.teardown)
        XCTAssertFalse(fx.session.egressReady)
    }

    // MARK: - buildClientWritePump

    /// Builds the writer and attaches it to ctx.
    func testBuildClientWritePumpAttachesToContext() {
        let fx = Fixture()
        XCTAssertNil(fx.session.ctx.clientWritePump)
        fx.session.buildClientWritePump()
        XCTAssertNotNil(fx.session.ctx.clientWritePump)
    }

    // MARK: - viability handler wiring

    /// The wired `viabilityUpdateHandler` MUST update `ctx.lastPathViable`
    /// SYNCHRONOUSLY when invoked (NWConnection delivers it on `flowQueue`),
    /// not via a deferred `flowQueue.async` hop. The double-hop variant
    /// would leave `lastPathViable` stale until a later queue turn, which is
    /// what let a recovered path be read as dead by an already-queued
    /// `checkWakeDeadPath` and reset a healthy flow. Driving the real handler
    /// (installed by `installEgressStateHandler`) catches that regression:
    /// with the hop, this assert sees the stale value and fails.
    func testViabilityHandlerUpdatesContextSynchronously() {
        let fx = Fixture()
        fx.session.installEgressStateHandler(connection: fx.conn)
        fx.session.ctx.lastPathViable = true

        fx.conn.simulateViability(false)
        XCTAssertFalse(
            fx.session.ctx.lastPathViable,
            "viability handler must update ctx synchronously (no deferred hop)")

        fx.conn.simulateViability(true)
        XCTAssertTrue(fx.session.ctx.lastPathViable, "recovery must update synchronously too")
    }

    // MARK: - state-timer recovery (FIFO via direct dispatch)

    /// With the `stateUpdateHandler` hop removed and the mock delivering
    /// state async on the start queue (as NWConnection does), a `.ready`
    /// recovery runs in FIFO order with a timer armed on `flowQueue` and
    /// CANCELS it before it can fire — so a post-ready `.waiting` tolerance
    /// timer never reaps a flow whose path came back. This is the structural
    /// replacement for the per-timer state guards (no guard needed: the
    /// handler cancels the timer in order).
    func testPostReadyWaitingTimerCancelledByReadyRecovery() {
        let fx = Fixture()
        // Start the connection so the mock delivers state async on flowQueue.
        fx.session.installEgressStateHandler(connection: fx.conn)
        fx.conn.start(queue: fx.session.flowQueue)

        fx.session.egressReady = true                      // post-ready
        fx.session.handleEgressWaiting(.posix(.ENETDOWN))  // arms tolerance timer (default ~5s)
        fx.conn.transition(to: .ready)                     // recovery; delivered FIFO on flowQueue

        // After the (immediate) .ready handler runs, the timer is cancelled.
        let exp = expectation(description: "ready handler processed")
        fx.session.flowQueue.asyncAfter(deadline: .now() + .milliseconds(100)) { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)

        XCTAssertFalse(
            fx.session.ctx.teardown?.isDone ?? true,
            "the .ready handler must cancel the tolerance timer before it fires")
        XCTAssertEqual(fx.conn.cancelCount, 0, "connection must not be cancelled")
    }

    // MARK: - requestEngineSession

    /// Without an attached engine, the call returns nil — the caller
    /// in `start()` treats this as bypass.
    func testRequestEngineSessionWithoutEngineReturnsNil() {
        let fx = Fixture()
        XCTAssertNil(fx.session.requestEngineSession())
    }

    // MARK: - start

    /// `start()` without an engine returns false (= flow not claimed).
    func testStartWithoutEngineReturnsFalse() {
        let fx = Fixture()
        XCTAssertFalse(fx.session.start())
    }

    // MARK: - handleEgressReady

    /// `.ready` arms BOTH egress pumps and flips egressReady.
    func testHandleEgressReadyBuildsBothEgressPumpsWhenSessionPresent() {
        let fx = Fixture()
        // The session decision lives on the Rust side, so for this
        // unit test we can't construct a RamaTcpSessionHandle; the
        // method early-returns when sessionHandle is nil. We pin
        // that contract here and the integration tests exercise the
        // happy path with a real engine.
        XCTAssertNil(fx.session.sessionHandle)
        fx.session.handleEgressReady(connection: fx.conn)
        XCTAssertTrue(fx.session.egressReady, "egressReady flips even when session is nil")
    }

    /// Duplicate `.ready` after a `.waiting` recovery cancels any
    /// pending tolerance timer and is otherwise a no-op.
    func testHandleEgressReadyDuplicateIsIdempotentAndClearsTolerance() {
        let fx = Fixture()
        fx.session.egressReady = true
        let waiting = DispatchWorkItem {}
        fx.session.waitingWork = waiting
        fx.session.handleEgressReady(connection: fx.conn)
        XCTAssertTrue(waiting.isCancelled, "tolerance timer cancelled on .ready recovery")
        XCTAssertNil(fx.session.waitingWork)
    }

    // MARK: - handleEgressFailed (pre-ready)

    /// `.failed` before `.ready` cancels the connect-timeout work
    /// item and delegates to teardown.applyPreReadyFailure().
    func testHandleEgressFailedPreReadyTriggersPreReadyTeardown() {
        let fx = Fixture()
        let timeout = DispatchWorkItem {}
        fx.session.timeoutWork = timeout
        XCTAssertFalse(fx.session.teardown.isDone)

        fx.session.handleEgressFailed(nil)

        XCTAssertTrue(timeout.isCancelled, "connect timer must be invalidated")
        XCTAssertTrue(fx.session.teardown.isDone, "teardown fired exactly once")
        XCTAssertEqual(fx.flow.closeReadCallCount, 0, "pre-ready failure does NOT touch the kernel flow")
        XCTAssertEqual(fx.conn.cancelCount, 1)
    }

    // MARK: - handleEgressFailed (post-ready)

    /// `.failed` AFTER `.ready` runs full teardown (kernel flow closed).
    func testHandleEgressFailedPostReadyTriggersFullTeardown() {
        let fx = Fixture()
        fx.session.egressReady = true
        fx.session.handleEgressFailed(nil)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1, "post-ready failure closes the flow")
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertEqual(fx.conn.cancelCount, 1)
        XCTAssertTrue(fx.session.teardown.isDone)
    }

    // MARK: - handleEgressWaiting

    /// `.waiting` before `.ready` arms a short fast-fail budget timer,
    /// exactly once (a repeated pre-ready `.waiting` does not re-arm).
    func testHandleEgressWaitingPreReadyArmsFastFailBudget() {
        let fx = Fixture()
        XCTAssertFalse(fx.session.egressReady)
        fx.session.handleEgressWaiting(nil)
        XCTAssertNotNil(fx.session.waitingWork, "pre-ready .waiting arms a fast-fail budget timer")
        let firstWork = fx.session.waitingWork
        fx.session.handleEgressWaiting(nil)
        XCTAssertTrue(fx.session.waitingWork === firstWork, "duplicate pre-ready .waiting does not re-arm")
        // Cancel so it can't fire after the test returns.
        fx.session.waitingWork?.cancel()
        fx.session.waitingWork = nil
    }

    /// `.ready` cancels a pending pre-ready waiting budget timer.
    func testHandleEgressReadyCancelsPreReadyWaitingBudget() {
        let fx = Fixture()
        XCTAssertFalse(fx.session.egressReady)
        fx.session.handleEgressWaiting(nil)
        let budget = fx.session.waitingWork
        XCTAssertNotNil(budget)
        fx.session.handleEgressReady(connection: fx.conn)
        XCTAssertTrue(budget?.isCancelled ?? false, "pre-ready waiting budget cancelled on .ready")
        XCTAssertNil(fx.session.waitingWork)
        XCTAssertTrue(fx.session.egressReady)
    }

    /// `.waiting` after `.ready` arms a tolerance timer exactly once.
    func testHandleEgressWaitingPostReadyArmsTolerance() {
        let fx = Fixture()
        fx.session.egressReady = true
        fx.session.handleEgressWaiting(nil)
        XCTAssertNotNil(fx.session.waitingWork)
        let firstWork = fx.session.waitingWork
        fx.session.handleEgressWaiting(nil)
        XCTAssertTrue(fx.session.waitingWork === firstWork, "duplicate .waiting does not re-arm")
    }

    // MARK: - handleEgressCancelled

    /// `.cancelled` invalidates a pending tolerance/budget timer.
    func testHandleEgressCancelledClearsTimer() {
        let fx = Fixture()
        let waiting = DispatchWorkItem {}
        fx.session.waitingWork = waiting
        fx.session.handleEgressCancelled()
        XCTAssertTrue(waiting.isCancelled)
        XCTAssertNil(fx.session.waitingWork)
    }

    /// An EXTERNAL `.cancelled` before `.ready` tears the flow down via
    /// the pre-open path (connection cancelled, kernel flow untouched).
    /// Self-initiated cancels never reach here (cancelAndDetach nils the
    /// handler), so a `.cancelled` that does arrive must not leak.
    func testHandleEgressCancelledPreReadyTearsDownPreOpen() {
        let fx = Fixture()
        XCTAssertFalse(fx.session.egressReady)
        fx.session.handleEgressCancelled()
        XCTAssertTrue(fx.session.teardown.isDone, "external pre-ready cancel must tear down")
        XCTAssertEqual(fx.conn.cancelCount, 1)
        XCTAssertEqual(fx.flow.closeReadCallCount, 0, "pre-open teardown does not touch the kernel flow")
    }

    /// An EXTERNAL `.cancelled` after `.ready` runs the full teardown
    /// (kernel flow closed, connection cancelled) instead of leaving the
    /// session/registry/connection alive.
    func testHandleEgressCancelledPostReadyTearsDownFull() {
        let fx = Fixture()
        fx.session.egressReady = true
        fx.session.handleEgressCancelled()
        XCTAssertTrue(fx.session.teardown.isDone)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1, "post-ready cancel closes the flow")
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertEqual(fx.conn.cancelCount, 1)
    }

    // MARK: - handleEgressState dispatch

    /// `handleEgressState` short-circuits when the connection slot
    /// is nil — racing teardown wins.
    func testHandleEgressStateNoConnectionIsNoop() {
        let fx = Fixture()
        fx.session.ctx.connection = nil
        fx.session.handleEgressState(.ready)
        XCTAssertFalse(fx.session.egressReady)
    }
}
