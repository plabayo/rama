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

    /// init() wires the teardown inputs (flow/core/flowId) onto ctx so its
    /// `applyX` methods can run.
    func testInitWiresTeardownIntoContext() {
        let fx = Fixture()
        XCTAssertNotNil(fx.session.ctx.flow, "ctx.flow wired for teardown")
        XCTAssertNotNil(fx.session.ctx.flowId, "ctx.flowId wired for teardown")
        XCTAssertFalse(fx.session.egressReady)
    }

    /// The ownership-inversion backstop: the registry is the session's sole
    /// owner, so dropping it must cancel the egress connection even if no
    /// teardown ran first (otherwise the `NWConnection` + its NECP entry
    /// outlive the session and leak). `deinit` hops the cancel onto
    /// `flowQueue`, so we poll for it.
    func testDeinitCancelsConnectionWhenDroppedWithoutTeardown() {
        let conn = MockNwConnection()
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        let meta = RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1, remoteHost: "example.com", remotePort: 443,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil, sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil, sourceAppPid: 4242)

        var session: TcpFlowSession<MockTcpFlow>? = TcpFlowSession(
            core: core, flow: flow, meta: meta)
        session!.ctx.connection = conn
        XCTAssertEqual(conn.cancelCount, 0, "not cancelled while the session is alive")

        session = nil  // sole strong ref dropped → deinit backstop fires

        let deadline = Date().addingTimeInterval(2.0)
        while conn.cancelCount == 0 && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.002)
        }
        XCTAssertEqual(
            conn.cancelCount, 1,
            "deinit must cancel a connection that no teardown released")
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

    /// The wired handler must also TRIGGER the mid-session dead-path
    /// re-check on a loss (not just cache it) — through the REAL
    /// `installEgressStateHandler` wiring, so the lifecycle tests' mirrored
    /// handler can't drift from production. With the kill switch (`0`) it
    /// schedules nothing; enabled, a `false` schedules the coalesced
    /// re-check. The long settle keeps the timer from firing in-test (the
    /// fixture dies first; the weak-ctx guard then no-ops).
    func testViabilityHandlerSchedulesMidSessionRecheck() {
        let prev = defaultViabilityLossRecheckMs
        defer { defaultViabilityLossRecheckMs = prev }

        // Kill switch: the real handler caches viability but schedules nothing.
        defaultViabilityLossRecheckMs = 0
        let fxOff = Fixture()
        fxOff.session.installEgressStateHandler(connection: fxOff.conn)
        fxOff.conn.simulateViability(false)
        XCTAssertFalse(
            fxOff.session.ctx.deadPathRecheckPending,
            "kill switch (0) must schedule nothing")

        // Enabled: the real handler schedules the coalesced re-check.
        defaultViabilityLossRecheckMs = 60_000
        let fxOn = Fixture()
        fxOn.session.installEgressStateHandler(connection: fxOn.conn)
        fxOn.conn.simulateViability(false)
        XCTAssertTrue(
            fxOn.session.ctx.deadPathRecheckPending,
            "enabled loss must schedule the re-check through the real handler")
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
            fx.session.ctx.isDone,
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

    /// `.ready` flips `egressReady` and then early-returns when there is no
    /// `sessionHandle` (we can't build a real `RamaTcpSessionHandle` in a
    /// unit test — the integration tests exercise the both-pumps-built happy
    /// path with a real engine). This pins the session-nil early-return; the
    /// name no longer over-claims pump construction it can't reach here.
    func testHandleEgressReadyFlipsEgressReadyThenEarlyReturnsWhenSessionNil() {
        let fx = Fixture()
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
        XCTAssertFalse(fx.session.ctx.isDone)

        fx.session.handleEgressFailed(nil)

        XCTAssertTrue(timeout.isCancelled, "connect timer must be invalidated")
        XCTAssertTrue(fx.session.ctx.isDone, "teardown fired exactly once")
        XCTAssertEqual(
            fx.flow.closeReadCallCount, 1, "pre-ready failure rejects the claimed (unopened) flow")
        XCTAssertEqual(fx.conn.cancelCount, 1)
    }

    // MARK: - connect-timeout fire

    /// The connect-timeout timer ACTUALLY FIRING (not just being cancelled):
    /// armed short, never reaching `.ready`, it must run pre-open cleanup —
    /// cancel the stale connect, clear the slot, mark teardown done. The
    /// lifecycle test at the core level can't override the 30s fallback, so
    /// this is the only place the fire path itself is exercised. The barrier
    /// is a later `flowQueue` work item: serial FIFO guarantees the timer
    /// (earlier deadline) has run by the time it resolves.
    func testConnectTimeoutFiresAndTearsDownPreOpen() {
        let fx = Fixture()
        XCTAssertFalse(fx.session.egressReady)

        fx.session.installConnectTimeout(connectTimeoutMs: 30, remoteHost: "example.com")

        let exp = expectation(description: "connect timeout fired")
        fx.session.flowQueue.asyncAfter(deadline: .now() + .milliseconds(250)) { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)

        XCTAssertTrue(fx.session.ctx.isDone, "connect timeout must tear the flow down")
        XCTAssertEqual(fx.conn.cancelCount, 1, "stale connect connection must be cancelled")
        XCTAssertNil(fx.session.ctx.connection, "connection slot cleared on connect timeout")
        XCTAssertEqual(
            fx.flow.closeReadCallCount, 1, "connect timeout rejects the claimed (unopened) flow")
    }

    /// A `.ready` arriving before the connect deadline flips `egressReady`,
    /// so the timer — when it later fires — is a no-op (guarded on
    /// `!egressReady`). Pins that the fire path can't reap a connected flow.
    func testConnectTimeoutAfterReadyIsNoop() {
        let fx = Fixture()
        fx.session.egressReady = true

        fx.session.installConnectTimeout(connectTimeoutMs: 30, remoteHost: "example.com")

        let exp = expectation(description: "connect deadline elapsed")
        fx.session.flowQueue.asyncAfter(deadline: .now() + .milliseconds(250)) { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)

        XCTAssertFalse(fx.session.ctx.isDone, "connected flow must survive the connect deadline")
        XCTAssertEqual(fx.conn.cancelCount, 0, "connected flow's connection must not be cancelled")
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
        XCTAssertTrue(fx.session.ctx.isDone)
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
    /// the pre-open path without cancelling the terminal connection again.
    /// Self-initiated cancels never reach here (cancelAndDetach nils the
    /// handler), so a `.cancelled` that does arrive must not leak.
    func testHandleEgressCancelledPreReadyTearsDownPreOpen() {
        let fx = Fixture()
        XCTAssertFalse(fx.session.egressReady)
        fx.session.handleEgressCancelled()
        XCTAssertTrue(fx.session.ctx.isDone, "external pre-ready cancel must tear down")
        XCTAssertEqual(fx.conn.cancelCount, 0)
        XCTAssertNil(fx.session.ctx.connection)
        XCTAssertEqual(
            fx.flow.closeReadCallCount, 1, "pre-open teardown rejects the claimed (unopened) flow")
    }

    /// An EXTERNAL `.cancelled` after `.ready` runs the full teardown without
    /// touching the terminal connection's handlers or cancelling it again.
    func testHandleEgressCancelledPostReadyTearsDownFull() {
        let fx = Fixture()
        fx.session.egressReady = true
        fx.session.handleEgressCancelled()
        XCTAssertTrue(fx.session.ctx.isDone)
        XCTAssertEqual(fx.flow.closeReadCallCount, 1, "post-ready cancel closes the flow")
        XCTAssertEqual(fx.flow.closeWriteCallCount, 1)
        XCTAssertEqual(fx.conn.cancelCount, 0)
        XCTAssertNil(fx.session.ctx.connection)
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
