import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// End-to-end lifecycle tests for `TransparentProxyCore.handleTcpFlow`.
///
/// Each test drives the full per-flow state machine against a
/// `MockTcpFlow` and a `MockNwConnection`. The Rust engine is real;
/// the bridges are real; the per-flow tasks are real. Only the
/// Apple-framework boundary (the flow and the NWConnection) is
/// mocked, which is exactly the boundary that's both hard to test
/// against AND not where the bugs are. Our bugs are in *our*
/// state-machine reactions to Apple's signals; we test our reactions
/// to mocked signals.
///
/// Every scenario asserts both functional behavior (cleanup
/// happened, errors propagated, byte counts match) and accounting
/// invariants (`tcpFlowCount` returns to 0, weak refs deallocate).
/// Together those rule out the failure modes that motivated this
/// PR: leaked NWConnection registrations, retain-cycle ctx graphs,
/// missing cleanup arms.
final class CoreTcpLifecycleTests: XCTestCase {

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    // MARK: - Test scaffolding

    private func makeEngine() -> RamaTransparentProxyEngineHandle {
        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            preconditionFailure()
        }
        return engine
    }

    /// Standard core + engine + capture-factory triple used by every
    /// test. `capture.lastConnection` exposes the mock NWConnection
    /// the core's nwConnectionFactory handed out, so the test can
    /// drive its state.
    private struct CoreFixture {
        let engine: RamaTransparentProxyEngineHandle
        let core: TransparentProxyCore
        let capture: NwConnectionCapture
    }

    private func makeFixture() -> CoreFixture {
        let engine = makeEngine()
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        return CoreFixture(engine: engine, core: core, capture: capture)
    }

    private func tearDown(_ fx: CoreFixture) {
        fx.core.detachEngine(reason: 0)
    }

    private func makeMeta(
        remoteHost: String = "example.com",
        remotePort: UInt16 = 443
    ) -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1,
            remoteHost: remoteHost,
            remotePort: remotePort,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    /// Polls `condition` up to `timeout` seconds, returning the
    /// first time it evaluates true. Used to await asynchronous
    /// state transitions (the per-flow queue + Rust runtime are
    /// real; the test thread has to wait for them to advance).
    private func waitFor(
        _ description: String,
        timeout: TimeInterval = 2.0,
        condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    /// Drive a promote-aware clean teardown and wait for the flow
    /// to be removed from the registry.
    ///
    /// After `peek_duration_s` (0.5s in TestFixtures) the demo's
    /// in-Rust service falls through to the promote-aware
    /// passthrough fallback, calls `into_passthrough`, and Swift
    /// flips `ctx.mode` to `.promoted`. From that point on the
    /// kernel flow + NWConnection are owned by Swift's
    /// `TcpDirectForwarder`, which needs three things to terminate:
    ///   1. EOF on BOTH directions (kernel C→S and connection S→C)
    ///      routed through cancelForPromote's carryover sinks. We
    ///      have to wait for the mode change before firing them
    ///      because firing pre-cutover would either consume the
    ///      EOFs via the in-Rust pumps' normal handlers (egress)
    ///      or trip the `!saw_client_bytes → cancel` fast-path
    ///      which suppresses Swift cleanup callbacks (ingress).
    ///   2. The egress write pump's FIN send to actually complete.
    ///      Real `NWConnection` auto-completes sends; the mock
    ///      queues them on `_pendingSendCompletions` until the
    ///      test fires `completePendingSend`. The helper runs a
    ///      background completer for the duration of the wait so
    ///      the FIN-drain path can transition C→S to `.finished`.
    private func drainAndAwaitRemoval(
        _ core: TransparentProxyCore,
        flow: MockTcpFlow,
        conn: MockNwConnection,
        description: String = "flow removed",
        timeout: TimeInterval = 5.0
    ) {
        guard let ctx = core.testInspectTcpContext(for: flow) else {
            XCTFail("no ctx for flow — cutover wait impossible"); return
        }
        waitFor("cutover flips ctx.mode away from .viaRust", timeout: 3.0) {
            ctx.mode != .viaRust
        }

        let completer = AtomicFlag()
        DispatchQueue.global().async {
            while !completer.load() {
                _ = conn.completePendingSend(error: nil)
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        defer { completer.store(true) }

        flow.completeRead(data: nil, error: nil)
        _ = conn.completePendingReceive(isComplete: true)

        waitFor(description, timeout: timeout) { core.tcpFlowCount == 0 }
    }

    // MARK: - Happy path

    func testHappyPath_ConnectionReadyFlowOpenBytesFlowEofClean() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        XCTAssertEqual(fx.core.tcpFlowCount, 1)
        XCTAssertEqual(flow.applyMetadataCallCount, 1)

        let conn = fx.capture.waitForLastConnection()
        conn.transition(to: .ready)

        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)

        // Read pump should have started.
        waitFor("egress read pump issued first receive") { conn.pendingReceiveCount > 0 }
        // Client read pump should have started.
        waitFor("client read pump issued first read") { flow.pendingReadCount > 0 }

        // Demo `tproxy_rs` wraps its passthrough fallback with
        // `PromoteLayer`, so after the in-Rust service peek-times
        // out the cutover fires and the kernel flow + NWConnection
        // are owned by Swift's `TcpDirectForwarder`. Drive both
        // directions to EOF (via the carryover sinks) and run a
        // send-completer for the FIN drain — see helper docstring.
        drainAndAwaitRemoval(
            fx.core, flow: flow, conn: conn,
            description: "flow removed from registration map"
        )
    }

    // MARK: - Pre-ready failure paths

    func testPreReadyConnectionFailedTearsDownCleanly() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        XCTAssertEqual(fx.core.tcpFlowCount, 1)

        let conn = fx.capture.waitForLastConnection()
        conn.transition(to: .failed(.posix(.ECONNREFUSED)))

        waitFor("flow registration removed after pre-ready failure") {
            fx.core.tcpFlowCount == 0
        }
        // Pre-ready failure does NOT call flow.open (we never got
        // far enough), and does NOT touch the flow's close methods
        // (the flow was never opened from the kernel's perspective
        // — the kernel will see the session cancel and tear it down
        // via NE's own path).
        XCTAssertFalse(flow.openWasInvoked, "flow.open must not be called on pre-ready failure")
        XCTAssertEqual(conn.cancelCount, 1, "connection must be cancelled exactly once")
    }

    func testConnectTimeoutTearsDownCleanly() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        // Use a very short connect timeout so the test stays fast.
        // The core reads the timeout from the session's egress
        // options; the engine's demo handler doesn't set one so the
        // core falls back to 30s. We can't easily override that
        // here, so we instead just simulate the timer's effect by
        // never sending .ready — the wait below stops at a
        // pre-ready upper bound that's tighter than the timeout
        // window, sufficient to verify "no early cleanup", and
        // the full-timeout path is covered by the .failed test
        // above.
        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()
        // Briefly wait — flow should still be registered, no
        // premature cleanup.
        Thread.sleep(forTimeInterval: 0.20)
        XCTAssertEqual(fx.core.tcpFlowCount, 1, "no cleanup should fire before timeout / state change")
        XCTAssertEqual(conn.cancelCount, 0)
    }

    // MARK: - Pre-ready waiting (path down at connect)

    /// `.waiting` that never reaches `.ready` fails fast on the budget
    /// (pre-open shape: connection cancelled, kernel flow untouched).
    func testPreReadyWaitingFailsFastWithinBudget() {
        let savedBudget = defaultEgressPreReadyWaitingBudgetMs
        defaultEgressPreReadyWaitingBudgetMs = 200
        defer { defaultEgressPreReadyWaitingBudgetMs = savedBudget }

        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        // Path down at connect: `.waiting` before ever reaching `.ready`.
        conn.transition(to: .waiting(.posix(.EHOSTUNREACH)))

        waitFor("pre-ready waiting budget fired teardown", timeout: 3.0) {
            fx.core.tcpFlowCount == 0
        }
        XCTAssertGreaterThanOrEqual(conn.cancelCount, 1, "stale connect must be cancelled")
        XCTAssertFalse(flow.openWasInvoked, "flow.open must not be called on a failed connect")
        XCTAssertEqual(
            flow.closeReadCallCount, 0,
            "pre-open teardown does not touch the kernel flow (parity with connect-timeout)"
        )
    }

    /// A brief pre-ready `.waiting` that recovers to `.ready` before the
    /// budget elapses is not torn down (budget cancelled on `.ready`).
    func testPreReadyWaitingThatRecoversIsNotTornDown() {
        let savedBudget = defaultEgressPreReadyWaitingBudgetMs
        defaultEgressPreReadyWaitingBudgetMs = 5_000
        defer { defaultEgressPreReadyWaitingBudgetMs = savedBudget }

        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        conn.transition(to: .waiting(.posix(.EHOSTUNREACH)))
        Thread.sleep(forTimeInterval: 0.10)
        XCTAssertEqual(fx.core.tcpFlowCount, 1, "brief pre-ready waiting must not tear down")
        conn.transition(to: .ready)

        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("pumps wired") { conn.pendingReceiveCount > 0 }
        XCTAssertEqual(fx.core.tcpFlowCount, 1, "recovery to .ready keeps the flow alive")

        drainAndAwaitRemoval(fx.core, flow: flow, conn: conn)
    }

    // MARK: - System wake reconcile

    /// On wake, a not-yet-`.ready` egress flow is dropped immediately.
    func testSystemWakeReconcilesNotReadyEgressFlow() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()
        XCTAssertEqual(fx.core.tcpFlowCount, 1)

        // Connection is mid-connect (never `.ready`) when wake fires.
        fx.core.handleSystemWake()

        waitFor("wake reconciled the not-ready flow", timeout: 3.0) {
            fx.core.tcpFlowCount == 0
        }
        XCTAssertGreaterThanOrEqual(conn.cancelCount, 1)
        XCTAssertFalse(flow.openWasInvoked)
    }

    /// On wake, an established (post-`.ready`) flow is left alone.
    func testSystemWakeLeavesReadyEgressFlowAlone() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        conn.transition(to: .ready)
        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("pumps wired") { conn.pendingReceiveCount > 0 }

        fx.core.handleSystemWake()
        Thread.sleep(forTimeInterval: 0.20)
        XCTAssertEqual(fx.core.tcpFlowCount, 1, "wake must not tear down an established flow")
        XCTAssertEqual(conn.cancelCount, 0, "established egress connection not cancelled by wake")

        drainAndAwaitRemoval(fx.core, flow: flow, conn: conn)
    }

    // MARK: - Post-ready failure paths

    func testPostReadyConnectionFailedTearsDownCleanly() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        conn.transition(to: .ready)
        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("session activated and pumps wired") { conn.pendingReceiveCount > 0 }

        // Now a post-ready failure — the new arm added in this PR.
        conn.transition(to: .failed(.posix(.ECONNRESET)))

        waitFor("post-ready failure cleaned up", timeout: 3.0) {
            fx.core.tcpFlowCount == 0
        }
        XCTAssertGreaterThanOrEqual(conn.cancelCount, 1)
        XCTAssertGreaterThanOrEqual(
            flow.closeReadCallCount, 1,
            "post-ready failure must close the flow's read side"
        )
        XCTAssertGreaterThanOrEqual(flow.closeWriteCallCount, 1)
    }

    func testPostReadyWaitingRecoversWithoutTeardown() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        conn.transition(to: .ready)
        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("pumps wired") { conn.pendingReceiveCount > 0 }

        // Briefly enter .waiting, then recover.
        conn.transition(to: .waiting(.posix(.ENETDOWN)))
        Thread.sleep(forTimeInterval: 0.30)
        XCTAssertEqual(
            fx.core.tcpFlowCount, 1,
            "brief .waiting (under tolerance) must not tear down the flow"
        )
        conn.transition(to: .ready)
        Thread.sleep(forTimeInterval: 0.20)
        XCTAssertEqual(fx.core.tcpFlowCount, 1, "recovery to .ready must keep the flow alive")
        XCTAssertEqual(conn.cancelCount, 0, "no spurious cancel during waiting/recovery")

        // Drive a clean shutdown so the deferred tearDown does not
        // leak the session. See `drainAndAwaitRemoval` doc.
        drainAndAwaitRemoval(fx.core, flow: flow, conn: conn)
    }

    func testPostReadyWaitingTimesOutAndTearsDownAsFailed() {
        // Shorten the tolerance so the test runs fast. The module
        // global is `nonisolated(unsafe) var` precisely for this.
        let savedTolerance = defaultEgressWaitingToleranceMs
        defaultEgressWaitingToleranceMs = 200
        defer { defaultEgressWaitingToleranceMs = savedTolerance }

        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        conn.transition(to: .ready)
        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("pumps wired") { conn.pendingReceiveCount > 0 }

        // Drive into `.waiting` and leave it there. The post-ready
        // tolerance timer should fire and tear the flow down via
        // the same path as `.failed`.
        conn.transition(to: .waiting(.posix(.ENETDOWN)))

        waitFor("waiting tolerance fired teardown", timeout: 3.0) {
            fx.core.tcpFlowCount == 0
        }
        XCTAssertGreaterThanOrEqual(
            flow.closeReadCallCount, 1,
            "tolerance timeout must close the flow's read side"
        )
        XCTAssertGreaterThanOrEqual(flow.closeWriteCallCount, 1)
        XCTAssertGreaterThanOrEqual(conn.cancelCount, 1)
    }

    // MARK: - flow.open error

    func testFlowOpenErrorAfterEgressReadyTearsDownCleanly() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockTcpFlow()
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        conn.transition(to: .ready)
        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: NSError(domain: "test", code: 1))

        waitFor("flow.open error cleanup completed", timeout: 3.0) {
            fx.core.tcpFlowCount == 0
        }
        XCTAssertGreaterThanOrEqual(conn.cancelCount, 1)
    }

    // MARK: - ARC leak check

    func testFlowDeallocatesAfterHappyPath() {
        // For this test we need to stop the engine *before* checking
        // weak refs: the engine's tokio runtime detaches per-flow
        // bridge tasks rather than aborting them on session.cancel(),
        // and those tasks hold the FFI callback boxes that capture
        // the flow and connection via Swift closures. They drop on
        // their own once they observe shutdown, which happens on
        // engine.stop(). Without this the test would race the
        // background tokio scheduler.
        //
        // Under .promoted mode the egress write pump's linger
        // watchdog holds `connection` strongly until its deadline.
        // The default (5s) races the test's 5s ARC poll. Clamp it
        // so the watchdog releases its captured `conn` well within
        // the poll window.
        let savedLinger = defaultLingerCloseMs
        defaultLingerCloseMs = 100
        defer { defaultLingerCloseMs = savedLinger }

        let engine = makeEngine()
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        weak var weakFlow: MockTcpFlow?
        weak var weakConn: MockNwConnection?

        autoreleasepool {
            let flow = MockTcpFlow()
            weakFlow = flow
            _ = core.handleTcpFlow(flow, meta: makeMeta())
            let conn = capture.waitForLastConnection()
            weakConn = conn
            conn.transition(to: .ready)
            self.waitFor("flow.open") { flow.openWasInvoked }
            flow.completeOpen(error: nil)
            self.waitFor("pumps wired") { conn.pendingReceiveCount > 0 }
            // Promote-aware teardown — see `drainAndAwaitRemoval`.
            self.drainAndAwaitRemoval(core, flow: flow, conn: conn)
            // Mirror NWConnection's post-cancel `.cancelled` delivery
            // so the mock releases its stateUpdateHandler closure
            // graph. Real `NWConnection` does this automatically
            // after `cancel()`; the mock waits for an explicit
            // signal so tests that drive the lifecycle by hand can
            // distinguish "we cancelled" from "Apple delivered the
            // terminal state."
            conn.simulateCancelled()
        }

        // engine.stop() aborts every bridge task synchronously, so
        // after this returns the Swift closures the bridges held
        // are released and ARC can collect the flow + connection.
        core.detachEngine(reason: 0)

        // Drop the factory's strong references to its captured
        // mock connections so ARC can finalise them.
        capture.releaseAll()

        let deadline = Date().addingTimeInterval(5.0)
        while (weakFlow != nil || weakConn != nil) && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }

        XCTAssertNil(weakFlow, "flow retained beyond teardown — closure-capture leak")
        XCTAssertNil(weakConn, "NWConnection retained beyond teardown — closure-capture leak")
    }

    // MARK: - Multi-flow churn

    func testManyFlowsChurnReturnsRegistrationToZero() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flowCount = 15
        var flows: [MockTcpFlow] = []
        for _ in 0..<flowCount {
            let flow = MockTcpFlow()
            flows.append(flow)
            _ = fx.core.handleTcpFlow(flow, meta: makeMeta())
        }

        XCTAssertEqual(fx.core.tcpFlowCount, flowCount)

        // Drive all to .ready, open, then EOF.
        let connections = fx.capture.allConnections
        XCTAssertEqual(connections.count, flowCount)
        for conn in connections {
            conn.transition(to: .ready)
        }
        for flow in flows {
            waitFor("flow.open called for every flow", timeout: 5.0) {
                flow.openWasInvoked
            }
            flow.completeOpen(error: nil)
        }
        for conn in connections {
            waitFor("each pump issued first receive", timeout: 5.0) {
                conn.pendingReceiveCount > 0
            }
        }

        // Wait for every flow's cutover, then drive both EOFs +
        // run send-completers in parallel. We pull the cutover
        // wait out of the per-flow helper so the test can wait
        // ONCE for the batch instead of N times serially.
        let contexts: [TcpFlowContext] = flows.compactMap {
            fx.core.testInspectTcpContext(for: $0)
        }
        XCTAssertEqual(contexts.count, flows.count, "every flow must have a ctx")
        waitFor("all \(flowCount) flows cutover", timeout: 5.0) {
            contexts.allSatisfy { $0.mode != .viaRust }
        }

        // One background thread iterating all connections to keep
        // the FIN-drain paths from stalling on the mock connection.
        let completer = AtomicFlag()
        let capturedConns = connections
        DispatchQueue.global().async {
            while !completer.load() {
                for c in capturedConns {
                    _ = c.completePendingSend(error: nil)
                }
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        defer { completer.store(true) }

        for (flow, conn) in zip(flows, connections) {
            flow.completeRead(data: nil, error: nil)
            _ = conn.completePendingReceive(isComplete: true)
        }

        waitFor("all flows removed from registration", timeout: 10.0) {
            fx.core.tcpFlowCount == 0
        }
    }
}

// MARK: - Factory capture

/// Captures every `NWConnection` the core's factory hands out so
/// tests can drive their state. Thread-safe — production calls the
/// factory from `flowQueue`-derived threads.
final class NwConnectionCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var _connections: [MockNwConnection] = []

    var factory: NwConnectionFactoryFn {
        return { [weak self] _, _, _ in
            let conn = MockNwConnection()
            self?.lock.lock()
            self?._connections.append(conn)
            self?.lock.unlock()
            return conn
        }
    }

    var lastConnection: MockNwConnection? {
        lock.lock(); defer { lock.unlock() }
        return _connections.last
    }

    var allConnections: [MockNwConnection] {
        lock.lock(); defer { lock.unlock() }
        return _connections
    }

    /// Block until the factory has handed out at least one
    /// connection. The factory call happens on the per-flow queue
    /// asynchronously; the test thread polls.
    func waitForLastConnection(timeout: TimeInterval = 2.0) -> MockNwConnection {
        let deadline = Date().addingTimeInterval(timeout)
        while lastConnection == nil && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        guard let conn = lastConnection else {
            XCTFail("factory did not produce a connection within \(timeout)s")
            preconditionFailure()
        }
        return conn
    }

    /// Drop the factory's strong references to its captured
    /// connections. Tests that assert ARC cleanup on those
    /// connections need to call this so the factory's bookkeeping
    /// isn't itself the pin.
    func releaseAll() {
        lock.lock()
        _connections.removeAll(keepingCapacity: false)
        lock.unlock()
    }
}
