import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for `TransparentProxyCore.handleSystemSleep` /
/// `handleSystemWake`.
///
/// `handleSystemSleep` is a brief pause-and-return hook: it stops
/// telemetry and fires the engine's sleep notification, but it does
/// NOT tear flows down. Flows that don't survive the suspend are
/// reaped post-wake by the per-flow `.failed` path. These tests pin
/// that non-destructive contract.
final class SystemLifecycleTests: XCTestCase {

    // MARK: - core.handleSystemSleep

    /// `handleSystemSleep` leaves every registered flow intact —
    /// no teardown, no connection cancel, registry untouched — and
    /// fires its completion promptly.
    func testHandleSystemSleepLeavesRegisteredTcpFlowsIntact() {
        let core = TransparentProxyCore()
        var ctxs: [TcpFlowContext] = []
        var flows: [MockTcpFlow] = []
        var conns: [MockNwConnection] = []
        // Build a few mock contexts and shove them straight into
        // the registry. Engine-less; we're only testing that sleep
        // does not disturb them.
        for _ in 0..<5 {
            let f = MockTcpFlow()
            let c = MockNwConnection()
            let ctx = TcpFlowContext()
            ctx.connection = c
            ctx.flow = f
            ctx.core = core
            ctx.flowId = ObjectIdentifier(f)
            // Use the registry directly — registerTcpFlow needs a
            // RamaTcpSessionHandle which we can't construct here.
            core.testInsertTcpContext(ObjectIdentifier(f), ctx)
            flows.append(f)
            conns.append(c)
            ctxs.append(ctx)
        }
        XCTAssertEqual(core.tcpFlowCount, 5)

        let exp = expectation(description: "sleep completion")
        core.handleSystemSleep { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)

        // Nothing was torn down: the flows survive the suspend and
        // are reaped (if needed) only by the post-wake path.
        XCTAssertEqual(core.tcpFlowCount, 5, "sleep must not drop flows")
        for (i, ctx) in ctxs.enumerated() {
            XCTAssertFalse(ctx.isDone, "teardown[\(i)] must not fire on sleep")
            XCTAssertEqual(conns[i].cancelCount, 0)
            XCTAssertEqual(flows[i].closeReadCallCount, 0)
        }
    }

    /// `handleSystemSleep` with NO registered flows fires its
    /// completion immediately and is a no-op otherwise.
    func testHandleSystemSleepOnEmptyRegistryFiresCompletion() {
        let core = TransparentProxyCore()
        let exp = expectation(description: "sleep completion")
        core.handleSystemSleep { exp.fulfill() }
        wait(for: [exp], timeout: 2.0)
    }

    /// `handleSystemWake` is a no-op when no engine attached;
    /// must not crash.
    func testHandleSystemWakeWithoutEngineIsHarmless() {
        let core = TransparentProxyCore()
        core.handleSystemWake()
    }

    // MARK: - path-recovery allowance (wake / viability / .waiting)

    /// Build a registered, established (`egressReady`) TCP flow with the
    /// given cached path viability. Engine-less: inserted straight into the
    /// registry like the sleep tests above.
    private func makeEstablishedFlow(
        on core: TransparentProxyCore,
        viable: Bool,
        flowQueue: DispatchQueue? = nil
    ) -> (flow: MockTcpFlow, conn: MockNwConnection, ctx: TcpFlowContext)
    {
        let f = MockTcpFlow()
        let c = MockNwConnection()
        let ctx = TcpFlowContext()
        ctx.connection = c
        ctx.egressReady = true
        ctx.lastPathViable = viable
        ctx.flowQueue = flowQueue
        ctx.flow = f
        ctx.core = core
        ctx.flowId = ObjectIdentifier(f)
        core.testInsertTcpContext(ObjectIdentifier(f), ctx)
        return (f, c, ctx)
    }

    /// Mirror the production `installEgressStateHandler` viability wiring for
    /// an engine-less flow.
    private func wireViabilityHandler(
        conn: MockNwConnection, ctx: TcpFlowContext, core: TransparentProxyCore
    ) {
        if let flowQueue = ctx.flowQueue {
            // Viability arrives on the start queue, as with NWConnection.
            conn.start(queue: flowQueue)
        }
        conn.viabilityUpdateHandler = { [weak ctx] viable in
            guard let ctx else { return }
            ctx.lastPathViable = viable
            if viable {
                core.handleEgressPathRecovered(ctx)
            } else {
                core.handleEgressPathLoss(ctx, trigger: "path change")
            }
        }
    }

    /// Post-ready `.waiting` / `.ready` as `TcpFlowSession` drives them.
    private func enterWaiting(_ ctx: TcpFlowContext, core: TransparentProxyCore, on queue: DispatchQueue) {
        queue.async {
            ctx.postReadyWaiting = true
            ctx.postReadyWaitingError = .posix(.ENETDOWN)
            core.handleEgressPathLoss(ctx, trigger: "waiting")
        }
    }

    private func leaveWaiting(_ ctx: TcpFlowContext, core: TransparentProxyCore, on queue: DispatchQueue) {
        queue.async {
            ctx.postReadyWaiting = false
            ctx.postReadyWaitingError = nil
            core.handleEgressPathRecovered(ctx)
        }
    }

    /// Wait until every block `queue` has due within `ms` has run.
    private func drain(_ queue: DispatchQueue, afterMs ms: Int) {
        let exp = expectation(description: "queue drained after \(ms)ms")
        queue.asyncAfter(deadline: .now() + .milliseconds(ms)) { exp.fulfill() }
        wait(for: [exp], timeout: Double(ms) / 1_000 + 2)
    }

    private func withRecoveryAllowance(_ ms: UInt32, _ body: () -> Void) {
        let saved = defaultPathRecoveryMs
        defaultPathRecoveryMs = ms
        defer { defaultPathRecoveryMs = saved }
        body()
    }

    /// An allowance no test outlives, so "not yet judged" never depends on
    /// runner speed; the verdict is then forced with `testExpirePathRecovery`.
    private let unreachableAllowanceMs: UInt32 = 600_000

    /// An expired allowance on a still non-viable path resets the flow: the
    /// silent `.ready`-over-dead-path wedge.
    func testExpiredAllowanceResetsEstablishedFlowWhenNotViable() {
        let core = TransparentProxyCore()
        let f = makeEstablishedFlow(on: core, viable: false)

        core.testExpirePathRecovery(f.ctx)

        XCTAssertTrue(f.ctx.isDone, "dead-path established flow must be torn down")
        XCTAssertEqual(f.conn.cancelCount, 1, "egress connection cancelled")
        XCTAssertEqual(core.tcpFlowCount, 0, "registry entry removed")
    }

    func testExpiredAllowanceKeepsEstablishedFlowWhenViable() {
        let core = TransparentProxyCore()
        let f = makeEstablishedFlow(on: core, viable: true)

        core.testExpirePathRecovery(f.ctx)

        XCTAssertFalse(f.ctx.isDone, "healthy flow must survive")
        XCTAssertEqual(f.conn.cancelCount, 0)
        XCTAssertEqual(core.tcpFlowCount, 1)
    }

    /// Pre-ready flows belong to the connect budgets and `applySystemWake`.
    func testExpiredAllowanceIgnoresPreReadyFlow() {
        let core = TransparentProxyCore()
        let f = makeEstablishedFlow(on: core, viable: false)
        f.ctx.egressReady = false

        core.testExpirePathRecovery(f.ctx)

        XCTAssertFalse(f.ctx.isDone)
        XCTAssertEqual(core.tcpFlowCount, 1)
    }

    /// The wired `viabilityUpdateHandler` caches into `ctx.lastPathViable`.
    func testViabilityHandlerCachesIntoContext() {
        let ctx = TcpFlowContext()
        let c = MockNwConnection()
        ctx.connection = c
        c.viabilityUpdateHandler = { viable in ctx.lastPathViable = viable }

        c.simulateViability(false)
        XCTAssertFalse(ctx.lastPathViable)
        c.simulateViability(true)
        XCTAssertTrue(ctx.lastPathViable)
    }

    /// Wake over a lost path resets the flow once the allowance runs out.
    func testWakeOverLostPathResetsAfterAllowance() {
        withRecoveryAllowance(10) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.wake")
            let f = makeEstablishedFlow(on: core, viable: false, flowQueue: queue)

            core.handleSystemWake()
            drain(queue, afterMs: 200)

            XCTAssertTrue(f.ctx.isDone, "allowance expiry must reset the dead-path flow")
            XCTAssertEqual(core.tcpFlowCount, 0)
        }
    }

    /// Wake over a healthy path starts no allowance at all.
    func testWakeKeepsHealthyFlow() {
        withRecoveryAllowance(10) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.wake.ok")
            let f = makeEstablishedFlow(on: core, viable: true, flowQueue: queue)

            core.handleSystemWake()
            drain(queue, afterMs: 100)

            XCTAssertFalse(f.ctx.isDone)
            XCTAssertNil(queue.sync { f.ctx.pathRecoveryDeadline })
            XCTAssertEqual(core.tcpFlowCount, 1)
        }
    }

    /// Delayed same-path recovery after wake: the path is lost right after
    /// resume and returns inside the allowance.
    func testWakeSparesDelayedSamePathRecovery() {
        withRecoveryAllowance(unreachableAllowanceMs) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.wake.delayed")
            let f = makeEstablishedFlow(on: core, viable: true, flowQueue: queue)
            wireViabilityHandler(conn: f.conn, ctx: f.ctx, core: core)

            core.handleSystemWake()
            f.conn.simulateViability(false)
            XCTAssertNotNil(queue.sync { f.ctx.pathRecoveryDeadline }, "loss starts the allowance")
            f.conn.simulateViability(true)
            XCTAssertNil(queue.sync { f.ctx.pathRecoveryDeadline })
            queue.sync { core.testExpirePathRecovery(f.ctx) }

            XCTAssertFalse(f.ctx.isDone, "recovered path must keep the flow")
            XCTAssertEqual(f.conn.cancelCount, 0)
        }
    }

    /// A path recovery that lands on `flowQueue` before the verdict spares the
    /// flow (FIFO with the timer).
    func testRecoveryQueuedBeforeVerdictSparesFlow() {
        let core = TransparentProxyCore()
        let queue = DispatchQueue(label: "rama.test.flow.wake.order")
        let f = makeEstablishedFlow(on: core, viable: false, flowQueue: queue)

        let hold = DispatchSemaphore(value: 0)
        queue.async { hold.wait() }
        queue.async { f.ctx.lastPathViable = true }
        queue.async { core.testExpirePathRecovery(f.ctx) }
        hold.signal()
        drain(queue, afterMs: 0)

        XCTAssertFalse(f.ctx.isDone, "recovery queued before the verdict must spare the flow")
        XCTAssertEqual(core.tcpFlowCount, 1)
    }

    /// Ordering: wake arms the verdict over a lost path, then the flow enters
    /// `.waiting` before it is due. The deadline must not move earlier, and a
    /// recovery inside it keeps the flow.
    func testWaitingAfterScheduledWakeCheckKeepsAllowance() {
        withRecoveryAllowance(unreachableAllowanceMs) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.wake.waiting")
            let f = makeEstablishedFlow(on: core, viable: false, flowQueue: queue)
            wireViabilityHandler(conn: f.conn, ctx: f.ctx, core: core)

            core.handleSystemWake()
            let deadline = queue.sync { f.ctx.pathRecoveryDeadline }
            XCTAssertNotNil(deadline, "wake arms the verdict")
            XCTAssertTrue(queue.sync { f.ctx.pathRecoveryTimerArmed })
            enterWaiting(f.ctx, core: core, on: queue)
            XCTAssertEqual(queue.sync { f.ctx.pathRecoveryDeadline }, deadline, "later signals keep the deadline")
            XCTAssertFalse(f.ctx.isDone)

            leaveWaiting(f.ctx, core: core, on: queue)
            f.conn.simulateViability(true)
            queue.sync { core.testExpirePathRecovery(f.ctx) }

            XCTAssertFalse(f.ctx.isDone, "recovery inside the allowance keeps the flow")
            XCTAssertEqual(f.conn.cancelCount, 0)
        }
    }

    /// Mid-session ordering: viability loss starts the allowance, `.waiting`
    /// follows; neither shortens it, and the verdict re-checks state at fire.
    func testWaitingAfterViabilityLossDoesNotShortenAllowance() {
        withRecoveryAllowance(unreachableAllowanceMs) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.mid.waiting")
            let f = makeEstablishedFlow(on: core, viable: true, flowQueue: queue)
            wireViabilityHandler(conn: f.conn, ctx: f.ctx, core: core)

            f.conn.simulateViability(false)
            let deadline = queue.sync { f.ctx.pathRecoveryDeadline }
            XCTAssertNotNil(deadline)
            enterWaiting(f.ctx, core: core, on: queue)
            XCTAssertEqual(queue.sync { f.ctx.pathRecoveryDeadline }, deadline)
            XCTAssertFalse(f.ctx.isDone)

            leaveWaiting(f.ctx, core: core, on: queue)
            f.conn.simulateViability(true)
            queue.sync { core.testExpirePathRecovery(f.ctx) }
            XCTAssertFalse(f.ctx.isDone)
            XCTAssertEqual(f.conn.cancelCount, 0)
        }
    }

    /// `.waiting` that never recovers resets with its own NWError, not the
    /// synthetic dead-path error.
    func testWaitingThatNeverRecoversResetsWithWaitingError() {
        withRecoveryAllowance(20) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.waiting.dead")
            let f = makeEstablishedFlow(on: core, viable: true, flowQueue: queue)

            enterWaiting(f.ctx, core: core, on: queue)
            drain(queue, afterMs: 200)

            XCTAssertTrue(f.ctx.isDone)
            XCTAssertEqual(core.tcpFlowCount, 0)
            XCTAssertEqual(f.flow.lastCloseReadError as? NWError, .posix(.ENETDOWN))
        }
    }

    /// A wake while a loss is already running restarts the allowance from
    /// resume: time spent asleep is not recovery time.
    func testWakeRestartsRunningAllowance() {
        withRecoveryAllowance(unreachableAllowanceMs) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.wake.restart")
            let f = makeEstablishedFlow(on: core, viable: true, flowQueue: queue)
            wireViabilityHandler(conn: f.conn, ctx: f.ctx, core: core)

            enterWaiting(f.ctx, core: core, on: queue)
            let first = queue.sync { f.ctx.pathRecoveryDeadline }
            XCTAssertNotNil(first)
            drain(queue, afterMs: 20)
            core.handleSystemWake()
            let restarted = queue.sync { f.ctx.pathRecoveryDeadline }
            XCTAssertNotNil(restarted)
            XCTAssertGreaterThan(restarted!, first!, "wake must restart, not keep, the running allowance")

            queue.sync { core.testExpirePathRecovery(f.ctx) }
            XCTAssertTrue(f.ctx.isDone, "restarted allowance still ends")
        }
    }

    /// Losing the path again after a recovery starts a fresh allowance; the
    /// earlier timer re-arms instead of judging the new loss early.
    func testReLossAfterRecoveryStartsFreshAllowance() {
        let core = TransparentProxyCore()
        let queue = DispatchQueue(label: "rama.test.flow.reloss")
        let f = makeEstablishedFlow(on: core, viable: true, flowQueue: queue)
        wireViabilityHandler(conn: f.conn, ctx: f.ctx, core: core)

        withRecoveryAllowance(20) {
            f.conn.simulateViability(false)
            f.conn.simulateViability(true)
            queue.sync {}
        }
        withRecoveryAllowance(unreachableAllowanceMs) {
            f.conn.simulateViability(false)
            // The first loss's timer comes due here and must re-arm.
            drain(queue, afterMs: 200)
            XCTAssertFalse(f.ctx.isDone, "first timer must not judge the second loss early")
            XCTAssertTrue(queue.sync { f.ctx.pathRecoveryTimerArmed })

            queue.sync { core.testExpirePathRecovery(f.ctx) }
            XCTAssertTrue(f.ctx.isDone, "second allowance ends")
        }
    }

    /// A viability flap keeps one timer, and a flap ending viable is spared.
    func testViabilityFlapKeepsOneTimer() {
        withRecoveryAllowance(200) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.flap")
            let f = makeEstablishedFlow(on: core, viable: true, flowQueue: queue)
            wireViabilityHandler(conn: f.conn, ctx: f.ctx, core: core)

            f.conn.simulateViability(false)
            f.conn.simulateViability(true)
            f.conn.simulateViability(false)
            f.conn.simulateViability(true)
            XCTAssertTrue(queue.sync { f.ctx.pathRecoveryTimerArmed })
            drain(queue, afterMs: 400)

            XCTAssertFalse(f.ctx.isDone, "flap ending viable must spare the flow")
            XCTAssertFalse(f.ctx.pathRecoveryTimerArmed)
        }
    }

    /// An explicit transport failure inside the allowance owns the teardown;
    /// the later verdict adds no second one.
    func testExplicitFailureInsideAllowanceTearsDownOnce() {
        withRecoveryAllowance(50) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.failed")
            let f = makeEstablishedFlow(on: core, viable: true, flowQueue: queue)
            wireViabilityHandler(conn: f.conn, ctx: f.ctx, core: core)

            f.conn.simulateViability(false)
            queue.async { f.ctx.applyPostReadyFailure(NWError.posix(.EADDRNOTAVAIL)) }
            drain(queue, afterMs: 200)

            XCTAssertTrue(f.ctx.isDone)
            XCTAssertEqual(f.conn.cancelCount, 1, "one teardown only")
            XCTAssertEqual(f.flow.closeReadCallCount, 1)
            XCTAssertEqual(f.flow.lastCloseReadError as? NWError, .posix(.EADDRNOTAVAIL))
        }
    }

    /// Resource and idle backstops keep their own clocks: a promoted flow
    /// past its idle timeout is reaped during a running allowance, and the
    /// later verdict adds no second teardown.
    func testIdleBackstopPreemptsRunningAllowance() {
        // Backdate by seconds, not the 900s default: a fresh CI VM has less
        // uptime than that, and `DispatchTime` clamps at boot.
        let savedIdleMs = defaultPromotedIdleTimeoutMs
        defaultPromotedIdleTimeoutMs = 1_000
        defer { defaultPromotedIdleTimeoutMs = savedIdleMs }
        withRecoveryAllowance(unreachableAllowanceMs) {
            let core = TransparentProxyCore()
            let flow = MockTcpFlow()
            let conn = MockNwConnection()
            let session = TcpFlowSession(
                core: core, flow: flow,
                meta: RamaTransparentProxyFlowMetaBridge(
                    protocolRaw: 1, remoteHost: "example.com", remotePort: 443,
                    localHost: nil, localPort: 0, sourceAppSigningIdentifier: nil,
                    sourceAppBundleIdentifier: nil, sourceAppAuditToken: nil,
                    sourceAppPid: 4242))
            session.flowQueue.sync {
                session.ctx.connection = conn
                session.ctx.egressReady = true
                session.egressReady = true
                session.ctx.lastPathViable = false
                session.ctx.mode = .promoted
                session.ctx.lastActivityAt =
                    .now() - .milliseconds(Int(defaultPromotedIdleTimeoutMs) + 1_000)
            }
            core.testInsertTcpContext(ObjectIdentifier(flow), session.ctx)

            core.handleSystemWake()
            XCTAssertNotNil(session.flowQueue.sync { session.ctx.pathRecoveryDeadline })
            core.testRunPeriodicMaintenance()
            XCTAssertTrue(session.flowQueue.sync { session.ctx.isDone }, "idle backstop wins")

            session.flowQueue.sync { core.testExpirePathRecovery(session.ctx) }
            XCTAssertEqual(conn.cancelCount, 1, "verdict after the backstop is a no-op")
            XCTAssertEqual(flow.closeReadCallCount, 1)
            XCTAssertEqual(core.tcpFlowCount, 0)
        }
    }

    /// Pre-ready flows are out of scope: a loss before `.ready` starts nothing.
    func testViabilityLossSparesPreReadyFlow() {
        withRecoveryAllowance(10) {
            let core = TransparentProxyCore()
            let queue = DispatchQueue(label: "rama.test.flow.pathloss.preready")
            let f = makeEstablishedFlow(on: core, viable: true, flowQueue: queue)
            f.ctx.egressReady = false
            wireViabilityHandler(conn: f.conn, ctx: f.ctx, core: core)

            f.conn.simulateViability(false)
            drain(queue, afterMs: 200)

            XCTAssertFalse(f.ctx.isDone)
            XCTAssertNil(queue.sync { f.ctx.pathRecoveryDeadline })
            XCTAssertEqual(core.tcpFlowCount, 1)
        }
    }

    /// Build a registered PRE-ready flow (`egressReady == false`) whose
    /// connection silently reached `.ready` — the reorder window where the
    /// `.ready` handler is still queued behind the wake reconcile.
    private func makePreReadyFlowThatSilentlyReachedReady(
        on core: TransparentProxyCore
    ) -> (flow: MockTcpFlow, conn: MockNwConnection, ctx: TcpFlowContext)
    {
        let f = MockTcpFlow()
        let c = MockNwConnection()
        c.setStateSilently(.ready)
        let ctx = TcpFlowContext()
        ctx.connection = c
        ctx.egressReady = false
        ctx.flow = f
        ctx.core = core
        ctx.flowId = ObjectIdentifier(f)
        core.testInsertTcpContext(ObjectIdentifier(f), ctx)
        return (f, c, ctx)
    }

    /// `handleSystemWake` consults live `connection.state` (via
    /// `hasReachedReady`) so it doesn't pre-open-cleanup a flow that reached
    /// `.ready` while `egressReady` is still stale.
    func testWakePreReadyResetSparesConnectionThatReachedReady() {
        let core = TransparentProxyCore()
        let f = makePreReadyFlowThatSilentlyReachedReady(on: core)

        core.handleSystemWake()

        XCTAssertFalse(
            f.ctx.isDone,
            "a flow that reached .ready must not be pre-ready-reset on wake")
        XCTAssertEqual(core.tcpFlowCount, 1)
    }

    /// Same window at the maintenance watchdog pre-ready kick.
    func testWatchdogPreReadyKickSparesConnectionThatReachedReady() {
        let core = TransparentProxyCore()
        let f = makePreReadyFlowThatSilentlyReachedReady(on: core)

        core.testRunPeriodicMaintenance()
        core.testRunPeriodicMaintenance()

        XCTAssertFalse(
            f.ctx.isDone,
            "watchdog must not connect-timeout a flow that already reached .ready")
        XCTAssertEqual(core.tcpFlowCount, 1)
    }

    /// After a promoted flow's natural terminal, a racing verdict must not
    /// cancel the egress connection whose FIN/linger the write pump owns.
    func testVerdictNoOpsAfterPromotedTerminal() {
        let core = TransparentProxyCore()
        let f = makeEstablishedFlow(on: core, viable: false)

        f.ctx.applyPromotedTerminal()
        XCTAssertTrue(f.ctx.isDone, "promoted terminal marks teardown done")
        XCTAssertEqual(f.conn.cancelCount, 0, "promoted terminal must NOT cancel the connection")
        let closesAfterTerminal = f.flow.closeReadCallCount

        core.testExpirePathRecovery(f.ctx)

        XCTAssertEqual(f.conn.cancelCount, 0, "verdict must not cancel the connection post-terminal")
        XCTAssertEqual(
            f.flow.closeReadCallCount, closesAfterTerminal,
            "verdict must not re-close the kernel flow post-terminal")
    }
}
