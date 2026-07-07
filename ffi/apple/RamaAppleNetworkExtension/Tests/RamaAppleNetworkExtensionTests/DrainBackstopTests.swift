import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for the graceful-close drain backstop — the fix for permanently
/// orphaned per-flow graphs when a peer stops reading mid-close.
///
/// When `onServerClosed` / `onCloseEgress` hand a flow to
/// `closeWhenDrained`, completion is gated on the write pump draining.
/// A peer that has stopped reading leaves the in-flight `flow.write` /
/// `connection.send` completion deferred forever, so the drain never
/// finishes and the drain-gated teardown (`applyDrainedClose`) never
/// runs — orphaning the whole per-flow graph (the egress write pump's
/// queued `Data`, its dispatch continuations, the `flowQueue`, and the
/// egress `NWConnection`). Two independent layers reap it:
///
///   * Per-flow: `TcpFlowSession.armTerminalDrainBackstop` forces a full
///     teardown `lingerCloseMs` after a terminal signal.
///   * Watchdog: `TransparentProxyCore`'s maintenance tick reaps any
///     post-`.ready` flow still in the registry one tick after it
///     signalled close (`ctx.terminalSignalled`), surviving a starved
///     per-flow queue.
final class DrainBackstopTests: XCTestCase {

    // MARK: - Per-flow backstop (TcpFlowSession.armTerminalDrainBackstop)

    private final class SessionFx {
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
            self.session.ctx.connection = conn
            self.session.egressReady = true
            self.session.ctx.egressReady = true
        }

        /// Barrier: return after any work scheduled on `flowQueue` with a
        /// deadline ≤ `afterMs` has run (serial queue ordering).
        func drainFlowQueue(afterMs: Int) {
            let sem = DispatchSemaphore(value: 0)
            session.flowQueue.asyncAfter(deadline: .now() + .milliseconds(afterMs)) {
                sem.signal()
            }
            _ = sem.wait(timeout: .now() + 2.0)
        }
    }

    /// `armTerminalDrainBackstop` marks the ctx `terminalSignalled`
    /// synchronously (so the watchdog can see it) and force-tears the
    /// flow down once `lingerCloseMs` elapses with the graceful close
    /// still pending.
    func testPerFlowBackstopForcesTeardownAfterDeadline() {
        let fx = SessionFx()
        fx.session.lingerCloseMs = 5
        fx.session.flowQueue.sync { fx.session.armTerminalDrainBackstop() }

        XCTAssertTrue(
            fx.session.ctx.terminalSignalled,
            "terminalSignalled must be set synchronously so the watchdog can observe it")
        XCTAssertFalse(
            fx.session.ctx.isDone,
            "teardown must not fire before the backstop deadline")

        fx.drainFlowQueue(afterMs: 60)

        XCTAssertTrue(fx.session.ctx.isDone, "backstop must force a full teardown")
        XCTAssertEqual(fx.conn.cancelCount, 1, "egress connection cancelled exactly once")
        XCTAssertNil(fx.session.ctx.connection, "connection slot nilled by applyFullTeardown")
    }

    /// If the graceful close already completed (teardown `done`), the
    /// backstop is a no-op — no double teardown, no double cancel.
    func testPerFlowBackstopNoOpsWhenGracefulCloseWon() {
        let fx = SessionFx()
        fx.session.lingerCloseMs = 5
        // Graceful close wins first (client drained in time).
        fx.session.flowQueue.sync {
            fx.session.ctx.applyDrainedClose(wasOpened: true)
        }
        XCTAssertTrue(fx.session.ctx.isDone)
        let cancelsAfterGraceful = fx.conn.cancelCount

        fx.session.flowQueue.sync { fx.session.armTerminalDrainBackstop() }
        fx.drainFlowQueue(afterMs: 60)

        XCTAssertEqual(
            fx.conn.cancelCount, cancelsAfterGraceful,
            "backstop must not cancel again after a graceful close already ran")
    }

    // MARK: - Maintenance watchdog (closing-stuck reap)

    private final class WatchdogFx {
        let flow = MockTcpFlow()
        let conn = MockNwConnection()
        let ctx = TcpFlowContext()
        let flowId: ObjectIdentifier

        init(core: TransparentProxyCore, ready: Bool, closing: Bool) {
            self.flowId = ObjectIdentifier(flow)
            self.ctx.connection = conn
            self.ctx.egressReady = ready
            self.ctx.terminalSignalled = closing
            self.ctx.flow = flow
            self.ctx.core = core
            self.ctx.flowId = flowId
            // The watchdog's wedge test is idle-gated in BOTH modes (a
            // closing flow still moving bytes is a live half-close and must
            // be spared). These fixtures model a QUIET wedge, so age the
            // activity clock past the linger budget.
            self.ctx.lingerCloseMs = 0
            self.ctx.lastActivityAt = DispatchTime(
                uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds &- 1_000_000_000)
        }

        var wasTornDown: Bool { ctx.isDone }
    }

    /// A post-`.ready` flow that signalled close but is still in the
    /// registry one tick later has a wedged drain → force-torn-down on
    /// the second consecutive tick (mirrors the pre-ready watchdog
    /// cadence). This is the queue-starvation-proof safety net for the
    /// permanent leak.
    func testWatchdogReapsWedgedClosingFlowOnSecondTick() {
        let core = TransparentProxyCore()
        let fx = WatchdogFx(core: core, ready: true, closing: true)
        core.testInsertTcpContext(fx.flowId, fx.ctx)

        core.testRunPeriodicMaintenance()  // tick 1: record only
        XCTAssertFalse(fx.wasTornDown, "first tick records, must not kick")
        XCTAssertTrue(
            core.testStuckClosingFlowIds.contains(fx.flowId),
            "closing-but-registered flow must be recorded for the next tick")

        core.testRunPeriodicMaintenance()  // tick 2: kick
        XCTAssertTrue(fx.wasTornDown, "wedged closing flow reaped on the second tick")
        XCTAssertEqual(fx.conn.cancelCount, 1, "egress connection cancelled once")
        XCTAssertNil(
            core.testInspectTcpContext(for: fx.flow),
            "force teardown must remove the ctx from the registry")
    }

    /// A post-`.ready` flow that has NOT signalled close is active —
    /// the watchdog must never touch it. Regression guard against
    /// killing live long-lived flows (keep-alive, SSE, websockets).
    func testWatchdogIgnoresActiveReadyFlow() {
        let core = TransparentProxyCore()
        let fx = WatchdogFx(core: core, ready: true, closing: false)
        core.testInsertTcpContext(fx.flowId, fx.ctx)

        core.testRunPeriodicMaintenance()
        core.testRunPeriodicMaintenance()

        XCTAssertFalse(fx.wasTornDown, "an active (non-closing) ready flow must survive")
        XCTAssertEqual(fx.conn.cancelCount, 0)
        XCTAssertFalse(core.testStuckClosingFlowIds.contains(fx.flowId))
    }

    /// A closing flow whose graceful close completes between ticks
    /// leaves the registry, so the watchdog finds nothing to kick and
    /// does not double-teardown.
    func testWatchdogSkipsFlowThatClosedBetweenTicks() {
        let core = TransparentProxyCore()
        let fx = WatchdogFx(core: core, ready: true, closing: true)
        core.testInsertTcpContext(fx.flowId, fx.ctx)

        core.testRunPeriodicMaintenance()  // tick 1: record
        // Graceful close (or the per-flow backstop) wins; ctx leaves
        // the registry and the watchdog tracking set.
        fx.ctx.applyDrainedClose(wasOpened: true)
        XCTAssertNil(core.testInspectTcpContext(for: fx.flow))
        XCTAssertFalse(core.testStuckClosingFlowIds.contains(fx.flowId))
        let cancels = fx.conn.cancelCount

        core.testRunPeriodicMaintenance()  // tick 2: nothing to kick
        XCTAssertEqual(
            fx.conn.cancelCount, cancels,
            "no second teardown after the graceful close already ran")
    }

    /// A flow that signals close only AFTER tick 1 must wait a full
    /// extra tick before being kicked — single observation is not
    /// enough, same one-tick-grace rule as the pre-ready watchdog.
    func testWatchdogClosingFlowNeedsTwoConsecutiveTicks() {
        let core = TransparentProxyCore()
        let fx = WatchdogFx(core: core, ready: true, closing: false)
        core.testInsertTcpContext(fx.flowId, fx.ctx)

        core.testRunPeriodicMaintenance()  // tick 1: active, not recorded
        fx.ctx.terminalSignalled = true  // signals close after tick 1
        core.testRunPeriodicMaintenance()  // tick 2: first observation → record only

        XCTAssertFalse(fx.wasTornDown, "only observed closing once; must wait one more tick")
        XCTAssertTrue(core.testStuckClosingFlowIds.contains(fx.flowId))

        core.testRunPeriodicMaintenance()  // tick 3: kick
        XCTAssertTrue(fx.wasTornDown)
        XCTAssertEqual(fx.conn.cancelCount, 1)
    }

    /// A closing (`terminalSignalled`) flow still moving bytes is a live
    /// half-close (e.g. upload EOF while the download keeps streaming) and
    /// the watchdog must not reset it, however many ticks pass.
    func testWatchdogSparesActivelyDrainingClosingFlow() {
        let core = TransparentProxyCore()
        let fx = WatchdogFx(core: core, ready: true, closing: true)
        fx.ctx.lingerCloseMs = 5_000
        core.testInsertTcpContext(fx.flowId, fx.ctx)

        for _ in 0..<3 {
            fx.ctx.lastActivityAt = .now()  // bytes keep moving
            core.testRunPeriodicMaintenance()
        }

        XCTAssertFalse(
            fx.wasTornDown,
            "closing flow still moving bytes is a live half-close, not a wedge")
        XCTAssertEqual(fx.conn.cancelCount, 0)
    }
}
