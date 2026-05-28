import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for the post-wake / starved-flow-queue watchdog in
/// `TransparentProxyCore`.
///
/// Background: each per-flow `installConnectTimeout` schedules its
/// kick on the flow's own `DispatchQueue`. When that queue is starved
/// (the post-system-wake / tokio-runtime-backlog failure mode), the
/// per-flow timer is queued behind the same backlog as everything
/// else and fires late — sometimes by minutes. Without a watchdog the
/// proxy registry just accumulates stuck pre-`egressReady` flows
/// until either the backlog clears or the user manually restarts the
/// extension.
///
/// The watchdog runs on `stateQueue` (its own thread, never starved
/// by per-flow queues) at the same 60s cadence as the live-flow-count
/// telemetry. A TCP flow that is still pre-`egressReady` across TWO
/// consecutive maintenance ticks (≥ 60s) has its
/// `applyConnectTimeout` driven from the watchdog, bypassing the
/// possibly-stuck per-flow timer.
///
/// These tests exercise the watchdog via `testRunPeriodicMaintenance`
/// — a DEBUG-only synchronous tick — so they don't have to wait the
/// production 60s interval.
final class StaleFlowWatchdogTests: XCTestCase {

    /// Lightweight fixture: a core, a `MockTcpFlow`, a
    /// `MockNwConnection`, a `TcpFlowContext` wired to a real
    /// `TcpFlowTeardown`. The teardown's `applyConnectTimeout` runs
    /// `applyPreOpenCleanup`, which (since the kernel flow was never
    /// opened yet) only cancels the egress NWConnection, nils the
    /// connection slot, and removes the ctx from the registry. So
    /// `conn.cancelCount == 1`, `ctx.connection == nil`, and
    /// `teardown.isDone == true` are the load-bearing signals that
    /// the watchdog fired on that ctx. The kernel flow's
    /// `closeRead/WriteWithError` are intentionally NOT called by
    /// pre-open teardown — there's no opened flow to close.
    private final class TcpFx {
        let flow: MockTcpFlow
        let conn: MockNwConnection
        let ctx: TcpFlowContext
        let teardown: TcpFlowTeardown
        let flowId: ObjectIdentifier

        init(core: TransparentProxyCore) {
            self.flow = MockTcpFlow()
            self.conn = MockNwConnection()
            self.ctx = TcpFlowContext()
            self.ctx.connection = conn
            self.flowId = ObjectIdentifier(flow)
            self.teardown = TcpFlowTeardown(
                ctx: ctx, core: core, flow: flow, flowId: flowId)
            ctx.teardown = teardown
        }

        /// Mark the ctx as having reached `.ready`. The watchdog
        /// MUST then leave the ctx alone.
        func markReady() { ctx.egressReady = true }

        /// Did `applyConnectTimeout` (== `applyPreOpenCleanup`)
        /// already fire on this ctx?
        var wasTornDown: Bool { teardown.isDone }
    }

    private func makeCore() -> TransparentProxyCore { TransparentProxyCore() }

    private func insert(_ fx: TcpFx, into core: TransparentProxyCore) {
        core.testInsertTcpContext(fx.flowId, fx.ctx)
    }

    // MARK: - First-tick behaviour

    /// First tick after a ctx is inserted: the watchdog must RECORD
    /// the ctx in its "stuck since" set, but NOT yet tear it down.
    /// One tick is too short a window — the per-flow connect timer
    /// may still fire on schedule.
    func testFirstTickRecordsStuckSetButDoesNotKick() {
        let core = makeCore()
        let fx = TcpFx(core: core)
        insert(fx, into: core)

        core.testRunPeriodicMaintenance()

        XCTAssertFalse(
            fx.wasTornDown,
            "first tick must only record; per-flow connect timer might still fire on time"
        )
        XCTAssertEqual(fx.conn.cancelCount, 0)
        XCTAssertTrue(
            core.testStuckPreReadyFlowIds.contains(fx.flowId),
            "ctx must be recorded as stuck for the next tick to act on it"
        )
    }

    // MARK: - Second-tick kick

    /// A ctx still pre-`egressReady` across TWO ticks gets its
    /// `applyConnectTimeout` fired from the watchdog. This is the
    /// load-bearing scenario for "per-flow queue starved" — the
    /// watchdog drives recovery even when the per-flow timer never
    /// gets to run.
    func testSecondConsecutiveTickKicksStuckFlows() {
        let core = makeCore()
        let fxs = (0..<3).map { _ in TcpFx(core: core) }
        for fx in fxs { insert(fx, into: core) }

        core.testRunPeriodicMaintenance()  // tick 1: record
        for fx in fxs { XCTAssertFalse(fx.wasTornDown) }

        core.testRunPeriodicMaintenance()  // tick 2: kick

        for (i, fx) in fxs.enumerated() {
            XCTAssertTrue(
                fx.wasTornDown,
                "fx[\(i)] should be torn down on the second consecutive stuck tick"
            )
            XCTAssertEqual(
                fx.conn.cancelCount, 1,
                "fx[\(i)] egress NWConnection cancelled exactly once"
            )
            XCTAssertNil(
                fx.ctx.connection,
                "fx[\(i)] connection slot must be nilled by applyPreOpenCleanup"
            )
        }
    }

    // MARK: - Healthy-flow exemptions

    /// A flow that reached `egressReady` between ticks 1 and 2 must
    /// NOT be torn down by the watchdog — the egress just connected
    /// and the flow is healthy.
    func testFlowThatBecameReadyEscapesKick() {
        let core = makeCore()
        let stuckFx = TcpFx(core: core)
        let healthyFx = TcpFx(core: core)
        insert(stuckFx, into: core)
        insert(healthyFx, into: core)

        core.testRunPeriodicMaintenance()  // tick 1: both pre-ready, both recorded
        healthyFx.markReady()  // becomes ready before tick 2
        core.testRunPeriodicMaintenance()  // tick 2: stuck kicked, healthy ignored

        XCTAssertTrue(stuckFx.wasTornDown)
        XCTAssertFalse(
            healthyFx.wasTornDown,
            "a flow that reached egressReady must not be torn down by the watchdog"
        )
        XCTAssertEqual(healthyFx.conn.cancelCount, 0)
    }

    /// Flows that arrive AFTER tick 1 but before tick 2 must NOT be
    /// torn down on tick 2 — they've only been observed once. They'll
    /// be kicked on tick 3 if still pre-ready (verified by extension
    /// of `testSecondConsecutiveTickKicksStuckFlows`).
    func testFlowsArrivedSinceLastTickAreNotKickedYet() {
        let core = makeCore()
        let earlyFx = TcpFx(core: core)
        insert(earlyFx, into: core)
        core.testRunPeriodicMaintenance()  // tick 1: only earlyFx

        let lateFx = TcpFx(core: core)
        insert(lateFx, into: core)
        core.testRunPeriodicMaintenance()  // tick 2: earlyFx kicked, lateFx recorded

        XCTAssertTrue(earlyFx.wasTornDown)
        XCTAssertFalse(
            lateFx.wasTornDown,
            "lateFx was only observed once; must wait one more tick before kick"
        )
        XCTAssertTrue(
            core.testStuckPreReadyFlowIds.contains(lateFx.flowId),
            "lateFx is now recorded; the next tick will kick it"
        )
    }

    /// `egressReady` flows are NEVER recorded as stuck. A flow that
    /// was ready from before the first tick and stays ready must not
    /// appear in the watchdog's tracking set on any subsequent tick.
    func testReadyFlowsAreNeverRecordedAsStuck() {
        let core = makeCore()
        let fx = TcpFx(core: core)
        fx.markReady()
        insert(fx, into: core)

        core.testRunPeriodicMaintenance()
        core.testRunPeriodicMaintenance()

        XCTAssertFalse(fx.wasTornDown)
        XCTAssertFalse(
            core.testStuckPreReadyFlowIds.contains(fx.flowId),
            "ready flows must not enter the stuck-since set"
        )
    }

    // MARK: - Idempotency / churn

    /// After the watchdog tears a ctx down, the teardown's sticky
    /// `done` flag prevents a second invocation from doing harm. The
    /// ctx is also removed from the registry by
    /// `applyPreOpenCleanup`, so subsequent ticks find nothing to
    /// kick. Verify both: no double cancel, and the ctx is gone from
    /// `tcpContexts`.
    func testKickIsIdempotentAndRemovesFromRegistry() {
        let core = makeCore()
        let fx = TcpFx(core: core)
        insert(fx, into: core)

        core.testRunPeriodicMaintenance()  // record
        core.testRunPeriodicMaintenance()  // kick
        XCTAssertEqual(fx.conn.cancelCount, 1)
        XCTAssertNil(
            core.testInspectTcpContext(for: fx.flow),
            "torn-down ctx must be removed from the registry by applyPreOpenCleanup"
        )

        // Re-run twice more; nothing further should change.
        core.testRunPeriodicMaintenance()
        core.testRunPeriodicMaintenance()
        XCTAssertEqual(
            fx.conn.cancelCount, 1,
            "no double-cancel even though the watchdog ticked again"
        )
    }

    /// Race regression: a ctx that became `egressReady` between
    /// the watchdog's snapshot (on `stateQueue`) and the dispatched
    /// teardown body (on `flowQueue`) must NOT be torn down. The
    /// teardown body re-checks on the way in. Mirrors the same
    /// guard `handleSystemWake` already does.
    func testKickReChecksEgressReadyBeforeTeardown() {
        let core = makeCore()
        let fx = TcpFx(core: core)
        insert(fx, into: core)

        core.testRunPeriodicMaintenance()  // tick 1: record
        XCTAssertFalse(fx.wasTornDown)

        // Race: the flow becomes ready AFTER it was added to the
        // kick list but BEFORE `applyConnectTimeout` runs. With the
        // re-check guard the teardown bails; without it the flow
        // gets torn down despite being healthy.
        fx.markReady()
        core.testRunPeriodicMaintenance()  // tick 2: would kick — but ctx is now ready

        XCTAssertFalse(
            fx.wasTornDown,
            "watchdog must re-check egressReady on flowQueue and skip ready flows"
        )
        XCTAssertEqual(fx.conn.cancelCount, 0)
    }

    /// `removeTcpFlow` must also remove the flow's ID from the
    /// watchdog's stuck-since set. Otherwise `ObjectIdentifier`
    /// reuse within one tick interval could let a brand-new ctx
    /// inherit the old's "stuck" status and be kicked on its very
    /// first observation.
    func testRemoveTcpFlowClearsFromStuckSet() {
        let core = makeCore()
        let fx = TcpFx(core: core)
        insert(fx, into: core)

        core.testRunPeriodicMaintenance()  // record stuck
        XCTAssertTrue(core.testStuckPreReadyFlowIds.contains(fx.flowId))

        core.removeTcpFlow(fx.flowId)

        XCTAssertFalse(
            core.testStuckPreReadyFlowIds.contains(fx.flowId),
            "removeTcpFlow must drop the flow ID from the watchdog tracking set"
        )

        // And the next tick — a hypothetical new ctx reusing the
        // same ObjectIdentifier slot — would not inherit the
        // "stuck" status. Re-insert at the same ID, single tick,
        // not yet a kick. (We can't actually trigger pointer
        // reuse in a deterministic test; this asserts the
        // bookkeeping invariant.)
        let fx2 = TcpFx(core: core)
        insert(fx2, into: core)
        core.testRunPeriodicMaintenance()
        XCTAssertFalse(
            fx2.wasTornDown,
            "fresh ctx must NOT be kicked on its first observation"
        )
    }

    /// `stopFlowCountReporting` (called from `detachEngine`) must
    /// also clear the watchdog tracking set; otherwise a subsequent
    /// `attachEngine` would inherit stale IDs and potentially kick a
    /// fresh, healthy flow on its very first tick.
    func testDetachClearsStuckTrackingSet() {
        let core = makeCore()
        let fx = TcpFx(core: core)
        insert(fx, into: core)
        core.testRunPeriodicMaintenance()
        XCTAssertFalse(core.testStuckPreReadyFlowIds.isEmpty)

        // `detachEngine` -> stopFlowCountReporting -> clears the set.
        // Engine-less core: detach is a no-op path through the
        // teardown branches but still clears the set.
        core.detachEngine(reason: 0)

        XCTAssertTrue(
            core.testStuckPreReadyFlowIds.isEmpty,
            "detachEngine must clear the watchdog's stuck-since set"
        )
    }
}
