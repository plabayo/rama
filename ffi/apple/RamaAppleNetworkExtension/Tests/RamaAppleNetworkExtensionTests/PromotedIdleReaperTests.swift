import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for the promoted-flow idle reaper in `TransparentProxyCore`'s
/// maintenance watchdog.
///
/// Background: a flow on the `viaRust` path is bounded by the Rust
/// engine's `DEFAULT_TCP_IDLE_TIMEOUT` (15 min, byte-progress based).
/// Promotion drops that backstop — the Rust service task drains to EOF
/// and exits at cutover — so a promoted flow whose peer goes silent
/// (yet stays TCP-alive, so egress keepalive never fails it) would pin
/// its egress `NWConnection`'s kernel nexus-flow slot indefinitely,
/// eventually exhausting the extension's per-process NECP allocation
/// and freezing ALL proxied networking
/// (`NECP_CLIENT_ACTION_ADD_FLOW … ENOMEM`).
///
/// The reaper restores parity: a promoted flow idle past
/// `defaultPromotedIdleTimeoutMs` is force-torn-down from the
/// `stateQueue` maintenance tick, exactly as the `viaRust` engine
/// would have reaped it. These tests drive the tick synchronously via
/// `testRunPeriodicMaintenance` and push `lastActivityAt` into the
/// past instead of waiting the production 15 min.
final class PromotedIdleReaperTests: XCTestCase {

    /// Saved + restored around each test because the reaper reads the
    /// process-global `defaultPromotedIdleTimeoutMs` (same `var`-tunable
    /// pattern as `defaultLingerCloseMs` et al.).
    private var savedTimeoutMs: UInt32 = 0

    override func setUp() {
        super.setUp()
        savedTimeoutMs = defaultPromotedIdleTimeoutMs
    }

    override func tearDown() {
        defaultPromotedIdleTimeoutMs = savedTimeoutMs
        super.tearDown()
    }

    /// A promoted, established ctx wired for teardown. Mirrors
    /// `StaleFlowWatchdogTests.TcpFx` but pre-set to the reaper's
    /// preconditions: `egressReady == true`, `mode == .promoted`,
    /// `terminalSignalled == false`, `lastActivityAt == now`.
    private final class PromotedFx {
        let flow: MockTcpFlow
        let conn: MockNwConnection
        let ctx: TcpFlowContext
        let flowId: ObjectIdentifier

        init(core: TransparentProxyCore) {
            self.flow = MockTcpFlow()
            self.conn = MockNwConnection()
            self.ctx = TcpFlowContext()
            self.ctx.connection = conn
            self.flowId = ObjectIdentifier(flow)
            self.ctx.flow = flow
            self.ctx.core = core
            self.ctx.flowId = flowId
            self.ctx.egressReady = true
            self.ctx.mode = .promoted
            self.ctx.lastActivityAt = .now()
        }

        /// Push `lastActivityAt` `seconds` into the past on the monotonic
        /// `DispatchTime` clock so the flow reads as idle without a wait.
        func backdateActivity(bySeconds seconds: UInt64) {
            let backNs = seconds &* 1_000_000_000
            let nowNs = DispatchTime.now().uptimeNanoseconds
            ctx.lastActivityAt = DispatchTime(
                uptimeNanoseconds: nowNs > backNs ? nowNs - backNs : 1)
        }

        var wasTornDown: Bool { ctx.isDone }
    }

    private func makeCore() -> TransparentProxyCore { TransparentProxyCore() }

    // MARK: - Reap on idle

    /// A promoted flow idle past the deadline is reaped on the FIRST
    /// tick that observes it — unlike the two-tick pre-ready watchdog,
    /// the multi-minute deadline is its own hysteresis. Teardown routes
    /// through `applyFullTeardown`: the egress NWConnection is cancelled
    /// once, the slot is nilled, and the ctx leaves the registry.
    func testIdlePromotedFlowIsReapedOnFirstTick() {
        defaultPromotedIdleTimeoutMs = 1_000  // 1s deadline
        let core = makeCore()
        let fx = PromotedFx(core: core)
        fx.backdateActivity(bySeconds: 10)  // 10s idle ≫ 1s deadline
        core.testInsertTcpContext(fx.flowId, fx.ctx)

        core.testRunPeriodicMaintenance()

        XCTAssertTrue(fx.wasTornDown, "idle promoted flow must be reaped")
        XCTAssertEqual(fx.conn.cancelCount, 1, "egress NWConnection cancelled exactly once")
        XCTAssertNil(fx.ctx.connection, "connection slot nilled by the full teardown")
        XCTAssertNil(
            core.testInspectTcpContext(for: fx.flow),
            "reaped ctx must be removed from the registry")
    }

    // MARK: - Spare the active

    /// The false-positive the reaper must avoid: a promoted flow with
    /// recent activity is healthy and must be left alone across ticks.
    func testActivePromotedFlowIsSpared() {
        defaultPromotedIdleTimeoutMs = 60_000  // 60s deadline
        let core = makeCore()
        let fx = PromotedFx(core: core)
        // lastActivityAt == now (set in init) — nowhere near 60s idle.
        core.testInsertTcpContext(fx.flowId, fx.ctx)

        core.testRunPeriodicMaintenance()
        core.testRunPeriodicMaintenance()

        XCTAssertFalse(fx.wasTornDown, "recently-active promoted flow must be spared")
        XCTAssertEqual(fx.conn.cancelCount, 0)
        XCTAssertNotNil(
            core.testInspectTcpContext(for: fx.flow), "active flow stays registered")
    }

    // MARK: - Scope: promoted-only

    /// The reaper is promoted-only. A `viaRust` flow — even idle past the
    /// deadline — is NOT reaped here: its idle backstop is the Rust
    /// engine's `DEFAULT_TCP_IDLE_TIMEOUT`, not this Swift watchdog.
    /// Reaping it here would double-reap and fight the engine.
    func testViaRustFlowIsNotReapedByIdleReaper() {
        defaultPromotedIdleTimeoutMs = 1_000
        let core = makeCore()
        let fx = PromotedFx(core: core)
        fx.ctx.mode = .viaRust  // override the promoted precondition
        fx.backdateActivity(bySeconds: 10)
        core.testInsertTcpContext(fx.flowId, fx.ctx)

        core.testRunPeriodicMaintenance()
        core.testRunPeriodicMaintenance()

        XCTAssertFalse(
            fx.wasTornDown,
            "viaRust idle is the engine's job; the Swift reaper must skip it")
        XCTAssertEqual(fx.conn.cancelCount, 0)
    }

    // MARK: - Disable knob

    /// `defaultPromotedIdleTimeoutMs == 0` disables the reaper entirely,
    /// even for a flow idle far past any sane deadline.
    func testZeroTimeoutDisablesReaper() {
        defaultPromotedIdleTimeoutMs = 0
        let core = makeCore()
        let fx = PromotedFx(core: core)
        fx.backdateActivity(bySeconds: 86_400)  // a day idle
        core.testInsertTcpContext(fx.flowId, fx.ctx)

        core.testRunPeriodicMaintenance()
        core.testRunPeriodicMaintenance()

        XCTAssertFalse(fx.wasTornDown, "timeout 0 must disable the reaper")
        XCTAssertEqual(fx.conn.cancelCount, 0)
    }

    // MARK: - Freshly-active flow is spared

    /// A flow that was idle but saw a byte just before the tick (its
    /// `lastActivityAt` bumped to now) must be spared: `promotedFlowIsIdle`
    /// reads the fresh timestamp at selection time and never adds it to
    /// the kick list. Models the forwarder moving a byte concurrently
    /// with a maintenance tick.
    func testFlowActiveAgainBeforeTickIsSpared() {
        defaultPromotedIdleTimeoutMs = 5_000  // 5s
        let core = makeCore()
        let fx = PromotedFx(core: core)
        fx.backdateActivity(bySeconds: 10)  // would be idle…
        core.testInsertTcpContext(fx.flowId, fx.ctx)
        fx.ctx.lastActivityAt = .now()  // …but a byte just moved

        core.testRunPeriodicMaintenance()

        XCTAssertFalse(
            fx.wasTornDown, "a flow active again before the tick must not be reaped")
        XCTAssertEqual(fx.conn.cancelCount, 0)
    }
}
