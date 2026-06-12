import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Tests for the flow-pressure backstop in `TransparentProxyCore`
/// (`reapIdleUnderPressure`).
///
/// Background: a macOS NE app-proxy provider has a per-process kernel
/// nexus-flow allocation; each intercepted flow consumes slots (the app's
/// ingress `NEAppProxyFlow` + our egress `NWConnection`). A fast burst of
/// connections can approach the ceiling faster than keepalive (~30s, dead
/// peers) or the idle reaper (minutes) reclaim, and exhaustion freezes ALL
/// proxied networking (`NECP_CLIENT_ACTION_ADD_FLOW … ENOMEM`).
///
/// The backstop: when admitting a flow pushes the COMBINED live count to/over
/// `defaultFlowPressureSoftCap`, reap `.promoted` flows idle past
/// `defaultFlowPressureIdleFloorMs`, oldest-idle first (LRU), down to
/// `defaultFlowPressureLowWater` — freeing slots for SUBSEQUENT flows while
/// NEVER refusing the new one and NEVER touching an active flow.
///
/// These drive the reap synchronously via `testReapIdleUnderPressure` and push
/// `lastActivityAt` into the past instead of waiting real time.
final class FlowPressureReaperTests: XCTestCase {

    private var savedSoftCap: UInt32 = 0
    private var savedLowWater: UInt32 = 0
    private var savedFloorMs: UInt32 = 0

    override func setUp() {
        super.setUp()
        savedSoftCap = defaultFlowPressureSoftCap
        savedLowWater = defaultFlowPressureLowWater
        savedFloorMs = defaultFlowPressureIdleFloorMs
    }

    override func tearDown() {
        defaultFlowPressureSoftCap = savedSoftCap
        defaultFlowPressureLowWater = savedLowWater
        defaultFlowPressureIdleFloorMs = savedFloorMs
        super.tearDown()
    }

    /// An established, `.promoted` ctx wired for teardown, backdated to a chosen
    /// idle age on the monotonic clock so it reads as idle without a wait.
    private final class Fx {
        let flow: MockTcpFlow
        let conn: MockNwConnection
        let ctx: TcpFlowContext
        let flowId: ObjectIdentifier

        init(core: TransparentProxyCore, idleSeconds: UInt64, mode: TcpFlowMode = .promoted) {
            self.flow = MockTcpFlow()
            self.conn = MockNwConnection()
            self.ctx = TcpFlowContext()
            self.ctx.connection = conn
            self.flowId = ObjectIdentifier(flow)
            self.ctx.flow = flow
            self.ctx.core = core
            self.ctx.flowId = flowId
            self.ctx.egressReady = true
            self.ctx.mode = mode
            let backNs = idleSeconds &* 1_000_000_000
            let nowNs = DispatchTime.now().uptimeNanoseconds
            self.ctx.lastActivityAt = DispatchTime(
                uptimeNanoseconds: nowNs > backNs ? nowNs - backNs : 1)
        }

        var wasTornDown: Bool { ctx.isDone }
    }

    private func makeCore() -> TransparentProxyCore { TransparentProxyCore() }

    private func insert(_ core: TransparentProxyCore, _ fxs: [Fx]) {
        for fx in fxs { core.testInsertTcpContext(fx.flowId, fx.ctx) }
    }

    // MARK: - Reap idle down to low-water

    func testIdlePromotedFlowsEvictedDownTowardLowWater() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        // 5 promoted flows, all idle 10s (> 5s floor). Occupancy 5 ≥ cap 3 ⇒
        // want = 5 − low-water 2 = 3 evicted.
        let fxs = (0..<5).map { _ in Fx(core: core, idleSeconds: 10) }
        insert(core, fxs)

        core.testReapIdleUnderPressure()

        XCTAssertEqual(
            fxs.filter { $0.wasTornDown }.count, 3,
            "evict down to low-water (occupancy 5 − low-water 2 = 3)")
    }

    // MARK: - LRU: oldest-idle first

    func testEvictsOldestIdleFirst() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 3
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        // 4 idle flows (6/7/8/9s). Occupancy 4 ≥ cap 3 ⇒ want = 4 − 3 = 1:
        // exactly the OLDEST-idle (9s) must go; the rest stay.
        let f6 = Fx(core: core, idleSeconds: 6)
        let f7 = Fx(core: core, idleSeconds: 7)
        let f8 = Fx(core: core, idleSeconds: 8)
        let f9 = Fx(core: core, idleSeconds: 9)
        insert(core, [f6, f7, f8, f9])

        core.testReapIdleUnderPressure()

        XCTAssertTrue(f9.wasTornDown, "oldest-idle (LRU) evicted first")
        XCTAssertFalse(f6.wasTornDown)
        XCTAssertFalse(f7.wasTornDown)
        XCTAssertFalse(f8.wasTornDown)
    }

    // MARK: - Never touch active flows

    func testActiveFlowsNeverEvictedEvenOverCap() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 60_000  // 60s floor
        let core = makeCore()
        // 5 recently-active flows (idle ~0): over the cap, but none idle past
        // the floor ⇒ admit-and-ride, evict NOTHING.
        let fxs = (0..<5).map { _ in Fx(core: core, idleSeconds: 0) }
        insert(core, fxs)

        core.testReapIdleUnderPressure()

        XCTAssertEqual(
            fxs.filter { $0.wasTornDown }.count, 0,
            "an active flow is never evicted — we admit-and-ride instead")
    }

    func testMixedLoadSparesActiveEvictsIdle() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let active1 = Fx(core: core, idleSeconds: 0)
        let active2 = Fx(core: core, idleSeconds: 1)
        let idle1 = Fx(core: core, idleSeconds: 10)
        let idle2 = Fx(core: core, idleSeconds: 20)
        let idle3 = Fx(core: core, idleSeconds: 30)
        insert(core, [active1, active2, idle1, idle2, idle3])

        // Occupancy 5 ≥ cap 3 ⇒ want = 3; eligible (idle > 5s) = idle1/2/3.
        core.testReapIdleUnderPressure()

        XCTAssertTrue(idle1.wasTornDown && idle2.wasTornDown && idle3.wasTornDown)
        XCTAssertFalse(active1.wasTornDown, "recently-active flow spared")
        XCTAssertFalse(active2.wasTornDown, "recently-active flow spared")
    }

    // MARK: - Scope: mode-agnostic (global)

    /// The pressure backstop is GLOBAL: nexus pressure is mode-agnostic, and
    /// both modes now bump `lastActivityAt` on the shared write-pump flowQueue
    /// hop. So idle `viaRust` flows ARE reapable under pressure — not only
    /// `.promoted`. (Their slower per-mode hygiene backstop is still the Rust
    /// engine's idle timeout; this is the fast global one.)
    func testIdleViaRustFlowsEvictedUnderPressure() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let viaRust = (0..<5).map { _ in Fx(core: core, idleSeconds: 30, mode: .viaRust) }
        insert(core, viaRust)

        core.testReapIdleUnderPressure()

        XCTAssertEqual(
            viaRust.filter { $0.wasTornDown }.count, 3,
            "idle viaRust flows are reapable under pressure too (occupancy 5 − low-water 2 = 3)")
    }

    /// The safety counterpart: an ACTIVE viaRust flow (recent `lastActivityAt`,
    /// as the write-pump `onActivity` hook keeps it) is never pressure-evicted,
    /// even over the cap — this is what the per-mode activity signal protects.
    func testActiveViaRustFlowSparedUnderPressure() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 60_000  // 60s floor
        let core = makeCore()
        let active = (0..<5).map { _ in Fx(core: core, idleSeconds: 0, mode: .viaRust) }
        insert(core, active)

        core.testReapIdleUnderPressure()

        XCTAssertEqual(
            active.filter { $0.wasTornDown }.count, 0,
            "actively-transferring viaRust flows must never be pressure-evicted")
    }

    // MARK: - Closing flows excluded

    func testAlreadyClosingFlowNotSelected() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let closing = Fx(core: core, idleSeconds: 30)
        closing.ctx.terminalSignalled = true  // already winding down
        let idle = Fx(core: core, idleSeconds: 30)
        insert(core, [closing, idle])

        core.testReapIdleUnderPressure()

        XCTAssertFalse(
            closing.wasTornDown, "a flow already closing is not double-torn by the backstop")
        XCTAssertTrue(idle.wasTornDown)
    }

    // MARK: - Below cap / disabled

    func testNoEvictionBelowSoftCap() {
        defaultFlowPressureSoftCap = 10
        defaultFlowPressureLowWater = 5
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        // 3 idle flows but only 3 < cap 10 ⇒ no pressure, no eviction.
        let fxs = (0..<3).map { _ in Fx(core: core, idleSeconds: 30) }
        insert(core, fxs)

        core.testReapIdleUnderPressure()

        XCTAssertEqual(fxs.filter { $0.wasTornDown }.count, 0, "no eviction below the soft cap")
    }

    func testZeroSoftCapDisablesBackstop() {
        defaultFlowPressureSoftCap = 0
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let fxs = (0..<10).map { _ in Fx(core: core, idleSeconds: 999) }
        insert(core, fxs)

        core.testReapIdleUnderPressure()

        XCTAssertEqual(
            fxs.filter { $0.wasTornDown }.count, 0, "soft cap 0 disables the backstop entirely")
    }
}
