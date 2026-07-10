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

        init(
            core: TransparentProxyCore, idleSeconds: UInt64, mode: TcpFlowMode = .promoted,
            ready: Bool = true, flowQueue: DispatchQueue? = nil
        ) {
            self.flow = MockTcpFlow()
            self.conn = MockNwConnection()
            self.ctx = TcpFlowContext()
            self.ctx.connection = conn
            self.flowId = ObjectIdentifier(flow)
            self.ctx.flow = flow
            self.ctx.core = core
            self.ctx.flowId = flowId
            // A real per-flow serial queue makes `runFlowTeardown` DISPATCH the
            // eviction (as in production) instead of running it inline, so the
            // on-`flowQueue` re-check is exercised against the real async window.
            // Defaults nil to preserve the synchronous-assertion tests.
            self.ctx.flowQueue = flowQueue
            self.ctx.egressReady = ready
            self.ctx.mode = mode
            let backNs = idleSeconds &* 1_000_000_000
            let nowNs = DispatchTime.now().uptimeNanoseconds
            self.ctx.lastActivityAt = DispatchTime(
                uptimeNanoseconds: nowNs > backNs ? nowNs - backNs : 1)
        }

        var wasTornDown: Bool { ctx.isDone }

        /// Bump activity to "now" so the flow reads as freshly active.
        func markActiveNow() { ctx.lastActivityAt = .now() }
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

    // MARK: - Closing flows

    /// A closing flow whose drain is still making progress (idle past the
    /// pressure floor but within its linger budget) is winding down
    /// GRACEFULLY — the reaper must not double-tear it.
    func testActivelyClosingFlowNotSelected() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let closing = Fx(core: core, idleSeconds: 30)
        closing.ctx.terminalSignalled = true  // winding down…
        closing.ctx.drainClosePending = true
        closing.ctx.lingerCloseMs = 60_000  // …within its linger budget
        let idle = Fx(core: core, idleSeconds: 30)
        insert(core, [closing, idle])

        core.testReapIdleUnderPressure()

        XCTAssertFalse(
            closing.wasTornDown,
            "a gracefully-closing flow (not drain-wedged) is not double-torn by the backstop")
        XCTAssertTrue(idle.wasTornDown)
    }

    /// A closing flow quiet past its linger budget has a wedged drain: dead
    /// weight holding a nexus slot. Under cap pressure it is eligible, not
    /// shielded by `terminalSignalled`.
    func testWedgedClosingFlowIsPressureEvicted() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let wedged = Fx(core: core, idleSeconds: 30)
        wedged.ctx.terminalSignalled = true  // closing…
        wedged.ctx.drainClosePending = true
        wedged.ctx.lingerCloseMs = 5_000  // …and quiet past the linger budget
        insert(core, [wedged, Fx(core: core, idleSeconds: 1), Fx(core: core, idleSeconds: 1)])

        core.testReapIdleUnderPressure()

        XCTAssertTrue(
            wedged.wasTornDown,
            "a drain-wedged closing flow is reapable under pressure")
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

    // MARK: - Near-cap fan-out (scale invariants)

    /// The proof-obligation test: a registry filled past the soft cap with a
    /// realistic MIX — actively-transferring flows, idle flows of varying age,
    /// and still-connecting (pre-ready) flows — reaped in one pass. Asserts the
    /// load-bearing invariants at scale: occupancy is brought DOWN TO low-water
    /// (not below), ONLY idle flows are evicted (oldest-first), and NO active
    /// or pre-ready flow is ever touched.
    func testFanOutReapsOldestIdleToLowWaterSparingActiveAndPreReady() {
        defaultFlowPressureSoftCap = 100
        defaultFlowPressureLowWater = 80
        defaultFlowPressureIdleFloorMs = 5_000  // 5s
        let core = makeCore()

        // 40 active (idle ~0 < floor), 70 idle (ages 11…80s, all > floor),
        // 10 pre-ready (old but egress not yet up). Total 120 ≥ cap 100 ⇒
        // want = 120 − low-water 80 = 40 evicted, all from the idle pool
        // (oldest first); everything else spared.
        let active = (0..<40).map { _ in Fx(core: core, idleSeconds: 0) }
        let idle = (11...80).map { Fx(core: core, idleSeconds: UInt64($0)) }
        let preReady = (0..<10).map { _ in Fx(core: core, idleSeconds: 999, ready: false) }
        insert(core, active)
        insert(core, idle)
        insert(core, preReady)

        core.testReapIdleUnderPressure()

        XCTAssertEqual(idle.filter { $0.wasTornDown }.count, 40, "evict 40 idle (down to low-water)")
        XCTAssertEqual(active.filter { $0.wasTornDown }.count, 0, "no active flow evicted")
        XCTAssertEqual(preReady.filter { $0.wasTornDown }.count, 0, "no pre-ready flow evicted")
        let survivors = (active + idle + preReady).filter { !$0.wasTornDown }.count
        XCTAssertEqual(
            survivors, 80, "occupancy brought down to exactly low-water (stops there, not below)")

        // LRU boundary: `idle` is built ages 11…80, so the stalest is last and
        // the freshest is first. The stalest must be evicted, the freshest kept.
        XCTAssertTrue(idle.last!.wasTornDown, "stalest idle flow (80s) evicted")
        XCTAssertFalse(idle.first!.wasTornDown, "freshest idle flow (11s) spared")
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

    // MARK: - TG-2: the select-then-revive on-flowQueue re-check

    /// The reaper SELECTS victims off-queue, then RE-CHECKS idleness on each
    /// victim's `flowQueue` before tearing it down. This injects activity into a
    /// selected victim AFTER selection but BEFORE the fire body, and asserts the
    /// re-check spares it. The existing reaper tests revive a flow BEFORE
    /// selection (so it's filtered at selection and the re-check never runs);
    /// this is the only test that exercises the guard itself — deleting it would
    /// tear the revived victim down and fail here.
    func testVictimRevivedBetweenSelectionAndFireIsSparedByRecheck() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        // 3 idle flows → want = 3 − low-water 1 = 2 victims (the two stalest).
        let stalest = Fx(core: core, idleSeconds: 30)
        let middle = Fx(core: core, idleSeconds: 20)
        let freshest = Fx(core: core, idleSeconds: 10)
        insert(core, [stalest, middle, freshest])

        let victims = core.testCollectPressureVictims()
        XCTAssertEqual(victims.count, 2, "the two stalest flows are selected")

        // Revive the stalest selected victim AFTER selection; the fire-body
        // re-check must now spare it.
        stalest.markActiveNow()
        core.testFirePressureEvictions(victims)

        XCTAssertFalse(
            stalest.wasTornDown,
            "a victim that became active between selection and teardown must be spared")
        XCTAssertTrue(middle.wasTornDown, "the still-idle selected victim is evicted")
        XCTAssertFalse(freshest.wasTornDown, "a non-selected flow is never touched")
    }

    // MARK: - TG-6: UDP counts toward occupancy but is never a victim

    /// Eviction selects ONLY from `tcpSessions`, but occupancy counts
    /// `tcp + udp` (the nexus ceiling is global). A UDP-dominated population
    /// over the cap must evict idle TCP flows (what it can) while never
    /// selecting a UDP flow as a victim.
    func testUdpCountsTowardOccupancyButIsNeverEvicted() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let idleTcp = Fx(core: core, idleSeconds: 30)
        insert(core, [idleTcp])
        // 5 UDP entries → combined occupancy 6 ≥ cap 4.
        var udpHolders: [NSObject] = []
        for _ in 0..<5 {
            let o = NSObject()
            udpHolders.append(o)
            core.testInsertUdpContext(ObjectIdentifier(o), UdpFlowContext())
        }
        XCTAssertEqual(core.udpFlowCount, 5)

        core.testReapIdleUnderPressure()

        XCTAssertTrue(idleTcp.wasTornDown, "the idle TCP flow IS evicted (TCP is evictable)")
        XCTAssertEqual(
            core.udpFlowCount, 5, "UDP flows count toward occupancy but are never evicted")
        _ = udpHolders
    }

    // MARK: - TG-7: the production async reap path (not the sync test shim)

    /// Drive the REAL `reapIdleUnderPressure()` (stateQueue.async selection →
    /// per-victim flowQueue.async teardown) end to end, with real per-flow
    /// queues, rather than the synchronous `testReapIdleUnderPressure` shim. The
    /// async path must evict down to low-water just like the shim.
    func testProductionAsyncReapEvictsIdleFlows() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let q = DispatchQueue(label: "rama.test.pressure.async")
        let fxs = (0..<5).map { _ in Fx(core: core, idleSeconds: 30, flowQueue: q) }
        insert(core, fxs)

        core.reapIdleUnderPressure()  // production async entrypoint

        // The teardowns are dispatched onto `q`; a barrier well after they are
        // enqueued runs strictly after them on this serial queue.
        let exp = expectation(description: "async reap completed")
        q.asyncAfter(deadline: .now() + .milliseconds(300)) { exp.fulfill() }
        wait(for: [exp], timeout: 3.0)

        XCTAssertEqual(
            fxs.filter { $0.wasTornDown }.count, 3,
            "the async production path evicts down to low-water (5 − 2 = 3)")
    }
}
