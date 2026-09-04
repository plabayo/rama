import Foundation
import Network
import NetworkExtension
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
/// The backstop reaps established idle TCP flows in either `.viaRust` or
/// `.promoted` mode, oldest-idle first, toward normalized low-water. It never
/// refuses the new flow or selects an active flow.
///
/// Selection-focused tests use the synchronous test seam and synthetic
/// activity times. Admission and composition tests use production entry points
/// and real per-flow queues.
final class FlowPressureReaperTests: XCTestCase {

    private var savedSoftCap: UInt32 = 0
    private var savedLowWater: UInt32 = 0
    private var savedFloorMs: UInt32 = 0
    private var cores: [TransparentProxyCore] = []
    private var pressureFlowQueues: [DispatchQueue] = []

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    override func setUp() {
        super.setUp()
        savedSoftCap = defaultFlowPressureSoftCap
        savedLowWater = defaultFlowPressureLowWater
        savedFloorMs = defaultFlowPressureIdleFloorMs
    }

    override func tearDown() {
        for core in cores { core.testDetachAndDrainFlowQueues() }
        for queue in pressureFlowQueues { queue.sync {} }
        for core in cores { _ = core.testPressureSelectionsTotal }
        pressureFlowQueues.removeAll(keepingCapacity: false)
        cores.removeAll(keepingCapacity: false)
        LifecycleLog.noticeOverride = nil
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

        /// Pressure teardown always closes the read half. Observe the mock's
        /// locked counter instead of racing the flow-queue-confined `isDone`.
        var wasTornDown: Bool { flow.closeReadCallCount > 0 }

        /// Bump activity to "now" so the flow reads as freshly active.
        func markActiveNow() { ctx.lastActivityAt = .now() }
    }

    private func makeCore(dispatchLeaseMs: UInt64 = 5_000) -> TransparentProxyCore {
        let core = TransparentProxyCore()
        core.testSetPressureVictimDispatchLeaseMs(dispatchLeaseMs)
        cores.append(core)
        return core
    }

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

    private func makeMeta(protocolRaw: UInt32) -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: protocolRaw,
            remoteHost: "127.0.0.1",
            remotePort: 443,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242)
    }

    func testProductionDispatchLeaseDefaultIsPinned() {
        XCTAssertEqual(TransparentProxyCore().testPressureVictimDispatchLeaseMs, 250)
    }

    func testDispatchLeaseToleratesBriefQueueContention() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        // Keep timing semantics separate from the exact production constant
        // pinned above. A generous test lease avoids false expiry when CI is
        // descheduled while this queue is intentionally blocked.
        let core = makeCore()
        let queue = DispatchQueue(label: "rama.test.pressure.production-lease")
        let victim = Fx(core: core, idleSeconds: 30, flowQueue: queue)
        let active = Fx(core: core, idleSeconds: 0)
        insert(core, [victim, active])

        let blockerEntered = DispatchSemaphore(value: 0)
        let releaseBlocker = DispatchSemaphore(value: 0)
        queue.async {
            blockerEntered.signal()
            releaseBlocker.wait()
        }
        XCTAssertEqual(blockerEntered.wait(timeout: .now() + 1), .success)
        var blockerReleased = false
        defer {
            if !blockerReleased { releaseBlocker.signal() }
        }

        core.testReapIdleUnderPressureIfDue()
        Thread.sleep(forTimeInterval: 0.10)
        XCTAssertEqual(core.testPressureExpiredTotal, 0)
        releaseBlocker.signal()
        blockerReleased = true
        pollUntil("victim commits before the dispatch lease") {
            victim.wasTornDown && core.testPressureEvictedTotal == 1
        }
    }

    func testTcpAdmissionDrivesProductionPressureTrigger() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let engine = makeEngine()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        defer { core.detachEngine(reason: 0) }

        let idle = Fx(core: core, idleSeconds: 30)
        insert(core, [idle])
        let admitted = MockTcpFlow()

        XCTAssertTrue(core.handleTcpFlow(admitted, meta: makeMeta(protocolRaw: 1)))
        pollUntil("TCP admission-triggered pressure reap") {
            idle.wasTornDown && core.testPressureEvictedTotal == 1
        }
        XCTAssertFalse(core.testInspectTcpContext(for: admitted)?.isDone ?? true)
    }

    func testUdpAdmissionDrivesProductionPressureTrigger() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let engine = makeEngine()
        core.attachEngine(engine)
        defer { core.detachEngine(reason: 0) }

        let idle = Fx(core: core, idleSeconds: 30)
        insert(core, [idle])
        let admitted = MockUdpFlow()

        XCTAssertEqual(
            core.handleUdpFlowDecision(admitted, meta: makeMeta(protocolRaw: 2)),
            .intercept)
        pollUntil("UDP admission-triggered pressure reap") {
            idle.wasTornDown && core.testPressureEvictedTotal == 1
        }
        XCTAssertEqual(core.udpFlowCount, 1)
    }

    func testPendingCloseUdpAdmissionCreditsReliefBeforePressureScan() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let generation = core.attachEngine(makeEngine())
        let firstQueue = DispatchQueue(label: "rama.test.pressure.pending-udp.first")
        let secondQueue = DispatchQueue(label: "rama.test.pressure.pending-udp.second")
        let tcp = [
            Fx(core: core, idleSeconds: 30, flowQueue: firstQueue),
            Fx(core: core, idleSeconds: 20, flowQueue: secondQueue),
        ]
        insert(core, tcp)

        // Keep the claimed UDP anchor resident after its pending close is
        // replayed. The pressure scan therefore observes registry occupancy 3;
        // its pre-announced natural relief must reduce projected occupancy to
        // 2 and select exactly one TCP victim toward low-water 1.
        let udpFlow = MockUdpFlow()
        let udpSession = UdpFlowSession(
            core: core, flow: udpFlow, meta: makeMeta(protocolRaw: 2))
        udpSession.ctx.engineGeneration = generation
        udpSession.installTerminate()
        udpSession.buildClientWritePump()
        udpSession.ctx.writer?.markOpened()
        let endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "443")
        udpSession.ctx.writer?.enqueue(Data("hold-drain".utf8), sentBy: endpoint)
        udpSession.flowQueue.sync {}
        XCTAssertFalse(udpSession.ctx.registrationGate.recordServerClose())

        let decision = core.registerUdpFlowAndScheduleStartupDecision(
            udpSession.flowId,
            anchor: udpSession,
            appId: "com.example.pending-close-pressure",
            engineGeneration: generation,
            on: udpSession.flowQueue,
            body: { XCTFail("pending close must suppress UDP open") },
            pendingServerClose: {
                udpSession.replayPendingServerCloseBeforeStartup()
            })
        guard case .started = decision else {
            return XCTFail("pending-close UDP should still transfer ownership")
        }

        pollUntil("pending-close admission pressure scan selects one victim") {
            core.testPressureSelectionsTotal >= 1
        }
        drain(firstQueue)
        drain(secondQueue)
        pollUntil("the single required pressure victim leaves") {
            core.testPressureEvictedTotal == 1 && core.tcpFlowCount == 1
        }
        XCTAssertEqual(core.testPressureSelectionsTotal, 1)
        XCTAssertEqual(tcp.filter(\.wasTornDown).count, 1)
        XCTAssertEqual(core.udpFlowCount, 1, "UDP drain is intentionally held")
        XCTAssertEqual(core.testPressurePendingRemovalCount, 1)

        XCTAssertTrue(udpFlow.completePendingWrite(error: nil))
        udpSession.flowQueue.sync {}
        pollUntil("pending-close UDP drain removes its anchor") {
            core.udpFlowCount == 0
        }
        XCTAssertEqual(
            core.tcpFlowCount + core.udpFlowCount, 1,
            "natural UDP relief plus one eviction must stop at low-water")
        XCTAssertEqual(core.testPressureEvictedTotal, 1)
    }

    func testPendingCloseUdpSelfReliefPreservesExistingVictimCredit() {
        defaultFlowPressureSoftCap = 5
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let generation = core.attachEngine(makeEngine())
        let blockedQueue = DispatchQueue(
            label: "rama.test.pressure.pending-udp.existing-victim")
        let releaseBlockedVictim = DispatchSemaphore(value: 0)
        blockedQueue.async { releaseBlockedVictim.wait() }
        defer { releaseBlockedVictim.signal() }

        // Six eligible flows select four toward low-water. The first three
        // tear down immediately; the fourth (the newest selected victim) is
        // held on its queue, leaving occupancy 3 with one victim credit.
        let tcp = [
            Fx(core: core, idleSeconds: 60),
            Fx(core: core, idleSeconds: 50),
            Fx(core: core, idleSeconds: 40),
            Fx(core: core, idleSeconds: 30, flowQueue: blockedQueue),
            Fx(core: core, idleSeconds: 20),
            Fx(core: core, idleSeconds: 10),
        ]
        insert(core, tcp)
        core.testReapIdleUnderPressure()
        pollUntil("three responsive victims leave while one stays selected") {
            core.tcpFlowCount == 3
                && core.testPressureEvictedTotal == 3
                && core.testPressurePendingVictimCount == 1
        }

        // Registering this already-closing UDP flow raises physical occupancy
        // to 4 and contributes its own pending-removal credit. That credit
        // offsets only the new UDP entry; it must coexist with, rather than
        // cancel, the blocked TCP victim selected by the earlier scan.
        let udpFlow = MockUdpFlow()
        let udpSession = UdpFlowSession(
            core: core, flow: udpFlow, meta: makeMeta(protocolRaw: 2))
        udpSession.ctx.engineGeneration = generation
        udpSession.installTerminate()
        udpSession.buildClientWritePump()
        udpSession.ctx.writer?.markOpened()
        let endpoint = NWHostEndpoint(hostname: "127.0.0.1", port: "443")
        udpSession.ctx.writer?.enqueue(Data("hold-drain".utf8), sentBy: endpoint)
        udpSession.flowQueue.sync {}
        XCTAssertFalse(udpSession.ctx.registrationGate.recordServerClose())

        let decision = core.registerUdpFlowAndScheduleStartupDecision(
            udpSession.flowId,
            anchor: udpSession,
            appId: "com.example.pending-close-existing-victim",
            engineGeneration: generation,
            on: udpSession.flowQueue,
            body: { XCTFail("pending close must suppress UDP open") },
            pendingServerClose: {
                udpSession.replayPendingServerCloseBeforeStartup()
            })
        guard case .started = decision else {
            return XCTFail("pending-close UDP should transfer ownership")
        }
        XCTAssertEqual(core.tcpFlowCount + core.udpFlowCount, 4)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)
        XCTAssertEqual(core.testPressurePendingRemovalCount, 1)
        XCTAssertEqual(core.testPressureCanceledTotal, 0)

        XCTAssertTrue(udpFlow.completePendingWrite(error: nil))
        udpSession.flowQueue.sync {}
        pollUntil("UDP self-offset relief lands without consuming victim credit") {
            core.udpFlowCount == 0 && core.testPressurePendingVictimCount == 1
        }

        releaseBlockedVictim.signal()
        drain(blockedQueue)
        pollUntil("the preserved victim converges occupancy to low-water") {
            core.tcpFlowCount == 2 && core.testPressureEvictedTotal == 4
        }
        XCTAssertEqual(core.testPressureCanceledTotal, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
        XCTAssertEqual(core.tcpFlowCount + core.udpFlowCount, 2)
    }

    private func insert(_ core: TransparentProxyCore, _ fxs: [Fx]) {
        for fx in fxs {
            if let queue = fx.ctx.flowQueue { pressureFlowQueues.append(queue) }
            core.testInsertTcpContext(fx.flowId, fx.ctx)
        }
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
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 3
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        // 4 idle flows (6/7/8/9s). Occupancy 4 ≥ cap 4 ⇒ want = 4 − 3 = 1:
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

    /// Candidate snapshots happen after the scan clock is captured. Activity
    /// in that window has a later timestamp and must have age zero, not wrap
    /// around to nearly `UInt64.max` and masquerade as the stalest flow.
    func testActivityNewerThanScanClockHasZeroIdleAge() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 600_000
        let core = makeCore()
        let active = Fx(core: core, idleSeconds: 0)
        let other = Fx(core: core, idleSeconds: 0)
        insert(core, [active, other])
        let scanNow = DispatchTime.now().uptimeNanoseconds
        active.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: scanNow + 1)

        let victims = core.testCollectPressureVictims(nowNs: scanNow)

        XCTAssertTrue(victims.isEmpty)
        XCTAssertEqual(core.testPressureSelectionsTotal, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
        XCTAssertEqual(
            core.testPressureRescanLastArmedMs, 5_000,
            "a future snapshot is fresh and arms the bounded suppression")
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

    func testWriteAcceptanceLosesCleanlyToPressureCommit() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let queue = DispatchQueue(label: "rama.test.pressure.write-linearization")
        let victim = Fx(
            core: core,
            idleSeconds: 30,
            flowQueue: queue)
        let active = Fx(core: core, idleSeconds: 0)
        insert(core, [victim, active])

        let activityEntered = DispatchSemaphore(value: 0)
        let allowActivity = DispatchSemaphore(value: 0)
        let result = TestValue<RamaTcpDeliverStatusBridge?>(nil)
        let pump = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { _, _ in XCTFail("rejected write must not reach transport") },
            logHwm: { _ in },
            onActivity: {
                activityEntered.signal()
                allowActivity.wait()
                return victim.ctx.recordActivityUnlessPressureEvicted()
            })
        DispatchQueue.global().async {
            result.set(pump.enqueue(Data([0x01])))
        }
        XCTAssertEqual(activityEntered.wait(timeout: .now() + 1), .success)

        core.testReapIdleUnderPressureIfDue()
        pollUntil("pressure commit tears victim down") { victim.wasTornDown }
        allowActivity.signal()
        pollUntil("enqueue reports its terminal decision") { result.get() != nil }
        pollUntil("pressure eviction is accounted") {
            core.testPressureEvictedTotal == 1
        }

        XCTAssertEqual(result.get(), .closed)
        XCTAssertEqual(core.testPressureEvictedTotal, 1)
        let invariant = queue.sync { pump.testInvariantSnapshot() }
        XCTAssertEqual(invariant.pendingBytes, 0, "rejected acceptance rolls back budget")
        XCTAssertTrue(invariant.pendingEmpty)
    }

    // MARK: - Scope: mode-agnostic (global)

    /// The pressure backstop is GLOBAL: nexus pressure is mode-agnostic, and
    /// both modes now bump `lastActivityAt` from their read and write pumps
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
    /// as the pump `onActivity` hooks keep it) is never pressure-evicted,
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

    /// Defensive invariant: production signals terminal before publishing a
    /// pending drain, but an inconsistent snapshot must still be protected.
    /// Selecting it would make the fire-time check spare and immediately
    /// rescan the same flow forever.
    func testPendingDrainWithoutTerminalIsNotSelected() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let inconsistent = Fx(core: core, idleSeconds: 30)
        inconsistent.ctx.drainClosePending = true
        insert(core, [inconsistent, Fx(core: core, idleSeconds: 0)])

        let victims = core.testCollectPressureVictims()

        XCTAssertTrue(victims.isEmpty)
        XCTAssertEqual(core.testPressureSelectionsTotal, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
    }

    /// A completed half-close leaves the sticky terminal flag set but no drain
    /// pending. It remains pressure-eligible once idle, at selection and fire.
    func testTerminalWithoutPendingRemainsEligibleAfterSelection() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let victim = Fx(core: core, idleSeconds: 30)
        insert(core, [victim, Fx(core: core, idleSeconds: 0)])
        let victims = core.testCollectPressureVictims()
        XCTAssertEqual(victims.count, 1)

        victim.ctx.terminalSignalled = true
        core.testFirePressureEvictions(victims)
        pollUntil("terminal-only eviction lands") { core.testPressurePendingVictimCount == 0 }

        XCTAssertTrue(victim.wasTornDown)
        XCTAssertEqual(core.testPressureSelectionsTotal, 1)
        XCTAssertEqual(core.testPressureEvictedTotal, 1)
        XCTAssertEqual(core.testPressureSparedTotal, 0)
    }

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
        // The spare hops to `stateQueue` and re-evaluates the cycle, which is
        // now one short of low-water: the next-oldest idle flow takes the place.
        _ = core.tcpFlowCount  // barrier behind that hop
        XCTAssertTrue(freshest.wasTornDown, "a spared victim is replaced by the next idle flow")
        XCTAssertEqual(core.testPressureSparedTotal, 1)
        XCTAssertEqual(core.tcpFlowCount, 1, "the cycle still reaches low-water")
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

        pollUntil("async reap reaches low-water") { core.tcpFlowCount == 2 }
        drain(q)

        XCTAssertEqual(
            fxs.filter { $0.wasTornDown }.count, 3,
            "the async production path evicts down to low-water (5 − 2 = 3)")
    }

    // MARK: - TG-8: rescan suppression after a no-headroom scan

    /// A churn burst is every flow seconds old against a floor of minutes:
    /// each admission's scan finds nothing, and the next admission scans
    /// again. After a no-headroom result the reaper must skip triggers until
    /// the closest established flow could cross the floor, then let the next
    /// real trigger scan. Drive both instants with one injected clock so the
    /// assertion cannot false-pass or flake on scheduler latency.
    func testNoHeadroomScanSuppressesRescansUntilClosestFlowCanCrossFloor() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let f1 = Fx(core: core, idleSeconds: 0)
        let f2 = Fx(core: core, idleSeconds: 0)
        let f4 = Fx(core: core, idleSeconds: 0)
        insert(core, [f1, f2, f4])
        let scanNow = DispatchTime.now().uptimeNanoseconds
        f1.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: scanNow - 1_000_000_000)
        f2.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: scanNow - 2_000_000_000)
        f4.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: scanNow - 4_000_000_000)

        XCTAssertTrue(core.testCollectPressureVictimsIfDue(nowNs: scanNow).isEmpty)
        XCTAssertEqual(core.testPressureScanCount, 1)
        XCTAssertFalse(f4.wasTornDown, "nothing idle past the floor yet")
        let armedMs = core.testPressureRescanLastArmedMs
        XCTAssertGreaterThanOrEqual(armedMs, 900, "bound derives from the closest flow (5s − 4s)")
        XCTAssertLessThanOrEqual(armedMs, 1_001, "+1ms: eligibility is strictly past the floor")

        XCTAssertTrue(
            core.testCollectPressureVictimsIfDue(nowNs: scanNow + 900_000_000).isEmpty)
        XCTAssertEqual(core.testPressureScanCount, 1, "rescan skipped while nothing can qualify")

        let victims = core.testCollectPressureVictimsIfDue(
            nowNs: scanNow + 1_001_000_000)
        XCTAssertEqual(core.testPressureScanCount, 2, "the next due trigger resumes scanning")
        XCTAssertEqual(victims.count, 1)
        XCTAssertTrue(victims.first?.ctx === f4.ctx)
    }

    func testRescanSuppressionIsBoundedWhenFloorIsFarAway() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 600_000
        let core = makeCore()
        insert(core, [Fx(core: core, idleSeconds: 1), Fx(core: core, idleSeconds: 1)])

        core.testReapIdleUnderPressureIfDue()

        XCTAssertEqual(
            core.testPressureRescanLastArmedMs, 5_000, "≈599s until anything qualifies, capped")
    }

    /// A flow about to cross the idle floor must still get the minimum
    /// suppression, avoiding a scan on every admission in the final fraction
    /// of the wait.
    func testRescanSuppressionHasAMinimumNearIdleFloor() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let almostIdle = Fx(core: core, idleSeconds: 0)
        let scanNow = DispatchTime.now().uptimeNanoseconds
        almostIdle.ctx.lastActivityAt = DispatchTime(
            uptimeNanoseconds: scanNow - 4_900_000_000)
        let fresh = Fx(core: core, idleSeconds: 1)
        insert(core, [almostIdle, fresh])

        _ = core.testCollectPressureVictims(nowNs: scanNow)

        XCTAssertFalse(almostIdle.wasTornDown)
        XCTAssertEqual(
            core.testPressureRescanLastArmedMs, 250, "the lower bound, not the zero the idle math gives")
    }

    func testTriggerUnderCapDoesNotScan() {
        defaultFlowPressureSoftCap = 5
        defaultFlowPressureLowWater = 4
        let core = makeCore()
        insert(core, [Fx(core: core, idleSeconds: 30), Fx(core: core, idleSeconds: 30)])

        core.testReapIdleUnderPressureIfDue()

        XCTAssertEqual(core.testPressureScanCount, 0, "the occupancy guard is O(1); no selection")
    }

    // MARK: - TG-9: trigger coalescing on the production async path

    /// One trigger fires per admission while over the cap. With the queue
    /// busy — as it is under exactly that load — ten triggers must collapse
    /// into ONE queued scan. The previous flag lived inside the serial block
    /// and could never be observed set by the block queued behind it.
    func testRapidTriggersCoalesceIntoOneScanWhileStateQueueIsBusy() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 60_000
        let core = makeCore()
        insert(core, [Fx(core: core, idleSeconds: 1), Fx(core: core, idleSeconds: 1)])

        let gate = core.testHoldStateQueue()
        defer { gate.signal() }
        for _ in 0..<10 { core.reapIdleUnderPressure() }
        XCTAssertTrue(core.testPressureReapScheduled, "exactly one scan is queued")
        XCTAssertEqual(core.testPressureScanCount, 0, "and it hasn't run: the queue is held")

        gate.signal()
        pollUntil("queued scan runs") { core.testPressureScanCount == 1 }
        pollUntil("slot released") { !core.testPressureReapScheduled }
        XCTAssertEqual(core.testPressureScanCount, 1, "ten triggers, one scan")

        // Nothing was idle past the 60s floor, so that scan armed suppression:
        // a fresh trigger claims the (free) slot but its scan is skipped.
        core.reapIdleUnderPressure()
        pollUntil("second trigger drains") { !core.testPressureReapScheduled }
        _ = core.testPressureRescanSuppressedForMs  // stateQueue.sync barrier behind the block
        XCTAssertEqual(core.testPressureScanCount, 1, "suppressed rescan on the async path")
    }

    func testTriggerNeverSelectsItsJustAdmittedFlowAtZeroIdleFloor() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 0
        let core = makeCore()
        let connecting = Fx(core: core, idleSeconds: 30, ready: false)
        let justAdmitted = Fx(core: core, idleSeconds: 1)
        insert(core, [connecting, justAdmitted])

        core.reapIdleUnderPressure(protecting: justAdmitted.flowId)
        pollUntil("protected admission scan completes") { !core.testPressureReapScheduled }
        _ = core.tcpFlowCount

        XCTAssertFalse(justAdmitted.wasTornDown)
        XCTAssertEqual(core.testPressureSelectionsTotal, 0)
    }

    func testRegistrationProtectsAdmissionBeforeTriggerIsPublished() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 0
        let core = makeCore()
        let old = Fx(core: core, idleSeconds: 30)
        insert(core, [old])
        let admitted = Fx(core: core, idleSeconds: 10)

        XCTAssertNotNil(
            core.registerTcpFlow(
                admitted.flowId,
                anchor: _TestTcpFlowSessionAnchor(ctx: admitted.ctx)))
        core.testReapIdleUnderPressureIfDue()

        XCTAssertTrue(old.wasTornDown)
        XCTAssertFalse(admitted.wasTornDown)
        XCTAssertEqual(core.testPressureEvictedTotal, 1)
    }

    func testCoalescedScanProtectsEveryAdmissionAtZeroIdleFloor() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 0
        let core = makeCore()
        let old = Fx(core: core, idleSeconds: 30)
        let firstAdmission = Fx(core: core, idleSeconds: 1)
        let secondAdmission = Fx(core: core, idleSeconds: 1)
        insert(core, [old, firstAdmission, secondAdmission])

        let gate = core.testHoldStateQueue()
        core.reapIdleUnderPressure(protecting: firstAdmission.flowId)
        core.reapIdleUnderPressure(protecting: secondAdmission.flowId)
        gate.signal()
        pollUntil("coalesced protected scan completes") {
            !core.testPressureReapScheduled
        }
        pollUntil("old victim leaves") { old.wasTornDown }

        XCTAssertFalse(firstAdmission.wasTornDown)
        XCTAssertFalse(secondAdmission.wasTornDown)
        XCTAssertEqual(core.testPressureScanCount, 1)
        XCTAssertEqual(core.testPressureSelectionsTotal, 1)
    }

    func testSettledBatchRechecksReleasedProductionAdmissions() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 0
        let core = makeCore()
        let old = [
            Fx(core: core, idleSeconds: 30),
            Fx(core: core, idleSeconds: 20),
        ]
        insert(core, old)
        let admissions = (0..<4).map { _ in Fx(core: core, idleSeconds: 1) }
        for admission in admissions {
            XCTAssertNotNil(
                core.registerTcpFlow(
                    admission.flowId,
                    anchor: _TestTcpFlowSessionAnchor(ctx: admission.ctx)))
        }

        core.reapIdleUnderPressure()
        pollUntil("released admissions autonomously reach low-water") {
            core.tcpFlowCount == 1
        }

        XCTAssertTrue(old.allSatisfy(\.wasTornDown))
        XCTAssertEqual(admissions.filter(\.wasTornDown).count, 3)
        XCTAssertEqual(core.testPressureEvictedTotal, 5)
        XCTAssertEqual(
            core.testPressureScanCount,
            3,
            "one initial scan, one protection boundary, one delayed continuation")
    }

    func testReplacementScanRetainsAdmissionProtection() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 0
        let core = makeCore()
        let (queue, gate) = gatedQueue("replacement-protection")
        let stale = Fx(
            core: core,
            idleSeconds: 30,
            flowQueue: queue)
        let admission = Fx(core: core, idleSeconds: 1)
        insert(core, [stale, admission])

        core.reapIdleUnderPressure(protecting: admission.flowId)
        pollUntil("stale victim selected") {
            core.testPressurePendingVictimCount == 1
        }
        stale.ctx.lastActivityAt = DispatchTime(
            uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds + 5_000_000_000)
        gate.signal()
        pollUntil("stale victim spared") {
            core.testPressureSparedTotal == 1
        }

        XCTAssertFalse(stale.wasTornDown)
        XCTAssertFalse(admission.wasTornDown)
        XCTAssertEqual(core.testPressureSelectionsTotal, 1)
        XCTAssertEqual(core.testPressureScanCount, 2)
        pollUntil("released admission is reconsidered once") {
            admission.wasTornDown
        }
        XCTAssertEqual(core.testPressureSelectionsTotal, 2)
        XCTAssertEqual(core.testPressureScanCount, 3)
    }

    func testProtectedCandidatesBoundSuppressionAfterProtectionClears() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 0
        let core = makeCore()
        let (queue, gate) = gatedQueue("protected-suppression")
        defer { gate.signal() }
        let old = Fx(core: core, idleSeconds: 30, flowQueue: queue)
        let firstAdmission = Fx(core: core, idleSeconds: 1)
        insert(core, [old, firstAdmission])

        core.reapIdleUnderPressure(protecting: firstAdmission.flowId)
        pollUntil("old flow is selected") {
            !core.testPressureReapScheduled
                && core.testPressurePendingVictimCount == 1
        }

        let secondAdmission = Fx(core: core, idleSeconds: 1)
        insert(core, [secondAdmission])
        core.reapIdleUnderPressure(protecting: secondAdmission.flowId)
        pollUntil("protected-only replacement scan completes") {
            !core.testPressureReapScheduled && core.testPressureScanCount == 2
        }

        XCTAssertEqual(
            core.testPressureRescanLastArmedMs,
            250,
            "protected idle flows bound suppression instead of hiding for 5s")

        gate.signal()
        pollUntil("selected old flow leaves") { old.wasTornDown }
        pollUntil("released admissions are reconsidered") {
            core.testPressureSelectionsTotal == 2
        }
        XCTAssertEqual(
            core.testPressureSelectionsTotal,
            2,
            "former admissions become eligible after one bounded continuation")
    }

    // MARK: - TG-10: episode hysteresis via the production removal path

    /// A removal is the production event that observes low-water. It must end
    /// the episode there so the next burst starts with a fresh scan and log.
    func testRemovalToLowWaterEndsTheEpisodeSoTheNextOneScansFresh() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 60_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        func noHeadroomLines() -> Int {
            notices.withLock { $0.filter { $0.contains("admitting without reap") }.count }
        }
        let a = Fx(core: core, idleSeconds: 1)
        let b = Fx(core: core, idleSeconds: 1)
        let c = Fx(core: core, idleSeconds: 1)
        insert(core, [a, b, c])

        core.testReapIdleUnderPressureIfDue()
        XCTAssertEqual(core.testPressureScanCount, 1)
        XCTAssertEqual(core.testPressureRescanLastArmedMs, 5_000, "episode 1 armed the cap")
        XCTAssertEqual(noHeadroomLines(), 1)
        core.testReapIdleUnderPressureIfDue()  // suppressed: counted as a skip, not a scan
        XCTAssertEqual(core.testPressureScanCount, 1)

        // Two removals through the production path take occupancy to low-water.
        core.removeTcpFlow(b.flowId)
        core.removeTcpFlow(c.flowId)
        XCTAssertEqual(
            core.testPressureRescanSuppressedForMs, 0,
            "reaching low-water ends the episode (the sync read doubles as the barrier)")
        let episodeLines = notices.withLock { $0.filter { $0.contains("flow pressure episode ended") } }
        XCTAssertEqual(episodeLines.count, 1, "one summary line per episode")
        XCTAssertTrue(
            episodeLines.first?.contains(
                "peakOccupancy=3 softCap=2 scans=1 skipped=1 selected=0 evicted=0")
                ?? false, episodeLines.first ?? "")

        // Episode 2, well inside the old 5s deadline: must scan and must log.
        insert(core, [Fx(core: core, idleSeconds: 1), Fx(core: core, idleSeconds: 1)])
        core.testReapIdleUnderPressureIfDue()
        XCTAssertEqual(core.testPressureScanCount, 2, "fresh scan, not a suppressed skip")
        XCTAssertEqual(noHeadroomLines(), 2, "once-per-episode log re-armed")
    }

    func testCapBoundaryChurnKeepsEpisodeSuppressionUntilLowWater() {
        defaultFlowPressureSoftCap = 5
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 60_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in
            notices.withLock { $0.append(message) }
        }
        var live = (0..<5).map { _ in Fx(core: core, idleSeconds: 0) }
        insert(core, live)

        core.testReapIdleUnderPressureIfDue()
        XCTAssertEqual(core.testPressureScanCount, 1)
        XCTAssertGreaterThan(core.testPressureRescanSuppressedForMs, 0)

        for _ in 0..<20 {
            let leaving = live.removeFirst()
            core.removeTcpFlow(leaving.flowId)
            pollUntil("boundary removal lands") { core.tcpFlowCount == 4 }
            let admitted = Fx(core: core, idleSeconds: 0)
            live.append(admitted)
            insert(core, [admitted])
            core.testReapIdleUnderPressureIfDue()
        }

        XCTAssertEqual(
            core.testPressureScanCount, 1,
            "cap-to-cap-minus-one churn must not re-sort the registry")
        XCTAssertEqual(
            notices.withLock {
                $0.filter { $0.contains("admitting without reap") }.count
            },
            1,
            "no-headroom remains once per hysteresis episode")
        XCTAssertFalse(
            notices.withLock {
                $0.contains { $0.contains("flow pressure episode ended") }
            })

        for flow in live.prefix(3) { core.removeTcpFlow(flow.flowId) }
        pollUntil("low-water ends hostile churn episode") {
            core.tcpFlowCount == 2
        }
        XCTAssertEqual(
            notices.withLock {
                $0.filter { $0.contains("flow pressure episode ended") }.count
            },
            1)
        XCTAssertEqual(core.testPressureRescanSuppressedForMs, 0)
    }

    // MARK: - TG-11: pending victims are not reselected while their teardown is queued

    /// A serial `flowQueue` parked behind a gate: every teardown dispatched
    /// onto it queues up without running, holding the victims in the
    /// selected-but-not-yet-removed window the reaper must account for.
    private func gatedQueue(_ label: String) -> (DispatchQueue, DispatchSemaphore) {
        let q = DispatchQueue(label: "rama.test.pressure.\(label)")
        let gate = DispatchSemaphore(value: 0)
        q.async { gate.wait() }
        return (q, gate)
    }

    /// Fire one production trigger and wait until its `stateQueue` block has
    /// run to completion (the `tcpFlowCount` sync read is the barrier). Unlike
    /// a burst, consecutive triggers here each get their own block — the
    /// coalescing slot is free again the moment the previous block starts.
    private func triggerAndDrain(_ core: TransparentProxyCore) {
        core.reapIdleUnderPressure()
        pollUntil("trigger block started") { !core.testPressureReapScheduled }
        _ = core.tcpFlowCount
    }

    /// Bounded serial-queue barrier. A deadlocked teardown fails this test
    /// promptly instead of hanging the whole test process in `sync`.
    private func drain(_ queue: DispatchQueue, timeout: TimeInterval = 2.0) {
        let drained = expectation(description: "flow queue drained")
        queue.async { drained.fulfill() }
        wait(for: [drained], timeout: timeout)
    }

    /// The coalescing test (TG-9) parks `stateQueue` BEFORE the first scan.
    /// This one lets the first scan select its victims and parks their
    /// `flowQueue` instead, so the victims stay registered and idle while
    /// more admissions trigger. Those triggers must not rescan the registry,
    /// re-account the same victims, or queue them a second teardown.
    func testTriggersWhileVictimTeardownIsBlockedDoNotReselectPendingVictims() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (q, gate) = gatedQueue("pending")
        defer { gate.signal() }
        // 5 idle flows → want = 5 − low-water 2 = 3 victims (the 3 stalest).
        let fxs = (0..<5).map { Fx(core: core, idleSeconds: 10 + UInt64($0), flowQueue: q) }
        insert(core, fxs)

        triggerAndDrain(core)
        XCTAssertEqual(core.testPressureScanCount, 1)
        XCTAssertEqual(core.testPressureSelectionsTotal, 3, "first scan selects 3 victims")
        XCTAssertEqual(core.testPressurePendingVictimCount, 3)
        XCTAssertEqual(core.tcpFlowCount, 5, "teardown is blocked: nothing left the registry")

        // Twenty more admissions' worth of triggers while the victims sit in
        // the window. Occupancy has not moved and the pending victims cover
        // the whole excess, so each trigger is an O(1) no-op.
        for _ in 0..<20 { triggerAndDrain(core) }

        XCTAssertEqual(core.testPressureScanCount, 1, "no full rescan while victims are pending")
        XCTAssertEqual(
            core.testPressureSelectionsTotal, 3, "the same victims are not re-accounted")
        XCTAssertEqual(core.testPressurePendingVictimCount, 3, "still the one outstanding set")

        gate.signal()
        pollUntil("victims torn down and removed") { core.tcpFlowCount == 2 }
        drain(q)
        XCTAssertEqual(core.testPressureEvictionBodyRuns, 3, "one teardown closure per victim")
        XCTAssertEqual(fxs.filter { $0.wasTornDown }.count, 3)
        XCTAssertEqual(core.testPressureEvictedTotal, 3)
        for fx in fxs where fx.wasTornDown {
            XCTAssertEqual(fx.flow.closeReadCallCount, 1, "each victim torn down exactly once")
        }
        XCTAssertEqual(core.testPressurePendingVictimCount, 0, "pending set drains with registry")
    }

    /// A pending victim that moves bytes before its `flowQueue` re-check is
    /// spared, leaves the pending set, and the cycle is re-evaluated: the
    /// next-oldest idle flow takes its place so the reap still reaches
    /// low-water. The spared flow is a normal flow again — idle long enough,
    /// it is selectable by a later cycle.
    func testPendingVictimRevivedBeforeRecheckIsSparedReplacedAndReArmed() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (q, gate) = gatedQueue("revive")
        defer { gate.signal() }
        let stalest = Fx(core: core, idleSeconds: 40, flowQueue: q)
        let middle = Fx(core: core, idleSeconds: 30, flowQueue: q)
        let next = Fx(core: core, idleSeconds: 20, flowQueue: q)
        let freshest = Fx(core: core, idleSeconds: 10, flowQueue: q)
        insert(core, [stalest, middle, next, freshest])

        // want = 4 − 2 = 2 → stalest + middle selected, teardown parked.
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressureSelectionsTotal, 2)
        XCTAssertEqual(core.testPressurePendingVictimCount, 2)

        stalest.markActiveNow()
        gate.signal()
        pollUntil("cycle converges to low-water") { core.tcpFlowCount == 2 }
        _ = core.tcpFlowCount

        XCTAssertFalse(stalest.wasTornDown, "the revived victim is spared by the re-check")
        XCTAssertTrue(middle.wasTornDown)
        XCTAssertTrue(next.wasTornDown, "the spare is re-evaluated: next-oldest idle replaces it")
        XCTAssertFalse(freshest.wasTornDown, "and only as many as low-water requires")
        XCTAssertEqual(
            core.testPressureSelectionsTotal, 3, "stalest, middle, next: unique selections")
        XCTAssertEqual(core.testPressureEvictedTotal, 2)
        XCTAssertEqual(core.testPressureSparedTotal, 1)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)

        // Re-armed: idle again and over the cap, the spared flow is a victim.
        stalest.ctx.lastActivityAt = DispatchTime(
            uptimeNanoseconds: DispatchTime.now().uptimeNanoseconds - 40_000_000_000)
        insert(core, [Fx(core: core, idleSeconds: 0, flowQueue: q)])
        triggerAndDrain(core)
        pollUntil("spared flow evicted by the later cycle") { stalest.wasTornDown }
        XCTAssertEqual(core.testPressureSelectionsTotal, 4)
        XCTAssertEqual(core.testPressureEvictedTotal, 3)
    }

    func testSpareIsReplacedAcrossMultiSlotLowWaterGap() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (queue, gate) = gatedQueue("multi-slot-spare")
        defer { gate.signal() }
        let spared = Fx(core: core, idleSeconds: 50, flowQueue: queue)
        let first = Fx(core: core, idleSeconds: 40, flowQueue: queue)
        let second = Fx(core: core, idleSeconds: 30, flowQueue: queue)
        let replacement = Fx(core: core, idleSeconds: 20, flowQueue: queue)
        let survivor = Fx(core: core, idleSeconds: 10, flowQueue: queue)
        insert(core, [spared, first, second, replacement, survivor])

        // Five flows toward low-water two reserves three victims. Reviving
        // one drops projected relief to only two; replacement must continue
        // toward low-water even though projected occupancy is below cap four.
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressureSelectionsTotal, 3)
        spared.markActiveNow()
        gate.signal()

        pollUntil("multi-slot spare replacement reaches low-water") {
            core.tcpFlowCount == 2
        }
        drain(queue)
        XCTAssertFalse(spared.wasTornDown)
        XCTAssertTrue(first.wasTornDown)
        XCTAssertTrue(second.wasTornDown)
        XCTAssertTrue(replacement.wasTornDown)
        XCTAssertFalse(survivor.wasTornDown)
        XCTAssertEqual(core.testPressureSelectionsTotal, 4)
        XCTAssertEqual(core.testPressureEvictedTotal, 3)
        XCTAssertEqual(core.testPressureSparedTotal, 1)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
    }

    /// Spared for a reason other than activity: a graceful drain began on
    /// the victim between selection and re-check. It must leave the pending
    /// set like an activity spare does, or it could never be selected again
    /// once drain-wedged.
    func testPendingVictimSparedByDrainRecheckLeavesPendingSet() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (q, gate) = gatedQueue("drain")
        defer { gate.signal() }
        let victim = Fx(core: core, idleSeconds: 30, flowQueue: q)
        let other = Fx(core: core, idleSeconds: 1, flowQueue: q)
        insert(core, [victim, other])

        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)

        // Graceful close started, within its linger budget: not wedged.
        victim.ctx.terminalSignalled = true
        victim.ctx.drainClosePending = true
        victim.ctx.lingerCloseMs = 60_000
        gate.signal()
        drain(q)
        pollUntil("spare lands on stateQueue") { core.testPressurePendingVictimCount == 0 }

        XCTAssertFalse(victim.wasTornDown, "a gracefully-closing victim is spared")
        XCTAssertEqual(core.testPressureSparedTotal, 1)
        XCTAssertEqual(core.testPressureEvictedTotal, 0)
        XCTAssertEqual(core.tcpFlowCount, 2)
    }

    /// Selection and committed eviction can land in different telemetry
    /// windows. Report each event in the interval where it happened rather
    /// than deriving eviction from selection minus spare deltas.
    func testTelemetryCountsSelectionAndCommittedEvictionInTheirOwnTicks() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        let (q, gate) = gatedQueue("telemetry")
        defer { gate.signal() }
        let victim = Fx(core: core, idleSeconds: 30, flowQueue: q)
        insert(core, [victim, Fx(core: core, idleSeconds: 0, flowQueue: q)])

        triggerAndDrain(core)
        core.testRunPeriodicMaintenance()
        let selectionTick = notices.withLock {
            $0.last { $0.contains("tproxy live-flow counts") } ?? ""
        }
        XCTAssertTrue(
            selectionTick.contains(
                "selected=1 evicted=0 spared=0 canceled=0 expired=0 pending=1"),
            selectionTick)

        gate.signal()
        drain(q)
        pollUntil("committed eviction lands") { core.tcpFlowCount == 1 }
        core.testRunPeriodicMaintenance()
        let evictionTick = notices.withLock {
            $0.last { $0.contains("tproxy live-flow counts") } ?? ""
        }
        XCTAssertTrue(
            evictionTick.contains(
                "selected=0 evicted=1 spared=0 canceled=0 expired=0 pending=0"),
            evictionTick)
        let episode = notices.withLock {
            $0.last { $0.contains("flow pressure episode ended") } ?? ""
        }
        XCTAssertTrue(episode.contains("selected=1 evicted=1 spared=0"), episode)
    }

    /// A pending victim torn down by another path first (here an engine
    /// detach on its queue) resolves through the registry removal, not the
    /// spare path: no double accounting either way.
    func testPendingVictimTornDownByAnotherPathResolvesViaRemoval() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let q = DispatchQueue(label: "rama.test.pressure.other-path")
        let gate = DispatchSemaphore(value: 0)
        defer { gate.signal() }
        let victim = Fx(core: core, idleSeconds: 30, flowQueue: q)
        // Runs BEFORE the eviction closure on the same serial queue.
        q.async {
            gate.wait()
            victim.ctx.applyEngineDetached()
        }
        insert(core, [victim, Fx(core: core, idleSeconds: 1, flowQueue: q)])

        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)

        gate.signal()
        drain(q)
        pollUntil("removal lands") { core.tcpFlowCount == 1 }
        XCTAssertEqual(core.testPressureEvictionBodyRuns, 1, "the eviction closure ran and no-oped")
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
        XCTAssertEqual(core.testPressureSparedTotal, 0, "already gone: not a spare")
        XCTAssertEqual(core.testPressureEvictedTotal, 0, "other teardown is not an eviction")
        XCTAssertEqual(core.testPressureCanceledTotal, 1, "selection was superseded")
        XCTAssertEqual(victim.flow.closeReadCallCount, 1, "torn down exactly once")
    }

    /// Admissions keep arriving while a cycle has pending victims. Pending
    /// victims count as leaving: occupancy net of them must reach the cap
    /// again before another scan runs (the same hysteresis as without
    /// pending victims), and that scan excludes the pending set.
    func testAdmissionsDuringPendingCycleScanIncrementallyAgainstProjectedOccupancy() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (q, gate) = gatedQueue("admit")
        defer { gate.signal() }
        // 6 idle → want = 6 − 2 = 4 pending; 2 idle flows remain unselected.
        let idle = (0..<6).map { Fx(core: core, idleSeconds: 10 + UInt64($0), flowQueue: q) }
        insert(core, idle)
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 4)
        XCTAssertEqual(core.testPressureScanCount, 1)

        // Projected occupancy 7 − 4 = 3 < cap 4: the admission is an O(1) no-op.
        let a1 = Fx(core: core, idleSeconds: 0, flowQueue: q)
        insert(core, [a1])
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressureScanCount, 1, "excess already covered by pending victims")
        XCTAssertEqual(core.testPressureSelectionsTotal, 4)

        // Projected 8 − 4 = 4 ≥ cap: scan for the 2 extra, excluding pending.
        let a2 = Fx(core: core, idleSeconds: 0, flowQueue: q)
        insert(core, [a2])
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressureScanCount, 2, "new excess: one incremental scan")
        XCTAssertEqual(core.testPressureSelectionsTotal, 6, "two more unique victims")
        XCTAssertEqual(core.testPressurePendingVictimCount, 6)

        gate.signal()
        pollUntil("converges to low-water") { core.tcpFlowCount == 2 }
        drain(q)
        XCTAssertEqual(core.testPressureEvictionBodyRuns, 6)
        XCTAssertEqual(idle.filter { $0.wasTornDown }.count, 6, "every idle flow, each once")
        XCTAssertFalse(a1.wasTornDown, "active admissions are never selected")
        XCTAssertFalse(a2.wasTornDown, "active admissions are never selected")
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
    }

    /// Detach mid-cycle: the registry and the pending set clear together,
    /// the parked eviction closures no-op when they finally run, and the
    /// next lifecycle's first over-cap trigger scans fresh.
    func testDetachDuringPendingCycleClearsPendingStateWithoutSuppressingLaterScans() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        let (q, gate) = gatedQueue("detach")
        defer { gate.signal() }
        let fxs = (0..<5).map { Fx(core: core, idleSeconds: 10 + UInt64($0), flowQueue: q) }
        insert(core, fxs)
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 3)

        core.detachEngine(reason: 0)
        XCTAssertEqual(core.tcpFlowCount, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0, "detach clears the pending set")

        gate.signal()
        drain(q)
        _ = core.tcpFlowCount
        XCTAssertEqual(fxs.filter { $0.wasTornDown }.count, 5, "every flow is torn down")
        for fx in fxs {
            XCTAssertEqual(fx.flow.closeReadCallCount, 1, "evict + detach never double-close")
        }
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
        XCTAssertFalse(
            notices.withLock { $0.contains { $0.contains("flow pressure episode ended") } },
            "detach must not mislabel an interrupted episode as naturally ended")
        let interrupted = notices.withLock {
            $0.last { $0.contains("flow pressure episode interrupted") } ?? ""
        }
        XCTAssertTrue(
            interrupted.contains("selected=3 evicted=0"),
            "detach must preserve the pre-reset episode evidence: \(interrupted)")

        // Next lifecycle: a fresh over-cap population scans and evicts.
        let again = (0..<5).map { Fx(core: core, idleSeconds: 10 + UInt64($0), flowQueue: q) }
        insert(core, again)
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressureScanCount, 2, "scans are not suppressed after detach")
        pollUntil("fresh cycle evicts") { core.tcpFlowCount == 2 }
    }

    func testDetachAccountsOffQueueVictimDecisionsExactlyOnce() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in
            notices.withLock { $0.append(message) }
        }
        let flows = (0..<4).map {
            Fx(core: core, idleSeconds: 40 - UInt64($0 * 10))
        }
        insert(core, flows)
        let victims = core.testCollectPressureVictims()
        XCTAssertEqual(victims.count, 3)

        XCTAssertTrue(core.testCommitPressureVictim(victims[0]))
        XCTAssertTrue(core.testMarkPressureVictimSpared(victims[1]))
        let selectedIds = Set(victims.map { ObjectIdentifier($0.ctx) })
        guard
            let natural = flows.first(where: {
                !selectedIds.contains(ObjectIdentifier($0.ctx))
            })
        else {
            return XCTFail("expected one unselected flow")
        }
        XCTAssertTrue(
            core.testAnnouncePressureRemoval(
                flowId: natural.flowId, context: natural.ctx),
            "independent removal retires the remaining selected victim")

        // None of the normal state-queue accounting callbacks has run. Detach
        // must atomically capture the three decisions before invalidating the
        // reservations, without charging them again during detached teardown.
        core.detachEngine(reason: 0)
        _ = core.tcpFlowCount

        XCTAssertEqual(core.testPressureEvictedTotal, 1)
        XCTAssertEqual(core.testPressureSparedTotal, 1)
        XCTAssertEqual(core.testPressureCanceledTotal, 1)
        let interrupted = notices.withLock {
            $0.last { $0.contains("flow pressure episode interrupted") } ?? ""
        }
        XCTAssertTrue(
            interrupted.contains(
                "selected=3 evicted=1 spared=1 canceled=1 expired=0"),
            interrupted)
    }

    func testSleepPreservesPendingVictimAndEpisode() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        let (queue, gate) = gatedQueue("sleep")
        defer { gate.signal() }
        let victim = Fx(core: core, idleSeconds: 30, flowQueue: queue)
        insert(core, [victim, Fx(core: core, idleSeconds: 0)])
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)

        let slept = expectation(description: "sleep completion")
        core.handleSystemSleep { slept.fulfill() }
        wait(for: [slept], timeout: 1.0)
        XCTAssertEqual(
            core.testPressurePendingVictimCount, 1,
            "pausing maintenance must not invalidate live pressure work")

        gate.signal()
        pollUntil("pre-sleep victim finishes") { core.tcpFlowCount == 1 }
        XCTAssertTrue(victim.wasTornDown)
        XCTAssertEqual(core.testPressureEvictedTotal, 1)
        let episode = notices.withLock {
            $0.last { $0.contains("flow pressure episode ended") } ?? ""
        }
        XCTAssertTrue(episode.contains("selected=1 evicted=1"), episode)
    }

    func testDetachResetsPressureTelemetryBaseline() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        insert(core, [Fx(core: core, idleSeconds: 30), Fx(core: core, idleSeconds: 0)])
        core.testReapIdleUnderPressure()
        pollUntil("eviction removal lands") { core.tcpFlowCount == 1 }
        XCTAssertEqual(core.testPressureEvictedTotal, 1)

        core.detachEngine(reason: 0)
        core.testRunPeriodicMaintenance()
        let firstTickAfterDetach = notices.withLock {
            $0.last { $0.contains("tproxy live-flow counts") } ?? ""
        }
        XCTAssertTrue(firstTickAfterDetach.contains("tcp=0 udp=0 total=0 peak=0"))
        XCTAssertTrue(
            firstTickAfterDetach.contains(
                "selected=0 evicted=0 spared=0 canceled=0 expired=0 pending=0"),
            firstTickAfterDetach)
    }

    /// Bounded stress: admissions churn from a background thread against a
    /// low cap while victims tear down on a small pool of real serial queues.
    /// Every selection must produce exactly one teardown closure and no flow
    /// may be selected twice; occupancy must settle between low-water and
    /// the cap once the churn stops.
    func testLowThresholdChurnConvergesWithoutDuplicateSelections() {
        defaultFlowPressureSoftCap = 20
        defaultFlowPressureLowWater = 10
        defaultFlowPressureIdleFloorMs = 0
        let core = makeCore()
        let queues = (0..<4).map { DispatchQueue(label: "rama.test.pressure.churn.\($0)") }
        let all = Locked([Fx]())
        let done = expectation(description: "churn finished")
        DispatchQueue.global().async {
            for i in 0..<300 {
                let fx = Fx(core: core, idleSeconds: 1, flowQueue: queues[i % queues.count])
                all.withLock { $0.append(fx) }
                core.testInsertTcpContext(fx.flowId, fx.ctx)
                core.reapIdleUnderPressure()
            }
            done.fulfill()
        }
        wait(for: [done], timeout: 10.0)

        // Slot first, then the sync read: a scan that already started runs
        // before the read, so a `0` here means no selection is still in flight.
        pollUntil("pending victims settle", timeout: 10.0) {
            !core.testPressureReapScheduled && core.testPressurePendingVictimCount == 0
        }
        for q in queues { drain(q) }
        _ = core.tcpFlowCount

        let fxs = all.withLock { $0 }
        let tornDown = fxs.filter { $0.wasTornDown }.count
        let victims = core.testPressureSelectionsTotal
        XCTAssertEqual(core.testPressureSparedTotal, 0, "idle floor 0: nothing revives")
        XCTAssertEqual(victims, tornDown, "every unique selection was evicted exactly once")
        XCTAssertEqual(core.testPressureEvictedTotal, tornDown)
        XCTAssertEqual(core.testPressureEvictionBodyRuns, victims, "one closure per selection")
        XCTAssertEqual(core.tcpFlowCount, 300 - tornDown)
        XCTAssertLessThan(
            core.testPressureScanCount, 40,
            "300 admissions should be relieved in low-water batches, not one sort each")
        XCTAssertGreaterThanOrEqual(core.tcpFlowCount, 10, "never reaped below low-water")
        XCTAssertLessThan(core.tcpFlowCount, 20, "every over-cap trigger was relieved")
        for fx in fxs where fx.wasTornDown {
            XCTAssertEqual(fx.flow.closeReadCallCount, 1)
        }
    }

    func testDispatchLeaseExpiresVictimAndSelectsResponsiveAlternate() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore(dispatchLeaseMs: 50)
        let (blockedQueue, gate) = gatedQueue("lease-expiry")
        defer { gate.signal() }
        let blocked = Fx(core: core, idleSeconds: 30, flowQueue: blockedQueue)
        let alternate = Fx(
            core: core,
            idleSeconds: 20,
            flowQueue: DispatchQueue(label: "rama.test.pressure.lease-alternate"))
        insert(core, [blocked, alternate])

        triggerAndDrain(core)
        pollUntil("alternate selected after lease expiry") {
            core.testPressureExpiredTotal == 1 && core.tcpFlowCount == 1
        }

        XCTAssertFalse(blocked.wasTornDown)
        XCTAssertTrue(alternate.wasTornDown)
        XCTAssertEqual(core.testPressureSelectionsTotal, 2)
        XCTAssertEqual(core.testPressureEvictedTotal, 1)
        XCTAssertEqual(core.testPressureExpiredTotal, 1)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)

        gate.signal()
        drain(blockedQueue)
        XCTAssertFalse(blocked.wasTornDown, "expired work is inert when its queue resumes")
        XCTAssertEqual(core.testPressureSelectionsTotal, 2)
    }

    func testProductionDispatchLeaseExpiresAtExactBoundary() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore(dispatchLeaseMs: 250)
        XCTAssertEqual(core.testPressureVictimDispatchLeaseMs, 250)
        let (queue, gate) = gatedQueue("exact-production-lease")
        defer { gate.signal() }
        let victim = Fx(core: core, idleSeconds: 30, flowQueue: queue)
        let active = Fx(core: core, idleSeconds: 0)
        insert(core, [victim, active])

        let selectedAtNs = DispatchTime.now().uptimeNanoseconds
        let victims = core.testCollectPressureVictims(nowNs: selectedAtNs)
        core.testFirePressureEvictions(victims)
        let expiredTotals = core.testRunPressureRechecks(nowNsValues: [
            selectedAtNs + 249_999_999,
            selectedAtNs + 250_000_000,
        ])

        XCTAssertEqual(expiredTotals, [0, 1])
        XCTAssertEqual(core.testPressureExpiredTotal, 1)
        XCTAssertFalse(victim.wasTornDown)
    }

    func testDispatchLeaseKeepsCreditForVictimAlreadyRemoving() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (blockedQueue, gate) = gatedQueue("removing-lease-credit")
        defer { gate.signal() }
        let removing = Fx(
            core: core,
            idleSeconds: 30,
            flowQueue: blockedQueue)
        let alternate = Fx(core: core, idleSeconds: 20)
        insert(core, [removing, alternate])

        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)
        XCTAssertFalse(
            core.testAnnouncePressureRemoval(
                flowId: removing.flowId,
                context: removing.ctx),
            "a selected victim already supplies its own relief credit")

        core.testRunPressureRecheck(afterMs: 6_000)
        XCTAssertEqual(core.testPressureExpiredTotal, 0)
        XCTAssertEqual(core.testPressureSelectionsTotal, 1)
        XCTAssertFalse(
            core.testPressureRecheckScheduled,
            "pending registry removal owns resolution, not a lease timer")

        core.removeTcpFlow(removing.flowId, context: removing.ctx)
        pollUntil("removing victim leaves registry") { core.tcpFlowCount == 1 }
        gate.signal()
        drain(blockedQueue)
        XCTAssertFalse(alternate.wasTornDown)
        XCTAssertEqual(core.testPressureEvictedTotal, 0)
        XCTAssertEqual(core.testPressureExpiredTotal, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
    }

    func testUnknownRemovalCannotCancelSelectedVictim() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (queue, gate) = gatedQueue("unknown-removal")
        defer { gate.signal() }
        let victim = Fx(core: core, idleSeconds: 30, flowQueue: queue)
        let active = Fx(core: core, idleSeconds: 0)
        insert(core, [victim, active])
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)

        let unknown = MockTcpFlow()
        core.removeTcpFlow(ObjectIdentifier(unknown))
        _ = core.tcpFlowCount

        XCTAssertEqual(core.testPressureCanceledTotal, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)
    }

    func testDuplicateRemovalCannotCancelSecondVictim() {
        defaultFlowPressureSoftCap = 3
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (queue, gate) = gatedQueue("duplicate-removal")
        defer { gate.signal() }
        let victims = [
            Fx(core: core, idleSeconds: 30, flowQueue: queue),
            Fx(core: core, idleSeconds: 20, flowQueue: queue),
        ]
        let natural = Fx(core: core, idleSeconds: 0)
        insert(core, victims + [natural])
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 2)

        core.removeTcpFlow(natural.flowId)
        pollUntil("natural removal lands") { core.tcpFlowCount == 2 }
        XCTAssertEqual(core.testPressureCanceledTotal, 1)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)

        core.removeTcpFlow(natural.flowId)
        _ = core.tcpFlowCount

        XCTAssertEqual(core.testPressureCanceledTotal, 1)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)
    }

    func testExpiredVictimIsNotRequeuedBehindBlockedFlowQueue() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore(dispatchLeaseMs: 50)
        let (blockedQueue, gate) = gatedQueue("lease-tombstone")
        defer { gate.signal() }
        let blocked = Fx(core: core, idleSeconds: 30, flowQueue: blockedQueue)
        let active = Fx(core: core, idleSeconds: 0)
        insert(core, [blocked, active])

        triggerAndDrain(core)
        pollUntil("blocked victim lease expires") { core.testPressureExpiredTotal == 1 }
        Thread.sleep(forTimeInterval: 0.35)

        XCTAssertEqual(core.testPressureSelectionsTotal, 1)
        XCTAssertEqual(core.testPressureEvictionBodyRuns, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
        XCTAssertFalse(
            core.testPressureRecheckScheduled,
            "an expired tombstone must not create autonomous retry polling")

        gate.signal()
        drain(blockedQueue)
        pollUntil("responsive flow is evicted after acknowledging stale work") {
            core.testPressureEvictedTotal == 1
        }
        XCTAssertEqual(core.testPressureSelectionsTotal, 2)
        XCTAssertEqual(core.testPressureEvictionBodyRuns, 2)
        XCTAssertEqual(core.testPressureEvictedTotal, 1)
    }

    func testNaturalRemovalsCancelQueuedVictimsBeforeOverEviction() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (queue, gate) = gatedQueue("natural-relief")
        defer { gate.signal() }
        let selected = (0..<4).map {
            Fx(core: core, idleSeconds: 100 + UInt64($0), flowQueue: queue)
        }
        let natural = [
            Fx(core: core, idleSeconds: 10, flowQueue: queue),
            Fx(core: core, idleSeconds: 11, flowQueue: queue),
        ]
        insert(core, selected + natural)

        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 4)
        core.removeTcpFlow(natural[0].flowId)
        core.removeTcpFlow(natural[1].flowId)
        pollUntil("natural removals reconcile reservations") {
            core.tcpFlowCount == 4 && core.testPressurePendingVictimCount == 2
        }
        XCTAssertEqual(core.testPressureCanceledTotal, 2)

        gate.signal()
        pollUntil("remaining pressure work reaches low-water") { core.tcpFlowCount == 2 }
        drain(queue)
        XCTAssertEqual(selected.filter { $0.wasTornDown }.count, 2)
        XCTAssertEqual(core.testPressureEvictedTotal, 2)
        XCTAssertEqual(core.testPressureCanceledTotal, 2)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
    }

    func testAnnouncedNaturalRemovalsBeatVictimCommitsWhileStateQueueIsBusy() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (victimQueue, victimGate) = gatedQueue("natural-relief-inverse")
        defer { victimGate.signal() }
        let selected = (0..<4).map {
            Fx(core: core, idleSeconds: 100 + UInt64($0), flowQueue: victimQueue)
        }
        let natural = [
            Fx(core: core, idleSeconds: 10),
            Fx(core: core, idleSeconds: 11),
        ]
        insert(core, selected + natural)
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 4)

        let stateGate = core.testHoldStateQueue()
        defer { stateGate.signal() }
        core.removeTcpFlow(natural[0].flowId)
        core.removeTcpFlow(natural[1].flowId)
        victimGate.signal()
        drain(victimQueue)
        stateGate.signal()

        pollUntil("announced relief and surviving victims reach low-water") {
            core.tcpFlowCount == 2 && core.testPressurePendingVictimCount == 0
        }
        XCTAssertEqual(selected.filter { $0.wasTornDown }.count, 2)
        XCTAssertEqual(core.testPressureEvictedTotal, 2)
        XCTAssertEqual(core.testPressureCanceledTotal, 2)
    }

    func testRemovingSelectedVictimKeepsItsReliefCredit() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (victimQueue, victimGate) = gatedQueue("selected-removal-credit")
        defer { victimGate.signal() }
        let first = Fx(
            core: core,
            idleSeconds: 100,
            flowQueue: victimQueue)
        let removing = Fx(
            core: core,
            idleSeconds: 90,
            flowQueue: victimQueue)
        let natural = Fx(core: core, idleSeconds: 0)
        let survivor = Fx(core: core, idleSeconds: 0)
        insert(core, [first, removing, natural, survivor])
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 2)

        let stateGate = core.testHoldStateQueue()
        defer { stateGate.signal() }
        // `removing` already owns victim credit. A second natural removal
        // must cancel `first`, not discard the credit of a flow already
        // certain to leave and then evict `first` below low-water.
        core.removeTcpFlow(removing.flowId, context: removing.ctx)
        core.removeTcpFlow(natural.flowId, context: natural.ctx)
        stateGate.signal()
        pollUntil("announced removals land") { core.tcpFlowCount == 2 }

        victimGate.signal()
        drain(victimQueue)
        _ = core.tcpFlowCount
        XCTAssertEqual(core.tcpFlowCount, 2, "must not evict below low-water")
        XCTAssertFalse(first.wasTornDown)
        XCTAssertEqual(core.testPressureEvictedTotal, 0)
        XCTAssertEqual(
            core.testPressureCanceledTotal,
            2,
            "one canceled selection plus the selected flow's natural teardown")
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
    }

    func testCanceledVictimNaturalRemovalSuppliesFreshRelief() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (victimQueue, victimGate) = gatedQueue("canceled-victim-relief")
        defer { victimGate.signal() }
        let selected = (0..<4).map {
            Fx(core: core, idleSeconds: 100 + UInt64($0), flowQueue: victimQueue)
        }
        let natural = [
            Fx(core: core, idleSeconds: 10),
            Fx(core: core, idleSeconds: 11),
        ]
        insert(core, selected + natural)
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 4)

        let stateGate = core.testHoldStateQueue()
        defer { stateGate.signal() }
        // The first removal cancels the newest reservation (selected[0]).
        // Its own natural removal must then count as fresh relief and cancel
        // one more victim before either surviving victim can commit.
        core.removeTcpFlow(natural[0].flowId)
        core.removeTcpFlow(selected[0].flowId, context: selected[0].ctx)
        victimGate.signal()
        drain(victimQueue)
        stateGate.signal()

        pollUntil("canceled victim relief reaches low-water") {
            core.tcpFlowCount == 2 && core.testPressurePendingVictimCount == 0
        }
        XCTAssertEqual(selected.filter { $0.wasTornDown }.count, 2)
        XCTAssertEqual(core.testPressureEvictedTotal, 2)
        XCTAssertEqual(core.testPressureCanceledTotal, 2)
    }

    func testCanceledTombstoneCannotHideVictimFromNextEpisode() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in
            notices.withLock { $0.append(message) }
        }
        let (queue, gate) = gatedQueue("canceled-next-episode")
        let stale = Fx(core: core, idleSeconds: 30, flowQueue: queue)
        let relief = Fx(core: core, idleSeconds: 0)
        insert(core, [stale, relief])

        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 1)
        core.removeTcpFlow(relief.flowId)
        pollUntil("natural removal ends first episode") {
            core.tcpFlowCount == 1 && core.testPressureCanceledTotal == 1
        }
        let firstEpisode = notices.withLock {
            $0.last { $0.contains("flow pressure episode ended") } ?? ""
        }
        XCTAssertTrue(
            firstEpisode.contains("selected=1 evicted=0 spared=0 canceled=1"),
            firstEpisode)

        let admission = Fx(core: core, idleSeconds: 0)
        insert(core, [admission])
        core.reapIdleUnderPressure(protecting: admission.flowId)
        pollUntil("second episode observes tombstone") {
            !core.testPressureReapScheduled && core.testPressureScanCount == 2
        }
        XCTAssertFalse(stale.wasTornDown)

        gate.signal()
        pollUntil("acknowledged tombstone is reconsidered") {
            stale.wasTornDown && core.tcpFlowCount == 1
        }
        XCTAssertFalse(admission.wasTornDown)
        XCTAssertEqual(
            core.testPressureScanCount,
            2,
            "the acknowledged flow-local check is re-armed without a full sort")
        XCTAssertEqual(core.testPressureEvictedTotal, 1)
    }

    func testClusteredSparesCauseOnlyOneReplacementScan() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (victimQueue, victimGate) = gatedQueue("clustered-spares")
        defer { victimGate.signal() }
        let flows = (0..<4).map {
            Fx(core: core, idleSeconds: 30 + UInt64($0), flowQueue: victimQueue)
        }
        insert(core, flows)
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 3)
        flows.forEach { $0.markActiveNow() }

        let stateGate = core.testHoldStateQueue()
        defer { stateGate.signal() }
        victimGate.signal()
        drain(victimQueue)
        stateGate.signal()
        pollUntil("all clustered spares are accounted") {
            core.testPressureSparedTotal == 3
        }

        XCTAssertEqual(core.testPressureScanCount, 2, "one initial and one replacement scan")
        XCTAssertEqual(core.testPressureSelectionsTotal, 3)
        XCTAssertEqual(core.testPressureEvictedTotal, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
    }

    func testLateFinalSpareRepairsAfterSiblingVictimsLeave() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (lateQueue, lateGate) = gatedQueue("late-spare")
        let (firstQueue, firstGate) = gatedQueue("late-spare-first")
        let (secondQueue, secondGate) = gatedQueue("late-spare-second")
        defer {
            lateGate.signal()
            firstGate.signal()
            secondGate.signal()
        }
        let late = Fx(core: core, idleSeconds: 100, flowQueue: lateQueue)
        let first = Fx(core: core, idleSeconds: 90, flowQueue: firstQueue)
        let second = Fx(core: core, idleSeconds: 80, flowQueue: secondQueue)
        let replacement = Fx(core: core, idleSeconds: 70)
        let active = Fx(core: core, idleSeconds: 0)
        insert(core, [late, first, second, replacement, active])
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 3)

        let stateGate = core.testHoldStateQueue()
        defer { stateGate.signal() }
        firstGate.signal()
        secondGate.signal()
        drain(firstQueue)
        drain(secondQueue)
        late.markActiveNow()
        lateGate.signal()
        drain(lateQueue)
        stateGate.signal()

        pollUntil("late spare replacement reaches low-water") {
            core.tcpFlowCount == 2 && core.testPressurePendingVictimCount == 0
        }
        XCTAssertFalse(late.wasTornDown)
        XCTAssertTrue(first.wasTornDown)
        XCTAssertTrue(second.wasTornDown)
        XCTAssertTrue(replacement.wasTornDown)
        XCTAssertEqual(core.testPressureScanCount, 2)
        XCTAssertEqual(core.testPressureSelectionsTotal, 4)
        XCTAssertEqual(core.testPressureEvictedTotal, 3)
        XCTAssertEqual(core.testPressureSparedTotal, 1)
    }

    func testLateFinalExpiryRepairsAfterSiblingVictimsLeave() {
        defaultFlowPressureSoftCap = 4
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (lateQueue, lateGate) = gatedQueue("late-expiry")
        defer { lateGate.signal() }
        let late = Fx(core: core, idleSeconds: 100, flowQueue: lateQueue)
        let first = Fx(core: core, idleSeconds: 90)
        let second = Fx(core: core, idleSeconds: 80)
        let replacement = Fx(core: core, idleSeconds: 70)
        let active = Fx(core: core, idleSeconds: 0)
        insert(core, [late, first, second, replacement, active])
        triggerAndDrain(core)
        pollUntil("responsive siblings leave before expiry") {
            core.tcpFlowCount == 3 && core.testPressureEvictedTotal == 2
        }

        core.testRunPressureRecheck(afterMs: 6_000)
        pollUntil("expired credit is repaired to low-water") {
            core.tcpFlowCount == 2 && core.testPressurePendingVictimCount == 0
        }
        XCTAssertFalse(late.wasTornDown)
        XCTAssertTrue(replacement.wasTornDown)
        XCTAssertEqual(core.testPressureScanCount, 2)
        XCTAssertEqual(core.testPressureSelectionsTotal, 4)
        XCTAssertEqual(core.testPressureEvictedTotal, 3)
        XCTAssertEqual(core.testPressureExpiredTotal, 1)

        lateGate.signal()
        drain(lateQueue)
        XCTAssertEqual(core.tcpFlowCount, 2)
        XCTAssertFalse(late.wasTornDown)
    }

    func testAdmissionBelowCapIsProtectedDuringActiveRepair() {
        defaultFlowPressureSoftCap = 5
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 0
        let core = makeCore()
        let (lateQueue, lateGate) = gatedQueue("below-cap-admission")
        defer { lateGate.signal() }
        let late = Fx(core: core, idleSeconds: 100, flowQueue: lateQueue)
        let siblings = (0..<3).map {
            Fx(core: core, idleSeconds: 90 - UInt64($0))
        }
        let replacement = Fx(core: core, idleSeconds: 70)
        let connecting = Fx(core: core, idleSeconds: 0, ready: false)
        insert(core, [late] + siblings + [replacement, connecting])
        triggerAndDrain(core)
        pollUntil("siblings leave below cap while one victim remains") {
            core.tcpFlowCount == 3 && core.testPressureEvictedTotal == 3
        }

        let admitted = Fx(core: core, idleSeconds: 10)
        XCTAssertEqual(
            core.registerTcpFlow(
                admitted.flowId,
                anchor: _TestTcpFlowSessionAnchor(ctx: admitted.ctx)),
            4,
            "admission lands below the soft cap while the episode is active")
        late.markActiveNow()
        lateGate.signal()

        pollUntil("late spare chooses only the older replacement") {
            replacement.wasTornDown && core.testPressureSparedTotal == 1
        }
        XCTAssertEqual(core.tcpFlowCount, 3)
        XCTAssertFalse(admitted.wasTornDown)
        XCTAssertFalse(late.wasTornDown)
        XCTAssertEqual(core.testPressureSelectionsTotal, 5)
        XCTAssertEqual(core.testPressureEvictedTotal, 4)
    }

    func testExpiredAcknowledgmentClusterAddsOnlyOneFullScan() {
        defaultFlowPressureSoftCap = 450
        defaultFlowPressureLowWater = 350
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let (queue, gate) = gatedQueue("expired-ack-cluster")
        defer { gate.signal() }
        let expired = (0..<100).map {
            Fx(core: core, idleSeconds: 30 + UInt64($0), flowQueue: queue)
        }
        let connecting = (0..<350).map {
            _ in Fx(core: core, idleSeconds: 0, ready: false)
        }
        insert(core, expired + connecting)
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressureSelectionsTotal, 100)

        core.testRunPressureRecheck(afterMs: 6_000)
        XCTAssertEqual(core.testPressureExpiredTotal, 100)
        XCTAssertEqual(core.testPressureScanCount, 2)
        XCTAssertFalse(core.testPressureRecheckScheduled)
        expired.forEach { $0.markActiveNow() }

        let stateGate = core.testHoldStateQueue()
        defer { stateGate.signal() }
        gate.signal()
        drain(queue, timeout: 5.0)
        stateGate.signal()
        pollUntil("clustered acknowledgments settle", timeout: 5.0) {
            core.testPressureScanCount == 3
        }

        XCTAssertEqual(core.testPressureScanCount, 3)
        XCTAssertEqual(core.testPressureSelectionsTotal, 100)
        XCTAssertEqual(core.testPressureEvictionBodyRuns, 100)
        XCTAssertEqual(core.testPressureEvictedTotal, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
        XCTAssertEqual(core.tcpFlowCount, 450)
    }

    func testRemovalChurnCannotBypassNoHeadroomSuppression() {
        defaultFlowPressureSoftCap = 5
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 60_000
        let core = makeCore()
        let flows = (0..<8).map { _ in Fx(core: core, idleSeconds: 0) }
        insert(core, flows)
        core.testReapIdleUnderPressureIfDue()
        XCTAssertEqual(core.testPressureScanCount, 1)

        for flow in flows.prefix(3) { core.removeTcpFlow(flow.flowId) }
        pollUntil("removal burst lands") { core.tcpFlowCount == 5 }

        XCTAssertEqual(core.testPressureScanCount, 1)
        XCTAssertEqual(core.testPressureEvictedTotal, 0)
        XCTAssertGreaterThanOrEqual(core.testPressureRescanSuppressedForMs, 1)
    }

    func testNoHeadroomSuppressionDoesNotCreateAutonomousPolling() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 60_000
        let core = makeCore()
        let oldest = Fx(core: core, idleSeconds: 0)
        let other = Fx(core: core, idleSeconds: 0)
        insert(core, [oldest, other])

        core.testReapIdleUnderPressureIfDue()
        XCTAssertEqual(core.testPressureScanCount, 1)
        XCTAssertGreaterThan(core.testPressureRescanSuppressedForMs, 0)
        XCTAssertFalse(
            core.testPressureRecheckScheduled,
            "suppression gates real triggers; it must not poll forever on its own")
        XCTAssertEqual(core.testPressureEvictedTotal, 0)
    }

    func testNaturalReliefClearsSuppressionWithoutDelayedWork() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 60_000
        let core = makeCore()
        let first = Fx(core: core, idleSeconds: 0)
        let second = Fx(core: core, idleSeconds: 0)
        insert(core, [first, second])

        core.testReapIdleUnderPressureIfDue()
        XCTAssertEqual(core.testPressureScanCount, 1)
        core.removeTcpFlow(second.flowId)
        pollUntil("natural relief reaches low-water") { core.tcpFlowCount == 1 }

        XCTAssertEqual(core.testPressureScanCount, 1, "canceled wake does not rescan")
        XCTAssertEqual(core.testPressureRescanSuppressedForMs, 0)
        XCTAssertFalse(core.testPressureRecheckScheduled)
    }

    func testLastSpareResolutionFinalizesEpisode() {
        defaultFlowPressureSoftCap = 2
        defaultFlowPressureLowWater = 1
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        let (queue, flowGate) = gatedQueue("last-spare")
        defer { flowGate.signal() }
        let victim = Fx(core: core, idleSeconds: 30, flowQueue: queue)
        let natural = Fx(core: core, idleSeconds: 0)
        insert(core, [victim, natural])
        triggerAndDrain(core)
        core.testRunPeriodicMaintenance()

        let stateGate = core.testHoldStateQueue()
        defer { stateGate.signal() }
        victim.markActiveNow()
        flowGate.signal()
        pollUntil("victim final check marks a spare") {
            core.testPressureEvictionBodyRuns == 1
        }
        core.removeTcpFlow(natural.flowId)
        stateGate.signal()
        pollUntil("spare accounting finalizes episode") {
            notices.withLock { $0.contains { $0.contains("flow pressure episode ended") } }
        }

        XCTAssertEqual(core.testPressureSparedTotal, 1)
        XCTAssertEqual(core.testPressureEvictedTotal, 0)
        XCTAssertEqual(core.testPressurePendingVictimCount, 0)
        core.testRunPeriodicMaintenance()
        let spareTick = notices.withLock {
            $0.last { $0.contains("tproxy live-flow counts") } ?? ""
        }
        XCTAssertTrue(
            spareTick.contains(
                "selected=0 evicted=0 spared=1 canceled=0 expired=0 pending=0"),
            spareTick)
        core.testRunPeriodicMaintenance()
        let resetTick = notices.withLock {
            $0.last { $0.contains("tproxy live-flow counts") } ?? ""
        }
        XCTAssertTrue(
            resetTick.contains(
                "selected=0 evicted=0 spared=0 canceled=0 expired=0 pending=0"),
            resetTick)
        let episode = notices.withLock {
            $0.last { $0.contains("flow pressure episode ended") } ?? ""
        }
        XCTAssertTrue(episode.contains("selected=1 evicted=0 spared=1"), episode)
    }

    func testEpisodePeakIncludesAdmissionsHiddenByPendingCredits() {
        defaultFlowPressureSoftCap = 5
        defaultFlowPressureLowWater = 2
        defaultFlowPressureIdleFloorMs = 5_000
        let core = makeCore()
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        let (queue, gate) = gatedQueue("episode-peak")
        defer { gate.signal() }
        let idle = (0..<6).map {
            Fx(core: core, idleSeconds: 10 + UInt64($0), flowQueue: queue)
        }
        insert(core, idle)
        triggerAndDrain(core)
        XCTAssertEqual(core.testPressurePendingVictimCount, 4)

        for _ in 0..<2 {
            insert(core, [Fx(core: core, idleSeconds: 0)])
            triggerAndDrain(core)
        }
        XCTAssertEqual(core.testPressureScanCount, 1, "pending credit avoids redundant sorts")

        gate.signal()
        // The original batch removes four from six. Two admissions land while
        // that capacity is pending, so the batch settles at four without
        // chasing those arrivals through one sort apiece. The episode remains
        // open inside the hysteresis band until ordinary relief reaches two.
        pollUntil("batch settles") { core.tcpFlowCount == 4 }
        XCTAssertEqual(core.testPressureScanCount, 1)
        core.removeTcpFlow(idle[0].flowId)
        core.removeTcpFlow(idle[1].flowId)
        pollUntil("episode reaches low-water") { core.tcpFlowCount == 2 }
        let episode = notices.withLock {
            $0.last { $0.contains("flow pressure episode ended") } ?? ""
        }
        XCTAssertTrue(episode.contains("peakOccupancy=8"), episode)
    }
}
