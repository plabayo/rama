import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

final class LiveFlowHardCapTests: XCTestCase {
    private var savedHardCap: UInt32 = 0
    private var savedRefusalPassthrough = true
    private var savedTcpStartHardCap: UInt32 = 0

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    override func setUp() {
        super.setUp()
        savedHardCap = defaultLiveFlowHardCap
        savedRefusalPassthrough = defaultFlowRefusalPassthrough
        savedTcpStartHardCap = defaultTcpStartInFlightHardCap
        defaultTcpStartInFlightHardCap = 0
    }

    override func tearDown() {
        defaultLiveFlowHardCap = savedHardCap
        defaultFlowRefusalPassthrough = savedRefusalPassthrough
        defaultTcpStartInFlightHardCap = savedTcpStartHardCap
        super.tearDown()
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

    private func meta(protocolRaw: UInt32, port: UInt16) -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: protocolRaw,
            remoteHost: "example.com",
            remotePort: port,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: "com.example.cap-test",
            sourceAppAuditToken: nil,
            sourceAppPid: 4242)
    }

    func testPendingTcpReservationBlocksRacingUdpAtCombinedCap() {
        defaultLiveFlowHardCap = 2
        let core = TransparentProxyCore()
        let generation = core.attachEngine(makeEngine())
        defer { core.testDetachAndDrainFlowQueues() }

        let firstUdp = MockUdpFlow()
        XCTAssertEqual(
            core.registerUdpFlow(
                ObjectIdentifier(firstUdp),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: generation),
            1)

        let tcpFlow = MockTcpFlow()
        let admission = core.admitTcpStart(
            flowId: ObjectIdentifier(tcpFlow),
            meta: meta(protocolRaw: 1, port: 443),
            engineGeneration: generation)
        guard case .admit(let token) = admission else {
            return XCTFail("second combined slot should be reserved for TCP")
        }

        let racingUdp = MockUdpFlow()
        let udpDecision = core.registerUdpFlowAndScheduleStartupDecision(
            ObjectIdentifier(racingUdp),
            anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
            appId: "com.example.udp",
            engineGeneration: generation,
            on: DispatchQueue(label: "rama.test.live-cap.udp"),
            body: { XCTFail("capacity-refused UDP must not start") })
        guard case .capacityRefused = udpDecision else {
            return XCTFail("pending TCP reservation must count against the cap")
        }

        XCTAssertEqual(
            core.registerTcpFlow(
                ObjectIdentifier(tcpFlow),
                anchor: _TestTcpFlowSessionAnchor(ctx: TcpFlowContext()),
                appId: token.appId,
                engineGeneration: generation),
            2)
        core.finishTcpStart(token, outcome: .ready)
        XCTAssertEqual(core.tcpFlowCount + core.udpFlowCount, 2)
    }

    func testRemovalRestoresOneHardCapSlotAndZeroDisablesCap() {
        defaultLiveFlowHardCap = 1
        let core = TransparentProxyCore()
        let generation = core.attachEngine(makeEngine())
        defer { core.testDetachAndDrainFlowQueues() }

        let first = MockUdpFlow()
        let firstId = ObjectIdentifier(first)
        XCTAssertEqual(
            core.registerUdpFlow(
                firstId,
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: generation),
            1)
        XCTAssertNil(
            core.registerUdpFlow(
                ObjectIdentifier(MockUdpFlow()),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: generation))

        core.removeUdpFlow(firstId, engineGeneration: generation)
        XCTAssertEqual(core.udpFlowCount, 0)
        var additionalFlows: [MockUdpFlow] = []
        let replacement = MockUdpFlow()
        additionalFlows.append(replacement)
        XCTAssertEqual(
            core.registerUdpFlow(
                ObjectIdentifier(replacement),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: generation),
            1)

        defaultLiveFlowHardCap = 0
        for _ in 0..<3 {
            let flow = MockUdpFlow()
            additionalFlows.append(flow)
            XCTAssertNotNil(
                core.registerUdpFlow(
                    ObjectIdentifier(flow),
                    anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                    engineGeneration: generation))
        }
        XCTAssertEqual(core.udpFlowCount, 4)
    }

    func testTcpAndUdpCapacityRefusalHonorConfiguredAction() {
        defaultLiveFlowHardCap = 1
        let core = TransparentProxyCore()
        let generation = core.attachEngine(makeEngine())
        defer { core.testDetachAndDrainFlowQueues() }
        let held = MockUdpFlow()
        XCTAssertNotNil(
            core.registerUdpFlow(
                ObjectIdentifier(held),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: generation))

        defaultFlowRefusalPassthrough = true
        let passTcp = MockTcpFlow()
        XCTAssertFalse(core.handleTcpFlow(passTcp, meta: meta(protocolRaw: 1, port: 443)))
        XCTAssertFalse(passTcp.openWasInvoked)
        let passUdp = MockUdpFlow()
        XCTAssertEqual(
            core.handleUdpFlowDecision(passUdp, meta: meta(protocolRaw: 2, port: 5000)),
            .passthrough)
        XCTAssertFalse(passUdp.openWasInvoked)

        defaultFlowRefusalPassthrough = false
        let blockTcp = MockTcpFlow()
        XCTAssertTrue(core.handleTcpFlow(blockTcp, meta: meta(protocolRaw: 1, port: 443)))
        XCTAssertFalse(blockTcp.openWasInvoked)
        XCTAssertEqual(blockTcp.closeReadCallCount, 1)
        XCTAssertEqual(blockTcp.closeWriteCallCount, 1)
        let blockUdp = MockUdpFlow()
        XCTAssertEqual(
            core.handleUdpFlowDecision(blockUdp, meta: meta(protocolRaw: 2, port: 5000)),
            .blocked)
        XCTAssertFalse(blockUdp.openWasInvoked)
        XCTAssertEqual(blockUdp.closeReadCallCount, 1)
        XCTAssertEqual(blockUdp.closeWriteCallCount, 1)
    }

    func testStaleStartupGenerationCannotDetachNewEngine() {
        let core = TransparentProxyCore()
        let first = core.attachEngine(makeEngine())
        core.detachEngine(reason: 0)
        let second = core.attachEngine(makeEngine())
        defer { core.detachEngine(reason: 0) }

        XCTAssertNotEqual(first, second)
        XCTAssertFalse(core.detachEngine(ifGeneration: first, reason: 0))
        XCTAssertNotNil(core.engine)
        XCTAssertTrue(core.detachEngine(ifGeneration: second, reason: 0))
        XCTAssertNil(core.engine)
    }

    func testPromotedTerminalStillConsumesCapBeforeLingerIsArmed() {
        defaultLiveFlowHardCap = 1
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        let connection = MockNwConnection()
        connection.transition(to: .ready)
        let queue = DispatchQueue(label: "rama.test.live-cap.promoted.pending-linger")
        let pump = NwTcpConnectionWritePump(
            connection: connection,
            queue: queue,
            lingerCloseDeadline: .milliseconds(300),
            onDrained: {})
        let ctx = TcpFlowContext()
        ctx.core = core
        ctx.flow = flow
        ctx.flowId = ObjectIdentifier(flow)
        ctx.flowQueue = queue
        ctx.connection = connection
        ctx.egressWritePump = pump
        XCTAssertEqual(
            core.registerTcpFlow(
                ObjectIdentifier(flow), anchor: _TestTcpFlowSessionAnchor(ctx: ctx)),
            1)

        queue.sync { ctx.applyPromotedTerminal() }

        XCTAssertEqual(core.tcpFlowCount, 0, "terminal flow leaves reclaimable registry")
        XCTAssertEqual(core.testRetiringResourceCount, 1)
        let replacement = MockUdpFlow()
        XCTAssertNil(
            core.registerUdpFlow(
                ObjectIdentifier(replacement),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext())),
            "the live NWConnection must still consume the only hard-cap slot")

        pump.armTerminalLingerCancel()
        pollUntil("test cleanup linger must release its token") {
            core.testRetiringResourceCount == 0
        }
    }

    func testPromotedLingerReleasesCapOnlyAfterConnectionCancel() {
        defaultLiveFlowHardCap = 1
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        let connection = MockNwConnection()
        connection.transition(to: .ready)
        let queue = DispatchQueue(label: "rama.test.live-cap.promoted.release")
        let pump = NwTcpConnectionWritePump(
            connection: connection,
            queue: queue,
            lingerCloseDeadline: .milliseconds(40),
            onDrained: {})
        let ctx = TcpFlowContext()
        ctx.core = core
        ctx.flow = flow
        ctx.flowId = ObjectIdentifier(flow)
        ctx.flowQueue = queue
        ctx.connection = connection
        ctx.egressWritePump = pump
        XCTAssertEqual(
            core.registerTcpFlow(
                ObjectIdentifier(flow), anchor: _TestTcpFlowSessionAnchor(ctx: ctx)),
            1)

        queue.sync { ctx.applyPromotedTerminal() }
        pump.armTerminalLingerCancel()
        XCTAssertEqual(core.testRetiringResourceCount, 1)

        pollUntil("linger must invoke connection cancellation") {
            connection.cancelCount == 1
        }
        XCTAssertEqual(
            core.testRetiringResourceCount, 0,
            "hard-cap retirement releases at the same cancellation point")
        let replacement = MockUdpFlow()
        XCTAssertEqual(
            core.registerUdpFlow(
                ObjectIdentifier(replacement),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext())),
            1)
        core.removeUdpFlow(ObjectIdentifier(replacement))
    }

    func testDetachReattachCountsTcpUntilBlockedFlowQueueCancelsConnection() {
        defaultLiveFlowHardCap = 1
        let core = TransparentProxyCore()
        let firstGeneration = core.attachEngine(makeEngine())
        let flow = MockTcpFlow()
        let connection = MockNwConnection()
        let queue = DispatchQueue(label: "rama.test.live-cap.detach.tcp")
        let blocker = DispatchSemaphore(value: 0)
        queue.async { blocker.wait() }
        defer { blocker.signal() }
        let ctx = TcpFlowContext()
        ctx.core = core
        ctx.flow = flow
        ctx.flowId = ObjectIdentifier(flow)
        ctx.flowQueue = queue
        ctx.connection = connection
        ctx.engineGeneration = firstGeneration
        XCTAssertEqual(
            core.registerTcpFlow(
                ObjectIdentifier(flow),
                anchor: _TestTcpFlowSessionAnchor(ctx: ctx),
                engineGeneration: firstGeneration),
            1)

        core.detachEngine(reason: 0)
        let secondGeneration = core.attachEngine(makeEngine())
        defer { core.testDetachAndDrainFlowQueues() }

        XCTAssertEqual(core.testRetiringResourceCount, 1)
        XCTAssertEqual(connection.cancelCount, 0, "teardown is still queued behind blocker")
        let replacement = MockUdpFlow()
        XCTAssertNil(
            core.registerUdpFlow(
                ObjectIdentifier(replacement),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: secondGeneration))

        blocker.signal()
        queue.sync {}
        XCTAssertEqual(connection.cancelCount, 1)
        XCTAssertEqual(core.testRetiringResourceCount, 0)
        XCTAssertEqual(
            core.registerUdpFlow(
                ObjectIdentifier(replacement),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: secondGeneration),
            1)
    }

    func testDetachReattachCountsUdpUntilBlockedFlowQueueClosesResource() {
        defaultLiveFlowHardCap = 1
        let core = TransparentProxyCore()
        let firstGeneration = core.attachEngine(makeEngine())
        let flow = MockUdpFlow()
        let queue = DispatchQueue(label: "rama.test.live-cap.detach.udp")
        let blocker = DispatchSemaphore(value: 0)
        let closed = TestValue(false)
        queue.async { blocker.wait() }
        defer { blocker.signal() }
        let ctx = UdpFlowContext()
        ctx.flowQueue = queue
        ctx.engineGeneration = firstGeneration
        ctx.terminate = { _ in queue.async { closed.set(true) } }
        XCTAssertEqual(
            core.registerUdpFlow(
                ObjectIdentifier(flow),
                anchor: _TestUdpFlowSessionAnchor(ctx: ctx),
                engineGeneration: firstGeneration),
            1)

        core.detachEngine(reason: 0)
        let secondGeneration = core.attachEngine(makeEngine())
        defer { core.testDetachAndDrainFlowQueues() }

        XCTAssertEqual(core.testRetiringResourceCount, 1)
        XCTAssertFalse(closed.get(), "UDP close is still queued behind blocker")
        let replacement = MockUdpFlow()
        XCTAssertNil(
            core.registerUdpFlow(
                ObjectIdentifier(replacement),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: secondGeneration))

        blocker.signal()
        queue.sync {}
        XCTAssertTrue(closed.get())
        XCTAssertEqual(core.testRetiringResourceCount, 0)
        XCTAssertEqual(
            core.registerUdpFlow(
                ObjectIdentifier(replacement),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: secondGeneration),
            1)
    }

    func testRetirementTokensAreUniqueIdempotentAndSurviveMaintenanceReset() {
        let core = TransparentProxyCore()
        let releaseFirst = core.beginResourceRetirement()
        let releaseSecond = core.beginResourceRetirement()
        XCTAssertEqual(core.testRetiringResourceCount, 2)

        releaseFirst()
        releaseFirst()
        XCTAssertEqual(core.testRetiringResourceCount, 1, "duplicate release is a no-op")

        core.detachEngine(reason: 0)
        XCTAssertEqual(
            core.testRetiringResourceCount, 1,
            "maintenance reset must not forgive an old generation's live resource")
        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        defer { LifecycleLog.noticeOverride = nil }
        core.testRunPeriodicMaintenance()
        let countLine = notices.withLock {
            $0.last { $0.contains("tproxy live-flow counts") } ?? ""
        }
        XCTAssertTrue(countLine.contains("tcp=0 udp=0 total=1 peak=1"), countLine)
        XCTAssertTrue(countLine.contains("retiring=1"), countLine)

        releaseSecond()
        XCTAssertEqual(core.testRetiringResourceCount, 0)
    }
}
