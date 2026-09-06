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
                admissionToken: token,
                engineGeneration: generation),
            2)
        core.finishTcpStart(token, outcome: .ready)
        XCTAssertEqual(core.tcpFlowCount + core.udpFlowCount, 2)
    }

    func testUdpCapRejectionAbandonsPendingCloseAndLeavesFlowUntouched() {
        defaultLiveFlowHardCap = 1
        let core = TransparentProxyCore()
        let generation = core.attachEngine(makeEngine())
        defer { core.testDetachAndDrainFlowQueues() }

        let held = MockUdpFlow()
        XCTAssertEqual(
            core.registerUdpFlow(
                ObjectIdentifier(held),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: generation),
            1)

        let rejected = MockUdpFlow()
        let ctx = UdpFlowContext()
        let queue = DispatchQueue(label: "rama.test.udp.pending-close.cap-reject")
        ctx.flowQueue = queue
        XCTAssertFalse(ctx.registrationGate.recordServerClose())
        let replayed = AtomicFlag()
        let decision = core.registerUdpFlowAndScheduleStartupDecision(
            ObjectIdentifier(rejected),
            anchor: _TestUdpFlowSessionAnchor(ctx: ctx),
            appId: "com.example.cap-reject",
            engineGeneration: generation,
            on: queue,
            body: { XCTFail("capacity-refused UDP must not start") },
            pendingServerClose: { replayed.store(true) })

        guard case .capacityRefused = decision else {
            return XCTFail("second flow must be refused at the hard cap")
        }
        XCTAssertFalse(ctx.registrationGate.recordServerClose())
        queue.sync {}
        XCTAssertFalse(replayed.load())
        XCTAssertFalse(rejected.openWasInvoked)
        XCTAssertEqual(rejected.closeReadCallCount, 0)
        XCTAssertEqual(rejected.closeWriteCallCount, 0)
        XCTAssertEqual(core.udpFlowCount, 1)
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

    func testUdpDominantPopulationStaysBoundedAtProductionHardCap() {
        defaultLiveFlowHardCap = 500
        let core = TransparentProxyCore()
        let generation = core.attachEngine(makeEngine())
        defer { core.testDetachAndDrainFlowQueues() }
        let flows = (0..<500).map { _ in MockUdpFlow() }
        // The registry retains identifiers, not these mocks. Prevent optimized
        // builds from reusing an existing identity for the replacement below.
        defer { withExtendedLifetime(flows) {} }
        for (index, flow) in flows.enumerated() {
            XCTAssertEqual(
                core.registerUdpFlow(
                    ObjectIdentifier(flow),
                    anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                    engineGeneration: generation),
                index + 1)
        }
        for passthrough in [true, false] {
            defaultFlowRefusalPassthrough = passthrough
            let udp = MockUdpFlow()
            XCTAssertEqual(
                core.handleUdpFlowDecision(udp, meta: meta(protocolRaw: 2, port: 443)),
                passthrough ? .passthrough : .blocked)
            let tcp = MockTcpFlow()
            XCTAssertEqual(
                core.handleTcpFlow(tcp, meta: meta(protocolRaw: 1, port: 443)),
                !passthrough)
            XCTAssertEqual(udp.closeReadCallCount, passthrough ? 0 : 1)
            XCTAssertEqual(tcp.closeReadCallCount, passthrough ? 0 : 1)
        }
        XCTAssertEqual(core.testLiveResourceOccupancy, 500)
        XCTAssertTrue(flows.allSatisfy { $0.closeReadCallCount == 0 })
        core.removeUdpFlow(ObjectIdentifier(flows[0]), engineGeneration: generation)
        XCTAssertEqual(core.udpFlowCount, 499)
        let replacement = MockUdpFlow()
        XCTAssertEqual(
            core.registerUdpFlow(
                ObjectIdentifier(replacement),
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: generation),
            500)
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

    func testRegisteredRetirementTransferDoesNotDoubleCountBeforeRemoval() {
        defaultLiveFlowHardCap = 3
        let core = TransparentProxyCore()
        let first = MockTcpFlow()
        let firstId = ObjectIdentifier(first)
        let firstContext = TcpFlowContext()
        firstContext.core = core
        firstContext.flow = first
        firstContext.flowId = firstId
        let second = MockTcpFlow()
        let secondId = ObjectIdentifier(second)
        let secondContext = TcpFlowContext()
        secondContext.core = core
        secondContext.flow = second
        secondContext.flowId = secondId
        XCTAssertEqual(
            core.registerTcpFlow(
                firstId, anchor: _TestTcpFlowSessionAnchor(ctx: firstContext)),
            1)
        XCTAssertEqual(
            core.registerTcpFlow(
                secondId, anchor: _TestTcpFlowSessionAnchor(ctx: secondContext)),
            2)

        let release = core.transferRegisteredResourceToRetirement(
            flowId: firstId,
            contextId: ObjectIdentifier(firstContext),
            engineGeneration: nil,
            identity: firstContext.retirementIdentity())
        defer {
            core.removeTcpFlow(firstId, context: firstContext)
            core.removeTcpFlow(secondId, context: secondContext)
            release()
            _ = core.tcpFlowCount
        }

        XCTAssertEqual(core.tcpFlowCount, 2, "async registry removal is intentionally held")
        XCTAssertEqual(core.testRetiringResourceCount, 1)
        XCTAssertEqual(core.testRegisteredRetirementOverlapCount, 1)
        XCTAssertEqual(core.testLiveResourceOccupancy, 2)

        let notices = Locked([String]())
        LifecycleLog.noticeOverride = { message in notices.withLock { $0.append(message) } }
        core.testRunPeriodicMaintenance()
        LifecycleLog.noticeOverride = nil
        let countLine = notices.withLock {
            $0.last { $0.contains("tproxy live-flow counts") } ?? ""
        }
        XCTAssertTrue(countLine.contains("tcp=2 udp=0 total=2"), countLine)
        XCTAssertTrue(countLine.contains("retiring=1 retirementOverlap=1"), countLine)

        let admitted = MockTcpFlow()
        guard case .admit(let token) = core.admitTcpStart(
            flowId: ObjectIdentifier(admitted),
            meta: meta(protocolRaw: 1, port: 443))
        else {
            return XCTFail("the transferred flow must consume exactly one live slot")
        }
        core.finishTcpStart(token, outcome: .failed)
        XCTAssertEqual(core.testTcpLiveFlowReservations, 0)

        let directTcp = MockTcpFlow()
        let directTcpId = ObjectIdentifier(directTcp)
        let directTcpContext = TcpFlowContext()
        XCTAssertEqual(
            core.registerTcpFlow(
                directTcpId,
                anchor: _TestTcpFlowSessionAnchor(ctx: directTcpContext)),
            3,
            "tokenless fallback registration must use overlap-aware occupancy")
        core.removeTcpFlow(directTcpId, context: directTcpContext)
        XCTAssertEqual(core.tcpFlowCount, 2)

        let udp = MockUdpFlow()
        let udpId = ObjectIdentifier(udp)
        XCTAssertEqual(
            core.registerUdpFlow(
                udpId,
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext())),
            3,
            "UDP admission must use the same overlap-aware occupancy")
        core.removeUdpFlow(udpId)
        XCTAssertEqual(core.udpFlowCount, 0)
    }

    func testReleasedRetirementStillOffsetsStaleRegistryOwner() {
        defaultLiveFlowHardCap = 1
        let core = TransparentProxyCore()
        let flow = MockTcpFlow()
        let flowId = ObjectIdentifier(flow)
        let context = TcpFlowContext()
        context.core = core
        context.flow = flow
        context.flowId = flowId
        XCTAssertEqual(
            core.registerTcpFlow(
                flowId, anchor: _TestTcpFlowSessionAnchor(ctx: context)),
            1)

        let release = core.transferRegisteredResourceToRetirement(
            flowId: flowId,
            contextId: ObjectIdentifier(context),
            engineGeneration: nil,
            identity: context.retirementIdentity())
        release()
        release()
        XCTAssertEqual(core.testRetiringResourceCount, 0)
        XCTAssertEqual(core.testRegisteredRetirementOverlapCount, 1)
        XCTAssertEqual(
            core.testLiveResourceOccupancy, 0,
            "a released connection must not be resurrected by its stale map owner")

        let replacement = MockUdpFlow()
        let replacementId = ObjectIdentifier(replacement)
        XCTAssertEqual(
            core.registerUdpFlow(
                replacementId,
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext())),
            2)
        core.removeTcpFlow(flowId, context: context)
        XCTAssertEqual(core.tcpFlowCount, 0)
        XCTAssertEqual(core.testRegisteredRetirementOverlapCount, 0)
        XCTAssertEqual(core.testLiveResourceOccupancy, 1)
        core.removeUdpFlow(replacementId)
        XCTAssertEqual(core.udpFlowCount, 0)
    }

    func testDetachAndQueuedPromotedTerminalShareOnePhysicalClaim() {
        defaultLiveFlowHardCap = 2
        let core = TransparentProxyCore()
        let firstGeneration = core.attachEngine(makeEngine())
        let flow = MockTcpFlow()
        let flowId = ObjectIdentifier(flow)
        let connection = MockNwConnection()
        connection.transition(to: .ready)
        let queue = DispatchQueue(label: "rama.test.live-cap.detach-promoted-claim")
        let startPromoted = DispatchSemaphore(value: 0)
        let promotedApplied = DispatchSemaphore(value: 0)
        let releaseQueue = DispatchSemaphore(value: 0)
        let pump = NwTcpConnectionWritePump(
            connection: connection,
            queue: queue,
            onDrained: {})
        let context = TcpFlowContext()
        context.core = core
        context.flow = flow
        context.flowId = flowId
        context.flowQueue = queue
        context.connection = connection
        context.egressWritePump = pump
        context.engineGeneration = firstGeneration
        XCTAssertEqual(
            core.registerTcpFlow(
                flowId,
                anchor: _TestTcpFlowSessionAnchor(ctx: context),
                engineGeneration: firstGeneration),
            1)
        queue.async {
            startPromoted.wait()
            context.applyPromotedTerminal()
            promotedApplied.signal()
            releaseQueue.wait()
        }
        defer {
            startPromoted.signal()
            releaseQueue.signal()
            queue.sync {}
            core.testDetachAndDrainFlowQueues()
        }

        core.detachEngine(reason: 0)
        let secondGeneration = core.attachEngine(makeEngine())
        XCTAssertEqual(core.testRetiringResourceCount, 1)

        startPromoted.signal()
        XCTAssertEqual(promotedApplied.wait(timeout: .now() + 2), .success)
        XCTAssertEqual(
            core.testRetiringResourceCount, 1,
            "detach and promoted linger are claimants of one physical connection")
        XCTAssertEqual(core.testRegisteredRetirementOverlapCount, 0)

        let replacement = MockUdpFlow()
        let replacementId = ObjectIdentifier(replacement)
        XCTAssertEqual(
            core.registerUdpFlow(
                replacementId,
                anchor: _TestUdpFlowSessionAnchor(ctx: UdpFlowContext()),
                engineGeneration: secondGeneration),
            1,
            "one old connection leaves one of two new-generation slots available")

        releaseQueue.signal()
        queue.sync {}
        XCTAssertEqual(
            core.testRetiringResourceCount, 1,
            "detach release must not release the promoted pump's claim")
        XCTAssertEqual(connection.cancelCount, 0)

        pump.releaseTerminalConnection()
        pollUntil("promoted linger releases the shared retirement resource") {
            core.testRetiringResourceCount == 0 && connection.cancelCount == 1
        }
        core.removeUdpFlow(replacementId, engineGeneration: secondGeneration)
        XCTAssertEqual(core.udpFlowCount, 0)
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

        pump.releaseTerminalConnection()
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
        queue.sync { pump.releaseTerminalConnection() }
        XCTAssertEqual(core.testRetiringResourceCount, 0)

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
