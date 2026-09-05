import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

final class RuntimePolicyGenerationTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
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

    private func makePolicy(
        writeCap: Int,
        pressureSoftCap: UInt32 = 20,
        pressureLowWater: UInt32 = 10,
        liveHardCap: UInt32 = 30,
        udpIdleTimeoutMs: UInt64,
        tcpStartHardCap: UInt32 = 8,
        tcpStartSoftCap: UInt32 = 4,
        refusalPassthrough: Bool,
        writerMemoryMaxBytes: Int = WriterMemoryPolicy.default.maxBytes,
        writerMemoryMaxItems: Int = WriterMemoryPolicy.default.maxItems
    ) -> TransparentProxyRuntimePolicy {
        TransparentProxyRuntimePolicy(
            tcpWritePumpMaxPendingBytes: writeCap,
            flowPressureSoftCap: pressureSoftCap,
            flowPressureLowWater: pressureLowWater,
            flowPressureIdleFloorMs: 1_000,
            liveFlowHardCap: liveHardCap,
            udpIdleTimeoutMs: udpIdleTimeoutMs,
            tcpStartInFlightHardCap: tcpStartHardCap,
            tcpStartInFlightSoftCap: tcpStartSoftCap,
            tcpStartLatencyBreakerP95Ms: 100,
            tcpStartLatencyBreakerCloseP95Ms: 50,
            tcpPressureConnectTimeoutMs: 80,
            tcpBreakerConnectTimeoutMs: 40,
            flowRefusalPassthrough: refusalPassthrough,
            writerMemoryMaxBytes: writerMemoryMaxBytes,
            writerMemoryMaxItems: writerMemoryMaxItems)
    }

    private func makeMeta(protocolRaw: UInt32) -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: protocolRaw,
            remoteHost: "127.0.0.1",
            remotePort: 443,
            localHost: nil,
            localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: "policy.test",
            sourceAppAuditToken: nil,
            sourceAppPid: 42)
    }

    private func makeStartup(
        writeCap: Int,
        pressureSoftCap: UInt32,
        pressureLowWater: UInt32,
        liveHardCap: UInt32,
        udpIdleTimeoutMs: UInt64,
        tcpStartHardCap: UInt32,
        tcpStartSoftCap: UInt32,
        refusalPassthrough: Bool
    ) -> RamaTransparentProxyConfigBridge {
        RamaTransparentProxyConfigBridge(
            tunnelRemoteAddress: "240.0.0.1",
            rules: [],
            tcpWritePumpMaxPendingBytes: writeCap,
            flowPressureSoftCap: pressureSoftCap,
            flowPressureLowWater: pressureLowWater,
            flowPressureIdleFloorMs: 1_000,
            liveFlowHardCap: liveHardCap,
            udpIdleTimeoutMs: udpIdleTimeoutMs,
            tcpStartInFlightHardCap: tcpStartHardCap,
            tcpStartInFlightSoftCap: tcpStartSoftCap,
            tcpStartLatencyBreakerP95Ms: 100,
            tcpStartLatencyBreakerCloseP95Ms: 50,
            tcpPressureConnectTimeoutMs: 80,
            tcpBreakerConnectTimeoutMs: 40,
            flowRefusalPassthrough: refusalPassthrough)
    }

    func testProductionPolicyBuilderIsPureAndNormalizesOnlyItsResult() {
        let legacyBefore = TransparentProxyRuntimePolicy.testDefaultsSnapshot
        let startup = makeStartup(
            writeCap: 777,
            pressureSoftCap: 12,
            pressureLowWater: 12,
            liveHardCap: 9,
            udpIdleTimeoutMs: 123,
            tcpStartHardCap: 5,
            tcpStartSoftCap: 8,
            refusalPassthrough: false)

        let built = RamaTransparentProxyProvider.makeRuntimePolicy(from: startup)

        XCTAssertEqual(built.tcpWritePump.maxPendingBytes, 777)
        XCTAssertEqual(built.flowPressure.softCap, 9)
        XCTAssertEqual(built.flowPressure.lowWater, 8)
        XCTAssertEqual(built.tcpStartAdmission.softCap, 5)
        XCTAssertEqual(built.flowRefusal, .block)
        XCTAssertEqual(
            TransparentProxyRuntimePolicy.testDefaultsSnapshot,
            legacyBefore,
            "production policy construction must not publish through test globals")
    }

    func testUdpStagingItemBudgetUsesBoundedFallbackWhenLiveHardCapIsDisabled() {
        let policy = makePolicy(
            writeCap: 1_024,
            liveHardCap: 0,
            udpIdleTimeoutMs: 60_000,
            refusalPassthrough: false)

        XCTAssertEqual(policy.udpIngressStaging.maxItemsPerFlow, 32)
        XCTAssertEqual(
            policy.udpIngressStaging.maxItemsPerGeneration,
            32 * udpIngressStagingUnboundedLiveFlowPopulation)
        XCTAssertEqual(policy.udpIngressStaging.maxItemsPerGeneration, 262_144)
    }

    func testUdpStagingItemBudgetUsesFiniteHardCapAndSaturatesOverflow() {
        let finite = TransparentProxyRuntimePolicy(
            tcpWritePumpMaxPendingBytes: 1_024,
            flowPressureSoftCap: 0,
            flowPressureLowWater: 0,
            flowPressureIdleFloorMs: 1_000,
            liveFlowHardCap: 500,
            udpIdleTimeoutMs: 60_000,
            tcpStartInFlightHardCap: 8,
            tcpStartInFlightSoftCap: 4,
            tcpStartLatencyBreakerP95Ms: 100,
            tcpStartLatencyBreakerCloseP95Ms: 50,
            tcpPressureConnectTimeoutMs: 80,
            tcpBreakerConnectTimeoutMs: 40,
            flowRefusalPassthrough: false,
            udpChannelCapacity: 32)
        XCTAssertEqual(finite.udpIngressStaging.maxItemsPerGeneration, 16_000)

        let overflow = TransparentProxyRuntimePolicy(
            tcpWritePumpMaxPendingBytes: 1_024,
            flowPressureSoftCap: 0,
            flowPressureLowWater: 0,
            flowPressureIdleFloorMs: 1_000,
            liveFlowHardCap: 2,
            udpIdleTimeoutMs: 60_000,
            tcpStartInFlightHardCap: 8,
            tcpStartInFlightSoftCap: 4,
            tcpStartLatencyBreakerP95Ms: 100,
            tcpStartLatencyBreakerCloseP95Ms: 50,
            tcpPressureConnectTimeoutMs: 80,
            tcpBreakerConnectTimeoutMs: 40,
            flowRefusalPassthrough: false,
            udpChannelCapacity: Int.max)
        XCTAssertEqual(overflow.udpIngressStaging.maxItemsPerFlow, Int.max)
        XCTAssertEqual(overflow.udpIngressStaging.maxItemsPerGeneration, Int.max)
    }

    func testReplacementPublishesOneCoherentPolicyAndOldLeaseKeepsSnapshot() {
        let core = TransparentProxyCore()
        let first = makePolicy(
            writeCap: 4_096, udpIdleTimeoutMs: 111,
            refusalPassthrough: false)
        let second = makePolicy(
            writeCap: 512, pressureSoftCap: 7, pressureLowWater: 3,
            liveHardCap: 9, udpIdleTimeoutMs: 222,
            tcpStartHardCap: 3, tcpStartSoftCap: 2,
            refusalPassthrough: true)

        core.attachEngine(makeEngine(), runtimePolicy: first)
        guard let oldLease = core.engineLeaseForNewFlow() else {
            return XCTFail("first lease")
        }

        core.attachEngine(makeEngine(), runtimePolicy: second)
        defer { core.detachEngine(reason: 0) }
        guard let currentLease = core.engineLeaseForNewFlow() else {
            return XCTFail("replacement lease")
        }

        XCTAssertEqual(oldLease.runtimePolicy, first)
        XCTAssertEqual(currentLease.runtimePolicy, second)
        XCTAssertNotEqual(oldLease.generation, currentLease.generation)
        XCTAssertTrue(
            oldLease.writerMemoryBudget === currentLease.writerMemoryBudget,
            "retiring and replacement generations must share one process envelope")
        XCTAssertEqual(currentLease.runtimePolicy.tcpWritePump.maxPendingBytes, 512)
        XCTAssertEqual(currentLease.runtimePolicy.flowPressure.liveHardCap, 9)
        XCTAssertEqual(currentLease.runtimePolicy.flowRefusal, .passthrough)
    }

    func testRapidGenerationRotationRetainsOneBudgetAndLoweredCapBlocks() {
        let core = TransparentProxyCore()
        let first = makePolicy(
            writeCap: 1_024,
            udpIdleTimeoutMs: 111,
            refusalPassthrough: false,
            writerMemoryMaxBytes: 16 * 1024 * 1024,
            writerMemoryMaxItems: 1_024)
        core.attachEngine(makeEngine(), runtimePolicy: first)
        guard let retiredLease = core.engineLeaseForNewFlow() else {
            return XCTFail("first lease")
        }
        XCTAssertTrue(retiredLease.writerMemoryBudget.tryReserve(
            bytes: 12 * 1024 * 1024, items: 512))

        let replacement = makePolicy(
            writeCap: 1_024,
            udpIdleTimeoutMs: 222,
            refusalPassthrough: true,
            writerMemoryMaxBytes: 8 * 1024 * 1024,
            writerMemoryMaxItems: 768)
        for _ in 0..<12 {
            core.attachEngine(makeEngine(), runtimePolicy: replacement)
            guard let current = core.engineLeaseForNewFlow() else {
                return XCTFail("replacement lease")
            }
            XCTAssertTrue(current.writerMemoryBudget === retiredLease.writerMemoryBudget)
            XCTAssertFalse(current.writerMemoryBudget.tryReserve(bytes: 1, items: 1))
        }
        defer { core.detachEngine(reason: 0) }

        retiredLease.writerMemoryBudget.release(
            bytes: 12 * 1024 * 1024, items: 512)
        XCTAssertTrue(retiredLease.writerMemoryBudget.tryReserve(
            bytes: 8 * 1024 * 1024, items: 768))
        XCTAssertFalse(retiredLease.writerMemoryBudget.tryReserve(bytes: 0, items: 1))
        retiredLease.writerMemoryBudget.release(
            bytes: 8 * 1024 * 1024, items: 768)
    }

    func testProductionCompositionWiresOneLeaseBudgetToTcpBothWaysAndUdp() {
        let core = TransparentProxyCore()
        let policy = makePolicy(
            writeCap: 4_096,
            udpIdleTimeoutMs: 60_000,
            refusalPassthrough: false)
        let connection = MockNwConnection()
        core.nwConnectionFactory = { _, _, _ in connection }
        core.attachEngine(makeEngine(), runtimePolicy: policy)
        defer { core.detachEngine(reason: 0) }
        guard let lease = core.engineLeaseForNewFlow() else {
            return XCTFail("lease")
        }

        let tcp = TcpFlowSession(
            core: core,
            flow: MockTcpFlow(),
            meta: makeMeta(protocolRaw: 1))
        XCTAssertTrue(tcp.start())
        connection.transition(to: .ready)
        tcp.flowQueue.sync {}
        XCTAssertTrue(tcp.testWriterMemoryBudget === lease.writerMemoryBudget)
        XCTAssertTrue(
            tcp.ctx.clientWritePump?.aggregateBudget === lease.writerMemoryBudget)
        XCTAssertTrue(
            tcp.ctx.egressWritePump?.aggregateBudget === lease.writerMemoryBudget)

        let udp = UdpFlowSession(
            core: core,
            flow: MockUdpFlow(),
            meta: makeMeta(protocolRaw: 2))
        XCTAssertEqual(udp.startWithDecision(), .intercept)
        udp.flowQueue.sync {}
        XCTAssertTrue(udp.testWriterMemoryBudget === lease.writerMemoryBudget)
        XCTAssertTrue(udp.ctx.writer?.aggregateBudget === lease.writerMemoryBudget)
    }

    func testTcpAdmissionUsesCurrentAttachedPolicyAndRejectsStaleGeneration() {
        let core = TransparentProxyCore()
        let first = makePolicy(
            writeCap: 1_024, udpIdleTimeoutMs: 111,
            tcpStartHardCap: 1, tcpStartSoftCap: 1,
            refusalPassthrough: false)
        let second = makePolicy(
            writeCap: 1_024, udpIdleTimeoutMs: 222,
            tcpStartHardCap: 2, tcpStartSoftCap: 2,
            refusalPassthrough: true)
        let firstGeneration = core.attachEngine(makeEngine(), runtimePolicy: first)
        let firstFlow = NSObject()
        guard
            case .admit = core.admitTcpStart(
                flowId: ObjectIdentifier(firstFlow),
                meta: makeMeta(protocolRaw: 1),
                engineGeneration: firstGeneration)
        else { return XCTFail("first generation should admit its first start") }
        let refused = NSObject()
        guard
            case .reject = core.admitTcpStart(
                flowId: ObjectIdentifier(refused),
                meta: makeMeta(protocolRaw: 1),
                engineGeneration: firstGeneration)
        else { return XCTFail("first generation hard cap must be one") }

        let secondGeneration = core.attachEngine(makeEngine(), runtimePolicy: second)
        defer { core.detachEngine(reason: 0) }
        XCTAssertNil(
            core.admitTcpStart(
                flowId: ObjectIdentifier(NSObject()),
                meta: makeMeta(protocolRaw: 1),
                engineGeneration: firstGeneration))

        let secondFlowA = NSObject()
        let secondFlowB = NSObject()
        guard
            case .admit = core.admitTcpStart(
                flowId: ObjectIdentifier(secondFlowA),
                meta: makeMeta(protocolRaw: 1),
                engineGeneration: secondGeneration),
            case .admit = core.admitTcpStart(
                flowId: ObjectIdentifier(secondFlowB),
                meta: makeMeta(protocolRaw: 1),
                engineGeneration: secondGeneration)
        else { return XCTFail("replacement generation hard cap must be two") }
    }

    func testPriorGenerationCompletionCannotReleaseReplacementAdmission() {
        let core = TransparentProxyCore()
        let policy = makePolicy(
            writeCap: 1_024,
            liveHardCap: 1,
            udpIdleTimeoutMs: 111,
            tcpStartHardCap: 2,
            tcpStartSoftCap: 2,
            refusalPassthrough: true)
        let reusedFlowIdentity = NSObject()
        let flowId = ObjectIdentifier(reusedFlowIdentity)

        let oldGeneration = core.attachEngine(makeEngine(), runtimePolicy: policy)
        guard
            case .admit(let oldToken) = core.admitTcpStart(
                flowId: flowId,
                meta: makeMeta(protocolRaw: 1),
                engineGeneration: oldGeneration)
        else { return XCTFail("old generation admission") }

        let replacementGeneration = core.attachEngine(makeEngine(), runtimePolicy: policy)
        defer { core.detachEngine(reason: 0) }
        guard
            case .admit(let replacementToken) = core.admitTcpStart(
                flowId: flowId,
                meta: makeMeta(protocolRaw: 1),
                engineGeneration: replacementGeneration)
        else { return XCTFail("replacement generation admission") }
        XCTAssertNotEqual(
            oldToken.identity.engineGeneration,
            replacementToken.identity.engineGeneration)
        XCTAssertNotEqual(oldToken.identity.nonce, replacementToken.identity.nonce)

        core.finishTcpStart(oldToken, outcome: .timeout)

        XCTAssertEqual(core.testTcpStartsInFlight, 1)
        XCTAssertEqual(core.testTcpLiveFlowReservations, 1)
        XCTAssertEqual(core.testTcpStartLatencySampleCount, 0)
        XCTAssertEqual(core.testTcpTimeoutsSinceTick, 0)

        let otherFlow = NSObject()
        guard
            case .reject(let reason, _, _) = core.admitTcpStart(
                flowId: ObjectIdentifier(otherFlow),
                meta: makeMeta(protocolRaw: 1),
                engineGeneration: replacementGeneration)
        else {
            return XCTFail("replacement reservation must retain the only live-cap slot")
        }
        XCTAssertTrue(reason.contains("combined live-flow hard cap reached"))

        core.finishTcpStart(replacementToken, outcome: .failed)
        XCTAssertEqual(core.testTcpStartsInFlight, 0)
        XCTAssertEqual(core.testTcpLiveFlowReservations, 0)

        guard
            case .admit(let nextToken) = core.admitTcpStart(
                flowId: ObjectIdentifier(otherFlow),
                meta: makeMeta(protocolRaw: 1),
                engineGeneration: replacementGeneration)
        else { return XCTFail("exact replacement completion must release capacity") }
        core.finishTcpStart(nextToken, outcome: .failed)
    }

    func testRestartCompletesWithBlockedRetiringFlowAndPumpKeepsOldCap() {
        let core = TransparentProxyCore()
        let first = makePolicy(
            writeCap: 4_096, udpIdleTimeoutMs: 111,
            refusalPassthrough: false)
        let second = makePolicy(
            writeCap: 128, udpIdleTimeoutMs: 222,
            refusalPassthrough: true)
        let connection = MockNwConnection()
        core.nwConnectionFactory = { _, _, _ in connection }
        core.attachEngine(makeEngine(), runtimePolicy: first)

        let flow = MockTcpFlow()
        let session = TcpFlowSession(
            core: core, flow: flow, meta: makeMeta(protocolRaw: 1))
        XCTAssertTrue(session.start())
        XCTAssertEqual(session.testRuntimePolicy, first)
        XCTAssertEqual(session.ctx.clientWritePump?.maxPendingBytes, 4_096)

        let blockerEntered = expectation(description: "old flow queue blocked")
        let releaseBlocker = DispatchSemaphore(value: 0)
        session.flowQueue.async {
            blockerEntered.fulfill()
            releaseBlocker.wait()
        }
        wait(for: [blockerEntered], timeout: 2)
        defer { releaseBlocker.signal() }

        let replacementAttached = expectation(
            description: "replacement attach does not await retiring flow queue")
        let replacement = makeEngine()
        DispatchQueue.global(qos: .userInitiated).async {
            core.attachEngine(replacement, runtimePolicy: second)
            replacementAttached.fulfill()
        }
        wait(for: [replacementAttached], timeout: 3)
        defer { core.detachEngine(reason: 0) }

        XCTAssertEqual(core.engineLeaseForNewFlow()?.runtimePolicy, second)
        XCTAssertEqual(session.testRuntimePolicy, first)
        XCTAssertEqual(session.ctx.clientWritePump?.maxPendingBytes, 4_096)
    }

    func testDetachSynchronouslyRetiresTcpPregrantButKeepsBlockedPayloadCharged() {
        let core = TransparentProxyCore()
        let policy = makePolicy(
            writeCap: 1_024,
            udpIdleTimeoutMs: 60_000,
            refusalPassthrough: false)
        core.nwConnectionFactory = { _, _, _ in MockNwConnection() }
        core.attachEngine(makeEngine(), runtimePolicy: policy)
        guard let oldLease = core.engineLeaseForNewFlow() else {
            return XCTFail("old lease")
        }
        let session = TcpFlowSession(
            core: core,
            flow: MockTcpFlow(),
            meta: makeMeta(protocolRaw: 1))
        XCTAssertTrue(session.start())
        session.flowQueue.sync {}
        guard let writer = session.ctx.clientWritePump else {
            return XCTFail("client writer")
        }

        let blockerEntered = expectation(description: "retiring flow queue blocked")
        let releaseBlocker = DispatchSemaphore(value: 0)
        session.flowQueue.async {
            blockerEntered.fulfill()
            releaseBlocker.wait()
        }
        wait(for: [blockerEntered], timeout: 3)

        XCTAssertEqual(writer.enqueue(Data(repeating: 1, count: 4)), .accepted)
        let fillerBytes = policy.writerMemory.maxBytes - 4
        XCTAssertTrue(oldLease.writerMemoryBudget.tryReserve(bytes: fillerBytes))
        XCTAssertEqual(writer.enqueue(Data([2])), .paused)
        XCTAssertEqual(oldLease.writerMemoryBudget.testWaiterCount, 1)
        oldLease.writerMemoryBudget.release(bytes: fillerBytes)
        for _ in 0..<1_000 {
            if oldLease.writerMemoryBudget.snapshot().retainedBytes == 5,
                oldLease.writerMemoryBudget.testWaiterCount == 0
            { break }
            Thread.sleep(forTimeInterval: 0.001)
        }
        XCTAssertEqual(oldLease.writerMemoryBudget.snapshot().retainedBytes, 5)

        let attached = expectation(description: "replacement attach")
        DispatchQueue.global(qos: .userInitiated).async {
            core.attachEngine(self.makeEngine(), runtimePolicy: policy)
            attached.fulfill()
        }
        wait(for: [attached], timeout: 3)
        defer { core.detachEngine(reason: 0) }
        guard let newLease = core.engineLeaseForNewFlow() else {
            releaseBlocker.signal()
            return XCTFail("new lease")
        }
        XCTAssertTrue(newLease.writerMemoryBudget === oldLease.writerMemoryBudget)
        XCTAssertEqual(oldLease.writerMemoryBudget.testWaiterCount, 0)
        XCTAssertFalse(oldLease.writerMemoryBudget.snapshot().tcpWaiterGate)
        XCTAssertEqual(
            oldLease.writerMemoryBudget.snapshot().retainedBytes, 4,
            "only the real dispatch-pending payload survives synchronous detach")
        XCTAssertEqual(writer.enqueue(Data([3])), .closed)

        releaseBlocker.signal()
        for _ in 0..<1_000 {
            if oldLease.writerMemoryBudget.snapshot().retainedBytes == 0 { break }
            Thread.sleep(forTimeInterval: 0.001)
        }
        XCTAssertEqual(oldLease.writerMemoryBudget.snapshot().retainedBytes, 0)
    }

    func testUdpSessionKeepsIdleAndRefusalPolicyAcrossReplacement() {
        let core = TransparentProxyCore()
        let first = makePolicy(
            writeCap: 4_096, udpIdleTimeoutMs: 111,
            refusalPassthrough: false)
        let second = makePolicy(
            writeCap: 512, udpIdleTimeoutMs: 222,
            refusalPassthrough: true)
        core.attachEngine(makeEngine(), runtimePolicy: first)

        let oldSession = UdpFlowSession(
            core: core, flow: MockUdpFlow(), meta: makeMeta(protocolRaw: 2))
        XCTAssertEqual(oldSession.startWithDecision(), .intercept)
        XCTAssertEqual(oldSession.idleTimeoutMs, 111)
        XCTAssertEqual(oldSession.testRuntimePolicy?.flowRefusal, .block)

        core.attachEngine(makeEngine(), runtimePolicy: second)
        defer { core.detachEngine(reason: 0) }

        let newSession = UdpFlowSession(
            core: core, flow: MockUdpFlow(), meta: makeMeta(protocolRaw: 2))
        XCTAssertEqual(newSession.startWithDecision(), .intercept)
        XCTAssertEqual(newSession.idleTimeoutMs, 222)
        XCTAssertEqual(newSession.testRuntimePolicy?.flowRefusal, .passthrough)
        XCTAssertEqual(oldSession.idleTimeoutMs, 111)
        XCTAssertEqual(oldSession.testRuntimePolicy?.flowRefusal, .block)
    }

    func testCapturedRefusalActionDoesNotConsultLegacyGlobal() {
        let block = FlowRefusalPolicy.block
        let passthrough = FlowRefusalPolicy.passthrough

        XCTAssertFalse(failOpenOnFlowRefusal("generation A", policy: block))
        XCTAssertTrue(failOpenOnFlowRefusal("generation B", policy: passthrough))
    }

    func testWritePumpUsesOneImmutableCapAndHighWaterThreshold() {
        let policy = makePolicy(
            writeCap: 256, udpIdleTimeoutMs: 111,
            refusalPassthrough: false)
        let highWaters = Locked<[Int]>([])
        let queue = DispatchQueue(label: "rama.test.policy.write-pump")
        let pump = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { _, _ in },
            logHwm: { value in highWaters.withLock { $0.append(value) } },
            writePolicy: policy.tcpWritePump)

        XCTAssertEqual(pump.enqueue(Data(repeating: 1, count: 200)), .accepted)
        // A hypothetical replacement generation has a much smaller cap; the
        // already-created pump must continue using its own 256-byte snapshot.
        _ = makePolicy(
            writeCap: 32, udpIdleTimeoutMs: 222,
            refusalPassthrough: true)
        XCTAssertEqual(pump.enqueue(Data(repeating: 2, count: 56)), .accepted)
        XCTAssertEqual(pump.enqueue(Data([3])), .paused)
        XCTAssertEqual(highWaters.withLock { $0 }, [200])

        let cleanup = pump.prepareCancel()
        queue.sync(execute: cleanup)
    }

    func testOverlappingPolicyBuildAndAttachNeverPublishesHybridPolicy() {
        let core = TransparentProxyCore()
        let firstStartup = makeStartup(
            writeCap: 8_192,
            pressureSoftCap: 18, pressureLowWater: 12, liveHardCap: 24,
            udpIdleTimeoutMs: 333,
            tcpStartHardCap: 12, tcpStartSoftCap: 6,
            refusalPassthrough: false)
        let secondStartup = makeStartup(
            writeCap: 256,
            pressureSoftCap: 5, pressureLowWater: 2, liveHardCap: 6,
            udpIdleTimeoutMs: 444,
            tcpStartHardCap: 4, tcpStartSoftCap: 2,
            refusalPassthrough: true)
        let first = RamaTransparentProxyProvider.makeRuntimePolicy(from: firstStartup)
        let second = RamaTransparentProxyProvider.makeRuntimePolicy(from: secondStartup)
        let firstEngine = makeEngine()
        let secondEngine = makeEngine()
        let ready = DispatchGroup()
        let start = DispatchSemaphore(value: 0)
        let done = DispatchGroup()

        for (engine, startup) in [
            (firstEngine, firstStartup), (secondEngine, secondStartup),
        ] {
            ready.enter()
            done.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                ready.leave()
                start.wait()
                let policy = RamaTransparentProxyProvider.makeRuntimePolicy(from: startup)
                core.attachEngine(engine, runtimePolicy: policy)
                done.leave()
            }
        }
        XCTAssertEqual(ready.wait(timeout: .now() + 2), .success)
        start.signal()
        start.signal()
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        defer { core.detachEngine(reason: 0) }

        guard let published = core.engineLeaseForNewFlow() else {
            return XCTFail("published lease")
        }
        let firstPair = published.engine === firstEngine
            && published.runtimePolicy == first
        let secondPair = published.engine === secondEngine
            && published.runtimePolicy == second
        XCTAssertTrue(
            firstPair || secondPair,
            "engine and policy must be published as one atomic generation")
    }
}
