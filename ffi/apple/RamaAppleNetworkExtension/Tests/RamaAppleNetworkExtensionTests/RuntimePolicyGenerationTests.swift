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
        refusalPassthrough: Bool
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
            flowRefusalPassthrough: refusalPassthrough)
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
        XCTAssertEqual(currentLease.runtimePolicy.tcpWritePump.maxPendingBytes, 512)
        XCTAssertEqual(currentLease.runtimePolicy.flowPressure.liveHardCap, 9)
        XCTAssertEqual(currentLease.runtimePolicy.flowRefusal, .passthrough)
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
