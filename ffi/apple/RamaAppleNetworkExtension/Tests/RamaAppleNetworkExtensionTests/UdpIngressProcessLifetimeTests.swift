import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

final class UdpIngressProcessLifetimeTests: XCTestCase {
    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private func makeEngine() -> RamaTransparentProxyEngineHandle {
        guard let engine = RamaTransparentProxyEngineHandle(
            engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            preconditionFailure()
        }
        return engine
    }

    private func makePolicy(
        perFlowBytes: Int,
        globalBytes: Int
    ) -> TransparentProxyRuntimePolicy {
        TransparentProxyRuntimePolicy(
            tcpWritePumpMaxPendingBytes: 1_024,
            flowPressureSoftCap: 4,
            flowPressureLowWater: 2,
            flowPressureIdleFloorMs: 1_000,
            liveFlowHardCap: 4,
            udpIdleTimeoutMs: 60_000,
            tcpStartInFlightHardCap: 4,
            tcpStartInFlightSoftCap: 2,
            tcpStartLatencyBreakerP95Ms: 100,
            tcpStartLatencyBreakerCloseP95Ms: 50,
            tcpPressureConnectTimeoutMs: 80,
            tcpBreakerConnectTimeoutMs: 40,
            flowRefusalPassthrough: false,
            udpChannelCapacity: 4,
            udpIngressPerFlowMaxBytes: perFlowBytes,
            udpIngressGlobalMaxBytes: globalBytes)
    }

    func testRapidEngineRotationSharesRetiredIngressBytesAndReconfiguresCaps() {
        let core = TransparentProxyCore()
        let high = makePolicy(perFlowBytes: 8, globalBytes: 8)
        core.attachEngine(makeEngine(), runtimePolicy: high)
        guard let retiredLease = core.engineLeaseForNewFlow() else {
            return XCTFail("first lease")
        }
        let retiredFlow = UdpIngressFlowStaging(
            generation: retiredLease.udpIngressStagingBudget,
            policy: retiredLease.runtimePolicy.udpIngressStaging)
        var retained = retiredFlow.stage(
            datagrams: [Data(count: 6)], endpoints: nil
        ).batch
        XCTAssertNotNil(retained)

        let low = makePolicy(perFlowBytes: 4, globalBytes: 4)
        var lowSnapshotFlow: UdpIngressFlowStaging?
        for _ in 0..<12 {
            core.attachEngine(makeEngine(), runtimePolicy: low)
            guard let current = core.engineLeaseForNewFlow() else {
                return XCTFail("replacement lease")
            }
            XCTAssertTrue(
                current.udpIngressStagingBudget === retiredLease.udpIngressStagingBudget,
                "all engine generations must share one process staging envelope")
            let flow = UdpIngressFlowStaging(
                generation: current.udpIngressStagingBudget,
                policy: current.runtimePolicy.udpIngressStaging)
            let blocked = flow.stage(datagrams: [Data([1])], endpoints: nil)
            XCTAssertNil(blocked.batch)
            XCTAssertEqual(blocked.blockedReason, .generationBytes)
            lowSnapshotFlow = flow
        }
        defer { core.detachEngine(reason: 0) }
        guard let lowSnapshotFlow else { return XCTFail("low-cap flow") }
        XCTAssertEqual(retiredLease.udpIngressStagingBudget.testRetainedBytes, 6)
        XCTAssertEqual(retiredLease.udpIngressStagingBudget.testGlobalMaxBytes, 4)

        retained = nil
        var exactLowCap = lowSnapshotFlow.stage(
            datagrams: [Data(count: 4)], endpoints: nil
        ).batch
        XCTAssertNotNil(exactLowCap)
        XCTAssertEqual(retiredLease.udpIngressStagingBudget.testRetainedBytes, 4)
        exactLowCap = nil

        core.attachEngine(makeEngine(), runtimePolicy: high)
        guard let raisedLease = core.engineLeaseForNewFlow() else {
            return XCTFail("raised lease")
        }
        XCTAssertTrue(
            raisedLease.udpIngressStagingBudget === retiredLease.udpIngressStagingBudget)
        XCTAssertEqual(raisedLease.udpIngressStagingBudget.testGlobalMaxBytes, 8)

        // The old high-cap flow keeps its local snapshot; the flow created
        // under the low generation does not inherit the later raise.
        var oldSnapshotBatch = retiredFlow.stage(
            datagrams: [Data(count: 8)], endpoints: nil
        ).batch
        XCTAssertNotNil(oldSnapshotBatch)
        oldSnapshotBatch = nil
        let lowStillLocal = lowSnapshotFlow.stage(
            datagrams: [Data(count: 5)], endpoints: nil)
        XCTAssertEqual(lowStillLocal.blockedReason, .oversizedBytes)
        XCTAssertNil(lowStillLocal.dropSample)

        retiredFlow.close()
        lowSnapshotFlow.close()
        XCTAssertEqual(raisedLease.udpIngressStagingBudget.testRetainedBytes, 0)
        XCTAssertEqual(raisedLease.udpIngressStagingBudget.testWaiterCount, 0)
    }

    func testDetachCancelsWaiterWithoutWaitingForStalledFlowQueue() {
        let core = TransparentProxyCore()
        let policy = makePolicy(perFlowBytes: 1, globalBytes: 1)
        core.attachEngine(makeEngine(), runtimePolicy: policy)
        guard let lease = core.engineLeaseForNewFlow() else {
            return XCTFail("lease")
        }
        let holder = UdpFlowSession(
            core: core,
            flow: MockUdpFlow(),
            meta: RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 2,
                remoteHost: "127.0.0.1",
                remotePort: 443,
                localHost: nil,
                localPort: 0,
                sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: "policy.test",
                sourceAppAuditToken: nil,
                sourceAppPid: 42))
        let waiter = UdpFlowSession(
            core: core,
            flow: MockUdpFlow(),
            meta: RamaTransparentProxyFlowMetaBridge(
                protocolRaw: 2,
                remoteHost: "127.0.0.1",
                remotePort: 443,
                localHost: nil,
                localPort: 0,
                sourceAppSigningIdentifier: nil,
                sourceAppBundleIdentifier: "policy.test",
                sourceAppAuditToken: nil,
                sourceAppPid: 43))
        XCTAssertEqual(holder.startWithDecision(), .intercept)
        XCTAssertEqual(waiter.startWithDecision(), .intercept)
        let holderStaging = UdpIngressFlowStaging(
            generation: lease.udpIngressStagingBudget,
            policy: lease.runtimePolicy.udpIngressStaging)
        var retained = holderStaging.stage(datagrams: [Data([1])], endpoints: nil).batch
        XCTAssertNotNil(retained)
        let lateGrants = Locked(0)
        XCTAssertTrue(
            waiter.testWaitForIngressStagingCapacity(
                neededItems: 1, neededBytes: 1
            ) { _ in lateGrants.withLock { $0 += 1 } })
        XCTAssertEqual(lease.udpIngressStagingBudget.testWaiterCount, 1)

        let blockerStarted = DispatchSemaphore(value: 0)
        let allowFlowQueue = DispatchSemaphore(value: 0)
        waiter.flowQueue.async {
            blockerStarted.signal()
            allowFlowQueue.wait()
        }
        XCTAssertEqual(blockerStarted.wait(timeout: .now() + 30), .success)
        defer { allowFlowQueue.signal() }

        let detachFinished = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            core.detachEngine(reason: 0)
            detachFinished.signal()
        }
        XCTAssertEqual(
            detachFinished.wait(timeout: .now() + 30), .success,
            "detach must not wait for a stalled flow queue")
        XCTAssertEqual(lease.udpIngressStagingBudget.testWaiterCount, 0)
        XCTAssertEqual(lease.udpIngressStagingBudget.testWaiterGate, 0)
        XCTAssertEqual(lateGrants.withLock { $0 }, 0)
        XCTAssertEqual(
            lease.udpIngressStagingBudget.testRetainedBytes, 1,
            "stalled retired payload remains charged until its final ARC owner drops")

        retained = nil
        XCTAssertEqual(lease.udpIngressStagingBudget.testRetainedBytes, 0)
        XCTAssertEqual(lease.udpIngressStagingBudget.testReservedBytes, 0)
    }
}
