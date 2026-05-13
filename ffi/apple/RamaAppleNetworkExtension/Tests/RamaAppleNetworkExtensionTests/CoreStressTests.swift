import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Stress / churn tests for `TransparentProxyCore`. Each test
/// exercises the per-flow state machine at higher concurrency than
/// the lifecycle suite (which validates one scenario at a time),
/// validating that no state leaks and the engine doesn't wedge when
/// many flows hit it in rapid succession.
///
/// The previous version of this suite was sequential — `for flow in
/// flows { transition; waitFor(flow.openWasInvoked); completeOpen }`
/// — which is `O(N · pollInterval)` of test-thread time per phase
/// and ran for minutes at N=60. The current version drives every
/// flow in parallel: fire all transitions, then a single `waitFor`
/// on the aggregate condition. That's two waits per phase regardless
/// of N, and the suite stays under a few seconds at N=100.
final class CoreStressTests: XCTestCase {

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private func makeFixture() -> (TransparentProxyCore, NwConnectionCapture) {
        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            preconditionFailure()
        }
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        return (core, capture)
    }

    private func makeMeta(
        protocolRaw: UInt32 = 1,
        port: UInt16 = 443
    ) -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: protocolRaw,
            remoteHost: "example.com",
            remotePort: port,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func waitFor(
        _ description: String,
        timeout: TimeInterval = 10.0,
        condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    // MARK: - Parallel-driven happy path

    /// 100 TCP flows all driven through the happy path concurrently.
    /// The test thread fires every transition then waits once per
    /// phase for the aggregate condition to hold. Validates that
    /// the engine + per-flow queues handle bursty arrival without
    /// falling behind.
    func testParallelTcpHappyPathChurn() {
        let (core, capture) = makeFixture()
        defer { core.detachEngine(reason: 0) }

        let flowCount = 100
        var flows: [MockTcpFlow] = []
        flows.reserveCapacity(flowCount)
        for _ in 0..<flowCount {
            let flow = MockTcpFlow()
            flows.append(flow)
            _ = core.handleTcpFlow(flow, meta: makeMeta())
        }
        XCTAssertEqual(core.tcpFlowCount, flowCount)

        // Wait for the factory to receive every connection. The
        // factory is invoked from each flow's per-flow queue
        // asynchronously, so the test thread polls a single
        // aggregate condition instead of N individual ones.
        waitFor("all \(flowCount) connections constructed") {
            capture.allConnections.count == flowCount
        }
        let connections = capture.allConnections

        // Phase 1: drive every connection to .ready in a tight
        // loop, then wait once for every flow to have invoked
        // flow.open. This is the key efficiency win over the old
        // sequential driver: O(1) waits per phase, not O(N).
        for conn in connections { conn.transition(to: .ready) }
        waitFor("all \(flowCount) flows reached flow.open", timeout: 30.0) {
            flows.allSatisfy { $0.openWasInvoked }
        }

        // Phase 2: complete every flow.open in a tight loop, then
        // wait once for every flow's egress read pump to have
        // issued its first receive.
        for flow in flows { flow.completeOpen(error: nil) }
        waitFor("all \(flowCount) egress receives in flight", timeout: 30.0) {
            connections.allSatisfy { $0.pendingReceiveCount > 0 }
        }

        // Phase 3: drive a peer EOF on every egress, then wait
        // for the aggregate registration count to drain.
        for conn in connections { conn.completePendingReceive(isComplete: true) }
        waitFor("all \(flowCount) flows cleaned up", timeout: 30.0) {
            core.tcpFlowCount == 0
        }
    }

    // MARK: - Parallel-driven failure mix

    /// 50 TCP flows split across all four cleanup arms in parallel:
    /// happy path, pre-ready failed, post-ready failed, flow.open
    /// error. Validates that every cleanup arm composes with every
    /// other at concurrency — no path corrupts shared state on
    /// behalf of another flow.
    func testParallelTcpFailureMixChurn() {
        let (core, capture) = makeFixture()
        defer { core.detachEngine(reason: 0) }

        enum Arm { case happyPath, preReadyFailed, postReadyFailed, flowOpenError }
        let arms: [Arm] = [.happyPath, .preReadyFailed, .postReadyFailed, .flowOpenError]
        let perArm = 13
        var flows: [(MockTcpFlow, Arm)] = []
        for arm in arms {
            for _ in 0..<perArm {
                let flow = MockTcpFlow()
                flows.append((flow, arm))
                _ = core.handleTcpFlow(flow, meta: makeMeta())
            }
        }
        XCTAssertEqual(core.tcpFlowCount, perArm * arms.count)

        waitFor("all connections constructed") {
            capture.allConnections.count == flows.count
        }
        let connections = capture.allConnections
        let pairs = Array(zip(flows, connections))

        // Drive arm 1: pre-ready failed — just transition to .failed.
        for (entry, conn) in pairs where entry.1 == .preReadyFailed {
            conn.transition(to: .failed(.posix(.ECONNREFUSED)))
        }

        // Drive arms 2-4: transition to .ready first.
        for (entry, conn) in pairs where entry.1 != .preReadyFailed {
            conn.transition(to: .ready)
        }
        waitFor("non-pre-ready flows reached flow.open", timeout: 30.0) {
            pairs.allSatisfy { entry, _ in
                entry.1 == .preReadyFailed || entry.0.openWasInvoked
            }
        }

        // happyPath + postReadyFailed: complete flow.open success.
        for (entry, _) in pairs where entry.1 == .happyPath || entry.1 == .postReadyFailed {
            entry.0.completeOpen(error: nil)
        }
        // flowOpenError: complete flow.open with error.
        for (entry, _) in pairs where entry.1 == .flowOpenError {
            entry.0.completeOpen(error: NSError(domain: "stress", code: 1))
        }

        // Wait for the happy-path arms to wire up their egress pumps.
        waitFor("happy/postReadyFailed flows have egress receives", timeout: 30.0) {
            pairs.allSatisfy { entry, conn in
                if entry.1 == .happyPath || entry.1 == .postReadyFailed {
                    return conn.pendingReceiveCount > 0
                }
                return true
            }
        }

        // postReadyFailed: now transition to .failed.
        for (entry, conn) in pairs where entry.1 == .postReadyFailed {
            conn.transition(to: .failed(.posix(.ECONNRESET)))
            _ = entry  // silence unused-warning
        }

        // happyPath: drive peer EOF.
        for (entry, conn) in pairs where entry.1 == .happyPath {
            conn.completePendingReceive(isComplete: true)
            _ = entry
        }

        // Final invariant: every registration drained.
        waitFor("all \(flows.count) flows cleaned up", timeout: 60.0) {
            core.tcpFlowCount == 0
        }
    }

    // MARK: - Engine.stop unblocks any mid-flight state

    /// Drive flows into a mix of pre-ready / ready / post-ready
    /// states then call detachEngine. Stop must complete in bounded
    /// time regardless. This is the "can we shutdown safely from
    /// any state" check, kept compact because the engine path is
    /// what's exercised.
    func testDetachEngineCompletesUnderMixedFlowStates() {
        let (core, capture) = makeFixture()

        let total = 20
        var flows: [MockTcpFlow] = []
        for i in 0..<total {
            let flow = MockTcpFlow()
            flows.append(flow)
            _ = core.handleTcpFlow(flow, meta: makeMeta())
            let conn = capture.waitForLastConnection()
            // Half pre-ready, half ready+open.
            if i % 2 == 0 {
                conn.transition(to: .ready)
            }
        }
        // Best-effort flow.open completion for the ready ones.
        waitFor("ready flows reached flow.open", timeout: 30.0) {
            flows.enumerated().allSatisfy { idx, flow in
                idx % 2 != 0 || flow.openWasInvoked
            }
        }
        for (idx, flow) in flows.enumerated() where idx % 2 == 0 {
            flow.completeOpen(error: nil)
        }

        let started = Date()
        core.detachEngine(reason: 0)
        let elapsed = Date().timeIntervalSince(started)
        XCTAssertLessThan(
            elapsed, 5.0,
            "detachEngine should complete in bounded time regardless of flow states; took \(elapsed)s"
        )
        XCTAssertEqual(core.tcpFlowCount, 0, "detachEngine clears registrations")
    }
}
