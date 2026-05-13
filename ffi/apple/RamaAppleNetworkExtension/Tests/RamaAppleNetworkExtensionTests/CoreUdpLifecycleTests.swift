import Foundation
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// End-to-end lifecycle tests for `TransparentProxyCore.handleUdpFlow`.
/// Symmetric to `CoreTcpLifecycleTests` — drives the full per-flow
/// state machine against a `MockUdpFlow` + `MockNwConnection`
/// against the real Rust engine.
final class CoreUdpLifecycleTests: XCTestCase {

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

    private struct CoreFixture {
        let engine: RamaTransparentProxyEngineHandle
        let core: TransparentProxyCore
        let capture: NwConnectionCapture
    }

    private func makeFixture() -> CoreFixture {
        let engine = makeEngine()
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        return CoreFixture(engine: engine, core: core, capture: capture)
    }

    private func tearDown(_ fx: CoreFixture) {
        fx.core.detachEngine(reason: 0)
    }

    private func makeMeta(
        remoteHost: String = "example.com",
        remotePort: UInt16 = 5000
    ) -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 2,
            remoteHost: remoteHost,
            remotePort: remotePort,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil,
            sourceAppPid: 4242
        )
    }

    private func waitFor(
        _ description: String,
        timeout: TimeInterval = 2.0,
        condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    // MARK: - Happy path

    func testHappyPath_UdpFlowOpenReadEofClean() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        XCTAssertEqual(fx.core.udpFlowCount, 1)

        let conn = fx.capture.waitForLastConnection()
        conn.transition(to: .ready)

        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)

        waitFor("client read pump issued first read") { flow.pendingReadCount > 0 }

        // Drive an EOF on the flow's read side — empty datagrams
        // array signals end-of-data in the production code.
        flow.completePendingRead(datagrams: [], endpoints: nil, error: nil)

        waitFor("flow removed from registration", timeout: 5.0) {
            fx.core.udpFlowCount == 0
        }
        XCTAssertGreaterThanOrEqual(conn.cancelCount, 1)
    }

    // MARK: - Pre-ready failure

    func testPreReadyConnectionFailedTearsDownCleanly() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        XCTAssertEqual(fx.core.udpFlowCount, 1)

        let conn = fx.capture.waitForLastConnection()
        conn.transition(to: .failed(.posix(.ECONNREFUSED)))

        waitFor("flow registration removed") { fx.core.udpFlowCount == 0 }
        XCTAssertEqual(conn.cancelCount, 1)
        XCTAssertFalse(flow.openWasInvoked)
    }

    // MARK: - Post-ready failure

    func testPostReadyConnectionFailedTearsDownCleanly() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        conn.transition(to: .ready)
        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump started") { flow.pendingReadCount > 0 }

        conn.transition(to: .failed(.posix(.ENETDOWN)))

        waitFor("post-ready failure cleaned up", timeout: 3.0) {
            fx.core.udpFlowCount == 0
        }
        XCTAssertGreaterThanOrEqual(flow.closeReadCallCount, 1)
        XCTAssertGreaterThanOrEqual(flow.closeWriteCallCount, 1)
    }

    func testPostReadyWaitingTimesOutAndTearsDown() {
        let savedTolerance = defaultEgressWaitingToleranceMs
        defaultEgressWaitingToleranceMs = 200
        defer { defaultEgressWaitingToleranceMs = savedTolerance }

        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        conn.transition(to: .ready)
        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump started") { flow.pendingReadCount > 0 }

        conn.transition(to: .waiting(.posix(.ENETDOWN)))

        waitFor("waiting tolerance fired teardown", timeout: 3.0) {
            fx.core.udpFlowCount == 0
        }
        XCTAssertGreaterThanOrEqual(flow.closeReadCallCount, 1)
        XCTAssertGreaterThanOrEqual(flow.closeWriteCallCount, 1)
    }

    // MARK: - flow.open error

    func testFlowOpenErrorAfterEgressReadyTearsDownCleanly() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()

        conn.transition(to: .ready)
        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: NSError(domain: "test", code: 1))

        waitFor("flow.open error cleanup", timeout: 3.0) {
            fx.core.udpFlowCount == 0
        }
        XCTAssertGreaterThanOrEqual(conn.cancelCount, 1)
    }

    // MARK: - Churn

    func testManyFlowsChurnReturnsRegistrationToZero() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flowCount = 12
        var flows: [MockUdpFlow] = []
        for _ in 0..<flowCount {
            let flow = MockUdpFlow()
            flows.append(flow)
            _ = fx.core.handleUdpFlow(flow, meta: makeMeta())
        }

        XCTAssertEqual(fx.core.udpFlowCount, flowCount)

        for conn in fx.capture.allConnections {
            conn.transition(to: .ready)
        }
        for flow in flows {
            waitFor("flow.open for all flows", timeout: 5.0) { flow.openWasInvoked }
            flow.completeOpen(error: nil)
        }
        for flow in flows {
            waitFor("read pump for all flows", timeout: 5.0) { flow.pendingReadCount > 0 }
            flow.completePendingRead(datagrams: [], endpoints: nil, error: nil)
        }

        waitFor("all UDP flows removed", timeout: 10.0) {
            fx.core.udpFlowCount == 0
        }
    }
}
