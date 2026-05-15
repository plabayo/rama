import Foundation
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// End-to-end lifecycle tests for `TransparentProxyCore.handleUdpFlow`.
///
/// The UDP path no longer drives an `NWConnection` state machine
/// (egress is a Rust-owned BSD socket on the service side), so these
/// tests drive the lifecycle purely through `MockUdpFlow` events
/// and the real Rust engine. Symmetric to `CoreTcpLifecycleTests`
/// but without any `NwConnectionCapture` wiring.
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
    }

    private func makeFixture() -> CoreFixture {
        let engine = makeEngine()
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        return CoreFixture(engine: engine, core: core)
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

    /// flow.open succeeds → read pump arms → EOF from kernel tears
    /// the flow down cleanly with the registration returning to zero.
    func testHappyPath_UdpFlowOpenReadEofClean() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        XCTAssertEqual(fx.core.udpFlowCount, 1)

        waitFor("flow.open called immediately on intercept") { flow.openWasInvoked }
        flow.completeOpen(error: nil)

        waitFor("client read pump issued first read") { flow.pendingReadCount > 0 }

        // EOF on the read side — empty datagrams array signals
        // end-of-data in production.
        flow.completePendingRead(datagrams: [], endpoints: nil, error: nil)

        waitFor("flow removed from registration", timeout: 5.0) {
            fx.core.udpFlowCount == 0
        }
    }

    // MARK: - flow.open error

    /// flow.open returning an error must tear the flow down without
    /// arming the read pump, and the registration must return to zero.
    func testFlowOpenErrorTearsDownCleanly() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))

        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: NSError(domain: "test", code: 1))

        waitFor("flow.open error cleanup", timeout: 3.0) {
            fx.core.udpFlowCount == 0
        }
        XCTAssertEqual(flow.pendingReadCount, 0)
    }

    // MARK: - Read error

    /// A flow.readDatagrams completion with an error must terminate
    /// the flow without leaving a dangling registration.
    func testReadErrorTearsDownCleanly() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))

        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("read pump started") { flow.pendingReadCount > 0 }

        flow.completePendingRead(
            datagrams: nil, endpoints: nil,
            error: NSError(domain: "test.read", code: 2)
        )

        waitFor("read-error cleanup", timeout: 3.0) {
            fx.core.udpFlowCount == 0
        }
    }

    // MARK: - Churn

    /// N back-to-back UDP flows, each driven through open → first
    /// read → EOF, must all clear out of the registration.
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
