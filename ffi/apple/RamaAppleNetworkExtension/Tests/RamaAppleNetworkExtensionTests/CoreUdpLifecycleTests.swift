import Foundation
import Network
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
    private let maxUdpDatagramBytes = Int(UInt16.max)
    private let udpIngressPerFlowBytes = 256 * 1024
    private let udpIngressFillFlowCount = 64
    // Keep expiry well beyond this test's five-second mutation-failure
    // deadline. Swift ThreadSanitizer can stretch the six real callback/queue
    // hops beyond 500 ms even though an uninstrumented run takes < 0.5 s.
    private let pressureProbeLeaseMs: UInt64 = 10_000

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

    private func makePressureEngine() -> RamaTransparentProxyEngineHandle {
        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson(
                    udpIngressProbeLeaseMs: pressureProbeLeaseMs))
        else {
            XCTFail("pressure engine init")
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

    private func newDirectUdpSession(
        on engine: RamaTransparentProxyEngineHandle,
        remotePort: UInt16
    ) -> RamaUdpSessionHandle {
        let decision = engine.newUdpSession(
            meta: makeMeta(remoteHost: "127.0.0.1", remotePort: remotePort),
            onServerDatagram: { _, _ in },
            onClientReadDemand: { _ in },
            onServerClosed: {})
        guard case .intercept(let session) = decision else {
            XCTFail("demo handler unexpectedly rejected direct UDP pressure session")
            preconditionFailure()
        }
        return session
    }

    /// Fill the real Rust generation budget exactly while keeping every
    /// service inactive: four maximum datagrams plus a four-byte tail reaches
    /// the production 256 KiB per-flow cap, and 64 such flows reach 16 MiB.
    private func fillRustUdpIngressBudget(
        on engine: RamaTransparentProxyEngineHandle,
        remotePort: UInt16
    ) -> [RamaUdpSessionHandle] {
        let payload = Data(repeating: 0xA5, count: maxUdpDatagramBytes)
        let tailBytes = udpIngressPerFlowBytes - 4 * maxUdpDatagramBytes
        XCTAssertEqual(tailBytes, 4)
        let tail = Data(repeating: 0x5A, count: tailBytes)
        return (0..<udpIngressFillFlowCount).map { _ in
            let session = newDirectUdpSession(on: engine, remotePort: remotePort)
            for _ in 0..<4 {
                session.onClientDatagram(payload, peer: nil)
            }
            session.onClientDatagram(tail, peer: nil)
            return session
        }
    }

    // MARK: - Happy path

    /// The example policy declines UDP/53. A declined flow must map to false
    /// and, critically, must remain completely untouched by the provider.
    func testPassthroughDecisionReturnsFalseWithoutTouchingFlow() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        let decision = fx.core.handleUdpFlowDecision(
            flow,
            meta: makeMeta(remoteHost: "127.0.0.1", remotePort: 53)
        )

        XCTAssertEqual(decision, .passthrough)
        XCTAssertFalse(decision.callbackReturnValue)
        XCTAssertFalse(flow.openWasInvoked)
        XCTAssertEqual(flow.pendingReadCount, 0)
        XCTAssertEqual(flow.writtenBatches.count, 0)
        XCTAssertEqual(flow.closeReadCallCount, 0)
        XCTAssertEqual(flow.closeWriteCallCount, 0)
        XCTAssertEqual(fx.core.udpFlowCount, 0)
    }

    /// A destination Rama accepts must map to true and transfer ownership to
    /// the provider, which queues opening the kernel flow.
    func testInterceptDecisionReturnsTrueAndOpensFlow() {
        let fx = makeFixture()
        defer { tearDown(fx) }

        let flow = MockUdpFlow()
        let decision = fx.core.handleUdpFlowDecision(
            flow,
            meta: makeMeta(remoteHost: "127.0.0.1", remotePort: 443)
        )

        XCTAssertEqual(decision, .intercept)
        XCTAssertTrue(decision.callbackReturnValue)
        waitFor("post-registration startup opens flow") { flow.openWasInvoked }
        XCTAssertEqual(fx.core.udpFlowCount, 1)
    }

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
        XCTAssertEqual(
            fx.core.testInspectUdpFlowReadState(for: flow),
            .reading,
            "activation must consume exactly Rust's first recv demand")

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

    func testOpenCompletionAfterDetachCannotReactivateSession() {
        let fx = makeFixture()
        let flow = MockUdpFlow()
        XCTAssertTrue(fx.core.handleUdpFlow(flow, meta: makeMeta()))
        waitFor("flow.open called") { flow.openWasInvoked }
        guard let flowQueue = fx.core.testInspectUdpFlowQueue(for: flow) else {
            XCTFail("registered UDP flow queue")
            return
        }

        fx.core.detachEngine(reason: 0)
        waitFor("detach closes UDP flow") {
            flow.closeReadCallCount == 1 && flow.closeWriteCallCount == 1
        }
        XCTAssertTrue(flow.completeOpen(error: nil))
        flowQueue.sync {}

        XCTAssertEqual(flow.pendingReadCount, 0)
        XCTAssertEqual(fx.core.udpFlowCount, 0)
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

    /// Linked Swift/Rust probe pressure contract. The first four real
    /// `UdpFlowSession`s receive non-zero leased reads. Completing the first
    /// Apple read runs the production
    /// `UdpFlowSession.acknowledgeProbe -> RamaUdpSessionHandle.completeClientRead`
    /// path before forwarding its payload. Rust consumes that owner's charged
    /// lease and advances the next FIFO waiter. Deleting the ACK or replacing
    /// its ID with zero makes Rust reject the payload and no successor can be
    /// scheduled before the configured expiry.
    func testProbePressureReadAcknowledgesExactLeaseAndAdvancesFifo() {
        let engine = makePressureEngine()
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let remotePort: UInt16 = 50_001
        var fillers = fillRustUdpIngressBudget(on: engine, remotePort: remotePort)
        defer {
            fillers.forEach { $0.onClientClose() }
            core.detachEngine(reason: 0)
        }

        let flows = (0..<6).map { _ in MockUdpFlow() }
        for flow in flows {
            XCTAssertTrue(
                core.handleUdpFlow(
                    flow,
                    meta: makeMeta(remoteHost: "127.0.0.1", remotePort: remotePort)))
        }
        for flow in flows {
            waitFor("pressure flow.open", timeout: 10) { flow.openWasInvoked }
            XCTAssertTrue(flow.completeOpen(error: nil))
            waitFor("ordinary UDP read", timeout: 10) { flow.pendingReadCount == 1 }

            // This payload cannot enter a generation whose 16 MiB budget is
            // exactly full. It registers the real session as a FIFO waiter.
            XCTAssertTrue(
                flow.completePendingRead(
                    datagrams: [Data(repeating: 0xCC, count: maxUdpDatagramBytes)],
                    endpoints: [
                        NWHostEndpoint(
                            hostname: "127.0.0.1", port: String(remotePort))
                    ],
                    error: nil))
            core.testInspectUdpFlowQueue(for: flow)?.sync {}
            XCTAssertEqual(flow.pendingReadCount, 0)
        }

        // One released fill flow creates room for exactly four 65,535-byte
        // provisional credits (with four bytes left over).
        fillers.removeFirst().onClientClose()
        for flow in flows.prefix(4) {
            waitFor("initial nonzero pressure read", timeout: 10) {
                flow.pendingReadCount == 1
            }
            XCTAssertEqual(flow.readInvocationUptimeNanoseconds.count, 2)
        }
        Thread.sleep(forTimeInterval: 0.05)
        XCTAssertEqual(flows[4].pendingReadCount, 0, "fifth flow bypassed FIFO batch")
        XCTAssertEqual(flows[5].pendingReadCount, 0, "sixth flow bypassed FIFO batch")

        let peer = NWHostEndpoint(hostname: "127.0.0.1", port: String(remotePort))
        let firstProbeCallback = flows[0].readInvocationUptimeNanoseconds[1]
        XCTAssertTrue(
            flows[0].completePendingRead(
                datagrams: [Data("swift-v2-owner-zero".utf8)],
                endpoints: [peer], error: nil))
        core.testInspectUdpFlowQueue(for: flows[0])?.sync {}
        waitFor("ACK + owner payload advances fifth FIFO flow", timeout: 5) {
            flows[4].pendingReadCount == 1
        }
        let fifthCallback = flows[4].readInvocationUptimeNanoseconds[1]
        XCTAssertLessThan(
            fifthCallback - firstProbeCallback,
            pressureProbeLeaseMs * 1_000_000,
            "fifth flow advanced only after probe expiry; production ACK was not effective")

        let secondProbeCallback = flows[1].readInvocationUptimeNanoseconds[1]
        XCTAssertTrue(
            flows[1].completePendingRead(
                datagrams: [Data("swift-v2-owner-one".utf8)],
                endpoints: [peer], error: nil))
        core.testInspectUdpFlowQueue(for: flows[1])?.sync {}
        waitFor("second ACK + owner payload advances sixth FIFO flow", timeout: 5) {
            flows[5].pendingReadCount == 1
        }
        let sixthCallback = flows[5].readInvocationUptimeNanoseconds[1]
        XCTAssertLessThan(
            sixthCallback - secondProbeCallback,
            pressureProbeLeaseMs * 1_000_000,
            "sixth flow advanced only after probe expiry; exact ACK/FIFO chain regressed")
    }
}
