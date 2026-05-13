import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Comprehensive ARC sweep across every class that participates in
/// the per-flow object graph. Each class instruments its `init` /
/// `deinit` with an atomic live-instance counter, gated on the
/// `tcpFlowContextDiagnosticsEnabled` flag (zero overhead in
/// production). This suite enables the flag, drives the system
/// through a happy-path TCP and UDP lifecycle, then asserts every
/// counter returns to its pre-test baseline.
///
/// The retain cycle we found in `TcpClientReadPump` would have
/// surfaced here as `TcpClientReadPumpLiveCounter.current > startTcp`
/// after teardown. The sweep is the safety net that prevents
/// re-introducing the same shape on any other class.
final class CoreArcLeakSweepTests: XCTestCase {

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    private struct CounterSnapshot {
        let mockTcpFlow: Int
        let tcpFlowContext: Int
        let tcpClientReadPump: Int
        let tcpClientWritePump: Int
        let nwTcpConnectionReadPump: Int
        let nwTcpConnectionWritePump: Int
        let udpFlowContext: Int
        let udpClientWritePump: Int
        let nwUdpConnectionReadPump: Int

        static func current() -> CounterSnapshot {
            CounterSnapshot(
                mockTcpFlow: MockTcpFlowLiveCounter.current,
                tcpFlowContext: TcpFlowContextLiveCounter.current,
                tcpClientReadPump: TcpClientReadPumpLiveCounter.current,
                tcpClientWritePump: TcpClientWritePumpLiveCounter.current,
                nwTcpConnectionReadPump: NwTcpConnectionReadPumpLiveCounter.current,
                nwTcpConnectionWritePump: NwTcpConnectionWritePumpLiveCounter.current,
                udpFlowContext: UdpFlowContextLiveCounter.current,
                udpClientWritePump: UdpClientWritePumpLiveCounter.current,
                nwUdpConnectionReadPump: NwUdpConnectionReadPumpLiveCounter.current
            )
        }
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
        timeout: TimeInterval = 5.0,
        condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.02)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    private func awaitCountersReturnTo(
        baseline: CounterSnapshot,
        timeout: TimeInterval = 5.0
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let now = CounterSnapshot.current()
            if now.mockTcpFlow == baseline.mockTcpFlow
                && now.tcpFlowContext == baseline.tcpFlowContext
                && now.tcpClientReadPump == baseline.tcpClientReadPump
                && now.tcpClientWritePump == baseline.tcpClientWritePump
                && now.nwTcpConnectionReadPump == baseline.nwTcpConnectionReadPump
                && now.nwTcpConnectionWritePump == baseline.nwTcpConnectionWritePump
                && now.udpFlowContext == baseline.udpFlowContext
                && now.udpClientWritePump == baseline.udpClientWritePump
                && now.nwUdpConnectionReadPump == baseline.nwUdpConnectionReadPump
            {
                return
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let now = CounterSnapshot.current()
        let leaks: [(String, Int, Int)] = [
            ("MockTcpFlow", baseline.mockTcpFlow, now.mockTcpFlow),
            ("TcpFlowContext", baseline.tcpFlowContext, now.tcpFlowContext),
            ("TcpClientReadPump", baseline.tcpClientReadPump, now.tcpClientReadPump),
            ("TcpClientWritePump", baseline.tcpClientWritePump, now.tcpClientWritePump),
            ("NwTcpConnectionReadPump", baseline.nwTcpConnectionReadPump, now.nwTcpConnectionReadPump),
            ("NwTcpConnectionWritePump", baseline.nwTcpConnectionWritePump, now.nwTcpConnectionWritePump),
            ("UdpFlowContext", baseline.udpFlowContext, now.udpFlowContext),
            ("UdpClientWritePump", baseline.udpClientWritePump, now.udpClientWritePump),
            ("NwUdpConnectionReadPump", baseline.nwUdpConnectionReadPump, now.nwUdpConnectionReadPump),
        ]
        for (name, base, current) in leaks where current != base {
            XCTFail("\(name) leaked: baseline=\(base) current=\(current)")
        }
    }

    // MARK: - TCP

    func testTcpHappyPath_NoLeaksAcrossEveryClass() {
        tcpFlowContextDiagnosticsEnabled = true
        defer { tcpFlowContextDiagnosticsEnabled = false }

        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            return
        }
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let baseline = CounterSnapshot.current()

        autoreleasepool {
            let flow = MockTcpFlow()
            _ = core.handleTcpFlow(flow, meta: makeMeta())
            let conn = capture.waitForLastConnection()
            conn.transition(to: .ready)
            waitFor("flow.open") { flow.openWasInvoked }
            flow.completeOpen(error: nil)
            waitFor("pumps wired") { conn.pendingReceiveCount > 0 }
            conn.completePendingReceive(isComplete: true)
            waitFor("flow removed", timeout: 5.0) { core.tcpFlowCount == 0 }
            conn.simulateCancelled()
        }
        capture.releaseAll()
        core.detachEngine(reason: 0)

        awaitCountersReturnTo(baseline: baseline)
    }

    func testTcpPreReadyFailedPath_NoLeaks() {
        tcpFlowContextDiagnosticsEnabled = true
        defer { tcpFlowContextDiagnosticsEnabled = false }

        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            return
        }
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let baseline = CounterSnapshot.current()

        autoreleasepool {
            let flow = MockTcpFlow()
            _ = core.handleTcpFlow(flow, meta: makeMeta())
            let conn = capture.waitForLastConnection()
            conn.transition(to: .failed(.posix(.ECONNREFUSED)))
            waitFor("flow removed", timeout: 5.0) { core.tcpFlowCount == 0 }
            conn.simulateCancelled()
        }
        capture.releaseAll()
        core.detachEngine(reason: 0)

        awaitCountersReturnTo(baseline: baseline)
    }

    func testTcpPostReadyFailedPath_NoLeaks() {
        tcpFlowContextDiagnosticsEnabled = true
        defer { tcpFlowContextDiagnosticsEnabled = false }

        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            return
        }
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let baseline = CounterSnapshot.current()

        autoreleasepool {
            let flow = MockTcpFlow()
            _ = core.handleTcpFlow(flow, meta: makeMeta())
            let conn = capture.waitForLastConnection()
            conn.transition(to: .ready)
            waitFor("flow.open") { flow.openWasInvoked }
            flow.completeOpen(error: nil)
            waitFor("pumps wired") { conn.pendingReceiveCount > 0 }
            conn.transition(to: .failed(.posix(.ECONNRESET)))
            waitFor("flow removed", timeout: 5.0) { core.tcpFlowCount == 0 }
            conn.simulateCancelled()
        }
        capture.releaseAll()
        core.detachEngine(reason: 0)

        awaitCountersReturnTo(baseline: baseline)
    }

    // MARK: - UDP

    func testUdpHappyPath_NoLeaks() {
        tcpFlowContextDiagnosticsEnabled = true
        defer { tcpFlowContextDiagnosticsEnabled = false }

        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            return
        }
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let baseline = CounterSnapshot.current()

        autoreleasepool {
            let flow = MockUdpFlow()
            _ = core.handleUdpFlow(flow, meta: makeMeta(protocolRaw: 2, port: 5000))
            let conn = capture.waitForLastConnection()
            conn.transition(to: .ready)
            waitFor("flow.open") { flow.openWasInvoked }
            flow.completeOpen(error: nil)
            waitFor("read pump started") { flow.pendingReadCount > 0 }
            // Drive an EOF on the flow's read side — empty datagrams
            // batch signals end-of-data in the production code.
            flow.completePendingRead(datagrams: [], endpoints: nil, error: nil)
            waitFor("flow removed", timeout: 5.0) { core.udpFlowCount == 0 }
            conn.simulateCancelled()
        }
        capture.releaseAll()
        core.detachEngine(reason: 0)

        awaitCountersReturnTo(baseline: baseline)
    }

    // MARK: - Multi-flow churn

    func testTcpChurn_NoLeaksAcrossAnyClass() {
        tcpFlowContextDiagnosticsEnabled = true
        defer { tcpFlowContextDiagnosticsEnabled = false }

        guard
            let engine = RamaTransparentProxyEngineHandle(
                engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init")
            return
        }
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory

        let baseline = CounterSnapshot.current()

        autoreleasepool {
            let flowCount = 25
            var flows: [MockTcpFlow] = []
            for _ in 0..<flowCount {
                let flow = MockTcpFlow()
                flows.append(flow)
                _ = core.handleTcpFlow(flow, meta: makeMeta())
            }
            waitFor("connections constructed") {
                capture.allConnections.count == flowCount
            }
            let conns = capture.allConnections

            for conn in conns { conn.transition(to: .ready) }
            waitFor("all flow.opens invoked", timeout: 10.0) {
                flows.allSatisfy { $0.openWasInvoked }
            }
            for flow in flows { flow.completeOpen(error: nil) }
            waitFor("all egress pumps wired", timeout: 10.0) {
                conns.allSatisfy { $0.pendingReceiveCount > 0 }
            }
            for conn in conns { conn.completePendingReceive(isComplete: true) }
            waitFor("all flows removed", timeout: 10.0) {
                core.tcpFlowCount == 0
            }
            for conn in conns { conn.simulateCancelled() }
        }
        capture.releaseAll()
        core.detachEngine(reason: 0)

        awaitCountersReturnTo(baseline: baseline, timeout: 10.0)
    }
}
