import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Regression coverage for the Swift NEAppProxyProvider half-close
/// path (Fix A): a client upload half-close (kernel `readData` EOF)
/// must close our read side and forward client EOF to the egress, but
/// must NOT tear down the egress (download) read pump — the
/// server→client direction has to keep flowing until the server
/// closes. This is fp's exact `/api/ws` shape (client done, server
/// keeps sending then closes) and the layer `tproxy_ffi_e2e` never
/// exercises: there the Rust engine is driven through a Rust ingress
/// listener, whereas here the `TcpFlowSession` + `NWConnection` pumps
/// are real and only the Apple flow/connection boundary is mocked.
final class TcpFlowSessionHalfCloseTests: XCTestCase {

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

    private func makeMeta() -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1, remoteHost: "example.com", remotePort: 443,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil, sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil, sourceAppPid: 4242)
    }

    /// Awaiting a no-op block on the per-flow queue forces the test to
    /// observe state produced by a single-hop async pump callback.
    private func drain(_ queue: DispatchQueue, timeout: TimeInterval = 1.0) {
        let exp = expectation(description: "flow queue drained")
        queue.async { exp.fulfill() }
        wait(for: [exp], timeout: timeout)
    }

    /// Polls `condition` until true or the timeout elapses. Needed for
    /// the half-close EOF path, which crosses TWO async hops
    /// (`MockTcpFlow.completeRead` dispatches the kernel callback on the
    /// global queue, the pump then re-dispatches onto `flowQueue`) — a
    /// single `drain` would race the first hop.
    private func waitFor(
        _ description: String, timeout: TimeInterval = 2.0, _ condition: () -> Bool
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.005)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    /// Build a session pinned to a real (pending) Rust session handle,
    /// with the egress download pump started and the client read pump
    /// armed through the production half-close terminal.
    ///
    /// Returns `core` strongly: `TcpFlowSession.core` is `weak`, and the
    /// core is what strongly retains the engine handle, so the caller
    /// must keep it alive for the duration of the test.
    private func makeArmedSession()
        -> (
            TcpFlowSession<MockTcpFlow>, TransparentProxyCore, MockTcpFlow, MockNwConnection,
            DispatchQueue
        )
    {
        let engine = makeEngine()
        let core = TransparentProxyCore()
        core.attachEngine(engine)

        let flow = MockTcpFlow()
        let conn = MockNwConnection()
        let session = TcpFlowSession(core: core, flow: flow, meta: makeMeta())
        session.ctx.connection = conn

        // The intercept decision is synchronous; pin the handle the way
        // `start()` would.
        guard let decision = session.requestEngineSession(),
            case .intercept(let handle) = decision
        else {
            XCTFail("engine did not intercept")
            preconditionFailure()
        }
        session.sessionHandle = handle
        session.ctx.session = handle

        let queue = session.flowQueue

        // Egress (download) read pump — the server→client direction.
        let egress = NwTcpConnectionReadPump(
            connection: conn, session: handle, queue: queue,
            eofGraceDeadline: .milliseconds(500))
        session.ctx.egressReadPump = egress
        egress.start()
        drain(queue)
        XCTAssertEqual(conn.pendingReceiveCount, 1, "egress pump issues a receive on start")

        // Client (upload) read pump, wired through the real terminal.
        session.armReadTerminal(session: handle)
        session.ctx.clientReadPump?.requestRead()
        drain(queue)
        XCTAssertEqual(flow.pendingReadCount, 1, "client read pump issued a readData")

        return (session, core, flow, conn, queue)
    }

    /// Client half-close closes our read side + forwards client EOF,
    /// and does NOT cancel the egress download pump / connection.
    func testClientHalfCloseKeepsEgressReadPumpAlive() {
        let (session, core, flow, conn, _) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }

        // Client half-close: kernel readData completes with EOF.
        flow.completeRead(data: nil, error: nil)
        waitFor("half-close ran the natural-EOF terminal") { flow.closeReadCallCount == 1 }

        XCTAssertEqual(flow.closeReadCallCount, 1, "half-close closes our read side")
        XCTAssertEqual(
            conn.cancelCount, 0, "half-close must NOT cancel the egress connection")
        XCTAssertNotNil(
            session.ctx.egressReadPump, "egress download pump must survive the half-close")
    }

    /// After the client half-close, server→client keeps flowing: each
    /// non-terminal egress receive re-arms the pump. A regression that
    /// cancelled the egress read pump on half-close would stop re-arming
    /// (truncating the download), which is what Fix A guards against.
    func testEgressDownloadContinuesAcrossClientHalfClose() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }

        flow.completeRead(data: nil, error: nil)
        waitFor("half-close ran the natural-EOF terminal") { flow.closeReadCallCount == 1 }

        // Two server→client read cycles after the upload half-close.
        // Empty non-terminal receives loop the pump back to
        // `scheduleReadLocked` without depending on the unactivated
        // session's `onEgressBytes` return — the same probe
        // `NwTcpConnectionReadPumpEofTests` uses.
        for round in 1...2 {
            XCTAssertTrue(
                conn.completePendingReceive(isComplete: false),
                "round \(round): a receive was outstanding")
            drain(queue)
            XCTAssertEqual(
                conn.pendingReceiveCount, 1,
                "round \(round): egress pump re-armed → server→client still open")
        }
        XCTAssertEqual(conn.cancelCount, 0, "download direction never force-closed")
        XCTAssertNotNil(session.ctx.egressReadPump, "egress pump alive through the conversation")
    }

    func testCompletedEgressFinClearsDrainPending() {
        let (session, core, _, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        // Generous linger: a tight window would race CI scheduling. The
        // invariant is asserted on timer STATE (backstop disarmed), not by
        // out-sleeping a wall-clock deadline.
        session.lingerCloseMs = 60_000
        session.ctx.lingerCloseMs = 60_000
        session.ctx.egressWritePump = NwTcpConnectionWritePump(
            connection: conn,
            queue: queue,
            lingerCloseDeadline: .milliseconds(60_000),
            onDrained: {},
            readSideIdleMs: { 0 })
        conn.transition(to: .ready)

        queue.sync { session.closeEgressAfterRustDrain() }
        XCTAssertTrue(session.ctx.drainClosePending)
        queue.sync {
            XCTAssertNotNil(session.terminalDrainBackstop, "backstop armed with the drain")
        }
        waitFor("egress FIN send") { conn.pendingSendCount == 1 }
        XCTAssertTrue(conn.completePendingSend(error: nil))
        waitFor("drain marker cleared") { !session.ctx.drainClosePending }

        drain(queue)
        queue.sync {
            XCTAssertNil(session.terminalDrainBackstop, "completed FIN disarms the drain backstop")
            XCTAssertFalse(session.ctx.isDone)
        }
    }
}
