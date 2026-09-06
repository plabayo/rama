import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Regression coverage for the Swift NEAppProxyProvider half-close
/// path (Fix A): a client upload half-close (kernel `readData` EOF)
/// must forward client EOF to the egress without redundantly closing
/// our read side, and must NOT tear down the egress read pump — the
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
    private func makeArmedSession(egressEofGraceMs: UInt32 = 500)
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
        session.buildClientWritePump()

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
        session.egressEofGraceMs = egressEofGraceMs
        let egress = session.buildEgressReadPump(
            connection: conn,
            session: handle)
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

    /// Client half-close forwards client EOF without issuing a provider
    /// close, and does NOT cancel the egress download pump / connection.
    func testClientHalfCloseKeepsEgressReadPumpAlive() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }

        // Client half-close: kernel readData completes with EOF.
        flow.completeReadSynchronously(data: nil, error: nil)
        drain(queue)

        XCTAssertEqual(
            flow.closeReadCallCount, 0,
            "observed EOF is not a provider-issued read close")
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

        flow.completeReadSynchronously(data: nil, error: nil)
        drain(queue)
        XCTAssertEqual(flow.closeReadCallCount, 0)

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

    func testSessionReadPumpsPublishActivityAtTransportBoundary() {
        let (session, core, flow, conn, _) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }

        session.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: 1)
        flow.completeRead(data: Data([0x01]), error: nil)
        waitFor("client read publishes activity") {
            session.ctx.lastActivityAt.uptimeNanoseconds > 1
        }

        session.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: 1)
        XCTAssertTrue(
            conn.completePendingReceive(
                data: Data([0x02]),
                isComplete: false,
                error: nil))
        waitFor("egress receive publishes activity") {
            session.ctx.lastActivityAt.uptimeNanoseconds > 1
        }
    }

    func testSessionWritePumpsPublishActivityAtAcceptanceBoundary() {
        let (session, core, _, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }

        session.ctx.clientWritePump?.markOpened()
        session.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: 1)
        XCTAssertEqual(
            session.ctx.clientWritePump?.enqueue(Data([0x01])),
            .accepted)
        XCTAssertGreaterThan(session.ctx.lastActivityAt.uptimeNanoseconds, 1)

        conn.transition(to: .ready)
        queue.sync { session.handleEgressReady(connection: conn) }
        session.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: 1)
        XCTAssertEqual(
            session.ctx.egressWritePump?.enqueue(Data([0x02])),
            .accepted)
        XCTAssertGreaterThan(session.ctx.lastActivityAt.uptimeNanoseconds, 1)
    }

    func testSuccessfulClientWriteRefreshesTerminalDrainProgress() {
        let (session, core, flow, _, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        flow.captureWriteCompletions = true
        session.ctx.clientWritePump?.markOpened()
        XCTAssertEqual(
            session.ctx.clientWritePump?.enqueue(Data([0x01])),
            .accepted)
        waitFor("client write is in flight") {
            flow.pendingWriteCompletionCount == 1
        }
        queue.sync { session.closeClientAfterRustDrain() }
        session.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: 1)

        XCTAssertTrue(flow.completeNextWrite())
        waitFor("successful drain write refreshes progress clock") {
            session.ctx.lastActivityAt.uptimeNanoseconds > 1
        }
    }

    func testSessionWritePumpsRejectAfterPressureCommit() {
        let (session, core, _, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }

        session.ctx.clientWritePump?.markOpened()
        conn.transition(to: .ready)
        queue.sync { session.handleEgressReady(connection: conn) }
        session.ctx.withMaintenanceStateLocked {
            $0.pressureEvictionCommitted = true
        }

        XCTAssertEqual(
            session.ctx.clientWritePump?.enqueue(Data([0x01])),
            .closed)
        XCTAssertEqual(
            session.ctx.egressWritePump?.enqueue(Data([0x02])),
            .closed)
        XCTAssertEqual(conn.pendingSendCount, 0)
    }

    func testCleanClientDrainNeedsNoShortEofBackstop() {
        let (session, core, flow, conn, queue) = makeArmedSession(
            egressEofGraceMs: 60_000)
        defer { core.detachEngine(reason: 0) }
        session.lingerCloseMs = 60_000
        session.ctx.lingerCloseMs = 60_000
        flow.captureWriteCompletions = true
        session.ctx.clientWritePump?.markOpened()
        XCTAssertEqual(
            session.ctx.clientWritePump?.enqueue(Data([0x01])),
            .accepted)
        waitFor("client write remains in flight") {
            flow.pendingWriteCompletionCount == 1
        }

        XCTAssertTrue(conn.completePendingReceive(isComplete: true))
        drain(queue)
        queue.sync {
            XCTAssertFalse(session.ctx.egressReadPump?.isEofBackstopArmed == true)
            session.closeClientAfterRustDrain()
        }
        drain(queue)
        queue.sync {
            XCTAssertFalse(session.ctx.egressReadPump?.isEofBackstopArmed == true)
        }

        XCTAssertEqual(conn.cancelCount, 0, "clean upload survives error grace")
        XCTAssertEqual(flow.closeWriteCallCount, 0, "client writer is still draining")

        XCTAssertTrue(flow.completeNextWrite())
        waitFor("client writer completes its half-close") {
            flow.closeWriteCallCount == 1
        }
        XCTAssertEqual(conn.cancelCount, 0)
    }

    func testDelayedRustClosePreservesQuietUploadAfterEgressEof() {
        let (session, core, _, conn, queue) = makeArmedSession(
            egressEofGraceMs: 120)
        defer { core.detachEngine(reason: 0) }

        // The opposite upload may legally remain quiet beyond the short error
        // grace before resuming; recency cannot distinguish it from a leak.
        session.ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: 1)
        XCTAssertTrue(conn.completePendingReceive(isComplete: true))
        drain(queue)

        Thread.sleep(forTimeInterval: 0.30)
        drain(queue)
        XCTAssertEqual(
            conn.cancelCount, 0,
            "clean egress EOF must preserve a quiet legal upload")
        queue.sync {
            XCTAssertFalse(session.ctx.egressReadPump?.isEofBackstopArmed == true)
        }
    }

    func testEgressWriteFailureDuringDrainTearsDownViaRustSession() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        session.ctx.clientWritePump?.markOpened()
        queue.sync { session.closeClientAfterRustDrain() }
        waitFor("client writer completes first drain") {
            flow.closeWriteCallCount == 1
        }
        conn.transition(to: .ready)
        queue.sync { session.handleEgressReady(connection: conn) }
        guard let writer = session.ctx.egressWritePump else {
            XCTFail("egress writer built")
            return
        }
        XCTAssertEqual(writer.enqueue(Data([0x01])), .accepted)
        waitFor("egress data send") { conn.pendingSendCount == 1 }
        queue.sync { session.closeEgressAfterRustDrain() }

        XCTAssertTrue(conn.completePendingSend(error: .posix(.ECONNRESET)))
        waitFor("terminal egress write tears session down") {
            queue.sync { session.ctx.isDone }
        }
        XCTAssertEqual(flow.closeReadCallCount, 1)
        XCTAssertEqual(flow.closeWriteCallCount, 1)
        XCTAssertGreaterThanOrEqual(conn.cancelCount, 1)
        guard case .posix(.ECONNRESET)? = flow.lastCloseReadError as? NWError else {
            return XCTFail("overlapping drain must preserve the egress send error")
        }
        XCTAssertNil(
            flow.lastCloseWriteError,
            "the already-closed download half must retain its clean EOF")
    }

    func testEgressFinFailureTearsDownViaRustSessionWithError() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        session.ctx.clientWritePump?.markOpened()
        queue.sync { session.closeClientAfterRustDrain() }
        waitFor("client writer completes first drain") {
            flow.closeWriteCallCount == 1
        }
        conn.transition(to: .ready)
        queue.sync { session.handleEgressReady(connection: conn) }

        queue.sync { session.closeEgressAfterRustDrain() }
        waitFor("egress FIN send") { conn.pendingSendCount == 1 }
        XCTAssertTrue(conn.completePendingSend(error: .posix(.ECONNRESET)))

        waitFor("FIN error tears session down") {
            queue.sync { session.ctx.isDone }
        }
        guard case .posix(.ECONNRESET)? = flow.lastCloseReadError as? NWError else {
            return XCTFail("read half must preserve the FIN error")
        }
        XCTAssertEqual(flow.closeReadCallCount, 1)
        XCTAssertEqual(flow.closeWriteCallCount, 1)
        XCTAssertNil(
            flow.lastCloseWriteError,
            "the already-closed download half must retain its clean EOF")
    }

    func testPromotedEgressWriteFailurePreservesError() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        session.ctx.clientWritePump?.markOpened()
        conn.transition(to: .ready)
        queue.sync {
            session.handleEgressReady(connection: conn)
            session.ctx.mode = .promoted
            guard let clientWriter = session.ctx.clientWritePump,
                let egressWriter = session.ctx.egressWritePump
            else { return }
            _ = core.makePromotedForwarder(
                ctx: session.ctx,
                flow: flow,
                connection: conn,
                clientWritePump: clientWriter,
                egressWritePump: egressWriter,
                flowQueue: queue)
        }
        XCTAssertNotNil(session.ctx.directForwarder)
        guard let writer = session.ctx.egressWritePump else {
            return XCTFail("egress writer built")
        }
        XCTAssertEqual(writer.enqueue(Data([0x01])), .accepted)
        waitFor("promoted egress data send") { conn.pendingSendCount == 1 }

        XCTAssertTrue(conn.completePendingSend(error: .posix(.ECONNRESET)))
        waitFor("promoted terminal error tears the session down") {
            flow.closeReadCallCount > 0
        }
        guard case .posix(.ECONNRESET)? = flow.lastCloseReadError as? NWError else {
            return XCTFail("promoted read close must preserve the send error")
        }
        guard case .posix(.ECONNRESET)? = flow.lastCloseWriteError as? NWError else {
            return XCTFail("promoted write close must preserve the send error")
        }
    }

    func testPromotedEgressFinFailurePreservesError() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        session.ctx.clientWritePump?.markOpened()
        conn.transition(to: .ready)
        queue.sync {
            session.handleEgressReady(connection: conn)
            session.ctx.mode = .promoted
            guard let clientWriter = session.ctx.clientWritePump,
                let egressWriter = session.ctx.egressWritePump
            else { return }
            _ = core.makePromotedForwarder(
                ctx: session.ctx,
                flow: flow,
                connection: conn,
                clientWritePump: clientWriter,
                egressWritePump: egressWriter,
                flowQueue: queue)
        }
        guard let forwarder = session.ctx.directForwarder else {
            return XCTFail("production promoted forwarder installed")
        }

        forwarder.acceptClientCarryover(.none)
        forwarder.markClientReadDrained()
        forwarder.markRustC2SDone()
        waitFor("promoted C-to-S FIN send") { conn.pendingSendCount == 1 }
        XCTAssertTrue(conn.completePendingSend(error: .posix(.ECONNRESET)))

        waitFor("promoted FIN error tears the session down") {
            queue.sync { session.ctx.isDone }
        }
        guard case .posix(.ECONNRESET)? = flow.lastCloseReadError as? NWError else {
            return XCTFail("promoted read half must preserve the FIN error")
        }
        guard case .posix(.ECONNRESET)? = flow.lastCloseWriteError as? NWError else {
            return XCTFail("promoted write half must preserve the FIN error")
        }
    }

    func testPromotedClientReadFailureUsesErrorfulContextTeardown() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        session.ctx.clientWritePump?.markOpened()
        conn.transition(to: .ready)
        queue.sync {
            session.handleEgressReady(connection: conn)
            session.ctx.mode = .promoted
            guard let clientWriter = session.ctx.clientWritePump,
                let egressWriter = session.ctx.egressWritePump
            else { return }
            _ = core.makePromotedForwarder(
                ctx: session.ctx,
                flow: flow,
                connection: conn,
                clientWritePump: clientWriter,
                egressWritePump: egressWriter,
                flowQueue: queue)
        }
        let error = NSError(domain: "test.promoted.client-read", code: 23)
        session.ctx.directForwarder?.acceptClientCarryoverError(error)

        waitFor("promoted client read error tears down context") {
            queue.sync { session.ctx.isDone }
        }
        XCTAssertEqual(
            (flow.lastCloseReadError as NSError?)?.domain,
            "test.promoted.client-read")
        XCTAssertEqual((flow.lastCloseReadError as NSError?)?.code, 23)
        XCTAssertEqual(
            (flow.lastCloseWriteError as NSError?)?.domain,
            "test.promoted.client-read")
        XCTAssertEqual((flow.lastCloseWriteError as NSError?)?.code, 23)
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
            onDrained: {})
        conn.transition(to: .ready)

        queue.sync { session.closeEgressAfterRustDrain() }
        XCTAssertTrue(session.ctx.maintenanceSnapshot().drainClosePending)
        queue.sync {
            XCTAssertNotNil(session.terminalDrainBackstop, "backstop armed with the drain")
        }
        waitFor("egress FIN send") { conn.pendingSendCount == 1 }
        XCTAssertTrue(conn.completePendingSend(error: nil))
        waitFor("drain marker cleared") {
            !session.ctx.maintenanceSnapshot().drainClosePending
        }

        drain(queue)
        queue.sync {
            XCTAssertNil(session.terminalDrainBackstop, "completed FIN disarms the drain backstop")
            XCTAssertFalse(session.ctx.isDone)
        }
    }

    func testClientDrainWaitsForLaterEgressClose() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        session.lingerCloseMs = 25
        session.ctx.lingerCloseMs = 25
        session.ctx.clientWritePump?.markOpened()
        session.ctx.egressWritePump = NwTcpConnectionWritePump(
            connection: conn,
            queue: queue,
            onDrained: {})
        conn.transition(to: .ready)

        queue.sync { session.closeClientAfterRustDrain() }
        waitFor("client writer half-closes") { flow.closeWriteCallCount == 1 }
        drain(queue)
        queue.sync {
            XCTAssertFalse(session.ctx.isDone)
            XCTAssertFalse(session.ctx.drainClosePending)
            XCTAssertNil(session.terminalDrainBackstop)
        }
        XCTAssertEqual(conn.cancelCount, 0)

        queue.sync { session.closeClientAfterRustDrain() }
        XCTAssertEqual(flow.closeWriteCallCount, 1, "duplicate close signal is inert")
        XCTAssertFalse(session.ctx.maintenanceSnapshot().drainClosePending)

        // Waiting for the independent upload-side close is a valid quiet
        // half-open state, not a wedged writer drain. Its absent timer state
        // proves no drain deadline can kill later traffic in that direction.
        queue.sync {
            XCTAssertFalse(session.ctx.isDone)
            XCTAssertNil(session.terminalDrainBackstop)
        }
        XCTAssertEqual(conn.cancelCount, 0)
        XCTAssertEqual(
            session.ctx.egressWritePump?.enqueue(Data([0x02])),
            .accepted,
            "quiet half-open upload must still accept later bytes")
        waitFor("post-half-close upload send") { conn.pendingSendCount == 1 }
        XCTAssertTrue(conn.completePendingSend(error: nil))

        queue.sync { session.closeEgressAfterRustDrain() }
        waitFor("later egress FIN is issued") { conn.pendingSendCount == 1 }
        XCTAssertTrue(conn.completePendingSend(error: nil))
        waitFor("both directions finalize") { flow.closeReadCallCount == 1 }
        XCTAssertEqual(flow.closeWriteCallCount, 1)
        XCTAssertEqual(flow.closeReadCallCount, 1)
    }

    func testEgressDrainWaitsForLaterClientClose() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        session.lingerCloseMs = 60_000
        session.ctx.lingerCloseMs = 60_000
        session.ctx.clientWritePump?.markOpened()
        session.ctx.egressWritePump = NwTcpConnectionWritePump(
            connection: conn,
            queue: queue,
            onDrained: {})
        conn.transition(to: .ready)

        queue.sync { session.closeEgressAfterRustDrain() }
        waitFor("egress FIN is issued") { conn.pendingSendCount == 1 }
        XCTAssertTrue(conn.completePendingSend(error: nil))
        waitFor("egress drain clears") {
            !session.ctx.maintenanceSnapshot().drainClosePending
        }
        queue.sync { XCTAssertFalse(session.ctx.isDone) }
        XCTAssertEqual(conn.cancelCount, 0)

        queue.sync { session.closeClientAfterRustDrain() }
        waitFor("later client drain finalizes") { flow.closeReadCallCount == 1 }
        XCTAssertEqual(flow.closeWriteCallCount, 1)
        XCTAssertEqual(flow.closeReadCallCount, 1)
    }

    func testEgressFinCannotClearOverlappingClientDrain() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        session.lingerCloseMs = 60_000
        session.ctx.lingerCloseMs = 60_000

        flow.captureWriteCompletions = true
        session.ctx.clientWritePump?.markOpened()
        XCTAssertEqual(
            session.ctx.clientWritePump?.enqueue(Data([0x01])),
            .accepted)

        session.ctx.egressWritePump = NwTcpConnectionWritePump(
            connection: conn,
            queue: queue,
            onDrained: {})
        conn.transition(to: .ready)

        waitFor("client write remains in flight") {
            flow.pendingWriteCompletionCount == 1
        }
        let drainsStarted = expectation(description: "both writer drains started")
        queue.async {
            session.closeClientAfterRustDrain()
            session.closeEgressAfterRustDrain()
            drainsStarted.fulfill()
        }
        wait(for: [drainsStarted], timeout: 1.0)
        waitFor("egress FIN send") { conn.pendingSendCount == 1 }
        XCTAssertTrue(session.ctx.maintenanceSnapshot().drainClosePending)

        XCTAssertTrue(conn.completePendingSend(error: nil))
        drain(queue)

        XCTAssertTrue(
            session.ctx.maintenanceSnapshot().drainClosePending,
            "egress FIN must not hide the still-pending client writer drain")
        let remainedArmed = TestValue(false)
        let firstInspection = expectation(description: "inspect overlapping drain")
        queue.async {
            remainedArmed.set(session.terminalDrainBackstop != nil)
            firstInspection.fulfill()
        }
        wait(for: [firstInspection], timeout: 1.0)
        XCTAssertTrue(
            remainedArmed.get(),
            "backstop must remain armed until every writer drain finishes")

        XCTAssertTrue(flow.completeNextWrite())
        waitFor("client drain finishes teardown") { flow.closeReadCallCount == 1 }
        drain(queue)
        XCTAssertFalse(session.ctx.maintenanceSnapshot().drainClosePending)
        let disarmed = TestValue(false)
        let finalInspection = expectation(description: "inspect completed drains")
        queue.async {
            disarmed.set(session.terminalDrainBackstop == nil)
            finalInspection.fulfill()
        }
        wait(for: [finalInspection], timeout: 1.0)
        XCTAssertTrue(disarmed.get(), "last completed drain disarms the shared backstop")
    }

    func testClientDrainCannotAbortOverlappingEgressFin() {
        let (session, core, flow, conn, queue) = makeArmedSession()
        defer { core.detachEngine(reason: 0) }
        session.lingerCloseMs = 60_000
        session.ctx.lingerCloseMs = 60_000

        flow.captureWriteCompletions = true
        session.ctx.clientWritePump?.markOpened()
        XCTAssertEqual(
            session.ctx.clientWritePump?.enqueue(Data([0x01])),
            .accepted)
        session.ctx.egressWritePump = NwTcpConnectionWritePump(
            connection: conn,
            queue: queue,
            onDrained: {})
        conn.transition(to: .ready)
        waitFor("client write remains in flight") {
            flow.pendingWriteCompletionCount == 1
        }

        queue.sync {
            session.closeClientAfterRustDrain()
            session.closeEgressAfterRustDrain()
        }
        waitFor("egress FIN remains in flight") { conn.pendingSendCount == 1 }
        XCTAssertTrue(flow.completeNextWrite())
        drain(queue)

        queue.sync { XCTAssertFalse(session.ctx.isDone) }
        XCTAssertEqual(conn.cancelCount, 0, "client drain must not abort the pending egress FIN")
        XCTAssertTrue(session.ctx.maintenanceSnapshot().drainClosePending)

        XCTAssertTrue(conn.completePendingSend(error: nil))
        waitFor("last drain performs final teardown") { flow.closeReadCallCount == 1 }
        XCTAssertFalse(session.ctx.maintenanceSnapshot().drainClosePending)
        XCTAssertEqual(conn.cancelCount, 1)
    }
}
