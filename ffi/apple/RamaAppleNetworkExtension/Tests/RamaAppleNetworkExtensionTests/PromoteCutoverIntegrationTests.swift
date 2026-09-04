import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// End-to-end Swift integration tests for the promote cutover.
///
/// Drives `TransparentProxyCore.handleTcpFlow` against
/// `MockTcpFlow` + `MockNwConnection`, pushes some bytes through
/// the in-Rust data path, then manually invokes
/// `beginPromoteCutover` (the orchestrator that Rust would
/// normally fire via the registered promote callback). Bytes
/// pushed AFTER the cutover should traverse the direct
/// kernel ↔ NWConnection forwarder without any Rust hop, and
/// must arrive in correct order.
///
/// We invoke the orchestrator directly because triggering it
/// "for real" requires a Rust service that calls
/// `PromoteHandle::into_passthrough` — which is exhaustively
/// tested on the Rust side already (see
/// `tproxy::engine::tests::promote`). What's worth testing on
/// the Swift side is the state-machine integration: the mode
/// transition flips the close-handlers off, the carryover
/// captures in-flight reads, the forwarder takes over, and
/// the post-cutover byte path is sound.
final class PromoteCutoverIntegrationTests: XCTestCase {

    override class func setUp() {
        super.setUp()
        TestFixtures.ensureInitialized()
    }

    // MARK: - Fixture (mirror of CoreTcpLifecycleTests pattern)

    private struct CoreFixture {
        let engine: RamaTransparentProxyEngineHandle
        let core: TransparentProxyCore
        let capture: NwConnectionCapture
    }

    private func makeFixture() -> CoreFixture {
        guard let engine = RamaTransparentProxyEngineHandle(
            engineConfigJson: TestFixtures.engineConfigJson())
        else {
            XCTFail("engine init"); preconditionFailure()
        }
        let core = TransparentProxyCore()
        core.attachEngine(engine)
        let capture = NwConnectionCapture()
        core.nwConnectionFactory = capture.factory
        return CoreFixture(engine: engine, core: core, capture: capture)
    }

    private func tearDown(_ fx: CoreFixture) {
        fx.core.detachEngine(reason: 0)
    }

    private func makeMeta() -> RamaTransparentProxyFlowMetaBridge {
        RamaTransparentProxyFlowMetaBridge(
            protocolRaw: 1, remoteHost: "example.com", remotePort: 443,
            localHost: nil, localPort: 0,
            sourceAppSigningIdentifier: nil,
            sourceAppBundleIdentifier: nil,
            sourceAppAuditToken: nil, sourceAppPid: 4242)
    }

    private func requireFlowQueue(
        _ ctx: TcpFlowContext,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> DispatchQueue {
        guard let flowQueue = ctx.flowQueue else {
            XCTFail("production context has a flow queue", file: file, line: line)
            preconditionFailure("missing production flow queue")
        }
        return flowQueue
    }

    @discardableResult
    private func onFlowQueue<T>(
        _ ctx: TcpFlowContext,
        _ body: (DispatchQueue) -> T
    ) -> T {
        let flowQueue = requireFlowQueue(ctx)
        return flowQueue.sync { body(flowQueue) }
    }

    @discardableResult
    private func beginPromoteCutover(
        _ fx: CoreFixture,
        ctx: TcpFlowContext,
        flow: MockTcpFlow
    ) -> DispatchQueue {
        let flowQueue = requireFlowQueue(ctx)
        flowQueue.sync {
            fx.core.beginPromoteCutover(
                ctx: ctx,
                flow: flow,
                flowQueue: flowQueue,
                flowId: ObjectIdentifier(flow))
        }
        return flowQueue
    }

    private func markRustDone(_ ctx: TcpFlowContext) {
        let flowQueue = requireFlowQueue(ctx)
        flowQueue.sync {
            ctx.directForwarder?.markRustC2SDone()
            ctx.directForwarder?.markRustS2CDone()
        }
        // The mark methods enqueue their state transitions onto the same
        // queue. This second hop waits until those transitions have run.
        flowQueue.sync {}
    }

    private func waitFor(
        _ description: String, timeout: TimeInterval = 5.0,
        condition: () -> Bool
    ) {
        let deadline = Date(timeIntervalSinceNow: timeout)
        while !condition() && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTAssertTrue(condition(), "timed out waiting for: \(description)")
    }

    /// Spin a background completer that fires `send` completions
    /// on the mock connection. The egress write pump serialises
    /// sends — it needs each completion before the next. Real
    /// NWConnection delivers these automatically; the mock needs
    /// help.
    private func startSendCompleter(_ conn: MockNwConnection) -> AtomicFlag {
        let flag = AtomicFlag()
        DispatchQueue.global().async {
            while !flag.load() {
                _ = conn.completePendingSend(error: nil)
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        return flag
    }

    /// Drive the per-flow lifecycle from `handleTcpFlow` up to
    /// fully active pumps. Returns the live ctx so the test can
    /// invoke the cutover.
    private func driveToActivePumps(
        _ fx: CoreFixture,
        flow: MockTcpFlow
    ) -> (conn: MockNwConnection, ctx: TcpFlowContext) {
        XCTAssertTrue(fx.core.handleTcpFlow(flow, meta: makeMeta()))
        let conn = fx.capture.waitForLastConnection()
        conn.transition(to: .ready)
        waitFor("flow.open called") { flow.openWasInvoked }
        flow.completeOpen(error: nil)
        waitFor("egress read pump issued first receive") {
            conn.pendingReceiveCount > 0
        }
        waitFor("client read pump issued first read") {
            flow.pendingReadCount > 0
        }
        guard let ctx = fx.core.testInspectTcpContext(for: flow) else {
            XCTFail("no ctx after handleTcpFlow"); preconditionFailure()
        }
        return (conn, ctx)
    }

    /// After `beginPromoteCutover`, the old read pumps have
    /// outstanding `flow.readData` / `connection.receive` calls.
    /// Until those complete (via the carryover sink) the
    /// forwarder won't issue its own reads — that's the
    /// `markClientReadDrained` / `markEgressReadDrained`
    /// barrier. Complete the in-flight reads with EOF to drain
    /// the barriers without injecting test bytes.
    ///
    /// EOF on carryover means the corresponding direction
    /// fast-paths to `.finished` once we mark Rust done. For
    /// tests that want to exercise post-cutover direct
    /// forwarding we use the data-carryover variant below.
    private func drainOldReadPumpsWithEof(
        _ flow: MockTcpFlow,
        _ conn: MockNwConnection
    ) {
        flow.completeRead(data: nil, error: nil)
        _ = conn.completePendingReceive(
            data: nil, isComplete: true, error: nil)
    }

    /// Like `drainOldReadPumpsWithEof` but the in-flight reads
    /// return tiny non-empty payloads that flow through the
    /// carryover path as data. The forwarder buffers them
    /// during cutover, then flushes them to the write pumps
    /// when `markRust{C2S,S2C}Done` lands. Returns the bytes
    /// the test should expect to see flowing through the
    /// post-cutover path (in FIFO order against any direct-
    /// forward reads).
    private func drainOldReadPumpsWithCarryoverBytes(
        _ flow: MockTcpFlow,
        _ conn: MockNwConnection
    ) -> (c2sCarryover: Data, s2cCarryover: Data) {
        let c2s = Data([0xCA, 0x12])
        let s2c = Data([0xCB, 0x34])
        flow.completeRead(data: c2s, error: nil)
        _ = conn.completePendingReceive(
            data: s2c, isComplete: false, error: nil)
        return (c2s, s2c)
    }

    // MARK: - Mode-aware close handler

    /// `beginPromoteCutover` flips `ctx.mode = .promoted` and
    /// instantiates the forwarder. The follow-up byte-flow
    /// behaviour is covered by the post-cutover tests below;
    /// this one is the bare state-transition contract.
    func testCutoverSwitchesModeToPromoting() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (_, ctx) = driveToActivePumps(fx, flow: flow)

        XCTAssertEqual(onFlowQueue(ctx) { _ in ctx.mode }, .viaRust,
            "initial mode")
        XCTAssertNil(onFlowQueue(ctx) { _ in ctx.directForwarder },
            "no forwarder before cutover")

        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        XCTAssertEqual(onFlowQueue(ctx) { _ in ctx.mode }, .promoted,
            "beginPromoteCutover must flip mode to .promoted")
        XCTAssertNotNil(onFlowQueue(ctx) { _ in ctx.directForwarder },
            "beginPromoteCutover must instantiate the forwarder")
    }

    /// Double promote-callback fire (e.g. if Rust racily fires
    /// twice somehow, or a test fixture invokes it again) MUST
    /// be a no-op on the second call — no new forwarder, no
    /// state corruption.
    func testCutoverIsIdempotentOnDoubleInvocation() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        let firstForwarder = onFlowQueue(ctx) { _ in ctx.directForwarder }
        XCTAssertNotNil(firstForwarder)

        // Second invocation must be a no-op.
        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        // The same forwarder instance survives — no replacement.
        XCTAssertTrue(
            onFlowQueue(ctx) { _ in ctx.directForwarder === firstForwarder },
            "second beginPromoteCutover must not replace the forwarder")
    }

    /// Cutover with a partially-torn-down ctx (e.g. connection
    /// already nil from a fast hard-error path) confirms `.failed`
    /// instead of attempting the cutover.
    func testCutoverWithoutConnectionConfirmsFailed() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        // Simulate "connection already gone" — a pre-empted
        // hard-error path raced ahead.
        onFlowQueue(ctx) { _ in ctx.connection = nil }

        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        XCTAssertEqual(onFlowQueue(ctx) { _ in ctx.mode }, .viaRust,
            "cutover must NOT advance mode when prerequisites are missing")
        XCTAssertNil(onFlowQueue(ctx) { _ in ctx.directForwarder })
    }

    func testCutoverRejectsFlowWhoseTerminalDrainAlreadyBegan() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (_, ctx) = driveToActivePumps(fx, flow: flow)
        onFlowQueue(ctx) { _ in
            ctx.withMaintenanceStateLocked { state in
                state.terminalSignalled = true
                state.drainClosePending = true
            }
        }

        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        XCTAssertEqual(onFlowQueue(ctx) { _ in ctx.mode }, .viaRust)
        XCTAssertNil(onFlowQueue(ctx) { _ in ctx.directForwarder })
    }

    func testCutoverReplaysClientEofObservedBeforePromotion() {
        let fx = makeFixture(); defer { tearDown(fx) }
        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }
        let flowQueue = requireFlowQueue(ctx)

        flow.completeReadSynchronously(data: nil, error: nil)
        flowQueue.sync {}
        XCTAssertEqual(flow.pendingReadCount, 0)
        XCTAssertEqual(
            flow.closeReadCallCount, 0,
            "observed EOF must not consume the final provider close")

        beginPromoteCutover(fx, ctx: ctx, flow: flow)
        XCTAssertEqual(onFlowQueue(ctx) { _ in ctx.mode }, .promoted)
        guard let forwarder = onFlowQueue(ctx, { _ in ctx.directForwarder }) else {
            return XCTFail("client half-close remains promotable")
        }

        let serverTail = Data([0xFA, 0x11])
        _ = conn.completePendingReceive(
            data: serverTail,
            isComplete: false,
            error: nil)
        markRustDone(ctx)

        waitFor("replayed client EOF finishes c2s") {
            flowQueue.sync { forwarder.c2sPhase == .finished }
        }
        XCTAssertEqual(
            flow.pendingReadCount,
            0,
            "promotion must not read the already-closed client half again")
        waitFor("server tail remains deliverable after client EOF") {
            flow.writes.contains(serverTail)
        }
        waitFor("promoted server read starts") { conn.pendingReceiveCount > 0 }
        _ = conn.completePendingReceive(data: nil, isComplete: true, error: nil)
        flow.completeNextWrite()

        waitFor("both half-closes release the registry") {
            fx.core.tcpFlowCount == 0
        }
        XCTAssertEqual(
            flow.closeReadCallCount, 1,
            "final aggregation issues the provider read close exactly once")
        XCTAssertEqual(flow.closeWriteCallCount, 1)
    }

    func testClientCarryoverReadErrorTearsDownWithOriginalError() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (_, ctx) = driveToActivePumps(fx, flow: flow)
        let flowQueue = beginPromoteCutover(fx, ctx: ctx, flow: flow)

        let error = NSError(domain: "test.promote.carryover", code: 73)
        flow.completeRead(data: nil, error: error)
        waitFor("carryover error tears down the promoted flow") {
            flowQueue.sync { ctx.isDone } && fx.core.tcpFlowCount == 0
        }
        XCTAssertEqual(
            (flow.lastCloseReadError as NSError?)?.domain,
            "test.promote.carryover")
        XCTAssertEqual((flow.lastCloseReadError as NSError?)?.code, 73)
        XCTAssertEqual(
            (flow.lastCloseWriteError as NSError?)?.domain,
            "test.promote.carryover")
        XCTAssertEqual((flow.lastCloseWriteError as NSError?)?.code, 73)
    }

    // MARK: - Direct-forward post-cutover byte flow

    /// After the cutover, kernel bytes flowing in via
    /// `flow.readData` should reach the connection via the
    /// direct forwarder (not via Rust onWriteToEgress).
    ///
    /// Sequence:
    ///   1. Drive lifecycle to active pumps.
    ///   2. Invoke beginPromoteCutover.
    ///   3. Complete the old read pumps' in-flight reads with
    ///      tiny carryover payloads — this fires the
    ///      drain barriers (`markClientReadDrained` /
    ///      `markEgressReadDrained`) AND seeds the buffers.
    ///   4. Fire `markRust{C2S,S2C}Done` so the forwarder
    ///      transitions to `.active` and starts its own read
    ///      loops (real Rust would fire onCloseEgress /
    ///      onServerClosed which the mode-aware handler
    ///      forwards as these calls).
    ///   5. Deliver a fresh payload via the forwarder's new
    ///      `flow.readData`.
    ///   6. Assert the payload reaches the connection.
    func testPostCutoverC2SBytesFlowDirectlyToConnection() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        let preSends = conn.sentChunks.count

        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        // Drain the old in-flight reads (carryover route).
        let (carryC2S, _) = drainOldReadPumpsWithCarryoverBytes(flow, conn)

        markRustDone(ctx)

        // Wait for the forwarder to issue its OWN flow.readData.
        waitFor("forwarder issued direct flow.readData") {
            flow.pendingReadCount > 0
        }

        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])
        flow.completeRead(data: payload, error: nil)

        // Both the carryover and the new payload must reach
        // the connection, in order.
        waitFor("carryover then direct bytes reached the connection") {
            let sent = conn.sentChunks.dropFirst(preSends)
                .compactMap { $0.content }
            return sent.contains(carryC2S) && sent.contains(payload)
        }
        // Strict FIFO: carryover precedes direct payload.
        let sent = conn.sentChunks.dropFirst(preSends)
            .compactMap { $0.content }
        if let carryIdx = sent.firstIndex(of: carryC2S),
           let directIdx = sent.firstIndex(of: payload) {
            XCTAssertLessThan(carryIdx, directIdx,
                "carryover MUST precede direct-forwarded bytes")
        }
    }

    /// Symmetric: NWConnection bytes flow directly to the kernel
    /// flow after the cutover.
    func testPostCutoverS2CBytesFlowDirectlyToFlow() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        let preWrites = flow.writes.count

        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        let (_, carryS2C) = drainOldReadPumpsWithCarryoverBytes(flow, conn)

        markRustDone(ctx)

        waitFor("forwarder issued direct connection.receive") {
            conn.pendingReceiveCount > 0
        }

        let payload = Data([0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45])
        _ = conn.completePendingReceive(
            data: payload, isComplete: false, error: nil)

        waitFor("carryover then direct bytes reached the flow") {
            let writes = flow.writes.dropFirst(preWrites)
            return writes.contains(carryS2C) && writes.contains(payload)
        }
        let writes = Array(flow.writes.dropFirst(preWrites))
        if let carryIdx = writes.firstIndex(of: carryS2C),
           let directIdx = writes.firstIndex(of: payload) {
            XCTAssertLessThan(carryIdx, directIdx,
                "carryover MUST precede direct-forwarded bytes")
        }
    }

    /// Both directions actively forward in parallel after cutover.
    /// Verifies independence (a slow side doesn't block the
    /// other).
    func testPostCutoverBothDirectionsForwardConcurrently() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        let preSends = conn.sentChunks.count
        let preWrites = flow.writes.count

        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        _ = drainOldReadPumpsWithCarryoverBytes(flow, conn)
        markRustDone(ctx)

        waitFor("both direct loops active") {
            flow.pendingReadCount > 0 && conn.pendingReceiveCount > 0
        }

        let c2sPayload = Data([0x11, 0x22, 0x33])
        let s2cPayload = Data([0xAA, 0xBB, 0xCC])
        flow.completeRead(data: c2sPayload, error: nil)
        _ = conn.completePendingReceive(
            data: s2cPayload, isComplete: false, error: nil)

        waitFor("c2s bytes delivered") {
            conn.sentChunks.dropFirst(preSends).contains {
                $0.content == c2sPayload
            }
        }
        waitFor("s2c bytes delivered") {
            flow.writes.dropFirst(preWrites).contains(s2cPayload)
        }
    }

    /// Larger end-to-end: multiple chunks in BOTH directions
    /// across the cutover, FIFO order preserved per direction.
    /// This is the byte-for-byte preservation invariant under a
    /// realistic load.
    func testPostCutoverManyChunksPreserveFifoOrderPerDirection() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        let preSends = conn.sentChunks.count
        let preWrites = flow.writes.count

        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        let (carryC2S, carryS2C) =
            drainOldReadPumpsWithCarryoverBytes(flow, conn)
        markRustDone(ctx)

        // Deliver C→S chunks sequentially. The forwarder issues
        // a fresh readData after each delivery; we wait for the
        // sentChunks count to catch up before the next chunk.
        let c2sChunks: [Data] = (0..<5).map { Data([UInt8($0), 0xC2, 0x0]) }
        for chunk in c2sChunks {
            waitFor("forwarder ready for next c2s read") {
                flow.pendingReadCount > 0
            }
            flow.completeRead(data: chunk, error: nil)
            waitFor("c2s chunk \(chunk) delivered to conn") {
                conn.sentChunks.dropFirst(preSends).contains {
                    $0.content == chunk
                }
            }
        }

        let s2cChunks: [Data] = (0..<5).map { Data([UInt8($0), 0x52, 0xC0]) }
        for chunk in s2cChunks {
            waitFor("forwarder ready for next s2c receive") {
                conn.pendingReceiveCount > 0
            }
            _ = conn.completePendingReceive(
                data: chunk, isComplete: false, error: nil)
            waitFor("s2c chunk \(chunk) delivered to flow") {
                flow.writes.dropFirst(preWrites).contains(chunk)
            }
        }

        // Strict FIFO check: carryover first, then the direct
        // chunks, in delivery order.
        let c2sDelivered = conn.sentChunks.dropFirst(preSends)
            .compactMap { $0.content }
            .filter { $0 == carryC2S || c2sChunks.contains($0) }
        XCTAssertEqual(c2sDelivered, [carryC2S] + c2sChunks,
            "FIFO violation in C→S direction across cutover")

        let s2cDelivered = Array(flow.writes.dropFirst(preWrites)
            .filter { $0 == carryS2C || s2cChunks.contains($0) })
        XCTAssertEqual(s2cDelivered, [carryS2C] + s2cChunks,
            "FIFO violation in S→C direction across cutover")
    }

    // MARK: - Teardown after cutover

    /// Kernel EOF after cutover finishes the C→S direction (FIN
    /// sent to NWConnection via egressWritePump.closeWhenDrained).
    /// Connection EOF then finishes S→C, fires forwarder
    /// terminal, removes the flow from the registry.
    ///
    /// Here we drive the carryover via EOF on the old in-flight
    /// reads — there's no carryover data to flush; the direction
    /// fast-paths to `.finished` once Rust-done lands. The
    /// follow-up "deliver more bytes" step is unnecessary
    /// because both directions are already winding down.
    func testPostCutoverEofInBothDirectionsRemovesFlow() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        let flowQueue = beginPromoteCutover(fx, ctx: ctx, flow: flow)

        // EOF the in-flight reads (carryover .none on both
        // sides). Drain barriers fire, but `*EofBuffered`
        // flips true, so the directions fast-path to
        // `.finished` once Rust-done lands.
        drainOldReadPumpsWithEof(flow, conn)
        markRustDone(ctx)

        waitFor("c2s finished") {
            flowQueue.sync { ctx.directForwarder?.c2sPhase == .finished }
        }
        waitFor("s2c finished") {
            flowQueue.sync { ctx.directForwarder?.s2cPhase == .finished }
        }

        // Forwarder's onTerminal removes the flow from registry
        // + closes the kernel flow.
        waitFor("flow removed from registry", timeout: 5.0) {
            fx.core.tcpFlowCount == 0
        }
        XCTAssertEqual(flow.closeReadCallCount, 1,
            "forwarder onTerminal must close the kernel flow read side")
        XCTAssertEqual(flow.closeWriteCallCount, 1,
            "forwarder onTerminal must close the kernel flow write side")
    }

    // MARK: - Read-drain barrier

    /// The drain barrier ensures the forwarder does NOT issue
    /// `flow.readData` until the cancelled read pump's in-flight
    /// callback has fired. Without the barrier, two outstanding
    /// `readData` calls would violate Apple's serial-only
    /// contract.
    ///
    /// Drive: invoke cutover but DO NOT complete the old
    /// in-flight reads. Mark Rust done. Verify the forwarder
    /// does not issue a new readData. THEN complete the old
    /// reads and observe the forwarder kicks in.
    func testReadDrainBarrierPreventsConcurrentReadData() {
        let fx = makeFixture(); defer { tearDown(fx) }

        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        // Before cutover, the active client read pump has
        // exactly 1 pending readData.
        XCTAssertEqual(flow.pendingReadCount, 1,
            "active client read pump issued exactly one in-flight readData")
        XCTAssertEqual(conn.pendingReceiveCount, 1,
            "active egress read pump issued exactly one in-flight receive")

        let flowQueue = beginPromoteCutover(fx, ctx: ctx, flow: flow)

        // Mark Rust done while the in-flight reads are STILL
        // pending. The forwarder transitions to `.active` per
        // direction but the barrier blocks the new readData /
        // receive.
        markRustDone(ctx)

        XCTAssertEqual(flow.pendingReadCount, 1,
            "barrier MUST suppress new flow.readData until the old in-flight read drains")
        XCTAssertEqual(conn.pendingReceiveCount, 1,
            "barrier MUST suppress new connection.receive until the old in-flight receive drains")
        XCTAssertEqual(
            flowQueue.sync { ctx.directForwarder?.c2sPhase }, .active)
        XCTAssertEqual(
            flowQueue.sync { ctx.directForwarder?.s2cPhase }, .active)

        // Drain the old in-flight reads (carryover route) →
        // markClient/EgressReadDrained fires → forwarder now
        // issues its own.
        let (_, _) = drainOldReadPumpsWithCarryoverBytes(flow, conn)

        waitFor("forwarder issued its own flow.readData", timeout: 1.0) {
            flow.pendingReadCount >= 1
        }
        waitFor("forwarder issued its own connection.receive", timeout: 1.0) {
            conn.pendingReceiveCount >= 1
        }
    }

    // MARK: - STUCK-1: half-close must not be force-torn-down

    /// A promoted flow that took a clean half-close on ONE direction (C→S EOFs
    /// and its FIN drains to `.finished`) while the OPPOSITE direction is still
    /// actively transferring (`.active`) must NOT be force-reset by the
    /// closing-stuck watchdog. `terminalSignalled` is sticky (set when C→S
    /// entered `.finishing`), so a `terminalSignalled`-only watchdog would
    /// wrongly tear this live download down after two ticks. The fix keys the
    /// watchdog on a GENUINE drain-wedge (a direction stuck in `.finishing`),
    /// which a clean half-close is not.
    func testHalfClosedPromotedFlowWithActiveOppositeDirectionIsSpared() {
        let fx = makeFixture(); defer { tearDown(fx) }
        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        let flowQueue = beginPromoteCutover(fx, ctx: ctx, flow: flow)

        // Half-close: client read EOFs (C→S finishes) while the egress receive
        // returns DATA (S→C stays active — server still streaming).
        flow.completeRead(data: nil, error: nil)
        _ = conn.completePendingReceive(data: Data([0x01, 0x02]), isComplete: false, error: nil)
        markRustDone(ctx)

        waitFor("C→S drained to .finished") {
            flowQueue.sync { ctx.directForwarder?.c2sPhase == .finished }
        }
        // Preconditions that make this the STUCK-1 scenario.
        XCTAssertEqual(
            flowQueue.sync { ctx.directForwarder?.s2cPhase }, .active,
            "S→C must still be actively transferring")
        XCTAssertTrue(
            flowQueue.sync { ctx.terminalSignalled },
            "terminalSignalled is sticky from C→S entering .finishing")

        // Model the still-active S→C direction making byte progress: a live
        // half-close keeps bumping `lastActivityAt`, which is exactly what marks
        // it not-drain-wedged. (Deterministic regardless of `lingerCloseMs` and
        // the time the cutover/drain took above.)
        flowQueue.sync { ctx.lastActivityAt = .now() }

        // Two consecutive maintenance ticks — the threshold a terminalSignalled-
        // only watchdog would tear down on. The drain-wedge re-check must spare
        // this live half-close.
        fx.core.testRunPeriodicMaintenance()
        fx.core.testRunPeriodicMaintenance()
        flowQueue.sync {}

        XCTAssertFalse(
            flowQueue.sync { ctx.isDone },
            "a live half-close with an active opposite direction must NOT be force-torn-down")
        XCTAssertEqual(fx.core.tcpFlowCount, 1, "flow must remain registered")
    }

    // MARK: - promoted-idle clock reset at cutover

    /// The promoted-idle reaper keys on `lastActivityAt`. A flow may spend time
    /// on the `viaRust` path first; `beginPromoteCutover` must reset the clock so
    /// a previously-idle flow gets a fresh full timeout once promoted (it only
    /// now loses the engine's in-Rust idle backstop). A regression would
    /// prematurely reap freshly-promoted flows.
    func testCutoverResetsPromotedIdleClock() {
        let fx = makeFixture(); defer { tearDown(fx) }
        let flow = MockTcpFlow()
        let (conn, ctx) = driveToActivePumps(fx, flow: flow)
        let completer = startSendCompleter(conn); defer { completer.store(true) }

        // Make the pre-cutover activity look ancient.
        let before = onFlowQueue(ctx) { _ -> UInt64 in
            ctx.lastActivityAt = DispatchTime(uptimeNanoseconds: 1)
            return ctx.lastActivityAt.uptimeNanoseconds
        }

        beginPromoteCutover(fx, ctx: ctx, flow: flow)

        XCTAssertGreaterThan(
            onFlowQueue(ctx) { _ in ctx.lastActivityAt.uptimeNanoseconds },
            before,
            "cutover must reset the promoted-idle clock to ~now, giving a fresh full timeout")
    }
}

/// Tiny atomic-bool helper for background coordination — same
/// shape as the one in `TcpDirectForwarderTests` but with a
/// distinct name to avoid module-level name collision.
final class AtomicFlag {
    private let lock = NSLock()
    private var _v: Bool = false
    func load() -> Bool { lock.lock(); defer { lock.unlock() }; return _v }
    func store(_ x: Bool) { lock.lock(); _v = x; lock.unlock() }
}
