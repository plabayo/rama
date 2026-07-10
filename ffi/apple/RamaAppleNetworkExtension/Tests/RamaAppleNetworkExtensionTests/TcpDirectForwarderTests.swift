import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// State-machine tests for `TcpDirectForwarder` — the Swift-only
/// kernel ↔ NWConnection direct data path that takes over after a
/// successful promote cutover.
///
/// All tests drive the forwarder against `MockTcpFlow` and
/// `MockNwConnection`. The forwarder is constructed against real
/// `TcpClientWritePump` / `NwTcpConnectionWritePump` instances —
/// those pumps are independently covered by their own test
/// modules, so we trust their enqueue/drain semantics and focus
/// purely on the forwarder's coordination.
///
/// Test naming convention:
///   * `c2s` / `s2c` directions
///   * `buffering` → `active` → `finishing` → `finished` phases
///   * `markRustC2SDone` / `markRustS2CDone` cause the transition
///   * `acceptClientCarryover` / `acceptEgressCarryover` capture
///     in-flight bytes from the read pumps
final class TcpDirectForwarderTests: XCTestCase {

    // MARK: - Fixture

    private final class Harness {
        let flow: MockTcpFlow
        let conn: MockNwConnection
        let queue: DispatchQueue
        let clientWritePump: TcpClientWritePump
        let egressWritePump: NwTcpConnectionWritePump
        let forwarder: TcpDirectForwarder
        var terminalCount = 0
        /// Counts the forwarder's `onClosing` (first `.finishing`) and
        /// `onDrainStall` (wedged-finish backstop) callbacks. Read via
        /// `queue.sync` so assertions see all queue-ordered writes.
        var closingCount = 0
        var drainPending = false
        var drainStallCount = 0
        /// Counts the forwarder's `onActivity` callback — fired on every
        /// byte moved in either direction. Production routes this to
        /// `ctx.lastActivityAt` for the promoted-idle reaper. Mutated on
        /// `queue`, read via `queue.sync`.
        var activityCount = 0
        /// Background thread that auto-fires pending send
        /// completions on the mock connection. The egress
        /// write pump serialises sends — each `send` call
        /// awaits its completion before the next. Without
        /// auto-completing, the FIN-on-drain (now
        /// async-completion based) never
        /// fires and `c2sPhase = .finished` never transitions,
        /// hanging every C→S finish test.
        private let stopAutoCompleter = AtomicBool()

        /// `preDrained` = `true` (default) auto-fires both
        /// read-drain barriers (`markClientReadDrained` +
        /// `markEgressReadDrained`) as if `cancelForPromote`
        /// had reported the old pumps as idle. Tests that
        /// specifically exercise the barrier behaviour pass
        /// `false` and fire the signals themselves.
        ///
        /// `autoCompleter` = `true` (default) runs a background
        /// loop that completes the mock connection's pending
        /// sends as they arrive — required by every test that
        /// expects normal `c2sPhase = .finished` progression.
        /// Backpressure tests pass `false` and trigger completions
        /// manually so the egress pump's `pendingBytes` can
        /// actually exceed `writePumpMaxPendingBytes` and
        /// force `.paused`.
        init(
            _ tag: String, preDrained: Bool = true, autoCompleter: Bool = true,
            drainStallDeadline: DispatchTimeInterval = .milliseconds(Int(defaultLingerCloseMs))
        ) {
            let flow = MockTcpFlow()
            let conn = MockNwConnection()
            self.flow = flow
            self.conn = conn
            queue = DispatchQueue(label: "rama.tproxy.test.fwd.\(tag)", qos: .utility)
            // Move connection to .ready so the egress write pump
            // is willing to send. Real production wires this via
            // stateUpdateHandler; here we transition directly.
            conn.transition(to: .ready)
            // Forward-declared ref so the pumps' drain callbacks
            // can route into the forwarder (set below). Mirrors
            // the production indirection via `TcpFlowContext`.
            let forwarderRef = TestValue<TcpDirectForwarder?>(nil)
            clientWritePump = TcpClientWritePump(
                flow: flow, queue: queue,
                logger: { _ in },
                onTerminalError: { _ in },
                onDrained: { forwarderRef.get()?.onClientPumpDrained() })
            egressWritePump = NwTcpConnectionWritePump(
                connection: conn, queue: queue,
                lingerCloseDeadline: .milliseconds(100),
                onDrained: { forwarderRef.get()?.onEgressPumpDrained() },
                // Mirror production's promoted-mode wiring
                // (`TcpFlowSession.buildEgressWritePump`): a terminal
                // egress write error drives the forwarder to terminal.
                onTerminal: { _ in forwarderRef.get()?.cancel() })
            // Mark client write pump opened so it accepts enqueues.
            clientWritePump.markOpened()

            var capturedTerminalRef: (() -> Void)? = nil
            var capturedClosingRef: (() -> Void)? = nil
            var capturedDrainPendingRef: ((Bool) -> Void)? = nil
            var capturedDrainStallRef: (() -> Void)? = nil
            var capturedActivityRef: (() -> Void)? = nil
            self.forwarder = TcpDirectForwarder(
                flow: flow, connection: conn,
                clientWritePump: clientWritePump,
                egressWritePump: egressWritePump,
                queue: queue,
                logger: { _ in },
                drainStallDeadline: drainStallDeadline,
                onClosing: { capturedClosingRef?() },
                onDrainPendingChanged: { capturedDrainPendingRef?($0) },
                onDrainStall: { capturedDrainStallRef?() },
                onActivity: { capturedActivityRef?() },
                closeClientWrite: { [flow] error in flow.closeWriteWithError(error) },
                onTerminal: { capturedTerminalRef?() }
            )
            forwarderRef.set(self.forwarder)
            capturedTerminalRef = { [weak self] in
                guard let self else { return }
                // Hop to queue to ensure consistent ordering for
                // assertions.
                self.queue.async { self.terminalCount += 1 }
            }
            // `onClosing` / `onDrainStall` already fire on `queue`; the
            // counts are mutated there too, so plain increments stay
            // serialised with the rest of the forwarder's state.
            capturedClosingRef = { [weak self] in self?.closingCount += 1 }
            capturedDrainPendingRef = { [weak self] in self?.drainPending = $0 }
            capturedDrainStallRef = { [weak self] in self?.drainStallCount += 1 }
            capturedActivityRef = { [weak self] in self?.activityCount += 1 }
            if preDrained {
                forwarder.markClientReadDrained()
                forwarder.markEgressReadDrained()
                queue.sync {}
            }
            // Spin up the auto-completer unless the test opts out.
            // Stops on `deinit`.
            if autoCompleter {
                let stop = stopAutoCompleter
                let conn = conn
                DispatchQueue.global().async {
                    while !stop.load() {
                        _ = conn.completePendingSend(error: nil)
                        Thread.sleep(forTimeInterval: 0.001)
                    }
                }
            }
        }

        deinit {
            stopAutoCompleter.store(true)
        }

        /// Wait until the queue has processed everything currently
        /// enqueued. Tight bound via `sync` barrier.
        func drain() {
            queue.sync {}
        }
    }

    // MARK: - Buffering phase

    /// In `.buffering` no read loops should fire — the forwarder
    /// is waiting for the per-direction Rust-done signal. Verify
    /// the flow / connection see no `readData` / `receive` calls
    /// just from constructing the forwarder + accepting carryover.
    func testBufferingPhaseDoesNotIssueReads() {
        let h = Harness("buffering.noreads")
        h.forwarder.acceptClientCarryover(Data([1, 2, 3]))
        h.forwarder.acceptEgressCarryover(Data([4, 5, 6]))
        h.drain()

        XCTAssertEqual(h.flow.pendingReadCount, 0,
            "no flow.readData until C→S direction is `.active`")
        XCTAssertEqual(h.conn.pendingReceiveCount, 0,
            "no connection.receive until S→C direction is `.active`")
        XCTAssertEqual(h.forwarder.c2sPhase, .buffering)
        XCTAssertEqual(h.forwarder.s2cPhase, .buffering)
    }

    /// `markRustC2SDone` flushes the C→S carryover buffer to the
    /// egress write pump in FIFO order, then issues the first
    /// `flow.readData`. Same shape for `markRustS2CDone` →
    /// clientWritePump + `connection.receive`.
    ///
    /// Note: the egress write pump serialises sends — it waits
    /// for `completion` of each send before issuing the next.
    /// The test fires send completions in a background spin so
    /// the pump can drain both buffered chunks.
    func testRustDoneFlushesCarryoverThenStartsReadLoop() {
        let h = Harness("rustdone.flush")
        let chunk1 = Data([0xAA, 0xBB])
        let chunk2 = Data([0xCC, 0xDD, 0xEE])
        h.forwarder.acceptClientCarryover(chunk1)
        h.forwarder.acceptClientCarryover(chunk2)
        h.drain()

        // Pre-transition: nothing should reach the NWConnection.
        XCTAssertEqual(h.conn.sentChunks.count, 0)

        // Background completer: fire `send` completions as they
        // queue up, so the pump can serially drain its queue.
        let stopCompleter = atomicFlag()
        DispatchQueue.global().async {
            while !stopCompleter.load() {
                _ = h.conn.completePendingSend(error: nil)
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        defer { stopCompleter.store(true) }

        h.forwarder.markRustC2SDone()
        h.drain()
        waitFor("egressWritePump dispatched both chunks", timeout: 2.0) {
            h.conn.sentChunks.count >= 2
        }

        // FIFO ordering preserved.
        XCTAssertEqual(h.conn.sentChunks[0].content, chunk1)
        XCTAssertEqual(h.conn.sentChunks[1].content, chunk2)
        XCTAssertEqual(h.forwarder.c2sPhase, .active)
        // First flow.readData should be in flight (issued after
        // buffer flush).
        waitFor("forwarder issued first flow.readData", timeout: 1.0) {
            h.flow.pendingReadCount >= 1
        }
    }

    /// Buffered EOF (`acceptClientCarryover(nil)`) seen during
    /// `.buffering` makes the direction skip the read loop and
    /// emit a FIN via the egress write pump. `.finished` is set
    /// once the FIN's `send` completion fires (the harness's
    /// auto-completer fires it for us).
    func testBufferedEofSkipsReadLoopOnTransitionToActive() {
        let h = Harness("eof.early")
        h.forwarder.acceptClientCarryover(.none)  // EOF
        h.drain()

        h.forwarder.markRustC2SDone()
        h.drain()

        XCTAssertEqual(h.flow.pendingReadCount, 0,
            "EOF buffered during cutover MUST suppress the read loop")
        waitFor("direction reaches .finished after FIN drain", timeout: 2.0) {
            h.forwarder.c2sPhase == .finished
        }
    }

    // MARK: - Active phase — direct read loops

    /// In the `.active` phase the forwarder reads from the flow
    /// and enqueues bytes to the egress write pump, which forwards
    /// them to the connection. End-to-end byte fidelity.
    func testActiveC2SReadLoopForwardsBytesToConnection() {
        let h = Harness("active.c2s")
        h.forwarder.markRustC2SDone()
        h.drain()
        XCTAssertEqual(h.flow.pendingReadCount, 1)

        let payload = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        h.flow.completeRead(data: payload, error: nil)
        waitFor("connection received forwarded chunk", timeout: 1.0) {
            h.conn.sentChunks.contains(where: { $0.content == payload })
        }
        // Forwarder loops — next readData should already be in
        // flight.
        waitFor("forwarder issued next flow.readData", timeout: 1.0) {
            h.flow.pendingReadCount >= 1
        }
    }

    /// S→C symmetric: forwarder receives from NWConnection, sends
    /// to flow via clientWritePump.
    func testActiveS2CReceiveLoopForwardsBytesToFlow() {
        let h = Harness("active.s2c")
        h.forwarder.markRustS2CDone()
        h.drain()
        XCTAssertEqual(h.conn.pendingReceiveCount, 1)

        let payload = Data([0xAA, 0xBB, 0xCC])
        _ = h.conn.completePendingReceive(data: payload, isComplete: false, error: nil)
        waitFor("flow received forwarded chunk", timeout: 1.0) {
            h.flow.writes.contains(payload)
        }
        waitFor("forwarder issued next connection.receive", timeout: 1.0) {
            h.conn.pendingReceiveCount >= 1
        }
    }

    /// Every byte moved in either direction fires `onActivity`.
    /// Production routes that to `ctx.lastActivityAt` so the
    /// promoted-idle reaper only drops genuinely-quiet flows; here we
    /// just prove the hook fires for a C→S read and an S→C receive.
    func testByteMovementFiresOnActivity() {
        let h = Harness("activity.bump")
        h.forwarder.markRustC2SDone()
        h.forwarder.markRustS2CDone()
        h.drain()
        XCTAssertEqual(
            h.queue.sync { h.activityCount }, 0, "no activity before any bytes move")

        h.flow.completeRead(data: Data([0x01, 0x02]), error: nil)
        waitFor("C→S byte bumped activity", timeout: 1.0) {
            h.queue.sync { h.activityCount } >= 1
        }

        let afterC2S = h.queue.sync { h.activityCount }
        _ = h.conn.completePendingReceive(data: Data([0xAA]), isComplete: false, error: nil)
        waitFor("S→C byte bumped activity", timeout: 1.0) {
            h.queue.sync { h.activityCount } > afterC2S
        }
    }

    // MARK: - Finishing / terminal

    /// Kernel half-close (flow.readData returns nil) transitions
    /// the C→S direction to `.finished` and begins FIN-on-the-
    /// connection via the egress write pump.
    func testKernelEofFinishesC2SDirection() {
        let h = Harness("eof.kernel")
        h.forwarder.markRustC2SDone()
        h.drain()

        // Drive the first read to EOF.
        h.flow.completeRead(data: nil, error: nil)
        waitFor("c2s direction finished", timeout: 1.0) {
            h.forwarder.c2sPhase == .finished
        }
    }

    /// NWConnection EOF (isComplete=true) finishes the S→C
    /// direction. With clientWritePump.closeWhenDrained, the
    /// transition to `.finished` is paced by the pump's actual
    /// drain.
    func testConnectionCompleteFinishesS2CDirection() {
        let h = Harness("eof.conn")
        h.forwarder.markRustS2CDone()
        h.drain()

        _ = h.conn.completePendingReceive(data: nil, isComplete: true, error: nil)
        waitFor("s2c direction finished", timeout: 2.0) {
            h.forwarder.s2cPhase == .finished
        }
    }

    /// Both directions finished → onTerminal fires exactly once.
    func testBothDirectionsFinishedFiresTerminalOnce() {
        let h = Harness("both.finished")
        h.forwarder.markRustC2SDone()
        h.forwarder.markRustS2CDone()
        h.drain()

        h.flow.completeRead(data: nil, error: nil)
        _ = h.conn.completePendingReceive(data: nil, isComplete: true, error: nil)

        waitFor("terminal fired", timeout: 2.0) {
            h.queue.sync { h.terminalCount } > 0
        }
        // Hammer additional poll iterations to make sure no
        // duplicate fires happen.
        h.drain()
        XCTAssertEqual(h.terminalCount, 1,
            "onTerminal must fire exactly once across the both-directions-done window")
    }

    /// External `cancel()` short-circuits to terminal regardless
    /// of phase. `onTerminal` still fires exactly once.
    func testExternalCancelFiresTerminalImmediately() {
        let h = Harness("ext.cancel")
        h.forwarder.cancel()
        waitFor("terminal fired on cancel", timeout: 1.0) {
            h.queue.sync { h.terminalCount } > 0
        }
        XCTAssertEqual(h.terminalCount, 1)
        XCTAssertEqual(h.forwarder.c2sPhase, .finished)
        XCTAssertEqual(h.forwarder.s2cPhase, .finished)
    }

    /// Double cancel is a no-op on the second call.
    func testCancelIsIdempotent() {
        let h = Harness("ext.cancel.idem")
        h.forwarder.cancel()
        h.forwarder.cancel()
        h.drain()
        // Allow the async terminal hop to land.
        waitFor("terminal hop landed", timeout: 1.0) {
            h.queue.sync { h.terminalCount } > 0
        }
        XCTAssertEqual(h.terminalCount, 1)
    }

    /// `acceptClientCarryover` may fire AFTER the direction has
    /// transitioned to `.active` — the old read pump's
    /// `cancelForPromote` and the engine's `markRustC2SDone` race,
    /// and `markClientReadDrained` (the barrier that flips
    /// `c2sReadDrained = true`) only fires once the pump's
    /// onComplete reports it idle, which happens AFTER any
    /// final carryover payloads. The forwarder must enqueue the
    /// late chunk through the same path as the buffered ones so
    /// FIFO order is preserved relative to anything already
    /// flushed to the egress pump.
    ///
    /// `preDrained: false` mirrors that production order: the
    /// read-drained barrier has NOT yet fired when the late
    /// carryover lands.
    func testAcceptCarryoverAfterActiveIsEnqueuedInOrder() {
        let h = Harness("late.carryover", preDrained: false)
        let earlyChunk = Data([0x11, 0x22])
        let lateChunk = Data([0xFF, 0xFE])

        // Pre-active chunk: parked in `c2sBuffer` until transition.
        h.forwarder.acceptClientCarryover(earlyChunk)
        h.drain()
        XCTAssertEqual(h.conn.sentChunks.count, 0,
            "buffered carryover must not flush before `.active`")

        // Transition to `.active`: flushes `c2sBuffer` to the
        // egress pump.
        h.forwarder.markRustC2SDone()
        waitFor("early chunk dispatched", timeout: 2.0) {
            h.conn.sentChunks.contains { $0.content == earlyChunk }
        }

        // Late carryover (sink fires after `.active`): goes via
        // `writeC2SLocked` and must arrive at the connection
        // strictly after the early chunk.
        h.forwarder.acceptClientCarryover(lateChunk)
        waitFor("late chunk dispatched", timeout: 2.0) {
            h.conn.sentChunks.contains { $0.content == lateChunk }
        }

        let earlyIdx = h.conn.sentChunks.firstIndex { $0.content == earlyChunk }
        let lateIdx = h.conn.sentChunks.firstIndex { $0.content == lateChunk }
        XCTAssertNotNil(earlyIdx)
        XCTAssertNotNil(lateIdx)
        if let e = earlyIdx, let l = lateIdx {
            XCTAssertLessThan(e, l,
                "late carryover must land after the buffered carryover")
        }
    }

    // MARK: - Multi-chunk FIFO flush ordering

    /// Many carryover chunks in both directions must flush in
    /// strict FIFO order to the respective write pumps. Order
    /// matters: a service that called `into_passthrough` at a
    /// clean record boundary can still rely on byte-order being
    /// preserved across the cutover.
    func testCarryoverFlushPreservesFifoOrderManyChunks() {
        let h = Harness("multi.chunk.fifo")
        let chunks = (0..<8).map { idx -> Data in
            Data([UInt8(idx), 0xA0, 0xB0])
        }
        for c in chunks {
            h.forwarder.acceptClientCarryover(c)
        }
        h.drain()

        let stopCompleter = AtomicBool()
        DispatchQueue.global().async {
            while !stopCompleter.load() {
                _ = h.conn.completePendingSend(error: nil)
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        defer { stopCompleter.store(true) }

        h.forwarder.markRustC2SDone()
        waitFor("all chunks dispatched", timeout: 2.0) {
            h.conn.sentChunks.count >= chunks.count
        }

        for (idx, expected) in chunks.enumerated() {
            XCTAssertEqual(h.conn.sentChunks[idx].content, expected,
                "FIFO violation at idx \(idx)")
        }
    }

    /// Mixed carryover: data then EOF in the SAME direction. The
    /// data must flush, then the direction transitions straight
    /// to `.finished` without starting a read loop.
    func testCarryoverDataThenEofFlushesDataThenFinishes() {
        let h = Harness("data.then.eof")
        let chunk = Data([0x42, 0x43])
        h.forwarder.acceptClientCarryover(chunk)
        h.forwarder.acceptClientCarryover(.none)  // EOF
        h.drain()

        let stopCompleter = AtomicBool()
        DispatchQueue.global().async {
            while !stopCompleter.load() {
                _ = h.conn.completePendingSend(error: nil)
                Thread.sleep(forTimeInterval: 0.001)
            }
        }
        defer { stopCompleter.store(true) }

        h.forwarder.markRustC2SDone()
        waitFor("data chunk dispatched", timeout: 2.0) {
            h.conn.sentChunks.contains { $0.content == chunk }
        }
        waitFor("direction finished", timeout: 1.0) {
            h.forwarder.c2sPhase == .finished
        }
        XCTAssertEqual(h.flow.pendingReadCount, 0,
            "buffered EOF must suppress the read loop even with prior data")
    }

    /// Egress side: buffered EOF (`acceptEgressCarryover(.none)`)
    /// also fast-paths to `.finished`. Symmetric guarantee to
    /// `testBufferedEofSkipsReadLoopOnTransitionToActive`.
    func testEgressBufferedEofSkipsReceiveLoopOnTransitionToActive() {
        let h = Harness("egress.eof.early")
        h.forwarder.acceptEgressCarryover(.none)
        h.drain()

        h.forwarder.markRustS2CDone()

        // The pump's `closeWhenDrained` is paced by an async
        // completion; spin until the direction settles.
        waitFor("direction finished", timeout: 2.0) {
            h.forwarder.s2cPhase == .finished
        }
        XCTAssertEqual(h.conn.pendingReceiveCount, 0,
            "EOF buffered during cutover MUST suppress the receive loop")
    }

    // MARK: - Direction independence

    /// Kernel EOF closes C→S without affecting S→C. The forwarder
    /// keeps reading from the connection until that direction
    /// hits its own EOF.
    func testKernelEofDoesNotAffectS2CDirection() {
        let h = Harness("dir.independence.kernel")
        h.forwarder.markRustC2SDone()
        h.forwarder.markRustS2CDone()
        h.drain()

        // Kernel half-close.
        h.flow.completeRead(data: nil, error: nil)
        waitFor("c2s finished", timeout: 2.0) {
            h.forwarder.c2sPhase == .finished
        }

        // S→C is still active and reading from connection.
        XCTAssertEqual(h.forwarder.s2cPhase, .active)
        XCTAssertGreaterThan(h.conn.pendingReceiveCount, 0,
            "S→C must keep receiving after C→S EOF")
    }

    /// NWConnection EOF closes S→C without affecting C→S.
    func testConnectionEofDoesNotAffectC2SDirection() {
        let h = Harness("dir.independence.conn")
        h.forwarder.markRustC2SDone()
        h.forwarder.markRustS2CDone()
        h.drain()

        _ = h.conn.completePendingReceive(
            data: nil, isComplete: true, error: nil)
        waitFor("s2c finished", timeout: 2.0) {
            h.forwarder.s2cPhase == .finished
        }
        XCTAssertEqual(h.forwarder.c2sPhase, .active)
        XCTAssertGreaterThan(h.flow.pendingReadCount, 0)
    }

    // MARK: - External cancel under various phases

    /// External `cancel()` while a `flow.readData` is in flight
    /// must terminate cleanly. Late completions (kernel callback
    /// firing post-cancel) must not crash.
    func testExternalCancelDuringActiveWithInFlightReadIsClean() {
        let h = Harness("cancel.during.active")
        h.forwarder.markRustC2SDone()
        h.drain()
        XCTAssertEqual(h.flow.pendingReadCount, 1)

        h.forwarder.cancel()
        waitFor("terminal fired", timeout: 1.0) {
            h.queue.sync { h.terminalCount } > 0
        }
        XCTAssertEqual(h.terminalCount, 1)

        // Late kernel callback — must not crash, must not
        // cause additional terminal fires.
        h.flow.completeRead(data: Data([0xDE, 0xAD]), error: nil)
        h.drain()
        XCTAssertEqual(h.terminalCount, 1,
            "post-cancel late callback must not re-fire terminal")
    }

    /// External cancel while in `.finishing` (FIN already requested,
    /// pump still draining) terminates cleanly.
    func testExternalCancelDuringFinishingIsClean() {
        let h = Harness("cancel.during.finishing")
        h.forwarder.markRustS2CDone()
        h.drain()

        _ = h.conn.completePendingReceive(
            data: nil, isComplete: true, error: nil)
        // We are now in `.finishing` waiting for the
        // clientWritePump.closeWhenDrained completion to fire
        // → `.finished`. Cancel pre-empts.
        h.forwarder.cancel()
        waitFor("terminal fired", timeout: 1.0) {
            h.queue.sync { h.terminalCount } > 0
        }
        XCTAssertEqual(h.terminalCount, 1)
    }

    /// Cancel during `.buffering` with carryover already
    /// captured. Buffer must be dropped; terminal fires once.
    func testExternalCancelDuringBufferingWithCarryoverIsClean() {
        let h = Harness("cancel.during.buffering")
        h.forwarder.acceptClientCarryover(Data([0xCA, 0xFE]))
        h.forwarder.acceptEgressCarryover(Data([0xBE, 0xEF]))
        h.drain()

        h.forwarder.cancel()
        waitFor("terminal fired", timeout: 1.0) {
            h.queue.sync { h.terminalCount } > 0
        }
        XCTAssertEqual(h.terminalCount, 1)
        // Carryover should have been dropped, not flushed (we
        // cancelled before the Rust-done signals).
        XCTAssertEqual(h.conn.sentChunks.count, 0,
            "cancel during buffering must NOT flush carryover")
    }

    // MARK: - Write-pump `.closed` mid-loop

    /// If the egress write pump reports `.closed` mid-read-loop,
    /// the forwarder transitions C→S to `.finished` without
    /// trying to issue more reads.
    ///
    /// We force the pump to `.closed` by cancelling it directly
    /// (its `core.prepareCancel` flips the lifecycle). The
    /// forwarder's enqueue check picks this up at the next
    /// iteration.
    func testEgressWritePumpClosedTerminatesC2SDirection() {
        let h = Harness("egress.pump.closed")
        h.forwarder.markRustC2SDone()
        h.drain()
        XCTAssertEqual(h.flow.pendingReadCount, 1)

        // Cancel the egress pump out from under the forwarder.
        h.egressWritePump.cancel()
        h.drain()

        // Deliver bytes — the forwarder's enqueue will return
        // `.closed`, triggering C→S finish.
        h.flow.completeRead(data: Data([0x01, 0x02]), error: nil)
        waitFor("c2s finished after pump closed", timeout: 1.0) {
            h.forwarder.c2sPhase == .finished
        }
    }

    /// Symmetric: clientWritePump `.closed` during S→C loop.
    func testClientWritePumpClosedTerminatesS2CDirection() {
        let h = Harness("client.pump.closed")
        h.forwarder.markRustS2CDone()
        h.drain()
        XCTAssertEqual(h.conn.pendingReceiveCount, 1)

        h.clientWritePump.cancel()
        h.drain()

        _ = h.conn.completePendingReceive(
            data: Data([0xAA, 0xBB]),
            isComplete: false, error: nil)
        waitFor("s2c finished after pump closed", timeout: 1.0) {
            h.forwarder.s2cPhase == .finished
        }
    }

    // MARK: - Phased ordering: kernel EOF arrives during read

    /// Kernel error (NSError) closes C→S the same as EOF.
    /// Treating errors as "direction done" is the contract for
    /// the direct-forward path.
    func testKernelReadErrorFinishesC2SDirection() {
        let h = Harness("kernel.error")
        h.forwarder.markRustC2SDone()
        h.drain()

        let err = NSError(domain: "test.fwd", code: 7)
        h.flow.completeRead(data: nil, error: err)
        waitFor("c2s finished on error", timeout: 1.0) {
            h.forwarder.c2sPhase == .finished
        }
    }

    /// NWConnection receive error closes S→C the same as EOF.
    func testConnectionReceiveErrorFinishesS2CDirection() {
        let h = Harness("conn.error")
        h.forwarder.markRustS2CDone()
        h.drain()

        _ = h.conn.completePendingReceive(
            data: nil, isComplete: false,
            error: NWError.posix(.ECONNRESET))
        waitFor("s2c finished on error", timeout: 2.0) {
            h.forwarder.s2cPhase == .finished
        }
        guard case .posix(.ECONNRESET)? = h.flow.lastCloseWriteError as? NWError else {
            return XCTFail("connection reset error was not forwarded")
        }
    }

    func testCarryoverErrorFinishesS2CWithError() {
        let h = Harness("carryover.error")
        let error = NSError(domain: "test.carryover", code: 19)

        h.forwarder.acceptEgressCarryoverError(error)
        h.forwarder.acceptEgressCarryover(.none)
        h.forwarder.markRustS2CDone()

        waitFor("s2c finished with carryover error", timeout: 2.0) {
            h.forwarder.s2cPhase == .finished
        }
        let observed = h.flow.lastCloseWriteError as NSError?
        XCTAssertEqual(observed?.domain, error.domain)
        XCTAssertEqual(observed?.code, error.code)
    }

    // MARK: - Markers without data

    /// `acceptClientCarryover(.none)` followed by
    /// `markRustC2SDone` with NO data carryover means: kernel
    /// already half-closed during the cutover window. Direction
    /// goes straight to `.finished`.
    func testEofOnlyCarryoverFinishesDirectly() {
        let h = Harness("eof.only")
        h.forwarder.acceptClientCarryover(.none)
        h.drain()
        h.forwarder.markRustC2SDone()
        waitFor("c2s finished", timeout: 1.0) {
            h.forwarder.c2sPhase == .finished
        }
        XCTAssertEqual(h.flow.pendingReadCount, 0)
    }

    /// markRustC2SDone is idempotent: a second call has no
    /// effect.
    func testRustDoneIsIdempotent() {
        let h = Harness("rust.done.idem")
        h.forwarder.markRustC2SDone()
        h.drain()
        let firstPendingReadCount = h.flow.pendingReadCount

        h.forwarder.markRustC2SDone()
        h.drain()
        XCTAssertEqual(h.flow.pendingReadCount, firstPendingReadCount,
            "second markRustC2SDone must not issue an extra readData")
    }

    // MARK: - Hardening (audit findings #6, #7)

    /// Audit finding #6: `finishC2SLocked` must wait for the
    /// FIN-drain to ACTUALLY complete before setting
    /// `c2sPhase = .finished`. The pre-fix code transitioned
    /// synchronously which could cause the pump to drop
    /// before drain ran → FIN lost → NWConnection
    /// registration leaked.
    ///
    /// This test pins the contract: with the harness's
    /// auto-completer firing send completions, the
    /// transition to `.finished` happens AFTER the FIN's
    /// `connection.send` is recorded.
    func testFinishC2SWaitsForFinSendBeforeFinished() {
        let h = Harness("audit.fin.wait")
        h.forwarder.markRustC2SDone()
        h.drain()

        let preSendCount = h.conn.sentChunks.count

        // Trigger kernel EOF → finishC2SLocked.
        h.flow.completeRead(data: nil, error: nil)

        // .finished is reached only AFTER the FIN send
        // completion fires. Verify the FIN appears in
        // sentChunks before .finished is observed.
        waitFor("c2s reaches .finished", timeout: 2.0) {
            h.forwarder.c2sPhase == .finished
        }
        XCTAssertGreaterThan(h.conn.sentChunks.count, preSendCount,
            "FIN must have been queued (visible in sentChunks) by the time .finished landed")
        // The last sent chunk should be the FIN (empty
        // content + isComplete=true via finalMessage). The
        // auto-completer fires its completion.
    }

    /// Audit finding #6 fallback: if the egress write pump
    /// is deallocated before its drain runs, the
    /// `onDrainedCallback` must still fire (via `deinit`)
    /// so the forwarder's state machine doesn't stall. We
    /// simulate the pump dying by external `cancel()` —
    /// which fires the pending callback in the cancel path.
    func testFinishC2SDirectlyAfterPumpCancelFinishesViaCallback() {
        let h = Harness("audit.fin.cancel.path")
        h.forwarder.markRustC2SDone()
        h.drain()

        // Cancel the pump AFTER the forwarder is in .active
        // but BEFORE we drive kernel EOF. The next enqueue
        // returns .closed → finishC2SLocked is called →
        // closeWhenDrained on a cancelled pump fires the
        // callback synchronously via the isClosed fast-
        // path. c2sPhase reaches .finished.
        h.egressWritePump.cancel()
        h.drain()

        h.flow.completeRead(data: Data([0x01]), error: nil)
        waitFor("c2s reaches .finished via cancelled-pump path",
                timeout: 2.0) {
            h.forwarder.c2sPhase == .finished
        }
    }

    // MARK: - Active phase — write-pump backpressure (round-4 audit)

    /// Round-4 audit (codex finding): pre-fix, every `enqueue`
    /// site in the forwarder treated `.paused` the same as
    /// `.accepted` — silently dropping the bytes. The fix buffers
    /// the rejected chunk in `c2sBuffer` and replays it from the
    /// pump's drain edge (`onEgressPumpDrained`).
    ///
    /// We exercise this through the carryover-flush path because
    /// it's the only one where two enqueues land synchronously
    /// inside a single queue block (the forwarder's
    /// `flushC2SBufferLocked` `while` loop). That keeps the pump's
    /// `pendingBytes` accumulating: chunk 1 is accepted and bumps
    /// `pendingBytes` to its size; chunk 2 hits the cap before
    /// the pump's async dispatch can dequeue chunk 1.
    ///
    /// The fix is unified across every `enqueue` call site
    /// (`writeC2SLocked` is the single entry point), so coverage
    /// of one site suffices for the design.
    func testActiveC2SBufferedReplayUnderBackpressure() {
        let h = Harness("backpressure.c2s.carryover", autoCompleter: false)
        // Sized to exceed `writePumpMaxPendingBytes` (256 KiB
        // default). The first chunk passes via the "first chunk
        // always accepts" invariant; the second pushes
        // `pendingBytes + data.count` over the cap → `.paused`.
        let big = Data(repeating: 0xAB, count: 300 * 1024)
        let small = Data([0xCD, 0xEF])

        // Pre-cutover: both chunks land in `c2sBuffer`.
        h.forwarder.acceptClientCarryover(big)
        h.forwarder.acceptClientCarryover(small)
        // Transition: synchronous flush. enqueue(big) → accepted,
        // pendingBytes = 300 KiB. enqueue(small) → paused, set
        // pausedSignaled. Loop exits with c2sWritePaused = true
        // and `small` still at the head of `c2sBuffer`.
        h.forwarder.markRustC2SDone()
        // The pump's flush of `big` happens on an async block
        // queued AFTER our `drain()` barrier, so a `waitFor` is
        // the only way to observe the send. After it fires, run
        // a second `drain` to let the drain-edge → forwarder
        // re-enqueue path settle.
        waitFor("first chunk reached the wire", timeout: 1.0) {
            h.conn.sentChunks.contains(where: { $0.content == big })
        }
        h.drain()

        XCTAssertEqual(
            h.conn.pendingSendCount, 1,
            "exactly the first chunk should be in flight"
        )
        XCTAssertFalse(
            h.conn.sentChunks.contains(where: { $0.content == small }),
            "second chunk MUST be buffered, not dropped (pre-fix bug)"
        )

        // Complete the in-flight send. Pump's `flush` completion
        // callback fires `writing = false` then re-enters flush;
        // since `pending` is non-empty (we pushed `big` into
        // `pump.pending` via the async path before the test
        // observed the drain), the pump drains it. The drain edge
        // — triggered by `pausedSignaled` going false on a
        // pendingBytes drop — calls `forwarder.onEgressPumpDrained`,
        // which calls `flushC2SBufferLocked`, which retries `small`
        // (now accepted) and routes it to `conn.send`.
        _ = h.conn.completePendingSend(error: nil)
        waitFor("buffered chunk replayed after drain", timeout: 2.0) {
            h.conn.sentChunks.contains(where: { $0.content == small })
        }
        // Drain the second send so the pump's lifecycle wraps up.
        _ = h.conn.completePendingSend(error: nil)
        h.drain()
    }

    /// S→C mirror of `testActiveC2SBufferedReplayUnderBackpressure`: the
    /// client write pump (kernel-bound) rejects an over-cap chunk with
    /// `.paused`, the forwarder holds it, and the pump's drain edge replays
    /// it — none dropped. The audit flagged the entire S→C backpressure
    /// path (`flushS2CBufferLocked` paused-latch + `onClientPumpDrained`
    /// replay) as untested; only C→S was covered.
    func testActiveS2CBufferedReplayUnderBackpressure() {
        let h = Harness("backpressure.s2c.carryover", autoCompleter: false)
        // Hold the client (S→C) writes in flight so `pendingBytes` stays high
        // and the second chunk pauses.
        h.flow.captureWriteCompletions = true
        let big = Data(repeating: 0xAB, count: 300 * 1024)
        let small = Data([0xCD, 0xEF])

        // Pre-cutover: both chunks land in `s2cBuffer`.
        h.forwarder.acceptEgressCarryover(big)
        h.forwarder.acceptEgressCarryover(small)
        // Transition: enqueue(big) → accepted (first-chunk rule);
        // enqueue(small) → paused; loop exits with `small` held.
        h.forwarder.markRustS2CDone()

        waitFor("first chunk reached the kernel flow", timeout: 1.0) {
            h.flow.writes.contains(big)
        }
        h.drain()
        XCTAssertEqual(h.flow.pendingWriteCompletionCount, 1, "exactly the first chunk in flight")
        XCTAssertFalse(
            h.flow.writes.contains(small), "second chunk MUST be buffered, not dropped")

        // Complete the in-flight write → drain edge → onClientPumpDrained →
        // flushS2CBufferLocked replays `small`.
        _ = h.flow.completeNextWrite()
        waitFor("buffered chunk replayed after drain", timeout: 2.0) {
            h.flow.writes.contains(small)
        }
        _ = h.flow.completeNextWrite()
        h.drain()
    }

    // MARK: - PROBE: egress write-pump terminal while C→S paused

    /// PROBE (audit): the egress write pump can hit a TERMINAL state
    /// (`pumpCore(_:didTerminateWith:)`) — a non-transient
    /// `NWConnection.send` error, or transient backpressure that
    /// exceeds `writeRetryHardDeadlineMs` — while the forwarder's
    /// C→S direction is `.active` AND holding a chunk it could not
    /// enqueue (`c2sWritePaused == true`).
    ///
    /// In that state the forwarder is NOT issuing a `flow.readData`
    /// (the read loop is gated off while paused) and is waiting
    /// SOLELY on the pump's drain edge (`onEgressPumpDrained`) to
    /// replay the buffered chunk. But the pump's terminal path only
    /// (1) force-cancels the connection and (2) fires the pending
    /// `closeWhenDrained` callback — which is nil unless C→S already
    /// reached `.finishing`. It does NOT fire the drain edge and does
    /// NOT drive C→S to terminal. So C→S wedges in `.active` forever,
    /// `onTerminal` never fires, and the kernel flow + per-flow ctx
    /// leak in the registry.
    ///
    /// We set S→C up to finish cleanly so the ONLY thing blocking
    /// `onTerminal` is the wedged C→S direction.
    func testEgressWritePumpTerminalWhileC2SPausedWedgesForwarder() {
        let h = Harness("probe.egress.terminal.paused", autoCompleter: false)

        // ── C→S: drive into .active with a paused, buffered chunk. ──
        // `big` > writePumpMaxPendingBytes (256 KiB) so the FIRST
        // chunk is accepted (first-chunk-always-passes) and bumps
        // pendingBytes over the cap; `small` is then rejected `.paused`
        // and parked at the head of c2sBuffer with c2sWritePaused=true.
        let big = Data(repeating: 0xAB, count: 300 * 1024)
        let small = Data([0xCD, 0xEF])
        h.forwarder.acceptClientCarryover(big)
        h.forwarder.acceptClientCarryover(small)
        h.forwarder.markRustC2SDone()
        h.drain()
        waitFor("big chunk dispatched to connection", timeout: 1.0) {
            h.conn.pendingSendCount == 1
        }

        // ── S→C: drive cleanly to .finished so it can't be what
        //    blocks onTerminal. ──
        h.forwarder.markRustS2CDone()
        h.drain()
        _ = h.conn.completePendingReceive(data: nil, isComplete: true, error: nil)
        waitFor("s2c reaches .finished", timeout: 2.0) {
            h.forwarder.s2cPhase == .finished
        }

        // ── Kill the egress write pump via a NON-transient send error
        //    while big is in flight. This terminates the pump core
        //    (`didTerminateWith`) while C→S is paused. ──
        _ = h.conn.completePendingSend(error: NWError.posix(.ECONNREFUSED))
        h.drain()

        // The forwarder should recover: the dead egress means C→S can
        // make no further progress, so it MUST reach `.finished` and
        // (with S→C already finished) fire onTerminal so the flow is
        // released. Pre-fix this never happens → leak.
        waitFor("c2s recovers to .finished after egress pump death", timeout: 2.0) {
            h.forwarder.c2sPhase == .finished
        }
        XCTAssertEqual(
            h.queue.sync { h.terminalCount }, 1,
            "onTerminal must fire so the flow is released; a wedged C→S leaks the kernel flow + ctx"
        )
    }

    // MARK: - Drain backstop (promoted-mode wedge reaper)

    /// S→C drain wedge: the client (kernel) stopped reading, so the
    /// client write pump's in-flight `flow.write` completion never
    /// fires, `closeWhenDrained` never completes, and the direction
    /// would sit in `.finishing` forever — orphaning the per-flow
    /// graph in the registry. The per-direction backstop fires
    /// `onClosing` once at finishing-begin (production sets
    /// `ctx.terminalSignalled`) and `onDrainStall` after the deadline
    /// (production routes it to a full teardown). This is the promoted
    /// analogue of `TcpFlowSession.armTerminalDrainBackstop`.
    func testS2CDrainStallForcesBackstopWhenClientNotReading() {
        let h = Harness("s2c.wedge", drainStallDeadline: .milliseconds(30))
        // Client writes are captured but never completed → the drain
        // can never finish (peer not reading).
        h.flow.captureWriteCompletions = true

        h.forwarder.markRustS2CDone()
        waitFor("s2c receive issued", timeout: 1.0) { h.conn.pendingReceiveCount >= 1 }
        // One chunk → leaves an in-flight, never-completing client write.
        _ = h.conn.completePendingReceive(data: Data([1, 2, 3]), isComplete: false)
        waitFor("next s2c receive issued", timeout: 1.0) { h.conn.pendingReceiveCount >= 1 }
        // Server EOF → the direction enters `.finishing` and waits on a
        // drain that can never complete.
        _ = h.conn.completePendingReceive(data: nil, isComplete: true)

        waitFor("s2c wedged in .finishing", timeout: 1.0) {
            h.forwarder.s2cPhase == .finishing
        }
        XCTAssertEqual(
            h.queue.sync { h.closingCount }, 1,
            "onClosing fires once when the first direction begins finishing")
        waitFor("drain backstop fires onDrainStall", timeout: 1.0) {
            h.queue.sync { h.drainStallCount } == 1
        }
    }

    /// A direction that drains cleanly (reaches `.finished`) must never
    /// trip its backstop — the timer's same-direction `.finishing`
    /// re-check no-ops once the drain completed.
    func testNoDrainStallWhenS2CFinishesCleanly() {
        let h = Harness("s2c.clean", drainStallDeadline: .milliseconds(30))
        h.forwarder.markRustS2CDone()
        waitFor("s2c receive issued", timeout: 1.0) { h.conn.pendingReceiveCount >= 1 }
        // Server EOF with an empty buffer → drain completes immediately.
        _ = h.conn.completePendingReceive(data: nil, isComplete: true)

        waitFor("s2c reaches .finished", timeout: 1.0) {
            h.forwarder.s2cPhase == .finished
        }
        // Past the (now-cancelled) backstop window: it must not fire.
        Thread.sleep(forTimeInterval: 0.06)
        XCTAssertEqual(
            h.queue.sync { h.drainStallCount }, 0,
            "clean drain must not trip the backstop")
        XCTAssertEqual(
            h.queue.sync { h.closingCount }, 1,
            "onClosing still fires once at finishing-begin")
        XCTAssertFalse(h.queue.sync { h.drainPending })
    }

    /// Half-close hygiene: C→S finishes cleanly while S→C stays
    /// `.active` (e.g. client SHUT_WR mid-download). The C→S backstop
    /// must no-op (its direction reached `.finished`), the live S→C
    /// direction must be untouched, and the flow must NOT be torn down.
    func testHalfCloseLeavesActiveDirectionUntouched() {
        let h = Harness("halfclose", drainStallDeadline: .milliseconds(30))
        h.forwarder.markRustC2SDone()
        h.forwarder.markRustS2CDone()
        h.drain()

        waitFor("c2s readData issued", timeout: 1.0) { h.flow.pendingReadCount >= 1 }
        // C→S kernel half-close (EOF) → finishC2S; egress FIN drains via
        // the harness auto-completer.
        h.flow.completeRead(data: nil, error: nil)
        waitFor("c2s reaches .finished", timeout: 1.0) {
            h.forwarder.c2sPhase == .finished
        }

        Thread.sleep(forTimeInterval: 0.06)
        XCTAssertEqual(
            h.queue.sync { h.drainStallCount }, 0,
            "a cleanly-finished direction must not trip the backstop")
        XCTAssertEqual(h.forwarder.s2cPhase, .active, "live S→C direction untouched")
        XCTAssertEqual(
            h.queue.sync { h.terminalCount }, 0,
            "flow must not tear down while one direction is still active")
        XCTAssertFalse(h.queue.sync { h.drainPending })
    }

    // MARK: - Helpers

    private func waitFor(
        _ description: String, timeout: TimeInterval, predicate: @escaping () -> Bool
    ) {
        let exp = expectation(description: description)
        DispatchQueue.global().async {
            let deadline = Date(timeIntervalSinceNow: timeout)
            while Date() < deadline {
                if predicate() { exp.fulfill(); return }
                Thread.sleep(forTimeInterval: 0.005)
            }
            XCTFail("waitFor timed out: \(description)")
        }
        wait(for: [exp], timeout: timeout + 0.5)
    }

    /// Tiny atomic-bool helper for background-thread coordination
    /// in the send-completer test. Backed by NSLock; the access
    /// pattern is too rare to care about cache-line contention.
    private func atomicFlag() -> AtomicBool {
        AtomicBool()
    }
}

private final class AtomicBool {
    private let lock = NSLock()
    private var _v: Bool = false
    func load() -> Bool { lock.lock(); defer { lock.unlock() }; return _v }
    func store(_ x: Bool) { lock.lock(); _v = x; lock.unlock() }
}
