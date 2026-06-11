import Foundation
import Network
import XCTest

@testable import RamaAppleNetworkExtension

/// Drives the read pumps' `.paused` → `pendingData` replay-buffer →
/// `resume()` state machine, and the `.paused`-replay carryover hand-off,
/// with a SCRIPTED sink.
///
/// This is the gap the audit flagged: the real demo engine handler always
/// returns `.accepted`, so the load-bearing "Rust rejected the chunk with
/// `.paused`, hold it, replay the SAME bytes before the next read" logic —
/// whose failure is the "bad record MAC" hole-in-the-stream — was never
/// exercised in Swift. The `TcpClientBytesSink` / `NwEgressBytesSink` seams
/// let a test script the status sequence.
final class TcpReadPumpReplayTests: XCTestCase {

    /// Sink whose `onClientBytes` / `onEgressBytes` return a scripted
    /// status sequence (one per call; defaults to `.accepted` once
    /// exhausted) and records every chunk it was handed, in order.
    private final class ScriptedBytesSink:
        TcpClientBytesSink, NwEgressBytesSink, @unchecked Sendable
    {
        private let lock = NSLock()
        private var statuses: [RamaTcpDeliverStatusBridge]
        private var _received: [Data] = []
        private var _eofCount = 0

        init(_ statuses: [RamaTcpDeliverStatusBridge]) { self.statuses = statuses }

        private func next(_ data: Data) -> RamaTcpDeliverStatusBridge {
            lock.lock()
            defer { lock.unlock() }
            _received.append(data)
            return statuses.isEmpty ? .accepted : statuses.removeFirst()
        }
        func onClientBytes(_ data: Data) -> RamaTcpDeliverStatusBridge { next(data) }
        func onEgressBytes(_ data: Data) -> RamaTcpDeliverStatusBridge { next(data) }
        func onEgressEof() {
            lock.lock()
            _eofCount += 1
            lock.unlock()
        }

        var received: [Data] {
            lock.lock()
            defer { lock.unlock() }
            return _received
        }
        var eofCount: Int {
            lock.lock()
            defer { lock.unlock() }
            return _eofCount
        }
    }

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.replay", qos: .utility)
    }

    // MARK: - Client read pump (ingress) replay

    /// On a `.paused` from the session the pump holds the chunk and stops
    /// issuing reads; `resume()` replays the SAME bytes BEFORE issuing the
    /// next read. A regression that dropped/duplicated/reordered the held
    /// bytes — or failed to gate the next read behind `resume()` — fails here.
    func testClientReadPumpPausedHoldsThenResumeReplaysInOrder() {
        let sink = ScriptedBytesSink([.paused, .accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in }, onTerminal: { _ in })

        pump.requestRead()
        pollUntil("pump issued first readData") { !flow.pendingReadCompletions.isEmpty }

        let chunk = Data([0x01, 0x02, 0x03, 0x04])
        flow.completeRead(data: chunk, error: nil)

        // Session returned .paused → pump holds the chunk and does NOT read again.
        pollUntil("chunk delivered to sink") { sink.received.count == 1 }
        queue.sync {}
        XCTAssertEqual(sink.received, [chunk])
        XCTAssertTrue(
            flow.pendingReadCompletions.isEmpty,
            "a paused pump must NOT issue another readData until resume()")

        // resume() replays the held chunk first, then reads afresh.
        pump.resume()
        pollUntil("held chunk replayed on resume") { sink.received.count == 2 }
        XCTAssertEqual(
            sink.received, [chunk, chunk],
            "resume() must replay the exact held bytes before reading more")
        pollUntil("fresh readData issued after successful replay") {
            !flow.pendingReadCompletions.isEmpty
        }
    }

    /// A `.paused` AGAIN on the replay attempt re-holds the same bytes (no
    /// duplication, no loss, no extra read) until the next resume.
    func testClientReadPumpRepausedReplayDoesNotDuplicateOrRead() {
        let sink = ScriptedBytesSink([.paused, .paused, .accepted])
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in }, onTerminal: { _ in })

        pump.requestRead()
        pollUntil("first readData") { !flow.pendingReadCompletions.isEmpty }
        let chunk = Data([0xAA, 0xBB])
        flow.completeRead(data: chunk, error: nil)
        pollUntil("delivered once") { sink.received.count == 1 }

        pump.resume()  // replay → .paused again → re-hold
        pollUntil("replayed once (still paused)") { sink.received.count == 2 }
        queue.sync {}
        XCTAssertEqual(sink.received, [chunk, chunk])
        XCTAssertTrue(
            flow.pendingReadCompletions.isEmpty, "still paused → no fresh read")

        pump.resume()  // replay → .accepted → read afresh
        pollUntil("replayed again, now accepted") { sink.received.count == 3 }
        XCTAssertEqual(sink.received, [chunk, chunk, chunk], "same bytes, never dropped or doubled")
        pollUntil("fresh read after accept") { !flow.pendingReadCompletions.isEmpty }
    }

    // MARK: - Egress read pump replay

    /// Egress (NWConnection-receive) counterpart of the client-pump replay.
    func testEgressReadPumpPausedHoldsThenResumeReplaysInOrder() {
        let sink = ScriptedBytesSink([.paused, .accepted])
        let conn = MockNwConnection()
        conn.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionReadPump(
            connection: conn, session: sink, queue: queue, eofGraceDeadline: .seconds(60))

        pump.start()
        pollUntil("pump issued first receive") { conn.pendingReceiveCount == 1 }

        let chunk = Data([0x09, 0x08, 0x07])
        _ = conn.completePendingReceive(data: chunk, isComplete: false, error: nil)

        pollUntil("chunk delivered to sink") { sink.received.count == 1 }
        queue.sync {}
        XCTAssertEqual(sink.received, [chunk])
        XCTAssertEqual(
            conn.pendingReceiveCount, 0, "a paused egress pump must NOT issue another receive")

        pump.resume()
        pollUntil("held chunk replayed on resume") { sink.received.count == 2 }
        XCTAssertEqual(sink.received, [chunk, chunk], "replay the exact held bytes first")
        pollUntil("fresh receive after replay") { conn.pendingReceiveCount == 1 }
    }

    // MARK: - cancelForPromote hands the held replay buffer to carryover

    /// When a promote cutover hits a pump that is holding a `.paused` chunk,
    /// `cancelForPromote` MUST hand that chunk to `onCarryover` before the
    /// barrier fires — otherwise the buffered bytes are lost across the
    /// cutover (the gap the degenerate carryover test couldn't reach).
    func testClientReadPumpCancelForPromoteFlushesHeldReplayBuffer() {
        let sink = ScriptedBytesSink([.paused])  // first delivery pauses → held
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let pump = TcpClientReadPump(
            flow: flow, session: sink, queue: queue, logger: { _ in }, onTerminal: { _ in })

        pump.requestRead()
        pollUntil("first readData") { !flow.pendingReadCompletions.isEmpty }
        let held = Data([0x11, 0x22, 0x33])
        flow.completeRead(data: held, error: nil)
        pollUntil("chunk held as pendingData") { sink.received.count == 1 }
        queue.sync {}

        var carryover: [Data] = []
        var sawNoneSentinel = false
        let completeFired = expectation(description: "onComplete barrier fires")
        pump.cancelForPromote(
            onCarryover: { payload in
                if let d = payload { carryover.append(d) } else { sawNoneSentinel = true }
            },
            onComplete: { completeFired.fulfill() })
        wait(for: [completeFired], timeout: 2.0)
        queue.sync {}

        XCTAssertEqual(
            carryover, [held],
            "the held .paused replay buffer must be handed to carryover, intact and in order")
        XCTAssertFalse(sawNoneSentinel, "no EOF sentinel — the pump was paused, not at EOF")
    }

    /// Egress counterpart of the carryover-flush test.
    func testEgressReadPumpCancelForPromoteFlushesHeldReplayBuffer() {
        let sink = ScriptedBytesSink([.paused])
        let conn = MockNwConnection()
        conn.transition(to: .ready)
        let queue = makeQueue()
        let pump = NwTcpConnectionReadPump(
            connection: conn, session: sink, queue: queue, eofGraceDeadline: .seconds(60))

        pump.start()
        pollUntil("first receive") { conn.pendingReceiveCount == 1 }
        let held = Data([0x44, 0x55])
        _ = conn.completePendingReceive(data: held, isComplete: false, error: nil)
        pollUntil("chunk held as pendingData") { sink.received.count == 1 }
        queue.sync {}

        var carryover: [Data] = []
        let completeFired = expectation(description: "onComplete barrier fires")
        pump.cancelForPromote(
            onCarryover: { payload in if let d = payload { carryover.append(d) } },
            onComplete: { completeFired.fulfill() })
        wait(for: [completeFired], timeout: 2.0)
        queue.sync {}

        XCTAssertEqual(carryover, [held], "egress held replay buffer handed to carryover intact")
    }
}
