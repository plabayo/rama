import Foundation
import XCTest

@testable import RamaAppleNetworkExtension

/// Mock flow whose `write` and `readData` run through configurable
/// handlers so tests can stage any sequence of responses and
/// observe how the pumps react. Conforms to both write and read
/// surfaces so the same fixture drives both pump tests.
final class MockTcpFlow: TcpFlowWritable, TcpFlowReadable {
    private let lock = NSLock()
    private var _writes: [Data] = []
    private var _writeCount = 0
    /// Optional write handler. Default: succeed (nil error). Tests
    /// override to stage transient/non-transient errors.
    var handler: (_ writeIndex: Int, _ data: Data) -> Error? = { _, _ in nil }

    /// Pending readData completions. Tests call `completeRead(...)`
    /// to deliver data, an EOF, or an error to the next read.
    /// Callbacks queue up so a flurry of `requestRead` calls can be
    /// answered in order.
    var pendingReadCompletions: [@Sendable (Data?, Error?) -> Void] {
        lock.lock(); defer { lock.unlock() }
        return _pendingReads
    }
    private var _pendingReads: [@Sendable (Data?, Error?) -> Void] = []

    var writes: [Data] {
        lock.lock(); defer { lock.unlock() }
        return _writes
    }
    var writeCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _writeCount
    }

    func write(_ data: Data, withCompletionHandler: @escaping @Sendable (Error?) -> Void) {
        lock.lock()
        let idx = _writeCount
        _writes.append(data)
        _writeCount += 1
        lock.unlock()
        let error = handler(idx, data)
        // Apple's NEAppProxyTCPFlow calls the completion handler off
        // the calling thread. Mirror that so the writer pump's
        // re-entry into `queue.async` is exercised the same way it is
        // in production.
        DispatchQueue.global().async {
            withCompletionHandler(error)
        }
    }

    func readData(completionHandler: @escaping @Sendable (Data?, Error?) -> Void) {
        lock.lock()
        _pendingReads.append(completionHandler)
        lock.unlock()
    }

    /// Deliver a result to the oldest pending readData callback.
    /// Tests call this from their own thread to simulate a kernel
    /// callback firing.
    func completeRead(data: Data?, error: Error?) {
        lock.lock()
        guard !_pendingReads.isEmpty else {
            lock.unlock()
            return
        }
        let cb = _pendingReads.removeFirst()
        lock.unlock()
        DispatchQueue.global().async {
            cb(data, error)
        }
    }
}

private func transientENOBUFS() -> Error {
    NSError(domain: NSPOSIXErrorDomain, code: Int(ENOBUFS))
}

private func nonTransientError() -> Error {
    NSError(domain: NSPOSIXErrorDomain, code: Int(EPIPE))
}

private final class NSLock_Counter {
    private let lock = NSLock()
    private var _value = 0
    func increment() {
        lock.lock(); defer { lock.unlock() }
        _value += 1
    }
    var value: Int {
        lock.lock(); defer { lock.unlock() }
        return _value
    }
}

final class TcpClientWritePumpTests: XCTestCase {
    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.writer", qos: .utility)
    }

    /// Sustained transient errors must not pin the pump alive forever.
    /// `flow.write` returning `ENOBUFS` repeatedly is the production
    /// failure mode that wedged the runtime: each retry strongly
    /// captured `self` via `asyncAfter`, so without a wall-clock
    /// deadline the writer had no terminating condition.
    func testTransientRetryLoopHonoursDeadline() {
        let flow = MockTcpFlow()
        flow.handler = { _, _ in transientENOBUFS() }

        let terminalError = expectation(description: "onTerminalError fires")
        var observedError: Error?
        let pump = TcpClientWritePump(
            flow: flow,
            queue: makeQueue(),
            logger: { _ in },
            onTerminalError: { error in
                observedError = error
                terminalError.fulfill()
            },
            onDrained: {}
        )
        pump.markOpened()
        XCTAssertEqual(pump.enqueue(Data(repeating: 0xAB, count: 64)), .accepted)

        // Deadline is 5s + per-attempt delays. Pad generously.
        wait(for: [terminalError], timeout: 10.0)
        XCTAssertNotNil(observedError)
        XCTAssertGreaterThan(flow.writeCount, 1, "should have retried at least once before giving up")
    }

    /// `cancel()` must short-circuit any in-flight retry chain so the
    /// dispatcher's hard-error teardown is immediate, not deadline-
    /// bounded. Without an explicit cancel, the only termination
    /// condition is the flow finally returning a non-transient error
    /// or the deadline expiring — neither acceptable when the caller
    /// already knows the flow is dead.
    func testCancelStopsRetryImmediately() {
        let flow = MockTcpFlow()
        flow.handler = { _, _ in transientENOBUFS() }

        let pump = TcpClientWritePump(
            flow: flow,
            queue: makeQueue(),
            logger: { _ in },
            onTerminalError: { _ in
                XCTFail("onTerminalError should not fire after explicit cancel")
            },
            onDrained: {}
        )
        pump.markOpened()
        XCTAssertEqual(pump.enqueue(Data(repeating: 0xAB, count: 64)), .accepted)

        // Let one or two retries fire so the pump is mid-loop.
        Thread.sleep(forTimeInterval: 0.05)
        let beforeCancel = flow.writeCount
        XCTAssertGreaterThan(beforeCancel, 0)

        pump.cancel()

        // cancel() must immediately make further enqueues report .closed.
        XCTAssertEqual(pump.enqueue(Data([0x01])), .closed)

        // Wait long enough that any unbounded retry would have fired
        // many more times. Allow up to one in-flight write to land
        // because `cancel()` arrives async-on-queue while a write may
        // already be issued.
        Thread.sleep(forTimeInterval: 0.5)
        XCTAssertLessThanOrEqual(
            flow.writeCount, beforeCancel + 1,
            "cancel must short-circuit the retry loop; saw \(flow.writeCount) writes vs \(beforeCancel) before cancel"
        )
    }

    /// `enqueue()` is called from the Rust side on a Tokio worker
    /// thread, sometimes from many threads concurrently. None of those
    /// callers may block on the writer's serial dispatch queue — a
    /// stalled Swift queue must not stall the Tokio runtime. This
    /// pins the property by enqueueing concurrently from many threads
    /// and asserting wall-clock progress is not capped by the queue's
    /// in-progress work.
    func testEnqueueDoesNotBlockOnQueue() {
        let flow = MockTcpFlow()
        // Holds every write open for ~50ms; the *queue* is therefore
        // continuously busy. Without the lock-protected fast path,
        // every concurrent enqueue would serialise behind the queue.
        flow.handler = { _, _ in nil }
        let pump = TcpClientWritePump(
            flow: flow,
            queue: makeQueue(),
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {}
        )
        pump.markOpened()
        // Prime the pump with one chunk so the queue has continuous
        // in-flight work for the duration of the test.
        XCTAssertEqual(pump.enqueue(Data(repeating: 0x00, count: 64)), .accepted)

        let group = DispatchGroup()
        let durationsLock = NSLock()
        var durations: [TimeInterval] = []
        for _ in 0..<32 {
            DispatchQueue.global().async(group: group) {
                let start = Date()
                _ = pump.enqueue(Data(repeating: 0x01, count: 16))
                let elapsed = Date().timeIntervalSince(start)
                durationsLock.lock()
                durations.append(elapsed)
                durationsLock.unlock()
            }
        }
        let waitResult = group.wait(timeout: .now() + .seconds(2))
        XCTAssertEqual(waitResult, .success)
        let worst = durations.max() ?? 0
        // 100ms ceiling is generous — a healthy fast path returns
        // in microseconds; an accidentally re-introduced `queue.sync`
        // would push the worst case above several hundred ms because
        // the queue is continuously running 50ms write callbacks.
        XCTAssertLessThan(
            worst, 0.1,
            "worst enqueue() wall-clock was \(worst)s; expected fast lock-only path"
        )
    }

    /// A single oversized chunk (larger than the byte cap) must go
    /// through unconditionally — the bridge has no way to break a
    /// payload up, so a strict cap would deadlock the relay.
    func testFirstOversizedChunkIsAccepted() {
        let flow = MockTcpFlow()
        let pump = TcpClientWritePump(
            flow: flow,
            queue: makeQueue(),
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {}
        )
        pump.markOpened()
        let oversize = Data(repeating: 0xAA, count: writePumpMaxPendingBytes + 4096)
        XCTAssertEqual(pump.enqueue(oversize), .accepted)
        // After the oversize chunk is queued we should pause additions.
        let secondary = Data(repeating: 0xBB, count: 64)
        XCTAssertEqual(pump.enqueue(secondary), .paused)
    }

    /// `cancel()` racing with an in-progress `closeWhenDrained` must
    /// still resolve cleanly: the drain completion fires exactly
    /// once, and the cancel side observes the same closed state. A
    /// reordering bug here would either double-fire the completion
    /// (free-after-fire on the dispatcher side) or leave it pending
    /// forever (dispatcher's teardown chain never runs).
    func testCancelRacingCloseWhenDrainedResolvesOnce() {
        let flow = MockTcpFlow()
        // Stage one transient retry, then succeed — gives `cancel`
        // and `closeWhenDrained` a real timing window to interleave.
        flow.handler = { idx, _ in idx < 2 ? transientENOBUFS() : nil }
        let pump = TcpClientWritePump(
            flow: flow,
            queue: makeQueue(),
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {}
        )
        pump.markOpened()
        XCTAssertEqual(pump.enqueue(Data([0x01])), .accepted)

        let drained = expectation(description: "closeWhenDrained completion fires once")
        let drainFireCount = NSLock_Counter()
        pump.closeWhenDrained { _ in
            drainFireCount.increment()
            drained.fulfill()
        }
        // Race: cancel() shortly after closeWhenDrained, while the
        // first retry attempt is still mid-backoff.
        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(2)) {
            pump.cancel()
        }
        wait(for: [drained], timeout: 2.0)
        // Give any rogue late-fire 100ms to expose itself.
        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(
            drainFireCount.value, 1,
            "closeWhenDrained completion fired \(drainFireCount.value) times — should be exactly once"
        )
    }

    /// `markOpened` after `cancel` must be a no-op. Without the
    /// closed-flag check, a late `markOpened` would re-open the
    /// pump and start writing pending bytes against a flow the
    /// dispatcher already considers dead.
    func testMarkOpenedAfterCancelIsNoop() {
        let flow = MockTcpFlow()
        let pump = TcpClientWritePump(
            flow: flow,
            queue: makeQueue(),
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {}
        )
        // Enqueue BEFORE markOpened — chunk sits in pending.
        XCTAssertEqual(pump.enqueue(Data([0x01, 0x02, 0x03])), .accepted)
        pump.cancel()
        // Subsequent enqueue must report .closed.
        XCTAssertEqual(pump.enqueue(Data([0x04])), .closed)

        pump.markOpened()  // would have triggered flush before fix
        Thread.sleep(forTimeInterval: 0.1)
        XCTAssertEqual(
            flow.writeCount, 0,
            "no flow.write may fire after cancel even if markOpened is called late"
        )
    }

    /// `closeWhenDrained` must fire its completion exactly once after
    /// every queued chunk has been delivered, so the dispatcher's
    /// teardown chain (close write side, cancel egress, remove from
    /// session map) runs at the right point.
    func testCloseWhenDrainedFiresAfterPendingFlush() {
        let flow = MockTcpFlow()
        let pump = TcpClientWritePump(
            flow: flow,
            queue: makeQueue(),
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {}
        )
        pump.markOpened()
        XCTAssertEqual(pump.enqueue(Data([0x01, 0x02, 0x03])), .accepted)
        XCTAssertEqual(pump.enqueue(Data([0x04, 0x05])), .accepted)

        let drained = expectation(description: "closeWhenDrained fires")
        var sawOpened: Bool?
        pump.closeWhenDrained { wasOpened in
            sawOpened = wasOpened
            drained.fulfill()
        }
        wait(for: [drained], timeout: 2.0)
        XCTAssertEqual(sawOpened, true)
        XCTAssertEqual(flow.writes.count, 2)
        XCTAssertEqual(flow.writes[0], Data([0x01, 0x02, 0x03]))
        XCTAssertEqual(flow.writes[1], Data([0x04, 0x05]))
    }
}
