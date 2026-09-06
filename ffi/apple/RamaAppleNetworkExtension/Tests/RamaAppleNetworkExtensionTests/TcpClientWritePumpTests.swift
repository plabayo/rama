import Foundation
import Network
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// Mock flow whose `write` and `readData` run through configurable
/// handlers so tests can stage any sequence of responses and
/// observe how the pumps react. Conforms to `TcpFlowLike` so it can
/// drive both the read / write pump tests *and* the full
/// `TransparentProxyCore.handleTcpFlow` lifecycle tests — the
/// latter calls `open`, `closeReadWithError`, `closeWriteWithError`,
/// and `applyMetadata(to:)` in addition to the read / write surfaces.
final class MockTcpFlow: TcpFlowLike, @unchecked Sendable {
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
    var pendingReadCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _pendingReads.count
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

    /// If true, `write` captures the completion handler into
    /// `_pendingWriteCompletions` instead of firing it on a global
    /// queue. Tests can later drive completions synchronously via
    /// `completeNextWrite()` — necessary when ordering a write
    /// completion against other queue work (e.g. verifying cancel
    /// cleanup ran first) must be deterministic.
    var captureWriteCompletions: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _captureWriteCompletions }
        set { lock.lock(); defer { lock.unlock() }; _captureWriteCompletions = newValue }
    }
    private var _captureWriteCompletions: Bool = false
    private var _pendingWriteCompletions: [(@Sendable (Error?) -> Void, Error?)] = []

    var pendingWriteCompletionCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _pendingWriteCompletions.count
    }

    /// Fires the oldest captured write completion synchronously on
    /// the calling thread. Because the completion's `self.queue.async`
    /// is enqueued synchronously from here, any subsequent
    /// `queue.async` issued by the same caller (e.g. an invariant
    /// snapshot) is FIFO-ordered after the completion's block —
    /// removing the global-queue race.
    @discardableResult
    func completeNextWrite() -> Bool {
        lock.lock()
        guard !_pendingWriteCompletions.isEmpty else {
            lock.unlock()
            return false
        }
        let (cb, err) = _pendingWriteCompletions.removeFirst()
        lock.unlock()
        cb(err)
        return true
    }

    func write(_ data: Data, withCompletionHandler: @escaping @Sendable (Error?) -> Void) {
        lock.lock()
        let idx = _writeCount
        let recorded = data.withUnsafeBytes { bytes in
            guard !bytes.isEmpty else { return Data() }
            return Data(bytes: bytes.baseAddress!, count: bytes.count)
        }
        _writes.append(recorded)
        _writeCount += 1
        let capture = _captureWriteCompletions
        lock.unlock()
        let error = handler(idx, data)
        if capture {
            lock.lock()
            _pendingWriteCompletions.append((withCompletionHandler, error))
            lock.unlock()
        } else {
            // Apple's NEAppProxyTCPFlow calls the completion handler off
            // the calling thread. Mirror that so the writer pump's
            // re-entry into `queue.async` is exercised the same way it is
            // in production.
            DispatchQueue.global().async {
                withCompletionHandler(error)
            }
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

    /// Deliver a read result inline so a following `flowQueue.sync` is a
    /// deterministic barrier after the pump's callback hop. Use only when a
    /// test must prove the result was consumed before a later transition.
    func completeReadSynchronously(data: Data?, error: Error?) {
        lock.lock()
        guard !_pendingReads.isEmpty else {
            lock.unlock()
            return
        }
        let cb = _pendingReads.removeFirst()
        lock.unlock()
        cb(data, error)
    }

    // MARK: - TcpFlowLike — lifecycle surface

    private var _pendingOpenCompletion: (@Sendable (Error?) -> Void)?
    private var _closeReadErrors: [Error?] = []
    private var _closeWriteErrors: [Error?] = []
    private var _applyMetadataCount: Int = 0
    private var _openInvoked: Bool = false

    func open(
        withLocalEndpoint localEndpoint: NWHostEndpoint?,
        completionHandler: @escaping @Sendable (Error?) -> Void
    ) {
        lock.lock()
        _pendingOpenCompletion = completionHandler
        _openInvoked = true
        lock.unlock()
    }

    func closeReadWithError(_ error: Error?) {
        lock.lock()
        _closeReadErrors.append(error)
        lock.unlock()
    }

    func closeWriteWithError(_ error: Error?) {
        lock.lock()
        _closeWriteErrors.append(error)
        lock.unlock()
    }

    func applyMetadata(to params: NWParameters) {
        lock.lock()
        _applyMetadataCount += 1
        lock.unlock()
    }

    // MARK: - Driving the lifecycle surface (test side)

    /// Fire the `open` completion handler. Returns `false` when no
    /// `open` is pending — usually a test bug.
    @discardableResult
    func completeOpen(error: Error? = nil) -> Bool {
        lock.lock()
        guard let cb = _pendingOpenCompletion else {
            lock.unlock()
            return false
        }
        _pendingOpenCompletion = nil
        lock.unlock()
        cb(error)
        return true
    }

    var openWasInvoked: Bool {
        lock.lock(); defer { lock.unlock() }
        return _openInvoked
    }

    var closeReadCallCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _closeReadErrors.count
    }

    var closeWriteCallCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _closeWriteErrors.count
    }

    var applyMetadataCallCount: Int {
        lock.lock(); defer { lock.unlock() }
        return _applyMetadataCount
    }

    var lastCloseReadError: Error? {
        lock.lock(); defer { lock.unlock() }
        return _closeReadErrors.last ?? nil
    }

    var lastCloseWriteError: Error? {
        lock.lock(); defer { lock.unlock() }
        return _closeWriteErrors.last ?? nil
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
    private func makeNoCopyData(
        _ bytes: [UInt8]
    ) -> (data: Data, pointer: UnsafeMutableRawPointer, released: TestValue<Bool>) {
        // Avoid Foundation's inline representation: these tests need an
        // externally mutable backing allocation to catch an accidental copy.
        let byteCount = max(96, bytes.count)
        let pointer = UnsafeMutableRawPointer.allocate(
            byteCount: byteCount,
            alignment: MemoryLayout<UInt8>.alignment)
        pointer.initializeMemory(as: UInt8.self, repeating: 0, count: byteCount)
        bytes.withUnsafeBytes { source in
            pointer.copyMemory(from: source.baseAddress!, byteCount: bytes.count)
        }
        let released = TestValue(false)
        let data = Data(
            bytesNoCopy: pointer,
            count: byteCount,
            deallocator: .custom { pointer, _ in
                released.set(true)
                pointer.deallocate()
            })
        return (data, pointer, released)
    }

    private func makeQueue() -> DispatchQueue {
        DispatchQueue(label: "rama.tproxy.test.writer", qos: .utility)
    }

    func testAcceptedWritePublishesActivityBeforeItsQueueHop() {
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let gate = DispatchSemaphore(value: 0)
        queue.async { gate.wait() }
        let activity = NSLock_Counter()
        let pump = TcpClientWritePump(
            flow: flow,
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {},
            onActivity: {
                activity.increment()
                return true
            })

        XCTAssertEqual(pump.enqueue(Data([0x01])), .accepted)
        XCTAssertEqual(activity.value, 1, "acceptance publishes before queued delivery")
        XCTAssertEqual(flow.writeCount, 0, "the data path is still parked behind the queue gate")

        gate.signal()
    }

    func testSuccessfulWriteCompletionPublishesDrainProgress() {
        let flow = MockTcpFlow()
        flow.captureWriteCompletions = true
        let queue = makeQueue()
        let activity = NSLock_Counter()
        let pump = TcpClientWritePump(
            flow: flow,
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {},
            onActivity: {
                activity.increment()
                return true
            })
        pump.markOpened()

        XCTAssertEqual(pump.enqueue(Data([0x01])), .accepted)
        queue.sync {}
        XCTAssertEqual(activity.value, 1, "acceptance is the first progress edge")
        pump.closeWhenDrained { _ in }
        queue.sync {}
        XCTAssertTrue(flow.completeNextWrite())
        queue.sync {}
        XCTAssertEqual(
            activity.value, 2,
            "successful underlying completion refreshes the drain-progress clock")
    }

    /// Sustained transient errors must not pin the pump alive forever.
    /// `flow.write` returning `ENOBUFS` repeatedly is the production
    /// failure mode that wedged the runtime: each retry strongly
    /// captured `self` via `asyncAfter`, so without a wall-clock
    /// deadline the writer had no terminating condition.
    ///
    /// Clamp the hard deadline so the test completes deterministically
    /// in well under a second; the production default (5s) was the
    /// source of CI-killing flakes on loaded test runners.
    func testTransientRetryLoopHonoursDeadline() {
        let savedDeadline = writeRetryHardDeadlineMs
        writeRetryHardDeadlineMs = 200
        defer { writeRetryHardDeadlineMs = savedDeadline }

        let flow = MockTcpFlow()
        flow.handler = { _, _ in transientENOBUFS() }

        let terminalError = expectation(description: "onTerminalError fires")
        let observedError = TestValue<Error?>(nil)
        let pump = TcpClientWritePump(
            flow: flow,
            queue: makeQueue(),
            logger: { _ in },
            onTerminalError: { error in
                observedError.set(error)
                terminalError.fulfill()
            },
            onDrained: {}
        )
        pump.markOpened()
        XCTAssertEqual(pump.enqueue(Data(repeating: 0xAB, count: 64)), .accepted)

        // 200ms deadline + per-attempt delays + slack.
        wait(for: [terminalError], timeout: 2.0)
        XCTAssertNotNil(observedError.get())
        XCTAssertGreaterThan(flow.writeCount, 1, "should have retried at least once before giving up")
    }

    /// Once a transient error arms its delay, later accepted enqueues must only
    /// append behind the failed head. They must not retry it immediately or arm
    /// parallel timers. A generation also makes duplicate/stale scheduler
    /// callbacks harmless after the next delay or a successful drain.
    func testWriteCoreRetryDelayGatesEnqueuesAndInvalidatesStaleTimers() {
        let queue = makeQueue()
        let writes = TestValue<[UInt8]>([])
        let retryDelays = TestValue<[Int]>([])
        let scheduledRetries = TestValue<[@Sendable () -> Void]>([])

        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { data, completion in
                let attempt = writes.update { observed -> Int in
                    observed.append(data[0])
                    return observed.count
                }
                completion(attempt <= 2 ? transientENOBUFS() : nil)
            },
            logHwm: { _ in },
            inlineWriteCompletionWhenOnQueue: true,
            retryScheduler: { delayMs, work in
                retryDelays.update { $0.append(delayMs) }
                scheduledRetries.update { $0.append(work) }
            }
        )
        queue.sync { core.markOpen() }

        XCTAssertEqual(core.enqueue(Data([0xA0])), .accepted)
        queue.sync {}
        XCTAssertEqual(writes.get(), [0xA0])
        XCTAssertEqual(retryDelays.get(), [writeRetryInitialDelayMs])
        XCTAssertEqual(scheduledRetries.get().count, 1)
        XCTAssertTrue(queue.sync { core.testInvariantSnapshot().retryDelayPending })

        for byte in UInt8(0xB0)...UInt8(0xB3) {
            XCTAssertEqual(core.enqueue(Data([byte])), .accepted)
        }
        queue.sync {}
        XCTAssertEqual(
            writes.get(), [0xA0],
            "enqueues during the retry delay must not bypass its backoff"
        )
        XCTAssertEqual(
            scheduledRetries.get().count, 1,
            "one retry episode must have only one live scheduler callback"
        )

        // Closing while delayed must retain the failed head and the newly
        // accepted tail until the valid retry callback reopens the pump.
        queue.sync { core.beginDraining() }
        XCTAssertFalse(core.isClosed())

        guard let firstRetry = scheduledRetries.update({ callbacks in
            callbacks.isEmpty ? nil : callbacks.removeFirst()
        }) else {
            XCTFail("missing first retry callback")
            return
        }
        firstRetry()
        queue.sync {}
        XCTAssertEqual(writes.get(), [0xA0, 0xA0])
        let secondDelay = min(writeRetryInitialDelayMs * 2, writeRetryMaxDelayMs)
        XCTAssertEqual(
            retryDelays.get(),
            [writeRetryInitialDelayMs, secondDelay]
        )
        XCTAssertEqual(scheduledRetries.get().count, 1)

        // Replaying an already-consumed callback models a stale timer. Its
        // generation must no longer be allowed to flush or schedule work.
        firstRetry()
        queue.sync {}
        XCTAssertEqual(writes.get(), [0xA0, 0xA0])
        XCTAssertEqual(scheduledRetries.get().count, 1)

        guard let secondRetry = scheduledRetries.update({ callbacks in
            callbacks.isEmpty ? nil : callbacks.removeFirst()
        }) else {
            XCTFail("missing second retry callback")
            return
        }
        secondRetry()
        queue.sync {}

        XCTAssertEqual(
            writes.get(),
            [0xA0, 0xA0, 0xA0, 0xB0, 0xB1, 0xB2, 0xB3],
            "the valid retry must preserve FIFO and drain every accepted item"
        )
        XCTAssertTrue(
            core.isClosed(),
            "draining must finish after the retried queue succeeds"
        )
        XCTAssertEqual(core.state.withLock { $0.pendingBytes }, 0)
        XCTAssertEqual(core.state.withLock { $0.pendingItems }, 0)
        XCTAssertFalse(queue.sync { core.testInvariantSnapshot().retryDelayPending })
        XCTAssertTrue(scheduledRetries.get().isEmpty)

        // Success invalidates the just-consumed generation too.
        secondRetry()
        queue.sync {}
        XCTAssertEqual(writes.get().count, 7)
        XCTAssertTrue(scheduledRetries.get().isEmpty)
    }

    /// `cancel()` must short-circuit any in-flight retry chain so the
    /// dispatcher's hard-error teardown is immediate, not deadline-
    /// bounded. Without an explicit cancel, the only termination
    /// condition is the flow finally returning a non-transient error
    /// or the deadline expiring — neither acceptable when the caller
    /// already knows the flow is dead.
    func testCancelStopsRetryImmediately() {
        let flow = MockTcpFlow()

        // Use an expectation to wait deterministically for at least
        // one write to fire before we issue cancel(). The previous
        // `Thread.sleep(0.05)` raced a starved dispatch queue on
        // loaded CI runners — wake-up could land before any write
        // had executed, leaving `beforeCancel = 0` and the cancel-
        // vs-retry contract effectively unverifiable (the post-cancel
        // bound `beforeCancel + 1 = 1` then trips on whatever the
        // queue eventually drains).
        let firstWriteFired = expectation(description: "first write fires")
        // The retry loop fires many writes; we only need to observe
        // the first one to know the pump is "mid-loop".
        firstWriteFired.assertForOverFulfill = false
        flow.handler = { _, _ in
            firstWriteFired.fulfill()
            return transientENOBUFS()
        }

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

        // Block until the pump is actually mid-loop. Generous timeout
        // tolerates worst-case dispatch latency on loaded CI without
        // crossing into "test is silently broken" territory.
        wait(for: [firstWriteFired], timeout: 2.0)
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

    /// Pin the post-cancel state-hygiene invariant:
    ///   `closed ⇒ pending empty ∧ retrying nil ∧ pendingBytes 0`
    /// must hold even when a write completion lands AFTER cancel's
    /// cleanup block ran.
    ///
    /// The race: `flush()` issued `doWrite(chunk, completion)` while
    /// open; before the completion fires, `cancel()` sets `closed=true`
    /// (synchronous) and enqueues cleanup (`pending.removeAll`,
    /// `retrying=nil`). The cleanup runs first because it was queued
    /// before the completion's `self.queue.async`. Then the completion
    /// fires. Without an `isClosed()` guard at the top of the
    /// completion's queue block, the transient-error branch silently
    /// revives `pending`, `pendingBytes`, and `retrying` — no extra
    /// write fires (the next flush bails on `isClosed`), but the
    /// invariant is quietly violated.
    ///
    /// Drives the completion synchronously from the test thread via
    /// `MockTcpFlow.completeNextWrite()` so the completion's queue
    /// block is FIFO-ordered before the snapshot block; this removes
    /// the global-queue race that would otherwise make the test
    /// flaky in either direction.
    func testCancelPreservesInvariantsAfterInFlightCompletion() {
        let flow = MockTcpFlow()
        flow.captureWriteCompletions = true
        let firstWriteFired = expectation(description: "first write fires")
        flow.handler = { _, _ in
            firstWriteFired.fulfill()
            return transientENOBUFS()
        }

        let pump = TcpClientWritePump(
            flow: flow,
            queue: makeQueue(),
            logger: { _ in },
            onTerminalError: { _ in
                XCTFail("onTerminalError must not fire after explicit cancel")
            },
            onDrained: {}
        )
        pump.markOpened()
        XCTAssertEqual(pump.enqueue(Data(repeating: 0xAB, count: 64)), .accepted)

        // The handler fulfills the expectation INSIDE `flow.write`,
        // just before `MockTcpFlow` captures the completion under
        // its lock. Spin briefly for the capture to land — bounded
        // and short; in practice the gap is microseconds.
        wait(for: [firstWriteFired], timeout: 2.0)
        let captureDeadline = Date().addingTimeInterval(1.0)
        while flow.pendingWriteCompletionCount == 0 {
            if Date() > captureDeadline {
                XCTFail("captured write did not land within 1s")
                return
            }
            Thread.sleep(forTimeInterval: 0.002)
        }
        XCTAssertEqual(flow.pendingWriteCompletionCount, 1)

        // Cancel BEFORE the completion is released — this is the race
        // window. `closed=true` is published synchronously here;
        // cleanup is queued on the core queue.
        pump.cancel()
        XCTAssertEqual(pump.enqueue(Data([0x01])), .closed)

        // Release the captured completion synchronously on the test
        // thread. The pump's `[weak self] error in self.queue.async {…}`
        // closure runs inline, enqueuing the completion's block onto
        // the core queue immediately after the cancel cleanup block.
        XCTAssertTrue(flow.completeNextWrite())

        // Snapshot the invariant. The block runs on the core queue,
        // FIFO-ordered strictly after the cleanup and the completion
        // blocks — so it observes the post-completion steady state.
        let snapshotFired = expectation(description: "invariant snapshot")
        let observed = TestValue((pendingEmpty: false, retryingNil: false, pendingBytes: -1))
        pump.testCoreInvariantSnapshot { pendingEmpty, retryingNil, pendingBytes in
            observed.set((pendingEmpty, retryingNil, pendingBytes))
            snapshotFired.fulfill()
        }
        wait(for: [snapshotFired], timeout: 2.0)

        XCTAssertTrue(observed.get().pendingEmpty, "pending must be empty after cancel + completion")
        XCTAssertTrue(observed.get().retryingNil, "retrying must be nil after cancel + completion")
        XCTAssertEqual(observed.get().pendingBytes, 0, "pendingBytes must be 0 after cancel + completion")
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
        let queue = makeQueue()
        let queueBlocked = expectation(description: "writer queue blocked")
        let releaseQueue = DispatchSemaphore(value: 0)
        queue.async {
            queueBlocked.fulfill()
            releaseQueue.wait()
        }
        wait(for: [queueBlocked], timeout: 2.0)

        let pump = TcpClientWritePump(
            flow: flow,
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {}
        )
        pump.markOpened()

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
        releaseQueue.signal()
        XCTAssertEqual(waitResult, .success)
        let worst = durations.max() ?? 0
        // A healthy fast path returns in microseconds; queue.sync would
        // remain blocked until releaseQueue is signalled above.
        XCTAssertLessThan(
            worst, 0.1,
            "worst enqueue() wall-clock was \(worst)s; expected fast lock-only path"
        )
    }

    /// Every producer slices before enqueueing, so even an empty pump must
    /// reject an oversized chunk without retaining or charging it. This keeps
    /// the configured byte cap authoritative rather than a soft first-item
    /// threshold.
    func testFirstOversizedChunkIsPausedWithoutExceedingBudget() {
        let queue = makeQueue()
        let releaseQueue = DispatchSemaphore(value: 0)
        queue.async { releaseQueue.wait() }
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { _, _ in XCTFail("blocked queue must not write") },
            logHwm: { _ in }
        )
        let oversize = Data(repeating: 0xAA, count: writePumpMaxPendingBytes + 4096)
        XCTAssertEqual(core.enqueue(oversize), .paused)
        XCTAssertEqual(core.state.withLock { $0.pendingBytes }, 0)
        XCTAssertEqual(core.state.withLock { $0.pendingItems }, 0)

        // A legitimate at-cap chunk remains admissible, proving the rejected
        // call did not poison the queue or consume either admission budget.
        let atCap = Data(repeating: 0xBB, count: writePumpMaxPendingBytes)
        XCTAssertEqual(core.enqueue(atCap), .accepted)
        XCTAssertEqual(
            core.state.withLock { $0.pendingBytes },
            writePumpMaxPendingBytes
        )
        XCTAssertEqual(core.state.withLock { $0.pendingItems }, 1)

        let cleanup = core.prepareCancel()
        queue.async(execute: cleanup)
        releaseQueue.signal()
        queue.sync {}
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

    func testOpenCompletionLeavesCallerLifecycleScope() {
        let queue = makeQueue()
        let pump = TcpClientWritePump(
            flow: MockTcpFlow(),
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {}
        )
        let insideCaller = TestValue(false)
        let completed = expectation(description: "open completes outside caller's lifecycle lease")
        queue.async {
            insideCaller.set(true)
            pump.markOpened {
                XCTAssertFalse(insideCaller.get(), "nested lifecycle leases can deadlock detach")
                completed.fulfill()
            }
            insideCaller.set(false)
        }
        wait(for: [completed], timeout: 1)
    }

    /// A service may enqueue its complete response and close its output while
    /// the claimed kernel flow is still opening. The close must wait for open,
    /// preserve the queued response, and complete immediately after its write.
    func testCloseBeforeOpenDrainsAfterSuccessfulOpen() {
        let flow = MockTcpFlow()
        flow.captureWriteCompletions = true
        let queue = makeQueue()
        let pump = TcpClientWritePump(
            flow: flow,
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in
                XCTFail("a successful write must not terminate the pump")
            },
            onDrained: {}
        )

        let response = Data([0x48, 0x69])
        XCTAssertEqual(pump.enqueue(response), .accepted)
        queue.sync {}

        let drained = expectation(description: "pre-open close drains")
        let drainCount = NSLock_Counter()
        let sawOpened = TestValue<Bool?>(nil)
        pump.closeWhenDrained { wasOpened in
            drainCount.increment()
            sawOpened.set(wasOpened)
            drained.fulfill()
        }
        queue.sync {}

        XCTAssertEqual(flow.writeCount, 0, "must not write before flow.open")
        XCTAssertEqual(drainCount.value, 0, "must not close cleanly before flow.open")

        pump.markOpened()
        queue.sync {}
        XCTAssertEqual(flow.writes, [response])
        XCTAssertEqual(flow.pendingWriteCompletionCount, 1)
        XCTAssertEqual(drainCount.value, 0, "close waits for the in-flight write")

        XCTAssertTrue(flow.completeNextWrite())
        queue.sync {}
        wait(for: [drained], timeout: 1.0)

        XCTAssertEqual(drainCount.value, 1)
        XCTAssertEqual(sawOpened.get(), true)
        XCTAssertEqual(pump.enqueue(Data([0x21])), .closed)
    }

    func testCloseBeforeOpenCancelCompletesAsUnopenedOnce() {
        let flow = MockTcpFlow()
        let queue = makeQueue()
        let pump = TcpClientWritePump(
            flow: flow,
            queue: queue,
            logger: { _ in },
            onTerminalError: { _ in },
            onDrained: {}
        )

        let drained = expectation(description: "pre-open cancel resolves drain")
        let drainCount = NSLock_Counter()
        let sawOpened = TestValue<Bool?>(nil)
        pump.closeWhenDrained { wasOpened in
            drainCount.increment()
            sawOpened.set(wasOpened)
            drained.fulfill()
        }
        queue.sync {}
        XCTAssertEqual(drainCount.value, 0)

        pump.cancel()
        wait(for: [drained], timeout: 1.0)
        XCTAssertEqual(drainCount.value, 1)
        XCTAssertEqual(sawOpened.get(), false)

        pump.markOpened()
        queue.sync {}
        XCTAssertEqual(drainCount.value, 1)
        XCTAssertEqual(flow.writeCount, 0)
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
        let sawOpened = TestValue<Bool?>(nil)
        pump.closeWhenDrained { wasOpened in
            sawOpened.set(wasOpened)
            drained.fulfill()
        }
        wait(for: [drained], timeout: 2.0)
        XCTAssertEqual(sawOpened.get(), true)
        XCTAssertEqual(flow.writes.count, 2)
        XCTAssertEqual(flow.writes[0], Data([0x01, 0x02, 0x03]))
        XCTAssertEqual(flow.writes[1], Data([0x04, 0x05]))
    }

    func testWriteCoreChargesInFlightBytesAndItemsUntilCompletion() {
        let queue = makeQueue()
        let writeCompletion = TestValue<(@Sendable (Error?) -> Void)?>(nil)
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { _, completion in writeCompletion.set(completion) },
            logHwm: { _ in }
        )
        queue.sync { core.markOpen() }

        let first = Data(repeating: 0xA1, count: writePumpMaxPendingBytes - 1)
        XCTAssertEqual(core.enqueue(first), .accepted)
        queue.sync {}
        XCTAssertEqual(core.state.withLock { $0.pendingBytes }, first.count)
        XCTAssertEqual(core.state.withLock { $0.pendingItems }, 1)
        XCTAssertEqual(
            core.enqueue(Data([0xB1, 0xB2])),
            .paused,
            "an in-flight write must continue consuming the byte budget"
        )

        writeCompletion.get()?(nil)
        queue.sync {}
        XCTAssertEqual(core.state.withLock { $0.pendingBytes }, 0)
        XCTAssertEqual(core.state.withLock { $0.pendingItems }, 0)
    }

    func testWriteCoreRejectedActivityRollsBackBothCharges() {
        let queue = makeQueue()
        let writeCount = NSLock_Counter()
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { _, _ in writeCount.increment() },
            logHwm: { _ in },
            onActivity: { false }
        )

        XCTAssertEqual(core.enqueue(Data([0xA1])), .closed)
        queue.sync {}
        let accounting = core.state.withLock {
            (pendingBytes: $0.pendingBytes, pendingItems: $0.pendingItems)
        }
        XCTAssertEqual(accounting.pendingBytes, 0)
        XCTAssertEqual(accounting.pendingItems, 0)
        XCTAssertEqual(writeCount.value, 0)
    }

    func testWriteCoreBoundsTinyDispatchBacklogAndDrainsInFifoOrder() {
        let queue = makeQueue()
        let queueEntered = expectation(description: "writer queue blocked")
        let releaseQueue = DispatchSemaphore(value: 0)
        queue.async {
            queueEntered.fulfill()
            releaseQueue.wait()
        }
        wait(for: [queueEntered], timeout: 1.0)

        let writes = TestValue<[UInt8]>([])
        let completions = TestValue<[@Sendable (Error?) -> Void]>([])
        let drainCount = NSLock_Counter()
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: { drainCount.increment() },
            doWrite: { data, completion in
                writes.update { $0.append(data[0]) }
                completions.update { $0.append(completion) }
            },
            logHwm: { _ in }
        )

        var accepted = 0
        var paused = 0
        for index in 0..<10_000 {
            switch core.enqueue(Data([UInt8(truncatingIfNeeded: index)])) {
            case .accepted: accepted += 1
            case .paused: paused += 1
            case .closed: XCTFail("open pump unexpectedly closed")
            }
        }

        XCTAssertEqual(accepted, tcpWritePumpMaxPendingItems)
        XCTAssertEqual(paused, 10_000 - tcpWritePumpMaxPendingItems)
        let saturated = core.state.withLock {
            (pendingBytes: $0.pendingBytes, pendingItems: $0.pendingItems)
        }
        XCTAssertEqual(saturated.pendingBytes, tcpWritePumpMaxPendingItems)
        XCTAssertEqual(saturated.pendingItems, tcpWritePumpMaxPendingItems)
        XCTAssertEqual(drainCount.value, 0)

        releaseQueue.signal()
        queue.sync {}
        queue.sync { core.beginDraining() }
        XCTAssertFalse(core.isClosed(), "queued items must keep a draining pump open")

        for index in 0..<tcpWritePumpMaxPendingItems {
            let completion = completions.update { callbacks -> (@Sendable (Error?) -> Void)? in
                callbacks.isEmpty ? nil : callbacks.removeFirst()
            }
            guard let completion else {
                XCTFail("missing completion for accepted item \(index)")
                return
            }
            completion(nil)
            queue.sync {}
            if index == 0 {
                let afterFirst = core.state.withLock {
                    (pendingBytes: $0.pendingBytes, pendingItems: $0.pendingItems)
                }
                XCTAssertEqual(afterFirst.pendingBytes, tcpWritePumpMaxPendingItems - 1)
                XCTAssertEqual(afterFirst.pendingItems, tcpWritePumpMaxPendingItems - 1)
                XCTAssertEqual(drainCount.value, 1, "one freed item must emit one drain edge")
            }
        }

        XCTAssertEqual(
            writes.get(),
            (0..<tcpWritePumpMaxPendingItems).map { UInt8($0) },
            "accepted tiny writes must retain FIFO order"
        )
        let drained = core.state.withLock {
            (pendingBytes: $0.pendingBytes, pendingItems: $0.pendingItems)
        }
        XCTAssertEqual(drained.pendingBytes, 0)
        XCTAssertEqual(drained.pendingItems, 0)
        XCTAssertEqual(drainCount.value, 1, "one pause episode must emit exactly one drain edge")
        XCTAssertTrue(core.isClosed(), "drain-close must finish after both charges reach zero")
    }

    func testWriteCoreCancelClearsItemChargeBeforeLateCompletion() {
        let queue = makeQueue()
        let writeCompletion = TestValue<(@Sendable (Error?) -> Void)?>(nil)
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { _, completion in writeCompletion.set(completion) },
            logHwm: { _ in }
        )

        XCTAssertEqual(core.enqueue(Data([0xA1])), .accepted)
        queue.sync {}
        XCTAssertEqual(core.state.withLock { $0.pendingItems }, 1)

        let cleanup = core.prepareCancel()
        queue.async(execute: cleanup)
        writeCompletion.get()?(nil)
        queue.sync {}

        let snapshot = queue.sync { core.testInvariantSnapshot() }
        XCTAssertTrue(snapshot.pendingEmpty)
        XCTAssertTrue(snapshot.retryingNil)
        XCTAssertFalse(snapshot.retryDelayPending)
        XCTAssertEqual(snapshot.pendingBytes, 0)
        XCTAssertEqual(snapshot.pendingItems, 0)
    }

    func testWriteCoreLogsOnlyFirstHighWaterThresholdCrossing() {
        let queue = makeQueue()
        let queueEntered = expectation(description: "writer queue blocked")
        let releaseQueue = DispatchSemaphore(value: 0)
        queue.async {
            queueEntered.fulfill()
            releaseQueue.wait()
        }
        wait(for: [queueEntered], timeout: 1.0)

        let logCount = NSLock_Counter()
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { _, _ in XCTFail("blocked queue must not write") },
            logHwm: { _ in logCount.increment() }
        )
        XCTAssertEqual(
            core.enqueue(Data(repeating: 0x01, count: writePumpHwmLogThresholdBytes)),
            .accepted
        )
        for _ in 0..<64 {
            XCTAssertEqual(core.enqueue(Data([0x02])), .accepted)
        }
        XCTAssertEqual(logCount.value, 1)

        let cleanup = core.prepareCancel()
        queue.async(execute: cleanup)
        releaseQueue.signal()
        queue.sync {}
    }

    func testWriteRetryRetainsNoCopyRootAndObservesSameBacking() {
        let queue = makeQueue()
        let budget = WriterMemoryBudget(
            policy: WriterMemoryPolicy(
                maxBytes: 256, maxItems: 8, tcpWaiterMaxBytes: 128,
                udpPressureReserveBytes: 0, udpPressureReserveItems: 0))
        let writes = TestValue<[UInt8]>([])
        let completions = TestValue<[@Sendable (Error?) -> Void]>([])
        let retries = TestValue<[@Sendable () -> Void]>([])
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { data, completion in
                writes.update { $0.append(data.first!) }
                completions.update { $0.append(completion) }
            },
            logHwm: { _ in },
            retryScheduler: { _, work in retries.update { $0.append(work) } },
            writerMemoryBudget: budget,
            writePolicy: TcpWritePumpPolicy(maxPendingBytes: 128))

        var source = makeNoCopyData([0x11, 0x22, 0x33, 0x44])
        var data: Data? = source.data
        XCTAssertEqual(core.enqueue(data!), .accepted)
        data = nil
        source.data = Data()
        queue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 96)
        XCTAssertFalse(source.released.get())

        var first = completions.update { $0.removeFirst() }
        first(transientENOBUFS())
        first = { _ in }
        queue.sync {}
        XCTAssertEqual(retries.get().count, 1)
        XCTAssertEqual(budget.snapshot().retainedBytes, 96)

        source.pointer.storeBytes(of: UInt8(0xA5), as: UInt8.self)
        var retry = retries.update { $0.removeFirst() }
        retry()
        retry = {}
        queue.sync {}
        XCTAssertEqual(writes.get(), [0x11, 0xA5], "retry must view the same backing allocation")

        var second = completions.update { $0.removeFirst() }
        second(nil)
        second = { _ in }
        queue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        withExtendedLifetime(core) {}
    }

    func testWriteCancelKeepsNoCopyRootUntilInflightCompletion() {
        let queue = makeQueue()
        let budget = WriterMemoryBudget()
        let completion = TestValue<(@Sendable (Error?) -> Void)?>(nil)
        let inFlight = TestValue<Data?>(nil)
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { data, callback in
                inFlight.set(data)
                completion.set(callback)
            },
            logHwm: { _ in },
            writerMemoryBudget: budget)

        var source = makeNoCopyData([0x41, 0x42])
        var data: Data? = source.data
        XCTAssertEqual(core.enqueue(data!), .accepted)
        data = nil
        source.data = Data()
        queue.sync {}
        let cleanup = core.prepareCancel()
        queue.sync(execute: cleanup)
        XCTAssertEqual(budget.snapshot().retainedBytes, 96)
        XCTAssertFalse(source.released.get(), "cancel cannot refund an in-flight transport owner")
        source.pointer.storeBytes(of: UInt8(0xA4), as: UInt8.self)
        XCTAssertEqual(inFlight.get()?.first, 0xA4)
        inFlight.set(nil)

        var callback = completion.update { value -> (@Sendable (Error?) -> Void)? in
            let result = value
            value = nil
            return result
        }
        callback?(nil)
        callback = nil
        queue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        withExtendedLifetime(core) {}
    }

    func testWriterDetachKeepsNoCopyRootUntilInflightCompletion() {
        let queue = makeQueue()
        let budget = WriterMemoryBudget()
        let completion = TestValue<(@Sendable (Error?) -> Void)?>(nil)
        let inFlight = TestValue<Data?>(nil)
        let core = TcpWritePumpCore(
            queue: queue,
            onDrained: {},
            doWrite: { data, callback in
                inFlight.set(data)
                completion.set(callback)
            },
            logHwm: { _ in },
            writerMemoryBudget: budget)

        var source = makeNoCopyData([0x51, 0x52, 0x53])
        var data: Data? = source.data
        XCTAssertEqual(core.enqueue(data!), .accepted)
        data = nil
        source.data = Data()
        queue.sync {}
        core.retireAdmission()
        XCTAssertEqual(budget.snapshot().retainedBytes, 96)
        XCTAssertFalse(source.released.get(), "detach retires admission, not physical in-flight data")
        source.pointer.storeBytes(of: UInt8(0xA6), as: UInt8.self)
        XCTAssertEqual(inFlight.get()?.first, 0xA6)
        inFlight.set(nil)

        var callback = completion.update { value -> (@Sendable (Error?) -> Void)? in
            let result = value
            value = nil
            return result
        }
        callback?(nil)
        callback = nil
        queue.sync {}
        XCTAssertEqual(budget.snapshot().retainedBytes, 0)
        withExtendedLifetime(core) {}
    }
}
