import Foundation

typealias TcpWritePumpRetryScheduler = @Sendable (
    _ delayMs: Int, _ work: @escaping @Sendable () -> Void
) -> Void

protocol TcpWritePumpCoreDelegate: AnyObject {
    /// The core has encountered a terminal write error and has closed its
    /// internal state.  The delegate performs its own teardown here.
    func pumpCore(_ core: TcpWritePumpCore, didTerminateWith error: Error)
    /// The core has flushed all pending chunks with `lifecycle == .draining`
    /// and has atomically closed.  The delegate runs its drain-complete action
    /// (e.g. send a TCP FIN, fire a completion callback).
    func pumpCoreDidFinishDraining(_ core: TcpWritePumpCore)
}

/// Shared write-pump state machine used by both `TcpClientWritePump` and
/// `NwTcpConnectionWritePump`. Owns the `Locked<TcpWriterState>` byte/item
/// budgets, the in-flight queue, and the exponential-backoff retry loop.
///
/// The actual write primitive and HWM logging are injected at construction
/// time as closures so the core is agnostic of whether the underlying
/// transport is an `NEAppProxyTCPFlow` or an `NWConnection`.
final class TcpWritePumpCore: @unchecked Sendable {
    private final class ChargedChunk: @unchecked Sendable {
        let payload: TcpPayloadSlice
        var data: Data { payload.data }

        init(payload: TcpPayloadSlice) { self.payload = payload }
    }

    let state = Locked(TcpWriterState())
    let queue: DispatchQueue
    /// Immutable for the pump lifetime. In production this comes from the
    /// engine lease, so a replacement generation cannot change admission or
    /// wake thresholds underneath a retiring write.
    let writePolicy: TcpWritePumpPolicy
    private let writerMemoryBudget: WriterMemoryBudget
    var aggregateBudget: WriterMemoryBudget { writerMemoryBudget }
    private let queueKey = DispatchSpecificKey<UInt8>()
    private let inlineWriteCompletionWhenOnQueue: Bool
    private let onDrained: @Sendable () -> Void
    private let doWrite: (Data, @escaping @Sendable (Error?) -> Void) -> Void
    private let logHwm: @Sendable (Int) -> Void
    private let retryScheduler: TcpWritePumpRetryScheduler
    weak var delegate: TcpWritePumpCoreDelegate?

    // Queue-only mutable state — never read/written outside a block
    // executing on `queue`. `ChunkQueue` replaces `[Data]` so the
    // hot-path dequeue and the retry push-back are amortised O(1)
    // instead of O(n) on every drain step.
    private var pending: ChunkQueue<ChargedChunk> = ChunkQueue()
    private var writing = false
    private var lifecycle: WritePumpLifecycle
    private var retrying: WriteRetry?
    /// True while the one valid retry timer is waiting to reopen `flush()`.
    /// New enqueues may append while this is set, but cannot bypass the
    /// transport's backoff interval.
    private var retryDelayPending = false
    /// Invalidates delayed callbacks after success, termination, or cancel.
    /// It also makes an accidentally repeated scheduler callback harmless.
    private var retryDelayGeneration: UInt64 = 0

    /// Fired before an accepted chunk is reported and, while draining, again
    /// when its underlying write completes successfully. The first edge
    /// linearizes acceptance against pressure teardown; the drain-only edge
    /// proves a pending close still progresses without adding an ordinary
    /// streaming hot-path lock. Both data-path modes flush through these pumps.
    private let onActivity: @Sendable () -> Bool

    init(
        queue: DispatchQueue,
        initialLifecycle: WritePumpLifecycle = .open,
        onDrained: @escaping @Sendable () -> Void,
        doWrite: @escaping (Data, @escaping @Sendable (Error?) -> Void) -> Void,
        logHwm: @escaping @Sendable (Int) -> Void,
        inlineWriteCompletionWhenOnQueue: Bool = false,
        onActivity: @escaping @Sendable () -> Bool = { true },
        retryScheduler: TcpWritePumpRetryScheduler? = nil,
        writerMemoryBudget: WriterMemoryBudget = WriterMemoryBudget(),
        writePolicy: TcpWritePumpPolicy =
            TcpWritePumpPolicy(maxPendingBytes: writePumpMaxPendingBytes)
    ) {
        self.queue = queue
        self.writePolicy = writePolicy
        self.writerMemoryBudget = writerMemoryBudget
        self.lifecycle = initialLifecycle
        self.onDrained = onDrained
        self.doWrite = doWrite
        self.logHwm = logHwm
        self.inlineWriteCompletionWhenOnQueue = inlineWriteCompletionWhenOnQueue
        self.onActivity = onActivity
        self.retryScheduler = retryScheduler ?? { [queue] delayMs, work in
            queue.asyncAfter(
                deadline: .now() + .milliseconds(delayMs),
                execute: work
            )
        }
        queue.setSpecific(key: queueKey, value: 1)
    }

    deinit {
        let retired = closeAdmission()
        retired.waiter?.cancel()
        retired.grant?.release()
        while pending.popFront() != nil {}
    }

    func isClosed() -> Bool { state.withLock { $0.closed } }

    #if DEBUG || RAMA_TESTING
        /// Test-only snapshot of the queue-only fields that should be
        /// quiescent after `cancel()` cleanup runs. Used to verify the
        /// post-cancel invariant
        ///   `closed ⇒ pending empty ∧ retrying nil ∧ retry delay absent
        ///              ∧ pendingBytes 0 ∧ pendingItems 0`
        /// is preserved across the race window where a write's
        /// completion lands after cleanup.  Must be called on `queue`.
        internal func testInvariantSnapshot()
            -> (
                pendingEmpty: Bool, retryingNil: Bool, retryDelayPending: Bool,
                pendingBytes: Int, pendingItems: Int
            )
        {
            let accounting = state.withLock { ($0.pendingBytes, $0.pendingItems) }
            return (
                pending.isEmpty, retrying == nil, retryDelayPending,
                accounting.0, accounting.1
            )
        }
    #endif

    /// Atomically stops admission, then returns queue-side payload cleanup.
    /// Returns a queue-side cleanup closure the caller must dispatch on
    /// `queue`.  Separating the atomic part from the queue work lets the
    /// outer class append its own cleanup (e.g. fire `onDrainedClose`)
    /// inside the same async block.
    func prepareCancel() -> @Sendable () -> Void {
        retireAdmission()
        return { [self] in
            self.releaseQueuedPayloadsLocked()
            self.retrying = nil
            self.invalidateRetryDelayLocked()
        }
    }

    /// Synchronous, idempotent detach boundary. It closes new admission and
    /// retires waiter/pregrant capacity without touching queued or in-flight
    /// payload charges; physical payload cleanup remains queue/completion owned.
    func retireAdmission() {
        let retired = closeAdmission()
        retired.waiter?.cancel()
        retired.grant?.release()
    }

    private func closeAdmission() -> (
        alreadyClosed: Bool,
        waiter: WriterMemoryWaiter?, grant: WriterMemoryGrant?
    ) {
        state.withLock { s in
            let wasClosed = s.closed
            s.closed = true
            let retired = (
                wasClosed, s.aggregateWaiter, s.aggregateGrant)
            s.aggregateWaitExpectedBytes = nil
            s.aggregateWaiter = nil
            s.aggregateGrant = nil
            return retired
        }
    }

    /// Drop queue-owned payloads and refund them only after their `Data`
    /// values have left the queue. Dispatch-pending and in-flight chunks are
    /// deliberately absent: their own closures retire those exact charges.
    private func releaseQueuedPayloadsLocked() {
        var bytes = 0
        var items = 0
        while let chunk = pending.popFront() {
            bytes += chunk.data.count
            items += 1
        }
        releasePayloadAccounting(bytes: bytes, items: items)
    }

    private func releasePayloadAccounting(bytes: Int, items: Int = 1) {
        guard items > 0 else { return }
        state.withLock { s in
            precondition(s.pendingBytes >= bytes && s.pendingItems >= items)
            s.pendingBytes -= bytes
            s.pendingItems -= items
        }
    }

    /// Marks the destination open and flushes any queued chunks. A close
    /// requested while the destination was still pending enters `.draining`
    /// before the first write, preserving that terminal intent.
    /// Must be called on `queue`.
    func markOpen(draining: Bool = false) {
        if isClosed() { return }
        lifecycle = draining ? .draining : .open
        flush()
    }

    /// Transitions lifecycle to `.draining` and fires the drain-complete
    /// callback if the queue is already empty.  Must be called on `queue`.
    func beginDraining() {
        if isClosed() { return }
        lifecycle = .draining
        finishCloseIfDrained()
    }

    /// Same status contract as documented on `TcpClientWritePump.enqueue`.
    @discardableResult
    func enqueue(_ data: Data) -> RamaTcpDeliverStatusBridge {
        enqueue(data, prechargedPayload: nil)
    }

    /// Retain a physical-root slice from the direct forwarder. On `.accepted`
    /// the pump keeps a root reference through transport completion; on
    /// `.paused`/`.closed` the caller's cursor remains the owner.
    @discardableResult
    func enqueuePrecharged(_ payload: TcpPayloadSlice) -> RamaTcpDeliverStatusBridge {
        enqueue(payload.data, prechargedPayload: payload)
    }

    private func enqueue(
        _ data: Data,
        prechargedPayload: TcpPayloadSlice? = nil
    ) -> RamaTcpDeliverStatusBridge {
        guard !data.isEmpty else { return .accepted }
        let aggregateAlreadyReserved = prechargedPayload != nil

        var staleGrant: WriterMemoryGrant?
        var staleWaiter: WriterMemoryWaiter?
        var needsAggregateWait = false
        let (decision, hwm): (RamaTcpDeliverStatusBridge, Int?) = state.withLock { s in
            if s.closed { return (.closed, nil) }
            // Every production producer slices to this cap before enqueueing,
            // so it is safe to reject an oversized first chunk too. Keep the
            // subtraction form overflow-safe for adversarial Data lengths.
            let byteCapReached = data.count > writePolicy.maxPendingBytes
                || s.pendingBytes > writePolicy.maxPendingBytes - data.count
            let itemCapReached = s.pendingItems >= tcpWritePumpMaxPendingItems
            if byteCapReached || itemCapReached {
                s.pausedSignaled = true
                return (.paused, nil)
            }

            if aggregateAlreadyReserved {
                // Preserve FIFO behind a Rust-side retry already registered
                // on this pump. The caller continues owning its charge.
                if s.aggregateWaitExpectedBytes != nil || s.aggregateGrant != nil {
                    s.pausedSignaled = true
                    return (.paused, nil)
                }
            } else if let grant = s.aggregateGrant {
                guard s.aggregateWaitExpectedBytes == data.count else {
                    staleGrant = grant
                    s.aggregateGrant = nil
                    s.aggregateWaiter = nil
                    s.aggregateWaitExpectedBytes = data.count
                    s.pausedSignaled = true
                    needsAggregateWait = true
                    return (.paused, nil)
                }
                precondition(grant.consume(), "writer-memory grant consumed twice")
                s.aggregateGrant = nil
                s.aggregateWaiter = nil
                s.aggregateWaitExpectedBytes = nil
            } else if let expected = s.aggregateWaitExpectedBytes {
                if expected != data.count {
                    staleWaiter = s.aggregateWaiter
                    s.aggregateWaiter = nil
                    s.aggregateWaitExpectedBytes = data.count
                    needsAggregateWait = true
                }
                s.pausedSignaled = true
                return (.paused, nil)
            } else if !writerMemoryBudget.tryReserve(bytes: data.count) {
                s.aggregateWaitExpectedBytes = data.count
                s.pausedSignaled = true
                needsAggregateWait = true
                return (.paused, nil)
            }
            s.pendingBytes += data.count
            s.pendingItems += 1
            var newHwm: Int? = nil
            let previousHwm = s.pendingBytesHwm
            if s.pendingBytes > previousHwm {
                s.pendingBytesHwm = s.pendingBytes
                // Keep the exact HWM, but log only the first threshold
                // crossing. Logging every byte-level peak lets one stalled
                // flow manufacture O(cap) strings and log calls.
                if previousHwm < writePolicy.hwmLogThresholdBytes,
                    s.pendingBytes >= writePolicy.hwmLogThresholdBytes
                {
                    newHwm = s.pendingBytes
                }
            }
            return (.accepted, newHwm)
        }
        staleGrant?.release()
        staleWaiter?.cancel()
        if needsAggregateWait { registerAggregateWaiter(bytes: data.count) }
        guard decision == .accepted else { return decision }

        // From here the aggregate reservation is owned by an ARC root. A
        // precharged promotion slice already has that root; a normal Rust
        // callback binds the just-reserved/pregranted charge now.
        let payload = prechargedPayload
            ?? writerMemoryBudget.makePregrantedWriterPayload(data)

        // Linearize acceptance against pressure teardown before reporting the
        // chunk accepted. If teardown won after the byte-budget reservation,
        // roll that reservation back and surface a closed destination.
        guard self.onActivity() else {
            state.withLock { s in
                precondition(s.pendingBytes >= data.count && s.pendingItems >= 1)
                s.pendingBytes -= data.count
                s.pendingItems -= 1
            }
            return .closed
        }
        if let hwm { logHwm(hwm) }

        let chunk = ChargedChunk(payload: payload)
        queue.async { [weak self, chunk] in
            guard let self else { return }
            // Re-check under lock; cancel() can have flipped the flag
            // between the FFI fast-path return and this dispatch.
            guard !self.state.withLock({ $0.closed }) else {
                self.releasePayloadAccounting(bytes: chunk.data.count)
                return
            }
            self.pending.pushBack(chunk)
            self.flush()
        }
        return .accepted
    }

    /// Publish one pressure waiter after admission has dropped the per-pump
    /// lock. The coordinator may deliver before this method installs the
    /// returned token; the grant field is the race-safe hand-off in that case.
    private func registerAggregateWaiter(bytes: Int) {
        let waiter = writerMemoryBudget.waitForTcpCapacity(
            bytes: bytes,
            onUnavailable: { [weak self] in
                self?.receiveAggregateUnavailable(expectedBytes: bytes)
            },
            onGrant: { [weak self] grant in
                self?.receiveAggregateGrant(grant, expectedBytes: bytes)
            })
        let keep = state.withLock { s -> Bool in
            guard !s.closed,
                s.aggregateWaitExpectedBytes == bytes,
                s.aggregateGrant == nil,
                s.aggregateWaiter == nil
            else { return false }
            s.aggregateWaiter = waiter
            return true
        }
        if !keep { waiter.cancel() }
    }

    /// A grant is already included in the aggregate totals. Retain it until
    /// the exact rejected chunk retries; stale and closing callbacks refund it.
    private func receiveAggregateGrant(
        _ grant: WriterMemoryGrant,
        expectedBytes: Int
    ) {
        let accepted = state.withLock { s -> Bool in
            guard !s.closed,
                s.aggregateWaitExpectedBytes == expectedBytes,
                s.aggregateGrant == nil
            else { return false }
            s.aggregateWaiter = nil
            s.aggregateGrant = grant
            s.pausedSignaled = false
            return true
        }
        guard accepted else {
            grant.release()
            return
        }
        // Drain callbacks also drive the promoted forwarder, whose state is
        // queue-confined. Normalize this pressure-only wake onto the pump queue
        // just like transport completions; cancellation or an eager retry may
        // make it stale before it runs.
        queue.async { [weak self, weak grant] in
            guard let self, let grant else { return }
            let stillWaiting = self.state.withLock { s in
                !s.closed && s.aggregateGrant === grant
            }
            if stillWaiting { self.onDrained() }
        }
    }

    /// A replacement generation lowered the process cap so this retiring
    /// pump's old-size retry can no longer coexist with the guaranteed UDP
    /// service reserve. Fail this flow explicitly; parking it forever would
    /// starve both the byte stream and future protocol service.
    private func receiveAggregateUnavailable(expectedBytes: Int) {
        queue.async { [weak self] in
            guard let self else { return }
            let stillWaiting = self.state.withLock { s in
                !s.closed && s.aggregateWaitExpectedBytes == expectedBytes
            }
            guard stillWaiting else { return }
            self.terminateLocked(
                with: NSError(
                    domain: "rama.tproxy.writer-memory",
                    code: 4,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "TCP retry exceeds reconfigured process payload share"
                    ]))
        }
    }

    /// Queue-side terminal cleanup.  Publishes the closed flag under the
    /// lock so concurrent FFI `enqueue` calls return `.closed` immediately.
    func terminateLocked(with error: Error) {
        let retired = closeAdmission()
        if retired.alreadyClosed { return }
        retired.waiter?.cancel()
        retired.grant?.release()
        lifecycle = .draining
        releaseQueuedPayloadsLocked()
        retrying = nil
        invalidateRetryDelayLocked()
        delegate?.pumpCore(self, didTerminateWith: error)
    }

    private func flush() {
        if isClosed() { return }
        if writing || retryDelayPending || pending.isEmpty || lifecycle == .pending {
            finishCloseIfDrained()
            return
        }

        writing = true
        guard let chunk = pending.popFront() else { return }

        doWrite(chunk.data) { [weak self, chunk] error in
            guard let self else { return }
            let finish: @Sendable () -> Void = { [weak self, chunk] in
                guard let self else { return }
                // If `cancel()` ran while this write was in flight and
                // its queue cleanup (`pending.removeAll`, `retrying = nil`,
                // `pendingBytes = 0`, `pendingItems = 0`) landed *before* this
                // completion,
                // the transient-retry branch below would silently revive
                // those fields — pushing `chunk` back onto `pending`,
                // retaining stale admission accounting and re-arming
                // `retrying`. No further write fires (the asyncAfter's
                // `flush()` would bail on `isClosed()`), but the
                // post-cancel invariant
                // `closed ⇒ pending empty ∧ retrying nil ∧ pendingBytes 0
                //            ∧ pendingItems 0`
                // would quietly break — a Heisenbug for any future code
                // that reads those fields as a "pump is idle" signal.
                // Drop the completion's result on the floor; we're done.
                if self.isClosed() {
                    self.writing = false
                    self.releasePayloadAccounting(bytes: chunk.data.count)
                    return
                }
                self.writing = false
                if let error {
                    if isTransientWriteBackpressure(error) {
                        let now = DispatchTime.now()
                        let currentDelayMs: Int
                        let deadline: DispatchTime
                        if let existing = self.retrying {
                            if now >= existing.deadline {
                                self.releasePayloadAccounting(bytes: chunk.data.count)
                                self.terminateLocked(with: error)
                                return
                            }
                            currentDelayMs = existing.delayMs
                            deadline = existing.deadline
                        } else {
                            currentDelayMs = writeRetryInitialDelayMs
                            deadline = now + .milliseconds(writeRetryHardDeadlineMs)
                        }
                        self.pending.pushFront(chunk)
                        self.retrying = WriteRetry(
                            delayMs: min(currentDelayMs * 2, writeRetryMaxDelayMs),
                            deadline: deadline
                        )
                        self.scheduleRetryLocked(after: currentDelayMs)
                        return
                    }
                    self.releasePayloadAccounting(bytes: chunk.data.count)
                    self.terminateLocked(with: error)
                    return
                }
                let shouldWake = self.state.withLock { s -> Bool in
                    precondition(s.pendingBytes >= chunk.data.count && s.pendingItems >= 1)
                    s.pendingBytes -= chunk.data.count
                    s.pendingItems -= 1
                    if s.pausedSignaled
                        && s.pendingBytes < self.writePolicy.maxPendingBytes
                        && s.pendingItems < tcpWritePumpMaxPendingItems
                    {
                        s.pausedSignaled = false
                        return true
                    }
                    return false
                }
                // Keep the in-flight Data charged until the transport has
                // released it. Both counters therefore cover dispatch-pending,
                // queued, retrying, and in-flight work while still waking Rust
                // as soon as real capacity becomes available.
                if shouldWake { self.onDrained() }
                // Only the closing path needs a second activity edge. Keep
                // ordinary streaming at its existing one lock per accepted
                // chunk, while a drain with no new enqueues still refreshes
                // its progress clock before advancing to the next chunk.
                if self.lifecycle == .draining { _ = self.onActivity() }
                self.retrying = nil
                self.invalidateRetryDelayLocked()
                self.flush()
            }
            if self.inlineWriteCompletionWhenOnQueue,
                DispatchQueue.getSpecific(key: self.queueKey) != nil
            {
                finish()
            } else {
                self.queue.async(execute: finish)
            }
        }
    }

    /// Arm exactly one retry delay for the current backoff generation.
    /// Scheduler callbacks may arrive on any queue; all generation state is
    /// inspected and mutated only after hopping back to `queue`.
    private func scheduleRetryLocked(after delayMs: Int) {
        retryDelayGeneration &+= 1
        let generation = retryDelayGeneration
        retryDelayPending = true
        retryScheduler(delayMs) { [weak self] in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self,
                    self.retryDelayPending,
                    self.retryDelayGeneration == generation
                else { return }
                self.retryDelayPending = false
                self.flush()
            }
        }
    }

    /// Make every previously scheduled callback stale before clearing the
    /// delay gate. Must run on `queue`.
    private func invalidateRetryDelayLocked() {
        retryDelayGeneration &+= 1
        retryDelayPending = false
    }

    private func finishCloseIfDrained() {
        guard lifecycle == .draining, !writing, !retryDelayPending, pending.isEmpty
        else { return }
        // Also require both admission charges to be zero: `enqueue` bumps them
        // and returns `.accepted` on the FFI thread, then appends to `pending`
        // via `queue.async`. Between those, `pending.isEmpty` is true while a
        // chunk is dispatch-pending — closing here would FIN and drop it. Checked
        // in the same lock that publishes `closed`, for one snapshot.
        let proceed: Bool = state.withLock { s in
            if s.closed || s.pendingBytes != 0 || s.pendingItems != 0
                || s.aggregateWaitExpectedBytes != nil || s.aggregateGrant != nil
            { return false }
            s.closed = true
            return true
        }
        if !proceed { return }
        delegate?.pumpCoreDidFinishDraining(self)
    }
}
