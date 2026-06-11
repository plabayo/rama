import Foundation

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
/// `NwTcpConnectionWritePump`.  Owns the `Locked<TcpWriterState>` byte
/// budget, the in-flight queue, and the exponential-backoff retry loop.
///
/// The actual write primitive and HWM logging are injected at construction
/// time as closures so the core is agnostic of whether the underlying
/// transport is an `NEAppProxyTCPFlow` or an `NWConnection`.
final class TcpWritePumpCore: @unchecked Sendable {
    let state = Locked(TcpWriterState())
    let queue: DispatchQueue
    private let onDrained: () -> Void
    private let doWrite: (Data, @escaping @Sendable (Error?) -> Void) -> Void
    private let logHwm: (Int) -> Void
    weak var delegate: TcpWritePumpCoreDelegate?

    // Queue-only mutable state — never read/written outside a block
    // executing on `queue`. `ChunkQueue` replaces `[Data]` so the
    // hot-path dequeue and the retry push-back are amortised O(1)
    // instead of O(n) on every drain step.
    private var pending: ChunkQueue<Data> = ChunkQueue()
    private var writing = false
    private var lifecycle: WritePumpLifecycle
    private var retrying: WriteRetry?

    init(
        queue: DispatchQueue,
        initialLifecycle: WritePumpLifecycle = .open,
        onDrained: @escaping () -> Void,
        doWrite: @escaping (Data, @escaping @Sendable (Error?) -> Void) -> Void,
        logHwm: @escaping (Int) -> Void
    ) {
        self.queue = queue
        self.lifecycle = initialLifecycle
        self.onDrained = onDrained
        self.doWrite = doWrite
        self.logHwm = logHwm
    }

    func isClosed() -> Bool { state.withLock { $0.closed } }

    #if DEBUG
        /// Test-only snapshot of the queue-only fields that should be
        /// quiescent after `cancel()` cleanup runs. Used to verify the
        /// post-cancel invariant
        ///   `closed ⇒ pending empty ∧ retrying nil ∧ pendingBytes 0`
        /// is preserved across the race window where a write's
        /// completion lands after cleanup.  Must be called on `queue`.
        internal func testInvariantSnapshot()
            -> (pendingEmpty: Bool, retryingNil: Bool, pendingBytes: Int)
        {
            let bytes = state.withLock { $0.pendingBytes }
            return (pending.isEmpty, retrying == nil, bytes)
        }
    #endif

    /// Atomically marks the core closed and zeroes the byte budget.
    /// Returns a queue-side cleanup closure the caller must dispatch on
    /// `queue`.  Separating the atomic part from the queue work lets the
    /// outer class append its own cleanup (e.g. fire `onDrainedClose`)
    /// inside the same async block.
    func prepareCancel() -> () -> Void {
        state.withLock { s in
            s.closed = true
            s.pendingBytes = 0
        }
        return { [self] in
            self.pending.removeAll()
            self.retrying = nil
        }
    }

    /// Transitions lifecycle to `.open` and flushes any queued chunks.
    /// Must be called on `queue`.
    func markOpen() {
        if isClosed() { return }
        lifecycle = .open
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
        guard !data.isEmpty else { return .accepted }

        let (decision, hwm): (RamaTcpDeliverStatusBridge, Int?) = state.withLock { s in
            if s.closed { return (.closed, nil) }
            // First chunk always passes through — an oversized single
            // chunk must not deadlock the bridge.
            if s.pendingBytes > 0
                && s.pendingBytes + data.count > writePumpMaxPendingBytes
            {
                s.pausedSignaled = true
                return (.paused, nil)
            }
            s.pendingBytes += data.count
            var newHwm: Int? = nil
            if s.pendingBytes > s.pendingBytesHwm {
                s.pendingBytesHwm = s.pendingBytes
                if s.pendingBytes >= writePumpHwmLogThresholdBytes {
                    newHwm = s.pendingBytes
                }
            }
            return (.accepted, newHwm)
        }
        if let hwm { logHwm(hwm) }
        guard decision == .accepted else { return decision }

        queue.async { [weak self] in
            guard let self else { return }
            // Re-check under lock; cancel() can have flipped the flag
            // between the FFI fast-path return and this dispatch.
            // Do NOT subtract pendingBytes here: if cancel() ran first it
            // already zeroed the counter, and subtracting again would push
            // it negative.
            guard !self.state.withLock({ $0.closed }) else { return }
            self.pending.pushBack(data)
            self.flush()
        }
        return .accepted
    }

    /// Queue-side terminal cleanup.  Publishes the closed flag under the
    /// lock so concurrent FFI `enqueue` calls return `.closed` immediately.
    func terminateLocked(with error: Error) {
        let alreadyClosed: Bool = state.withLock { s in
            let wasClosed = s.closed
            s.closed = true
            s.pendingBytes = 0
            return wasClosed
        }
        if alreadyClosed { return }
        lifecycle = .draining
        pending.removeAll()
        retrying = nil
        delegate?.pumpCore(self, didTerminateWith: error)
    }

    private func flush() {
        if isClosed() { return }
        if writing || pending.isEmpty || lifecycle == .pending {
            finishCloseIfDrained()
            return
        }

        writing = true
        guard let chunk = pending.popFront() else { return }

        let fireDrain: Bool = state.withLock { s in
            s.pendingBytes -= chunk.count
            if s.pausedSignaled && s.pendingBytes < writePumpMaxPendingBytes {
                s.pausedSignaled = false
                return true
            }
            return false
        }
        // Edge-triggered drain signal — wakes Rust before the current write
        // completes so it can start producing in parallel.
        if fireDrain { onDrained() }

        doWrite(chunk) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                // If `cancel()` ran while this write was in flight and
                // its queue cleanup (`pending.removeAll`, `retrying = nil`,
                // `pendingBytes = 0`) landed *before* this completion,
                // the transient-retry branch below would silently revive
                // those fields — pushing `chunk` back onto `pending`,
                // re-incrementing `pendingBytes`, and re-arming
                // `retrying`. No further write fires (the asyncAfter's
                // `flush()` would bail on `isClosed()`), but the
                // post-cancel invariant
                // `closed ⇒ pending empty ∧ retrying nil ∧ pendingBytes 0`
                // would quietly break — a Heisenbug for any future code
                // that reads those fields as a "pump is idle" signal.
                // Drop the completion's result on the floor; we're done.
                if self.isClosed() {
                    self.writing = false
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
                        self.state.withLock { $0.pendingBytes += chunk.count }
                        self.retrying = WriteRetry(
                            delayMs: min(currentDelayMs * 2, writeRetryMaxDelayMs),
                            deadline: deadline
                        )
                        self.queue.asyncAfter(
                            deadline: .now() + .milliseconds(currentDelayMs)
                        ) { [weak self] in
                            self?.flush()
                        }
                        return
                    }
                    self.terminateLocked(with: error)
                    return
                }
                self.retrying = nil
                self.flush()
            }
        }
    }

    private func finishCloseIfDrained() {
        guard lifecycle == .draining, !writing, pending.isEmpty else { return }
        // Also require `pendingBytes == 0`: `enqueue` bumps the count and
        // returns `.accepted` on the FFI thread, then appends to `pending`
        // via `queue.async`. Between those, `pending.isEmpty` is true while
        // a chunk is in flight — closing here would FIN and drop it. Checked
        // in the same lock that publishes `closed`, for one snapshot.
        let proceed: Bool = state.withLock { s in
            if s.closed || s.pendingBytes != 0 { return false }
            s.closed = true
            return true
        }
        if !proceed { return }
        delegate?.pumpCoreDidFinishDraining(self)
    }
}
