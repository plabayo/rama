import Foundation
import Network
import NetworkExtension
import RamaAppleNEFFI

final class NwTcpConnectionWritePump: @unchecked Sendable {
    private let connection: any NwConnectionLike
    private let core: TcpWritePumpCore
    private let callbackQueue: DispatchQueue
    private let callbackQueueKey = DispatchSpecificKey<UInt8>()
    /// Fired (on `core.queue`, at most once) when the pump hits a
    /// terminal write error. Symmetric to
    /// `TcpClientWritePump.onTerminalError`: the egress write pump
    /// has no other teardown hook, so without this a promoted-mode
    /// forwarder whose C→S direction is parked (blocked on
    /// `flow.readData`, or holding a `.paused` chunk) never learns
    /// the egress is dead and wedges → flow leak. See
    /// `pumpCore(_:didTerminateWith:)`.
    private let onTerminal: @Sendable (Error) -> Void
    /// Grace after the whole promoted flow reaches terminal before this pump
    /// force-cancels the egress connection. It is deliberately not armed by a
    /// successful local FIN: a quiet response half is still valid TCP.
    private let lingerCloseDeadline: DispatchTimeInterval
    /// Scheduled linger-cancel work, retained so we can invalidate it
    /// when the connection closes naturally before the deadline (or
    /// when the pump is externally cancelled).
    private var lingerWork: DispatchWorkItem?
    /// Milliseconds since the flow last moved a byte, read on `core.queue`.
    /// The terminal linger watchdog consults this before force-cancelling.
    /// Default `.max` (always idle) keeps the plain bounded linger for
    /// callers without a flow-activity clock.
    private let readSideIdleMs: @Sendable () -> UInt64
    /// `lingerCloseDeadline` in milliseconds, for comparison against
    /// `readSideIdleMs()`.
    private let lingerCloseMs: UInt64
    /// Pending callback installed by
    /// `closeWhenDrained(_:)` — fires exactly once when the FIN
    /// completes (success or after reporting a local error), or
    /// from `deinit` as
    /// a fallback if the pump is deallocated before drain has a
    /// chance to run. This guarantees a caller awaiting the FIN
    /// (e.g. `TcpDirectForwarder`) is never stranded.
    private var onDrainedCallback: (@Sendable () -> Void)?
    /// Draining reached an empty queue while an established connection was
    /// temporarily `.waiting`. Preserve the FIN intent until the session's
    /// state handler observes recovery to `.ready`.
    private var finWaitingForReady = false
    /// Installed by the promoted natural-terminal path. It represents hard-cap
    /// occupancy after registry removal and is released only when this pump
    /// actually invokes `cancelAndDetach` (or observes it already did so).
    private var terminalResourceRelease: (@Sendable () -> Void)?
    private var connectionReleaseIssued = false

    init(
        connection: any NwConnectionLike,
        queue: DispatchQueue,
        lingerCloseDeadline: DispatchTimeInterval,
        onDrained: @escaping @Sendable () -> Void,
        onTerminal: @escaping @Sendable (Error) -> Void = { _ in },
        onActivity: @escaping @Sendable () -> Bool = { true },
        readSideIdleMs: @escaping @Sendable () -> UInt64 = { .max },
        writerMemoryBudget: WriterMemoryBudget = WriterMemoryBudget(),
        writePolicy: TcpWritePumpPolicy =
            TcpWritePumpPolicy(maxPendingBytes: writePumpMaxPendingBytes)
    ) {
        self.connection = connection
        self.lingerCloseDeadline = lingerCloseDeadline
        self.lingerCloseMs = Self.millis(from: lingerCloseDeadline)
        self.readSideIdleMs = readSideIdleMs
        self.onTerminal = onTerminal
        self.callbackQueue = queue
        let core = TcpWritePumpCore(
            queue: queue,
            initialLifecycle: .open,
            onDrained: onDrained,
            doWrite: { data, completion in
                // `isComplete: true` matches `NWConnection.send`'s own
                // default for TCP; the value is a no-op for stream
                // transports but is set explicitly here because the
                // injectable protocol surface has no default arguments.
                connection.send(
                    content: data,
                    contentContext: .defaultMessage,
                    isComplete: true,
                    completion: .contentProcessed(completion)
                )
            },
            logHwm: { hwm in
                RamaLog.trace(
                    "tcp egress write pump pendingBytes hwm=\(hwm) cap=\(writePolicy.maxPendingBytes)"
                )
            },
            inlineWriteCompletionWhenOnQueue: true,
            onActivity: onActivity,
            writerMemoryBudget: writerMemoryBudget,
            writePolicy: writePolicy
        )
        self.core = core
        core.delegate = self
        queue.setSpecific(key: callbackQueueKey, value: 1)
    }


    /// Same status contract as `TcpClientWritePump.enqueue`.
    @discardableResult
    func enqueue(_ data: Data) -> RamaTcpDeliverStatusBridge { core.enqueue(data) }

    @discardableResult
    func enqueuePrecharged(_ payload: TcpPayloadSlice) -> RamaTcpDeliverStatusBridge {
        core.enqueuePrecharged(payload)
    }

    var aggregateBudget: WriterMemoryBudget { core.aggregateBudget }

    func retireAdmissionForEngineDetach() { core.retireAdmission() }

    /// Drain the queue, then send a FIN to the remote.
    ///
    /// `onDrained` (if non-nil) fires EXACTLY ONCE on the
    /// `core.queue`, after either:
    ///   * The FIN's `send` completion has fired (success or
    ///     local error path), OR
    ///   * The pump is externally cancelled before the FIN
    ///     completes, OR
    ///   * The pump is deallocated before either of the above
    ///     (fallback in `deinit`).
    ///
    /// The fallbacks are load-bearing for the
    /// `TcpDirectForwarder` state machine: if the pump dies
    /// mid-drain (e.g. because the per-flow ctx that holds it
    /// was removed from the registry due to an unrelated
    /// teardown path), the forwarder's `c2sPhase = .finished`
    /// transition would otherwise hang waiting for a callback
    /// that never fires, and the flow would leak in the
    /// registry.
    func closeWhenDrained(_ onDrained: (@Sendable () -> Void)? = nil) {
        core.queue.async { [weak self] in
            guard let self else {
                // Pump already gone — fire the callback so the
                // caller's state machine progresses.
                onDrained?()
                return
            }
            if self.core.isClosed() {
                // Core already closed: no FIN and no later natural terminal
                // can arm the release grace. Cancel here or the connection
                // graph can leak. Safe — no FIN to clip — and idempotent.
                self.cancelConnectionAndReleaseLocked()
                onDrained?()
                return
            }
            // Replace any prior pending callback. Real callers
            // call this at most once per pump lifetime; this
            // guard is for defensive safety.
            if let stale = self.onDrainedCallback {
                stale()
            }
            self.onDrainedCallback = onDrained
            self.core.beginDraining()
        }
    }

    func cancel() {
        let coreCleanup = core.prepareCancel()
        core.queue.async { [weak self] in
            coreCleanup()
            self?.finWaitingForReady = false
            // External cancel pre-empts any terminal linger watchdog.
            self?.lingerWork?.cancel()
            self?.lingerWork = nil
            // Fire any pending closeWhenDrained callback so a
            // caller waiting on FIN completion doesn't stall.
            if let cb = self?.onDrainedCallback {
                self?.onDrainedCallback = nil
                cb()
            }
        }
    }

    /// Call on the pump callback queue, as the promoted forwarder's terminal
    /// callback does. A connection already force-cancelled by an earlier drain
    /// or error path releases the new retirement token immediately.
    func installTerminalResourceRelease(_ release: @escaping @Sendable () -> Void) {
        dispatchPrecondition(condition: .onQueue(callbackQueue))
        if connectionReleaseIssued {
            release()
            return
        }
        terminalResourceRelease = release
    }

    private func cancelConnectionAndReleaseLocked() {
        connection.cancelAndDetach()
        connectionReleaseIssued = true
        let release = terminalResourceRelease
        terminalResourceRelease = nil
        release?()
    }

    deinit {
        // Fallback: if the pump is deallocated before drain
        // completes, fire the callback so the caller's state
        // machine isn't stranded. `deinit` runs synchronously on whichever
        // thread releases the last strong ref, so normalize this rare fallback
        // onto the same queue as ordinary pump completions.
        if let cb = onDrainedCallback {
            if DispatchQueue.getSpecific(key: callbackQueueKey) != nil {
                cb()
            } else {
                callbackQueue.async(execute: cb)
            }
        }
    }
}

extension NwTcpConnectionWritePump: TcpWritePumpCoreDelegate {
    internal func pumpCore(_ core: TcpWritePumpCore, didTerminateWith error: Error) {
        // A terminal write error closes the core WITHOUT reaching
        // `pumpCoreDidFinishDraining` — so no FIN is sent and no terminal
        // release grace can be armed. Two things must still happen, mirroring
        // `TcpClientWritePump.pumpCore(_:didTerminateWith:)` and the
        // `cancel()` path. Without them the promoted (`TcpDirectForwarder`)
        // hot path leaks:
        //
        //  1. Fire any pending `closeWhenDrained` callback. The forwarder's
        //     C→S `.finishing → .finished` transition is gated SOLELY on
        //     this callback (`finishC2SLocked`). If it never fires the
        //     forwarder wedges in `.finishing`, `onTerminal` never fires,
        //     and the per-flow ctx — which strongly holds this pump — leaks
        //     in the registry. `deinit` can't rescue it: the ctx is pinned
        //     waiting for the very `.finished` this callback unblocks.
        //
        //  2. Force-cancel the connection so its NECP registration is
        //     released. The error path skips the natural terminal-release
        //     sequence, and `fireTerminalLocked` deliberately does NOT cancel the
        //     connection (it delegates to that watchdog). The nastiest
        //     trigger makes this load-bearing: the transient-backpressure
        //     retry hard-deadline (`TcpWritePumpCore`) terminates while the
        //     NWConnection is still `.ready`, so the egress state handler
        //     never observes `.failed`/`.cancelled` and there is NO other
        //     teardown path. `cancelAndDetach` is idempotent and nils the
        //     state handler, so it won't re-enter teardown and any later
        //     cancel from `onTerminal` is a no-op.
        //
        // In either mode the force-cancel is correct: a terminal write error
        // means the egress is broken. The owner callback below then performs
        // mode-appropriate session teardown.
        lingerWork?.cancel()
        lingerWork = nil
        finWaitingForReady = false
        cancelConnectionAndReleaseLocked()
        let drainCallback = onDrainedCallback
        onDrainedCallback = nil
        // Drive the owner's teardown. In promoted mode the forwarder
        // owns the kernel flow + connection lifecycle; its C→S
        // direction can be parked indefinitely — blocked on a
        // `flow.readData` (idle/slow client) or holding a `.paused`
        // chunk — neither of which is woken by the connection cancel
        // above (that only unwinds the S→C `receive` loop). The
        // pending-callback fire only helps if C→S already reached
        // `.finishing`. Without an explicit terminal hook the forwarder
        // wedges and `onTerminal` never fires → the kernel flow + ctx
        // leak in the registry. This mirrors
        // `TcpClientWritePump.onTerminalError`, the equivalent hook on
        // the sibling write pump.
        onTerminal(error)
        // A drain waiter must still be released, but only AFTER errorful
        // teardown has won. Otherwise the callback can complete the sibling
        // drain pair as clean EOF and make `onTerminal(error)` a no-op.
        drainCallback?()
    }

    internal func pumpCoreDidFinishDraining(_ core: TcpWritePumpCore) {
        switch connection.state {
        case .waiting(_):
            // The session owns a bounded post-ready recovery timer. Do not
            // turn a recoverable path blip into an immediate hard cancel just
            // because the client half-closed during it.
            finWaitingForReady = true
            return
        case .ready:
            sendFinLocked()
        default:
            finishNonReadyDrainLocked()
        }
    }

    /// Called by the owning session for a duplicate `.ready` transition after
    /// an established connection recovered from `.waiting`.
    func connectionBecameReady() {
        let resume: @Sendable () -> Void = { [weak self] in
            guard let self, self.finWaitingForReady else { return }
            self.finWaitingForReady = false
            guard self.connection.state == .ready else { return }
            self.sendFinLocked()
        }
        if DispatchQueue.getSpecific(key: callbackQueueKey) != nil {
            resume()
        } else {
            core.queue.async(execute: resume)
        }
    }

    private func finishNonReadyDrainLocked() {
        // Snapshot the pending close-callback and clear the
        // slot before force-cancelling the unusable connection.
        let cb = self.onDrainedCallback
        self.onDrainedCallback = nil
        finWaitingForReady = false
        cancelConnectionAndReleaseLocked()
        cb?()
    }

    private func sendFinLocked() {
        // Snapshot and clear before issuing the FIN. The send completion
        // retains `cb`, so a concurrent owner teardown cannot strand it.
        let cb = self.onDrainedCallback
        self.onDrainedCallback = nil
        finWaitingForReady = false
        // `.finalMessage` + `isComplete: true` is the documented way
        // to trigger a TCP half-close (FIN) on a `NWConnection`. Using
        // `.defaultMessage` only marks the logical message complete and
        // leaves the stream open, so the peer would never observe a
        // half-close. See
        // <https://developer.apple.com/documentation/network/nwconnection/contentcontext/finalmessage>.
        let callbackQueue = self.callbackQueue
        let callbackQueueKey = self.callbackQueueKey
        connection.send(
            content: nil,
            contentContext: .finalMessage,
            isComplete: true,
            completion: .contentProcessed({ [weak self] error in
                // Preserve a FIN submission failure as a hard transport
                // error. Notify the owner before releasing its drain waiter;
                // otherwise the waiter can complete a clean two-sided drain
                // and make the errorful teardown lose its one-shot race.
                let finish: @Sendable () -> Void = { [weak self] in
                    if let error {
                        self?.lingerWork?.cancel()
                        self?.lingerWork = nil
                        self?.cancelConnectionAndReleaseLocked()
                        self?.onTerminal(error)
                    }
                    cb?()
                }
                if DispatchQueue.getSpecific(key: callbackQueueKey) != nil {
                    finish()
                } else {
                    callbackQueue.async(execute: finish)
                }
            })
        )
    }

    /// Start the bounded release only after both promoted directions reached
    /// terminal. Calling this before a quiet response half closes would impose
    /// an application response deadline and truncate valid TCP traffic.
    func armTerminalLingerCancel() {
        if DispatchQueue.getSpecific(key: callbackQueueKey) != nil {
            armLingerCancel(afterMs: lingerCloseMs)
        } else {
            core.queue.async { self.armLingerCancel(afterMs: self.lingerCloseMs) }
        }
    }

    /// Arm (or re-arm) terminal force-cancel `afterMs` from now.
    ///
    /// Capture `connection` strongly: a promote teardown can drop the
    /// per-flow ctx (and us with it) right after the FIN send completes —
    /// `[weak self]` alone would no-op and leak the NWConnection. A gone
    /// pump means the whole per-flow graph is gone, so cancellation proceeds.
    private func armLingerCancel(afterMs: UInt64) {
        guard afterMs != .max else { return }  // `.never` deadline: no watchdog
        let conn = connection
        let resourceRelease = terminalResourceRelease
        let work = DispatchWorkItem { [weak self] in
            guard let self else {
                conn.cancelAndDetach()
                resourceRelease?()
                return
            }
            let idle = self.readSideIdleMs()
            if idle < self.lingerCloseMs {
                self.armLingerCancel(afterMs: max(self.lingerCloseMs - idle, 50))
            } else {
                self.cancelConnectionAndReleaseLocked()
                self.lingerWork = nil
            }
        }
        lingerWork = work
        core.queue.asyncAfter(deadline: .now() + .milliseconds(Int(afterMs)), execute: work)
    }

    private static func millis(from interval: DispatchTimeInterval) -> UInt64 {
        switch interval {
        case .seconds(let s): return s <= 0 ? 0 : UInt64(s) * 1_000
        case .milliseconds(let ms): return ms <= 0 ? 0 : UInt64(ms)
        case .microseconds(let us): return us <= 0 ? 0 : UInt64(us) / 1_000
        case .nanoseconds(let ns): return ns <= 0 ? 0 : UInt64(ns) / 1_000_000
        case .never: return .max
        @unknown default: return UInt64(defaultLingerCloseMs)
        }
    }

    #if DEBUG
        var testHasTerminalLinger: Bool {
            if DispatchQueue.getSpecific(key: callbackQueueKey) != nil {
                return lingerWork != nil
            }
            return core.queue.sync { lingerWork != nil }
        }
    #endif
}
