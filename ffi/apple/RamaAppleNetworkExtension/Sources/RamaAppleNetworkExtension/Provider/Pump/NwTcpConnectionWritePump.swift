import Foundation
import Network
import NetworkExtension
import RamaAppleNEFFI

final class NwTcpConnectionWritePump: @unchecked Sendable {
    private let connection: any NwConnectionLike
    private let core: TcpWritePumpCore
    /// Fired (on `core.queue`, at most once) when the pump hits a
    /// terminal write error. Symmetric to
    /// `TcpClientWritePump.onTerminalError`: the egress write pump
    /// has no other teardown hook, so without this a promoted-mode
    /// forwarder whose C→S direction is parked (blocked on
    /// `flow.readData`, or holding a `.paused` chunk) never learns
    /// the egress is dead and wedges → flow leak. See
    /// `pumpCore(_:didTerminateWith:)`.
    private let onTerminal: (Error) -> Void
    /// Wall-clock cap on how long the egress NWConnection lingers after
    /// the local side has sent its FIN (an empty `send` with
    /// `isComplete: true`) before this pump force-cancels the
    /// connection. A peer that fails to send its own FIN-ACK would
    /// otherwise keep the kernel socket in FIN_WAIT_1 and the macOS
    /// NECP flow registration alive — accumulating leaked
    /// registrations is what makes new `nw_connection_start` calls
    /// linearly slower on the workloop queue.
    private let lingerCloseDeadline: DispatchTimeInterval
    /// Scheduled linger-cancel work, retained so we can invalidate it
    /// when the connection closes naturally before the deadline (or
    /// when the pump is externally cancelled).
    private var lingerWork: DispatchWorkItem?
    /// Pending callback installed by
    /// `closeWhenDrained(_:)` — fires exactly once when the FIN
    /// completes (success or local error), or from `deinit` as
    /// a fallback if the pump is deallocated before drain has a
    /// chance to run. This guarantees a caller awaiting the FIN
    /// (e.g. `TcpDirectForwarder`) is never stranded.
    private var onDrainedCallback: (() -> Void)?

    init(
        connection: any NwConnectionLike,
        queue: DispatchQueue,
        lingerCloseDeadline: DispatchTimeInterval,
        onDrained: @escaping () -> Void,
        onTerminal: @escaping (Error) -> Void = { _ in }
    ) {
        self.connection = connection
        self.lingerCloseDeadline = lingerCloseDeadline
        self.onTerminal = onTerminal
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
                    "tcp egress write pump pendingBytes hwm=\(hwm) cap=\(writePumpMaxPendingBytes)"
                )
            }
        )
        self.core = core
        core.delegate = self
    }


    /// Same status contract as `TcpClientWritePump.enqueue`.
    @discardableResult
    func enqueue(_ data: Data) -> RamaTcpDeliverStatusBridge { core.enqueue(data) }

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
    func closeWhenDrained(_ onDrained: (() -> Void)? = nil) {
        core.queue.async { [weak self] in
            guard let self else {
                // Pump already gone — fire the callback so the
                // caller's state machine progresses.
                onDrained?()
                return
            }
            if self.core.isClosed() {
                // Core already closed: no FIN, so the linger watchdog that
                // normally cancels the connection was never armed. In
                // promoted mode `applyPromotedTerminal` delegates the cancel
                // to this pump, so cancel here or the connection (and the
                // graph anchored by its stateUpdateHandler) leaks. Safe — no
                // FIN to clip on a closed core — and idempotent.
                self.connection.cancelAndDetach()
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
            // External cancel makes any outstanding linger watchdog
            // moot — its only job is to force-cancel a connection
            // whose peer never closed, and that path has now been
            // pre-empted.
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

    deinit {
        // Fallback: if the pump is deallocated before drain
        // completes, fire the callback so the caller's state
        // machine isn't stranded. `deinit` runs synchronously
        // on whichever thread releases the last strong ref —
        // the callback contract doesn't promise a specific
        // queue, but for safety the caller should treat it as
        // "not necessarily on `core.queue`" and hop if needed.
        if let cb = onDrainedCallback {
            cb()
        }
    }
}

extension NwTcpConnectionWritePump: TcpWritePumpCoreDelegate {
    internal func pumpCore(_ core: TcpWritePumpCore, didTerminateWith error: Error) {
        // A terminal write error closes the core WITHOUT reaching
        // `pumpCoreDidFinishDraining` — so no FIN is sent and no linger
        // watchdog is armed. Two things must still happen, mirroring
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
        //     released. The FIN → linger watchdog sequence that normally
        //     owns connection teardown is skipped on the error path, and
        //     `fireTerminalLocked` deliberately does NOT cancel the
        //     connection (it delegates to that watchdog). The nastiest
        //     trigger makes this load-bearing: the transient-backpressure
        //     retry hard-deadline (`TcpWritePumpCore`) terminates while the
        //     NWConnection is still `.ready`, so the egress state handler
        //     never observes `.failed`/`.cancelled` and there is NO other
        //     teardown path. `cancelAndDetach` is idempotent and nils the
        //     state handler, so it won't re-enter teardown and any later
        //     cancel from `onTerminal` is a no-op.
        //
        // In `viaRust` mode `onDrainedCallback` is nil (the `onCloseEgress`
        // hook calls `closeWhenDrained()` with no callback) so step 1 is a
        // no-op there; the force-cancel is still correct — a terminal write
        // error means the egress is broken/abandoned either way.
        lingerWork?.cancel()
        lingerWork = nil
        connection.cancelAndDetach()
        if let cb = onDrainedCallback {
            onDrainedCallback = nil
            cb()
        }
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
    }

    internal func pumpCoreDidFinishDraining(_ core: TcpWritePumpCore) {
        // Snapshot the pending close-callback and clear the
        // slot BEFORE issuing the FIN send. We capture `cb`
        // strongly inside the `send` completion so the
        // callback fires regardless of whether `self` is
        // still alive when the completion lands.
        let cb = self.onDrainedCallback
        self.onDrainedCallback = nil
        guard connection.state == .ready else {
            // Can't FIN on a non-`.ready` connection (e.g. the path
            // dropped to `.waiting`). The promoted terminal path
            // (`TcpDirectForwarder.fireTerminalLocked`) delegates the
            // NWConnection cancel to the linger watchdog armed below —
            // which we skip in this branch — so force-cancel here.
            // Otherwise the connection (and the `connection → session →
            // ctx → connection` cycle + its NECP entry) leaks: a later
            // duplicate `.ready` even disarms the state handler's
            // tolerance teardown. `cancelAndDetach` is idempotent.
            connection.cancelAndDetach()
            cb?()
            return
        }
        // `.finalMessage` + `isComplete: true` is the documented way
        // to trigger a TCP half-close (FIN) on a `NWConnection`. Using
        // `.defaultMessage` only marks the logical message complete and
        // leaves the stream open — the peer would never observe a
        // half-close and the linger watchdog would have to escalate to
        // a force-cancel. See
        // <https://developer.apple.com/documentation/network/nwconnection/contentcontext/finalmessage>.
        connection.send(
            content: nil,
            contentContext: .finalMessage,
            isComplete: true,
            completion: .contentProcessed({ _ in
                // The FIN has been processed locally (queued
                // for transmission). Fire the close-callback
                // for the caller waiting on drain completion.
                cb?()
            })
        )
        // The FIN is queued. Schedule the linger watchdog so the
        // NWConnection registration is released even if the peer
        // never replies with its own FIN. `cancel()` is idempotent.
        //
        // Capture `connection` strongly: a promote teardown can
        // drop the per-flow ctx (and us with it) right after the
        // FIN send completes, well before the linger deadline —
        // `[weak self]` would no-op and leak the NWConnection.
        let conn = connection
        let work = DispatchWorkItem { [weak self] in
            conn.cancelAndDetach()
            self?.lingerWork = nil
        }
        lingerWork = work
        core.queue.asyncAfter(deadline: .now() + lingerCloseDeadline, execute: work)
    }
}
