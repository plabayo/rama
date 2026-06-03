import Foundation

/// Drives the kernel-flow ↔ egress-NWConnection data path
/// directly, without any Rust hop, after a successful promote
/// cutover.
///
/// The forwarder is created in `.buffering` mode on the per-flow
/// `DispatchQueue` at the moment the in-Rust service calls
/// `PromoteHandle::into_passthrough`. From that moment on:
///
///  1. The read pumps are cancelled with carryover handlers
///     routing in-flight bytes (the `.paused` replay buffer plus
///     whatever any in-flight `readData` / `receive` callback
///     produces) into the forwarder's per-direction buffers.
///  2. The forwarder waits for Rust to fully unwind. Each
///     direction transitions from `.buffering` → `.active` when
///     the corresponding "Rust done" signal arrives:
///       * C → S: `markRustC2SDone()` (fired from the engine's
///         `onCloseEgress` once Rust has no more bytes to
///         enqueue to `egressWritePump`).
///       * S → C: `markRustS2CDone()` (fired from the engine's
///         `onServerClosed` once Rust has no more bytes to
///         enqueue to `clientWritePump`).
///  3. On the `.active` transition each direction flushes its
///     carryover/cutover buffer to the corresponding write pump
///     (FIFO after any tail Rust enqueued), then starts a direct
///     `flow.readData` / `connection.receive` loop that enqueues
///     to the write pump.
///  4. Each direction's read loop, on EOF/error, calls
///     `closeWhenDrained` on the matching write pump to send a
///     FIN; once both directions reach `.finished` the
///     forwarder calls `onTerminal()` so the registry can drop
///     the flow.
///
/// Concurrency: every method runs on `queue`. Tests construct
/// the forwarder with a private serial queue and then drive it
/// step-by-step, waiting on the queue's `sync` barrier between
/// state transitions.
///
/// Reachable from outside the file because `TcpFlowContext`
/// holds a reference and tests construct it directly with mocks.
final class TcpDirectForwarder: @unchecked Sendable {
    // ── Wiring ───────────────────────────────────────────────────

    private let flow: any TcpFlowReadable & TcpFlowWritable
    private let connection: any NwConnectionLike
    private let queue: DispatchQueue
    private let logger: (FlowLogMessage) -> Void
    /// Fired once both directions reach `.finished` (or the
    /// forwarder is externally cancelled). The registry uses
    /// this to remove the flow.
    private let onTerminal: () -> Void

    /// How long a direction may sit in `.finishing` (its write pump's
    /// `closeWhenDrained` pending) before the drain is declared wedged
    /// and the flow force-torn-down. Mirrors the `viaRust` path's
    /// `lingerCloseMs`. See `armC2SBackstopLocked`.
    private let drainStallDeadline: DispatchTimeInterval
    /// Fired (once, on `queue`) the first time either direction enters
    /// `.finishing`. Production sets `ctx.terminalSignalled` so the
    /// on-`stateQueue` maintenance watchdog can also reap this flow if
    /// `queue` later starves — the promoted-mode analogue of the
    /// `viaRust` terminal-signal bookkeeping.
    private let onClosing: () -> Void
    /// Fired (on `queue`) when a `.finishing` direction is still stuck
    /// `drainStallDeadline` later: the peer stopped reading, so the
    /// `closeWhenDrained` completion never arrived and the forwarder
    /// would otherwise never reach `.finished`. Production routes this
    /// to `ctx.teardown.applyDrainBackstop()` (a full teardown), the
    /// same reaper the `viaRust` backstop uses.
    private let onDrainStall: () -> Void

    // Existing per-flow write pumps. We do NOT take ownership —
    // tests can also hand in standalone pumps. The forwarder
    // enqueues to them; when its read direction hits EOF it
    // calls `closeWhenDrained` on the corresponding pump to
    // emit the FIN.
    private let clientWritePump: TcpClientWritePump
    private let egressWritePump: NwTcpConnectionWritePump

    // ── State ────────────────────────────────────────────────────

    /// One-direction phase. The forwarder tracks two of these.
    enum DirectionPhase: Equatable {
        /// Cutover in progress — Rust hasn't signalled "done"
        /// for this direction yet. Carryover bytes accumulate
        /// here; no read loop is running.
        case buffering
        /// Read loop active; bytes flow read-source → write
        /// pump → destination. No more Rust enqueues to the
        /// destination pump.
        case active
        /// Read side hit EOF/error; `closeWhenDrained` called
        /// on the destination write pump. Waiting for the FIN
        /// to flush.
        case finishing
        /// Both the read EOF and the pump's drain have been
        /// observed. Direction is fully wound down.
        case finished
    }

    /// `kernel → NWConnection` direction.
    private(set) var c2sPhase: DirectionPhase = .buffering
    /// `NWConnection → kernel` direction.
    private(set) var s2cPhase: DirectionPhase = .buffering

    /// Carryover + cutover-window buffer for the C→S direction.
    /// Bytes captured by `TcpClientReadPump.cancelForPromote`
    /// (the `.paused` replay buffer and any in-flight `readData`
    /// result). Flushed in FIFO order on the `.active`
    /// transition.
    private var c2sBuffer = ChunkQueue<Data>()
    /// Same for S→C — bytes captured by
    /// `NwTcpConnectionReadPump.cancelForPromote`.
    private var s2cBuffer = ChunkQueue<Data>()
    /// `true` if a carryover handler signalled EOF for this
    /// direction during the buffering phase (e.g. an in-flight
    /// `readData` returned `(nil, nil)`). On the `.active`
    /// transition we skip the read loop and go straight to
    /// `finishing` after draining the buffer.
    private var c2sEofBuffered: Bool = false
    private var s2cEofBuffered: Bool = false

    /// Set by `markClientReadDrained` / `markEgressReadDrained`
    /// after the cancelled-for-promote read pump has fired its
    /// `onComplete` barrier. Required before the forwarder may
    /// issue its OWN `flow.readData` / `connection.receive`,
    /// because `NEAppProxyTCPFlow.readData` / `NWConnection.receive`
    /// are caller-enforced serial — the in-flight read on the
    /// old pump MUST complete before a new one is issued.
    private var c2sReadDrained: Bool = false
    private var s2cReadDrained: Bool = false

    /// Guard against concurrent `flow.readData` calls
    /// (`NEAppProxyTCPFlow` is caller-enforced serial).
    private var inFlightRead: Bool = false
    /// Same role for `connection.receive`.
    private var inFlightReceive: Bool = false

    /// `true` while the egress (C→S) write pump has rejected a
    /// chunk with `.paused`. The forwarder stops issuing reads
    /// and holds the buffer head until the pump fires its drain
    /// callback (see `onEgressPumpDrained`). Without this, every
    /// `.paused` would silently drop bytes — same contract Rust's
    /// bridge honors in `viaRust` mode.
    private var c2sWritePaused: Bool = false
    /// S→C counterpart for the client write pump.
    private var s2cWritePaused: Bool = false

    /// `true` once `cancel()` has been called externally. All
    /// further state transitions are dropped — `onTerminal`
    /// fires exactly once.
    private var cancelled: Bool = false
    /// `true` once `onTerminal` has fired. Multiple
    /// `maybeFinish` calls collapse to one terminal callback.
    private var terminalFired: Bool = false

    /// Drain backstop per direction. Armed when the direction enters
    /// `.finishing`; cancelled when it reaches `.finished` (or on
    /// terminal). At most one timer per direction (nil-guarded).
    private var c2sBackstop: DispatchWorkItem?
    private var s2cBackstop: DispatchWorkItem?
    /// `onClosing` fired (once) for this forwarder.
    private var closingSignalled: Bool = false

    // ── Init ─────────────────────────────────────────────────────

    init(
        flow: any TcpFlowReadable & TcpFlowWritable,
        connection: any NwConnectionLike,
        clientWritePump: TcpClientWritePump,
        egressWritePump: NwTcpConnectionWritePump,
        queue: DispatchQueue,
        logger: @escaping (FlowLogMessage) -> Void,
        drainStallDeadline: DispatchTimeInterval = .milliseconds(Int(defaultLingerCloseMs)),
        onClosing: @escaping () -> Void = {},
        onDrainStall: @escaping () -> Void = {},
        onTerminal: @escaping () -> Void
    ) {
        self.flow = flow
        self.connection = connection
        self.clientWritePump = clientWritePump
        self.egressWritePump = egressWritePump
        self.queue = queue
        self.logger = logger
        self.drainStallDeadline = drainStallDeadline
        self.onClosing = onClosing
        self.onDrainStall = onDrainStall
        self.onTerminal = onTerminal
    }

    // ── Carryover sinks (called by cancelForPromote on the
    //    read pumps) ───────────────────────────────────────────────

    /// Sink for `TcpClientReadPump.cancelForPromote` — kernel
    /// reads in flight at cutover time. `.some(data)` appends
    /// to `c2sBuffer`; `.none` flags EOF for the C→S direction.
    ///
    /// Late carryover (sink fires AFTER `markRustC2SDone` has
    /// transitioned the direction to `.active`) is enqueued
    /// directly to the egress write pump. This preserves
    /// chronological FIFO order: the in-flight read produced
    /// bytes earlier in the kernel stream than anything the
    /// forwarder would have read; the read-loop barrier
    /// (`c2sReadDrained`) ensures the forwarder hasn't issued
    /// its own `readData` yet, so no out-of-order interleaving
    /// is possible.
    func acceptClientCarryover(_ payload: Data?) {
        queue.async {
            guard !self.cancelled else { return }
            switch self.c2sPhase {
            case .buffering:
                if let data = payload, !data.isEmpty {
                    self.c2sBuffer.pushBack(data)
                } else {
                    self.c2sEofBuffered = true
                }
            case .active:
                // Late carryover after the active transition.
                // `c2sReadDrained` was still false (we install
                // it via `markClientReadDrained` only AFTER the
                // pump's onComplete fires), so the forwarder
                // hasn't issued its own readData yet — the
                // pump's FIFO is preserved.
                if let data = payload, !data.isEmpty {
                    self.writeC2SLocked(data)
                } else {
                    self.c2sEofBuffered = true
                    if self.c2sBuffer.isEmpty && !self.c2sWritePaused {
                        self.finishC2SLocked()
                    }
                    // If buffer is non-empty or paused, finish
                    // fires from `flushC2SBufferLocked` once the
                    // buffer drains.
                }
            case .finishing, .finished:
                // Direction already wound down — drop.
                break
            }
        }
    }

    /// Sink for `NwTcpConnectionReadPump.cancelForPromote` —
    /// receives in flight at cutover time. See
    /// `acceptClientCarryover` for the late-arrival semantics.
    func acceptEgressCarryover(_ payload: Data?) {
        queue.async {
            guard !self.cancelled else { return }
            switch self.s2cPhase {
            case .buffering:
                if let data = payload, !data.isEmpty {
                    self.s2cBuffer.pushBack(data)
                } else {
                    self.s2cEofBuffered = true
                }
            case .active:
                if let data = payload, !data.isEmpty {
                    self.writeS2CLocked(data)
                } else {
                    self.s2cEofBuffered = true
                    if self.s2cBuffer.isEmpty && !self.s2cWritePaused {
                        self.finishS2CLocked()
                    }
                }
            case .finishing, .finished:
                break
            }
        }
    }

    /// Fires from the read pump's `cancelForPromote` `onComplete`
    /// barrier (C→S direction). Tells the forwarder: "the old
    /// `flow.readData` is fully drained — you may now issue your
    /// own". If the direction is already `.active`, this kicks
    /// off the read loop.
    func markClientReadDrained() {
        queue.async {
            guard !self.cancelled, !self.c2sReadDrained else { return }
            self.c2sReadDrained = true
            if self.c2sPhase == .active && !self.c2sEofBuffered {
                self.scheduleClientReadLocked()
            }
        }
    }

    /// S→C counterpart.
    func markEgressReadDrained() {
        queue.async {
            guard !self.cancelled, !self.s2cReadDrained else { return }
            self.s2cReadDrained = true
            if self.s2cPhase == .active && !self.s2cEofBuffered {
                self.scheduleServerReadLocked()
            }
        }
    }

    // ── Rust-done signals (called from mode-aware
    //    onServerClosed / onCloseEgress) ─────────────────────────

    /// Rust has stopped enqueueing to `egressWritePump` — it is
    /// now safe for the forwarder to enqueue C→S bytes (no
    /// risk of interleaving with Rust output).
    func markRustC2SDone() {
        queue.async { self.transitionC2SActiveLocked() }
    }

    /// Rust has stopped enqueueing to `clientWritePump`.
    func markRustS2CDone() {
        queue.async { self.transitionS2CActiveLocked() }
    }

    // ── External cancellation ────────────────────────────────────

    /// Force the forwarder to terminal state (e.g. engine
    /// shutdown, kernel flow hard-error from outside). Cancels
    /// both read loops; the write pumps and flow/connection
    /// lifecycle are NOT touched here — the caller owns them.
    /// `onTerminal` fires exactly once.
    func cancel() {
        queue.async {
            guard !self.cancelled else { return }
            self.cancelled = true
            self.c2sPhase = .finished
            self.s2cPhase = .finished
            self.fireTerminalLocked()
        }
    }

    // ── Internal: direction transitions ──────────────────────────

    private func transitionC2SActiveLocked() {
        guard !cancelled, c2sPhase == .buffering else { return }
        c2sPhase = .active
        flushC2SBufferLocked()
    }

    private func transitionS2CActiveLocked() {
        guard !cancelled, s2cPhase == .buffering else { return }
        s2cPhase = .active
        flushS2CBufferLocked()
    }

    // ── Internal: backpressure-aware write helpers ────────────────

    /// Append `data` to `c2sBuffer` and flush. Single entry point
    /// for every C→S write in the `.active` phase so the paused/
    /// buffered-replay logic lives in exactly one place.
    private func writeC2SLocked(_ data: Data) {
        c2sBuffer.pushBack(data)
        flushC2SBufferLocked()
    }

    /// S→C counterpart.
    private func writeS2CLocked(_ data: Data) {
        s2cBuffer.pushBack(data)
        flushS2CBufferLocked()
    }

    /// Drain `c2sBuffer` into `egressWritePump` until empty or
    /// the pump returns `.paused`. On `.paused`, leaves the chunk
    /// at the head of the buffer for replay from the pump's drain
    /// callback (`onEgressPumpDrained`). After full drain, fires
    /// EOF/read transitions.
    private func flushC2SBufferLocked() {
        guard !cancelled, c2sPhase == .active else { return }
        while let chunk = c2sBuffer.first() {
            let status = egressWritePump.enqueue(chunk)
            switch status {
            case .accepted:
                _ = c2sBuffer.popFront()
            case .paused:
                // Head stays in buffer. Pump's drain edge will
                // re-enter via `onEgressPumpDrained`.
                c2sWritePaused = true
                return
            case .closed:
                // Downstream gone — direction is effectively
                // dead. Skip the read loop, transition straight
                // to finishing → finished.
                finishC2SLocked()
                return
            }
        }
        c2sWritePaused = false
        if c2sEofBuffered {
            // Carryover handler already saw EOF — go straight
            // to FIN now that the buffer is drained.
            finishC2SLocked()
            return
        }
        // Gated on `c2sReadDrained`: the OLD read pump's
        // in-flight `flow.readData` MUST complete before we
        // issue our own. `markClientReadDrained` flips the
        // flag and re-enters this path.
        if c2sReadDrained && !inFlightRead {
            scheduleClientReadLocked()
        }
    }

    /// S→C counterpart.
    private func flushS2CBufferLocked() {
        guard !cancelled, s2cPhase == .active else { return }
        while let chunk = s2cBuffer.first() {
            let status = clientWritePump.enqueue(chunk)
            switch status {
            case .accepted:
                _ = s2cBuffer.popFront()
            case .paused:
                s2cWritePaused = true
                return
            case .closed:
                finishS2CLocked()
                return
            }
        }
        s2cWritePaused = false
        if s2cEofBuffered {
            finishS2CLocked()
            return
        }
        if s2cReadDrained && !inFlightReceive {
            scheduleServerReadLocked()
        }
    }

    // ── Pump drain hooks ─────────────────────────────────────────

    /// Called from `egressWritePump`'s drain edge (routed via
    /// `TcpFlowContext.directForwarder`). Replays whatever the
    /// pump rejected with `.paused` and resumes reads when the
    /// buffer is drained.
    func onEgressPumpDrained() {
        queue.async {
            guard !self.cancelled, self.c2sWritePaused else { return }
            self.flushC2SBufferLocked()
        }
    }

    /// S→C counterpart for `clientWritePump`.
    func onClientPumpDrained() {
        queue.async {
            guard !self.cancelled, self.s2cWritePaused else { return }
            self.flushS2CBufferLocked()
        }
    }

    // ── Internal: direct read loops ──────────────────────────────

    /// Issue the next `flow.readData`. Must run on `queue`. If
    /// the C→S direction is not `.active`, or the write pump is
    /// holding a paused chunk, no-op.
    private func scheduleClientReadLocked() {
        guard !cancelled, c2sPhase == .active,
              !inFlightRead, !c2sWritePaused else { return }
        inFlightRead = true
        flow.readData { [weak self] data, error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self else { return }
                self.inFlightRead = false
                guard !self.cancelled, self.c2sPhase == .active else { return }
                if let error {
                    self.logger(classifyFlowCallbackError(
                        error, operation: "direct flow.read"))
                    self.finishC2SLocked()
                    return
                }
                guard let data, !data.isEmpty else {
                    // Kernel half-closed C→S.
                    self.finishC2SLocked()
                    return
                }
                // Route through the unified write path so a
                // `.paused` response buffers the rejected chunk
                // instead of dropping it.
                self.writeC2SLocked(data)
            }
        }
    }

    private func scheduleServerReadLocked() {
        guard !cancelled, s2cPhase == .active,
              !inFlightReceive, !s2cWritePaused else { return }
        inFlightReceive = true
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self else { return }
                self.inFlightReceive = false
                guard !self.cancelled, self.s2cPhase == .active else { return }
                if let data, !data.isEmpty {
                    self.writeS2CLocked(data)
                }
                if isComplete || error != nil {
                    // EOF/error: mark the terminal flag and let
                    // the flush function finish once the buffer
                    // drains. If the buffer is empty and we're
                    // not paused, finish now.
                    self.s2cEofBuffered = true
                    if self.s2cBuffer.isEmpty && !self.s2cWritePaused {
                        self.finishS2CLocked()
                    }
                    return
                }
                // Normal read continues only if we're not paused
                // — the guard in `scheduleServerReadLocked`
                // would no-op in that case anyway, but skipping
                // the call avoids the redundant scheduling.
                if !self.s2cWritePaused {
                    self.scheduleServerReadLocked()
                }
            }
        }
    }

    // ── Internal: direction finish ───────────────────────────────

    /// Transition C→S to `.finishing`: send FIN via the egress
    /// write pump and wait for the drain to actually complete
    /// before marking `.finished`. This is load-bearing for
    /// NWConnection lifecycle hygiene — firing terminal
    /// (and consequently dropping the per-flow ctx) BEFORE
    /// the pump's drain → FIN sequence completes risked the
    /// pump being deallocated mid-flight, losing the FIN, and
    /// leaving the NWConnection registration parked in the
    /// system until the linger watchdog or OS reaps it.
    ///
    /// `closeWhenDrained`'s completion ALWAYS fires (after
    /// FIN send completion, on external cancel, or as a
    /// `deinit` fallback) so the state machine cannot stall.
    private func finishC2SLocked() {
        guard !cancelled, c2sPhase != .finishing, c2sPhase != .finished else {
            return
        }
        c2sPhase = .finishing
        armC2SBackstopLocked()
        egressWritePump.closeWhenDrained { [weak self] in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self else { return }
                self.c2sBackstop?.cancel()
                self.c2sBackstop = nil
                self.c2sPhase = .finished
                self.maybeFireTerminalLocked()
            }
        }
    }

    private func finishS2CLocked() {
        guard !cancelled, s2cPhase != .finishing, s2cPhase != .finished else {
            return
        }
        s2cPhase = .finishing
        armS2CBackstopLocked()
        // `TcpClientWritePump.closeWhenDrained` takes a
        // callback. Use it to detect drain completion so the
        // terminal-fire is paced by the pump's actual close.
        clientWritePump.closeWhenDrained { [weak self] _ in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self else { return }
                self.s2cBackstop?.cancel()
                self.s2cBackstop = nil
                self.s2cPhase = .finished
                self.maybeFireTerminalLocked()
            }
        }
    }

    // ── Internal: drain backstop ─────────────────────────────────

    /// First entry into `.finishing` (either direction) signals the
    /// owner that the flow is closing. Mirrors the `viaRust` path
    /// setting `ctx.terminalSignalled` so the maintenance watchdog can
    /// reap a `queue`-starved promoted flow too.
    private func signalClosingLocked() {
        guard !closingSignalled else { return }
        closingSignalled = true
        onClosing()
    }

    /// Arm the C→S drain backstop. A direction still in `.finishing`
    /// `drainStallDeadline` later has a wedged drain (the peer stopped
    /// reading → the egress `connection.send` completion never fired →
    /// `closeWhenDrained` never completed). Force a full teardown so
    /// the per-flow graph can't orphan. The same-direction `.finishing`
    /// re-check means a direction that drained cleanly (reached
    /// `.finished`) never triggers it — so a half-close that leaves the
    /// OTHER direction legitimately active is untouched.
    private func armC2SBackstopLocked() {
        signalClosingLocked()
        guard c2sBackstop == nil else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.cancelled, !self.terminalFired,
                self.c2sPhase == .finishing
            else { return }
            self.logger(
                FlowLogMessage(
                    level: .debug,
                    text:
                        "promote forwarder C→S drain backstop fired; forcing teardown (peer not draining)"
                ))
            self.onDrainStall()
        }
        c2sBackstop = work
        queue.asyncAfter(deadline: .now() + drainStallDeadline, execute: work)
    }

    /// S→C counterpart of `armC2SBackstopLocked`.
    private func armS2CBackstopLocked() {
        signalClosingLocked()
        guard s2cBackstop == nil else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self, !self.cancelled, !self.terminalFired,
                self.s2cPhase == .finishing
            else { return }
            self.logger(
                FlowLogMessage(
                    level: .debug,
                    text:
                        "promote forwarder S→C drain backstop fired; forcing teardown (peer not draining)"
                ))
            self.onDrainStall()
        }
        s2cBackstop = work
        queue.asyncAfter(deadline: .now() + drainStallDeadline, execute: work)
    }

    private func maybeFireTerminalLocked() {
        guard !terminalFired else { return }
        guard c2sPhase == .finished, s2cPhase == .finished else { return }
        fireTerminalLocked()
    }

    private func fireTerminalLocked() {
        guard !terminalFired else { return }
        terminalFired = true
        // Any pending drain backstop is moot now.
        c2sBackstop?.cancel()
        c2sBackstop = nil
        s2cBackstop?.cancel()
        s2cBackstop = nil
        // Do NOT cancel the NWConnection here — the egress
        // write pump's `beginDraining` → FIN → linger watchdog
        // sequence handles connection lifecycle. Cancelling
        // pre-emptively short-circuits the FIN flush. The
        // forwarder's owner (`onTerminal`) is responsible for
        // any further cleanup (close kernel flow, remove from
        // registry).
        onTerminal()
    }
}
