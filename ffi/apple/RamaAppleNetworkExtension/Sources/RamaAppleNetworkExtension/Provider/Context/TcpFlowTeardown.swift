import Foundation

/// Single source of truth for tearing down an intercepted TCP flow.
///
/// Several terminal-state transitions can race each other (egress
/// NWConnection `.failed`/`.waiting`/`.cancelled`, connect timeout,
/// writer/read pump errors, `closeWhenDrained` completion, `flow.open`
/// error, external `engine.stop`). Inlining a teardown sequence at
/// each site let the sequences drift, which produced double-cancel /
/// "flow is closed for writes" log spam under stress. This class
/// consolidates them into one idempotent method per terminal-state
/// shape (sticky `done` flag). All methods run on the per-flow
/// `DispatchQueue` that owns `TcpFlowContext`'s slots, so `done`
/// needs no lock.
///
/// Scoping: `ctx`/`core` are captured weakly (a fast-path teardown
/// that already dropped the context makes the methods no-op), `flow`
/// strongly (Apple owns the kernel `NEAppProxyTCPFlow` lifecycle).
/// Choose the `applyX` variant naming the transition that fired.
final class TcpFlowTeardown: @unchecked Sendable {
    /// Weak: a fast-path teardown that already removed the
    /// context from the registry must not be re-pinned by a
    /// later closure firing.
    private weak var ctx: TcpFlowContext?
    /// Weak: don't pin the core past `detachEngine`.
    private weak var core: TransparentProxyCore?
    /// Strong: see scoping intent on the class doc.
    private let flow: any TcpFlowLike
    private let flowId: ObjectIdentifier
    /// Sticky one-shot. Mutated and read only on the per-flow
    /// queue (single-threaded by construction).
    private var done = false

    init(
        ctx: TcpFlowContext,
        core: TransparentProxyCore,
        flow: any TcpFlowLike,
        flowId: ObjectIdentifier
    ) {
        self.ctx = ctx
        self.core = core
        self.flow = flow
        self.flowId = flowId
    }

    /// Has the first terminal-state path already run? Test-facing
    /// signal so an XCTest can assert that the idempotency guard
    /// fires for racing teardown paths.
    var isDone: Bool { done }

    // MARK: - Pre-open terminal states

    /// Egress NWConnection went to `.failed` before reaching
    /// `.ready`. No kernel flow open, no pumps wired. The minimal
    /// cleanup: cancel + detach the connection, cancel the
    /// session, remove from the registry.
    func applyPreReadyFailure() {
        applyPreOpenCleanup()
    }

    /// Connect-timeout fire (the dispatched `DispatchWorkItem` ran
    /// before the egress reached `.ready`). Symmetric of
    /// `applyPreReadyFailure`.
    func applyConnectTimeout() {
        applyPreOpenCleanup()
    }

    /// Pre-ready `.waiting` exceeded its budget (path down at connect).
    /// Pre-open cleanup; distinct name for trace attribution.
    func applyPreReadyWaitingTimeout() {
        applyPreOpenCleanup()
    }

    /// System-wake reconcile of a still-connecting egress (its NECP
    /// flow is gone post-sleep). Pre-open cleanup — never opened.
    func applySystemWake() {
        applyPreOpenCleanup()
    }

    /// Shared body for the two pre-open shapes: nothing was
    /// queued, nothing to drain, no pumps to cancel.
    private func applyPreOpenCleanup() {
        guard !done else { return }
        done = true
        ctx?.connection?.cancelAndDetach()
        ctx?.connection = nil
        ctx?.session?.cancel()
        core?.removeTcpFlow(flowId)
    }

    // MARK: - Post-open writer-self-terminal

    /// `TcpClientWritePump.onTerminalError` fired: the writer
    /// exhausted its retry budget or hit a non-transient error.
    /// Closes the kernel flow with the writer's error, cancels
    /// the egress NWConnection, cancels the session. Other pumps
    /// are NOT explicitly cancelled — the NWConnection cancel
    /// surfaces in their read loops' error paths as the
    /// canonical signal to unwind. Matches the historic
    /// behaviour, kept verbatim so this refactor is purely a
    /// consolidation.
    func applyWriterTerminal(_ error: Error) {
        guard !done else { return }
        done = true
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
        ctx?.connection?.cancelAndDetach()
        ctx?.connection = nil
        ctx?.session?.cancel()
        core?.removeTcpFlow(flowId)
    }

    // MARK: - Post-open natural close

    /// `onServerClosed → closeWhenDrained` completion path: the
    /// Rust session signalled server EOF and the client write
    /// pump finished draining its queue. Close the kernel flow
    /// with `nil` (a clean EOF) when the flow was actually
    /// opened; with `upstreamUnavailable` when it never reached
    /// the open state.
    ///
    /// Deliberately does NOT cancel the Rust session — the
    /// session already drove the EOF, so cancelling it here
    /// is a no-op that just adds log noise. Matches the
    /// historic shape.
    func applyDrainedClose(wasOpened: Bool) {
        guard !done else { return }
        done = true
        if wasOpened {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        } else {
            let error = tcpUpstreamUnavailableError()
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
        }
        ctx?.connection?.cancelAndDetach()
        ctx?.connection = nil
        core?.removeTcpFlow(flowId)
    }

    /// The promoted direct forwarder reached its natural terminal (both
    /// directions finished). Distinct from `applyDrainedClose`: in
    /// `.promoted` mode the egress NWConnection's FIN/linger is owned by the
    /// egress write pump (it holds its OWN ref and force-cancels via its
    /// linger watchdog), so we MUST NOT cancel the connection or the write
    /// pump here — that would abort the FIN. What we DO:
    ///   - mark `done`, so a post-terminal `checkWakeDeadPath` / maintenance
    ///     watchdog (which can still observe this ctx during the window
    ///     before the async `removeTcpFlow` lands) no-ops instead of running
    ///     a second, connection-cancelling full teardown;
    ///   - detach the connection's handlers (break the connection→session
    ///     retain cycle now rather than waiting for the linger watchdog; the
    ///     write pump drives FIN via its own ref and uses neither handler);
    ///   - remove the registry entry, close the kernel flow clean.
    /// We deliberately do NOT nil `ctx.directForwarder` here: the forwarder
    /// has no strong back-ref to the ctx (its callbacks capture `[weak ctx]`),
    /// so it drops naturally when the ctx leaves the registry — and niling it
    /// in this callback would race observers that read its terminal phase.
    /// Idempotent via `done`. Replaces the prior inline cleanup in
    /// `beginPromoteCutover`'s `onTerminal`, which skipped `done` and so left
    /// a stale-live window.
    func applyPromotedTerminal() {
        guard !done else { return }
        done = true
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        // Detach handlers WITHOUT cancelling — see doc above.
        ctx?.connection?.stateUpdateHandler = nil
        ctx?.connection?.viabilityUpdateHandler = nil
        ctx?.connection = nil
        core?.removeTcpFlow(flowId)
    }

    // MARK: - Post-open full teardown

    /// Egress NWConnection went to `.failed` after `.ready`, or
    /// stayed in `.waiting` past the tolerance window. Full
    /// teardown of all pumps, the connection, the direct
    /// forwarder (if in `.promoted` mode), and the session.
    ///
    /// `error` may be `nil`; we synthesize a descriptive
    /// `NSError` so the kernel flow's close carries some signal
    /// downstream.
    func applyPostReadyFailure(_ error: Error?) {
        let nsErr =
            error
            ?? NSError(
                domain: "rama.tproxy.tcp",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey: "egress NWConnection terminated post-ready"
                ]
            )
        applyFullTeardown(error: nsErr, driveForwarder: true)
    }

    /// `flow.open` itself errored after the egress reached
    /// `.ready`. Pumps are partially wired (writer + egress R/W)
    /// but `clientReadPump` is not yet attached. Full teardown
    /// with that nuance — the direct forwarder cannot exist yet
    /// (promote callback registration happens AFTER the read
    /// loop is armed).
    func applyFlowOpenFailure(_ error: Error) {
        applyFullTeardown(error: error, driveForwarder: false)
    }

    /// Read pump reported a non-recoverable error after the
    /// kernel flow was open. Symmetric of
    /// `applyPostReadyFailure`, but originated from the read
    /// side.
    func applyReadHardError(_ error: Error) {
        applyFullTeardown(error: error, driveForwarder: true)
    }

    /// Engine is being detached (stopProxy / re-attach). Drop the flow:
    /// the egress NWConnection must be cancelled here, otherwise its
    /// `stateUpdateHandler` keeps the per-flow graph alive and the
    /// Rust→Swift close callbacks are suppressed once the engine is
    /// gone — leaking the connection (and its NECP entry) until process
    /// exit. Distinct `domain` so traces can attribute the cause.
    func applyEngineDetached() {
        let err = NSError(
            domain: "rama.tproxy.engine-detached", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "engine detached; flow dropped"])
        applyFullTeardown(error: err, driveForwarder: true)
    }

    /// The graceful close path (`onServerClosed`/`onCloseEgress` →
    /// `closeWhenDrained` → `applyDrainedClose` / the egress drain)
    /// stalled past its backstop: the peer stopped reading, so the
    /// in-flight `flow.write` / `connection.send` completion never fired,
    /// the pump never finished draining, and the drain-gated teardown
    /// never ran. Force a full teardown so the per-flow graph (egress
    /// write pump's queued `Data`, its dispatch continuations, the
    /// `flowQueue`, and the egress `NWConnection`) can't orphan.
    /// Idempotent via `done`, so a graceful close that beat the backstop
    /// wins and this no-ops. Driven by the per-flow
    /// `TcpFlowSession.armTerminalDrainBackstop` timer or, if that queue
    /// is starved, by the on-`stateQueue` maintenance watchdog. Distinct
    /// `domain` for trace attribution.
    func applyDrainBackstop() {
        let err = NSError(
            domain: "rama.tproxy.drain-backstop", code: -1,
            userInfo: [
                NSLocalizedDescriptionKey: "graceful close drain stalled; flow force-dropped"
            ])
        applyFullTeardown(error: err, driveForwarder: true)
    }

    /// The post-wake reconcile found this established flow's egress path no
    /// longer viable after the settle window (`viabilityUpdateHandler` last
    /// reported `false`): the system tore the path down across a
    /// network-changing sleep, but the `NWConnection` stayed `.ready` over
    /// the dead path, so neither `.waiting` nor `.failed` fired and the
    /// per-flow `handleEgressState` reaper never ran. Without this the flow
    /// would wedge until the 60s maintenance watchdog. Full teardown so the
    /// client (e.g. Chrome reusing a stale HTTP/2 connection to a Google
    /// host) gets a prompt reset and reconnects instead of hanging.
    /// Idempotent via `done`, so a connection that DID report
    /// `.failed`/`.waiting` (or closed gracefully) in the settle window
    /// wins and this no-ops. Distinct `domain` for trace attribution.
    func applyWakeDeadPath() {
        let err = NSError(
            domain: "rama.tproxy.wake-dead-path", code: -1,
            userInfo: [
                NSLocalizedDescriptionKey:
                    "established egress path not satisfied after system wake; flow reset"
            ])
        applyFullTeardown(error: err, driveForwarder: true)
    }

    /// Shared body for full teardowns.
    ///
    /// **Order matters** — pump cancel BEFORE kernel flow close:
    /// `TcpClientWritePump.cancel()` publishes
    /// `state.closed = true` synchronously in
    /// `TcpWritePumpCore.prepareCancel`, so any in-flight or
    /// queued `flow.write` short-circuits before reaching the
    /// kernel. Reversing the order is what produced 1,520
    /// `(N): flow is closed for writes, cannot write K bytes of
    /// data` libnetworkextension errors per 5 min of stress
    /// traffic before this refactor.
    private func applyFullTeardown(error: Error, driveForwarder: Bool) {
        guard !done else { return }
        done = true
        // 1. Cancel the client writer FIRST — publishes
        //    `closed = true` synchronously so no further
        //    `flow.write` reaches the now-being-closed kernel
        //    flow.
        ctx?.clientWritePump?.cancel()
        // 2. Close the kernel flow.
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
        // 3. Tear down the egress connection.
        ctx?.connection?.cancelAndDetach()
        ctx?.connection = nil
        // 4. Cancel the remaining pumps.
        ctx?.egressReadPump?.cancel()
        ctx?.egressReadPump = nil
        ctx?.egressWritePump?.cancel()
        ctx?.egressWritePump = nil
        ctx?.clientReadPump = nil
        ctx?.clientWritePump = nil
        // 5. Drive the direct forwarder to terminal (if any).
        //    In `.promoted` mode the forwarder owns the data
        //    path; without this, its read loops would unwind
        //    via their own error paths non-deterministically.
        if driveForwarder {
            ctx?.directForwarder?.cancel()
            ctx?.directForwarder = nil
        }
        // 6. Cancel the Rust session handle.
        ctx?.session?.cancel()
        // 7. Drop the per-flow registry entry.
        core?.removeTcpFlow(flowId)
    }
}
