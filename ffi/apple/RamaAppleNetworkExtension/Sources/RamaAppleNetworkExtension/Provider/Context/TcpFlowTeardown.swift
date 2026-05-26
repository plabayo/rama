import Foundation

/// Single source of truth for tearing down an intercepted TCP flow.
///
/// `TransparentProxyCore.handleTcpFlow` orchestrates a state machine
/// whose terminal-state transitions can race each other:
///
///   * the egress NWConnection state handler (`.failed` /
///     `.waiting` past tolerance / `.cancelled`)
///   * the connect-timeout work item
///   * the writer pump's `onTerminalError` closure
///   * the read pump's hard-error path
///   * `onServerClosed` → `closeWhenDrained` completion
///   * `flow.open` completion error
///   * external `engine.stop`
///
/// Every one of those used to inline its own teardown sequence
/// (close kernel flow R/W, cancel egress NWConnection, cancel each
/// pump, drive the direct forwarder, cancel the Rust session,
/// remove the per-flow registration). With seven sites the
/// sequences drifted — the audit on the 5-min stress trace
/// surfaced 1,177 `is already cancelled, ignoring cancel` Apple
/// log lines and 1,520 `flow is closed for writes` errors from
/// ordering mistakes, both feeding macOS's
/// `QUARANTINED DUE TO HIGH LOGGING VOLUME` fault on the system
/// extension.
///
/// This class makes the teardown a single method per
/// terminal-state shape, idempotent by construction via the
/// sticky `done` flag. All methods run on the per-flow
/// `DispatchQueue` (the same queue that owns every mutation of
/// `TcpFlowContext`'s pump / connection slots), so the
/// single-threaded `done` flag needs no lock.
///
/// **Scoping intent**: the class deliberately captures `ctx` and
/// `core` weakly. If the registry has already dropped the
/// context (e.g. a fast-path teardown won the race), the methods
/// no-op cleanly. The `flow` reference is strong — Apple owns
/// the kernel `NEAppProxyTCPFlow`'s lifecycle and releases the
/// reference graph (including us) once both sides are closed.
///
/// All `applyX` methods are no-ops on subsequent calls after the
/// first one. Choose the variant that names the state transition
/// that fired; the class encodes the exact pump / connection /
/// session shape each transition needs to clean up.
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

    /// System sleep arrived. Drop the flow rather than freeze it:
    /// NWConnections held across sleep usually wake up already
    /// `.failed`, and the kernel NECP entry behind them is gone.
    /// Distinct `domain` so traces can attribute the cause.
    func applySystemSleep() {
        let err = NSError(
            domain: "rama.tproxy.system-sleep", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "system entered sleep; flow dropped"])
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
