import Foundation
import Network

/// `@unchecked Sendable` because every mutable field is read or written
/// only from a block executing on the flow's dedicated serial
/// `flowQueue`. The type system cannot see this invariant; the
/// annotation makes it explicit so the per-flow closures that capture
/// the context (flow.open / connection.receive completions, etc.) stay
/// Swift-6-clean instead of forcing those closures to drop their
/// `@Sendable` requirement.
/// Per-flow data-path mode. Switches from `.viaRust` to
/// `.promoted` when the in-Rust service calls
/// `PromoteHandle::into_passthrough` — from that moment on
/// the per-flow `TcpDirectForwarder` owns the kernel flow and
/// the egress `NWConnection`.
///
/// Mode-aware close handlers (`onServerClosed`, `onCloseEgress`)
/// use `mode != .viaRust` to skip teardown of the kernel flow /
/// egress connection — they are owned by the forwarder until
/// both directions finish.
///
/// Internally the forwarder distinguishes its OWN per-direction
/// phases (buffering / active / finishing / finished) — see
/// `TcpDirectForwarder.DirectionPhase`. Carrying that granularity
/// on `TcpFlowContext.mode` too would be redundant: every other
/// caller only cares about the binary "is the forwarder running
/// or not" question, and the forwarder is the source of truth
/// for the finer states.
enum TcpFlowMode {
    /// Bytes flow through the in-Rust service (default).
    case viaRust
    /// Promote cutover initiated. The `TcpDirectForwarder`
    /// owns the kernel flow and the egress NWConnection
    /// lifecycle from this point. Mode-aware close handlers
    /// observe this and skip their own teardown.
    case promoted
}

final class TcpFlowContext: @unchecked Sendable {
    // Connection is held behind the injectable protocol so unit tests
    // can drive the per-flow state machine via a mock instead of
    // standing up a real NWConnection.
    weak var session: RamaTcpSessionHandle?
    /// Egress NWConnection, reachable from late callbacks that must
    /// still be able to `cancel()` the flow.
    var connection: (any NwConnectionLike)?
    /// Read pumps reachable from the Rust → Swift demand callbacks.
    var clientReadPump: TcpClientReadPump?
    var egressReadPump: NwTcpConnectionReadPump?
    /// Writer pumps retained until terminal teardown so we can
    /// cancel them from dispatcher-owned close paths.
    var clientWritePump: TcpClientWritePump?
    var egressWritePump: NwTcpConnectionWritePump?
    /// Egress `NWConnection` reached `.ready`. Set on `flowQueue`; read
    /// off-queue by the stop-the-world wake reconcile (same relaxation
    /// the sleep teardown already relies on).
    var egressReady = false
    /// True once the egress has reached `.ready` by EITHER our processed
    /// `egressReady` flag OR the live `connection.state` (NW's truth).
    ///
    /// Used by the two PRE-READY reapers that READ `egressReady` from a
    /// block a `.ready` callback can be queued BEHIND — the
    /// `handleSystemWake` pre-ready reset and the maintenance watchdog
    /// pre-ready kick. FIFO state dispatch does NOT help them: it orders the
    /// `.ready` *handler* vs other `flowQueue` work, but if that handler is
    /// still queued behind the reconcile block, `egressReady` is stale
    /// `false` when the block runs — so it would reap a flow that already
    /// reached `.ready`. Consulting `connection.state` closes that window.
    ///
    /// The four TIMER sites (connect timeout, pre-ready / post-ready
    /// waiting) do NOT need this: a `.ready` runs FIFO and *cancels* the
    /// timer before it fires, so plain `egressReady` suffices there.
    var hasReachedReady: Bool {
        egressReady || connection?.state == .ready
    }
    /// Latest viability reported by the egress `NWConnection`'s
    /// `viabilityUpdateHandler`. `false` means Network.framework decided
    /// the path can't carry traffic (torn down across a network change /
    /// sleep). The post-wake reconcile reads this (instead of allocating a
    /// fresh `currentPath` snapshot per read) to decide whether an
    /// established flow stranded on a dead path should be reset. Defaults
    /// `true` so a flow we have no signal about is never reset. Mutated on
    /// `flowQueue`; read off-queue by `checkWakeDeadPath` (same relaxation
    /// as `egressReady`).
    var lastPathViable = true
    /// A terminal close signal (server EOF / egress close, `viaRust`
    /// mode) was observed on `flowQueue` and the graceful drain +
    /// teardown was kicked off. Set on `flowQueue`; read off-queue by the
    /// periodic maintenance watchdog (same relaxation as `egressReady`).
    /// A flow still in the registry a maintenance tick after this is set
    /// has a wedged drain (the peer stopped reading, so the in-flight
    /// `flow.write` / `connection.send` completion never fired and
    /// `closeWhenDrained` never finished) and is force-torn-down — see
    /// `TcpFlowSession.armTerminalDrainBackstop` /
    /// `TransparentProxyCore.collectMaintenanceKicksLocked`.
    var terminalSignalled = false
    /// Effective graceful-close linger budget for this flow (from the
    /// egress connect options, else `defaultLingerCloseMs`). Set once by
    /// `TcpFlowSession.startEgressConnection`; read by
    /// `beginPromoteCutover` to size the promoted forwarder's drain
    /// backstop so it matches the `viaRust` path's
    /// `TcpFlowSession.armTerminalDrainBackstop` budget.
    var lingerCloseMs: UInt32 = defaultLingerCloseMs
    /// Mode of the per-flow data path. Mutated only on the
    /// per-flow `DispatchQueue`. See [`TcpFlowMode`].
    var mode: TcpFlowMode = .viaRust
    /// Active when `mode == .promoted`. Owns the kernel ↔
    /// NWConnection direct read/write loops + cutover
    /// buffer.
    var directForwarder: TcpDirectForwarder?
    /// Monotonic timestamp (`DispatchTime`, mach-uptime — pauses during
    /// system sleep, like the engine's tokio idle timers) of the last byte
    /// observed on the promoted (`TcpDirectForwarder`) data path. Bumped by
    /// the forwarder's `onActivity` hook on `flowQueue`; read off-queue by the
    /// maintenance watchdog (same relaxation as `egressReady` /
    /// `terminalSignalled`). A promoted flow idle past
    /// `defaultPromotedIdleTimeoutMs` is reaped by `applyIdleTimeout`.
    ///
    /// Restores the idle backstop a flow already had on the `viaRust` path
    /// (the Rust engine's `DEFAULT_TCP_IDLE_TIMEOUT`, also byte-progress
    /// based) but LOST at promote cutover: once promoted, the Rust service
    /// task exits and its idle timer is gone, so without this an established
    /// promoted flow whose peer goes silent — yet stays TCP-alive, so
    /// keepalive never fails it — pins its egress `NWConnection`'s kernel
    /// nexus-flow slot forever. Defaults to creation time so a flow that
    /// promotes and never transfers is still reaped on schedule.
    var lastActivityAt: DispatchTime = .now()
    /// The per-flow serial queue that confines every mutation of this
    /// context (and the `isDone` teardown flag). Set once by
    /// `TcpFlowSession.init`. Lifecycle paths that originate off this
    /// queue — system sleep/wake and engine detach — dispatch their
    /// teardown onto it so it stays single-threaded with the kernel /
    /// NWConnection callbacks rather than racing them.
    var flowQueue: DispatchQueue?

    // MARK: - Teardown

    /// The kernel flow, type-erased. Set by `TcpFlowSession.init` for a
    /// real flow; `nil` for registry-only test contexts that never drive
    /// `applyX`. The teardown methods below close it.
    var flow: (any TcpFlowLike)?
    /// Owning core (weak: don't pin it past `detachEngine`). Set by
    /// `TcpFlowSession.init`.
    weak var core: TransparentProxyCore?
    /// Registry key, so the teardown methods can remove themselves.
    var flowId: ObjectIdentifier?
    /// Sticky one-shot teardown guard. Mutated and read only on
    /// `flowQueue` (single-threaded by construction), so it needs no lock.
    private(set) var isDone = false

    init() {
    }

    // ── Teardown (folded in from the former `TcpFlowTeardown`) ──────────
    //
    // Several terminal-state transitions race each other (egress
    // `.failed`/`.waiting`/`.cancelled`, connect timeout, writer/read pump
    // errors, `closeWhenDrained` completion, `flow.open` error, external
    // `engine.stop`). Each `applyX` is one idempotent variant per terminal
    // shape; the sticky `isDone` flag collapses races. All run on `flowQueue`.

    // MARK: Pre-open terminal states

    /// Egress NWConnection went to `.failed` before reaching `.ready`. No
    /// kernel flow open, no pumps wired. Reject the claimed flow, cancel +
    /// detach the connection, cancel the session, remove from the registry.
    func applyPreReadyFailure() { applyPreOpenCleanup() }

    /// Connect-timeout fire (the dispatched work item ran before the egress
    /// reached `.ready`). Symmetric of `applyPreReadyFailure`.
    func applyConnectTimeout() { applyPreOpenCleanup() }

    /// Pre-ready `.waiting` exceeded its budget (path down at connect).
    /// Pre-open cleanup; distinct name for trace attribution.
    func applyPreReadyWaitingTimeout() { applyPreOpenCleanup() }

    /// System-wake reconcile of a still-connecting egress (its NECP flow is
    /// gone post-sleep). Pre-open cleanup — never opened.
    func applySystemWake() { applyPreOpenCleanup() }

    /// Shared body for the pre-open shapes: nothing queued, no pumps.
    ///
    /// Closes the kernel flow with an error: we claimed it (`handleNewFlow`
    /// returned `true`) but never `flow.open()`-ed it, and per Apple's
    /// `NEAppProxyFlow` contract a claimed flow must be opened or closed —
    /// dropping it strands the app's `connect()` until its own timeout.
    /// Rejecting it (as the `blocked` path does) fails the connect fast so
    /// the app can retry; matters most for the `applySystemWake` reap.
    private func applyPreOpenCleanup() {
        guard !isDone else { return }
        isDone = true
        let err = tcpUpstreamUnavailableError()
        flow?.closeReadWithError(err)
        flow?.closeWriteWithError(err)
        connection?.cancelAndDetach()
        connection = nil
        session?.cancel()
        if let flowId { core?.removeTcpFlow(flowId) }
    }

    // MARK: Post-open writer-self-terminal

    /// `TcpClientWritePump.onTerminalError` fired: the writer exhausted its
    /// retry budget or hit a non-transient error. Closes the kernel flow,
    /// cancels the egress NWConnection + session. Other pumps are NOT
    /// explicitly cancelled — the NWConnection cancel surfaces in their read
    /// loops as the canonical unwind signal.
    func applyWriterTerminal(_ error: Error) {
        guard !isDone else { return }
        isDone = true
        flow?.closeReadWithError(error)
        flow?.closeWriteWithError(error)
        connection?.cancelAndDetach()
        connection = nil
        session?.cancel()
        if let flowId { core?.removeTcpFlow(flowId) }
    }

    // MARK: Post-open natural close

    /// `onServerClosed → closeWhenDrained` completion: the Rust session
    /// signalled server EOF and the client write pump drained. Close the
    /// kernel flow clean (`nil`) when it was opened, else with
    /// `upstreamUnavailable`. Does NOT cancel the Rust session — it already
    /// drove the EOF.
    func applyDrainedClose(wasOpened: Bool) {
        guard !isDone else { return }
        isDone = true
        if wasOpened {
            flow?.closeReadWithError(nil)
            flow?.closeWriteWithError(nil)
        } else {
            let error = tcpUpstreamUnavailableError()
            flow?.closeReadWithError(error)
            flow?.closeWriteWithError(error)
        }
        connection?.cancelAndDetach()
        connection = nil
        if let flowId { core?.removeTcpFlow(flowId) }
    }

    /// The promoted forwarder reached its natural terminal (both directions
    /// finished). Unlike `applyDrainedClose`, in `.promoted` mode the egress
    /// NWConnection's FIN/linger is owned by the egress write pump, so we
    /// MUST NOT cancel the connection here — that would abort the FIN. We
    /// mark `isDone` (so a racing wake-recheck / watchdog no-ops), detach the
    /// connection's handlers, drop the registry entry, and close the kernel
    /// flow clean. We deliberately do NOT nil `directForwarder` (its
    /// callbacks capture `[weak ctx]`, so it drops when the ctx leaves the
    /// registry; niling here would race observers reading its phase).
    func applyPromotedTerminal() {
        guard !isDone else { return }
        isDone = true
        flow?.closeReadWithError(nil)
        flow?.closeWriteWithError(nil)
        connection?.stateUpdateHandler = nil
        connection?.viabilityUpdateHandler = nil
        connection = nil
        if let flowId { core?.removeTcpFlow(flowId) }
    }

    // MARK: Post-open full teardown

    /// Egress NWConnection went to `.failed` after `.ready`, or stayed
    /// `.waiting` past tolerance. Full teardown. `error` may be `nil`; we
    /// synthesize a descriptive one so the kernel flow's close carries signal.
    func applyPostReadyFailure(_ error: Error?) {
        let nsErr =
            error
            ?? NSError(
                domain: "rama.tproxy.tcp", code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey: "egress NWConnection terminated post-ready"
                ])
        applyFullTeardown(error: nsErr, driveForwarder: true)
    }

    /// `flow.open` itself errored after the egress reached `.ready`. Pumps
    /// are partially wired (writer + egress R/W) but `clientReadPump` is not
    /// yet attached, so the forwarder cannot exist yet.
    func applyFlowOpenFailure(_ error: Error) {
        applyFullTeardown(error: error, driveForwarder: false)
    }

    /// Read pump reported a non-recoverable error after the kernel flow was
    /// open. Symmetric of `applyPostReadyFailure`, originated read-side.
    func applyReadHardError(_ error: Error) {
        applyFullTeardown(error: error, driveForwarder: true)
    }

    /// Engine detached (stopProxy / re-attach). The egress NWConnection must
    /// be cancelled or its handlers keep the per-flow graph alive after the
    /// engine is gone, leaking the connection + its NECP entry.
    func applyEngineDetached() {
        let err = NSError(
            domain: "rama.tproxy.engine-detached", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "engine detached; flow dropped"])
        applyFullTeardown(error: err, driveForwarder: true)
    }

    /// The graceful close stalled past its backstop (peer stopped reading →
    /// the in-flight write completion never fired → `closeWhenDrained` never
    /// finished). Force a full teardown so the per-flow graph can't orphan.
    /// Driven by `TcpFlowSession.armTerminalDrainBackstop` or the
    /// `stateQueue` maintenance watchdog.
    func applyDrainBackstop() {
        let err = NSError(
            domain: "rama.tproxy.drain-backstop", code: -1,
            userInfo: [
                NSLocalizedDescriptionKey: "graceful close drain stalled; flow force-dropped"
            ])
        applyFullTeardown(error: err, driveForwarder: true)
    }

    /// The promoted (`TcpDirectForwarder`) data path made no progress for
    /// longer than `defaultPromotedIdleTimeoutMs`. The promoted path has no
    /// in-Rust idle backstop (the Rust service task exits at cutover), so
    /// without this an established promoted flow whose peer is silently gone
    /// — or one wedged mid-cutover before either direction reaches
    /// `.finishing` — pins its egress `NWConnection`'s kernel nexus-flow slot
    /// until the per-process NECP allocation exhausts and ALL proxied
    /// networking stalls. Force a full teardown. Idempotent via `isDone`.
    ///
    /// NOTE: this is APP-byte idle, not liveness — it cannot distinguish a
    /// silently-dead peer from a genuinely idle-but-alive one, exactly like
    /// the engine's `viaRust` idle timeout whose parity it restores. Dead
    /// peers are caught faster and more precisely by egress TCP keepalive
    /// (`applyTcpKeepalive`); this is the coarse last-resort backstop for the
    /// alive-but-idle remainder.
    func applyIdleTimeout() {
        let err = NSError(
            domain: "rama.tproxy.idle-timeout", code: -1,
            userInfo: [
                NSLocalizedDescriptionKey:
                    "promoted flow idle past timeout; flow force-dropped"
            ])
        applyFullTeardown(error: err, driveForwarder: true)
    }

    /// Post-wake reconcile found this established flow's egress path no
    /// longer viable after the settle window: the path was torn down across
    /// a network-changing sleep but the NWConnection stayed `.ready`, so
    /// neither `.waiting` nor `.failed` fired. Reset it so the client
    /// reconnects instead of hanging until the 60s watchdog.
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
    /// `TcpClientWritePump.cancel()` publishes `closed = true` synchronously,
    /// so any in-flight / queued `flow.write` short-circuits before reaching
    /// the kernel. Reversing the order produced thousands of "flow is closed
    /// for writes" libnetworkextension errors under stress.
    private func applyFullTeardown(error: Error, driveForwarder: Bool) {
        guard !isDone else { return }
        isDone = true
        clientWritePump?.cancel()
        flow?.closeReadWithError(error)
        flow?.closeWriteWithError(error)
        connection?.cancelAndDetach()
        connection = nil
        egressReadPump?.cancel()
        egressReadPump = nil
        egressWritePump?.cancel()
        egressWritePump = nil
        clientReadPump = nil
        clientWritePump = nil
        if driveForwarder {
            directForwarder?.cancel()
            directForwarder = nil
        }
        session?.cancel()
        if let flowId { core?.removeTcpFlow(flowId) }
    }
}
