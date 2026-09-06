import Foundation
import Network
import NetworkExtension

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

struct TcpFlowMaintenanceState {
    var egressReady = false
    var terminalSignalled = false
    var drainClosePending = false
    var lastActivityAt: DispatchTime = .now()
    var lingerCloseMs: UInt32 = defaultLingerCloseMs
    var mode: TcpFlowMode = .viaRust
    /// Set in the same lock scope that commits a pressure reservation. Data
    /// producers use it to avoid reporting accepted bytes after teardown won.
    var pressureEvictionCommitted = false
    /// Created only for promoted retirement or detach, not on the normal
    /// data/admission path. Sharing this stable handle lets those two terminal
    /// paths claim one physical NWConnection without relying on reusable object
    /// addresses.
    var resourceRetirementIdentity: ResourceRetirementIdentity?
}

/// Mutable flow state is confined to its dedicated serial queue. Fields read
/// by maintenance scans are mirrored through one locked snapshot.
final class TcpFlowContext: @unchecked Sendable {
    enum DiagnosticEvent: UInt8 {
        case kernelOpen, clientEof, rustServerClosed, kernelWriteClose, egressFin

        var name: String {
            switch self {
            case .kernelOpen: return "kernel_open_result"
            case .clientEof: return "client_read_eof"
            case .rustServerClosed: return "rust_server_closed"
            case .kernelWriteClose: return "kernel_write_close"
            case .egressFin: return "egress_fin_result"
            }
        }
    }

    // Correlate bounded terminal diagnostics without exposing object addresses,
    // application identity, or endpoints. Provider process identity scopes IDs.
    private static let nextDiagnosticId = Locked<UInt64>(0)
    let diagnosticId = TcpFlowContext.nextDiagnosticId.withLock { value in
        value &+= 1
        return value
    }
    private var reportedDiagnosticEvents: UInt8 = 0
    private let maintenanceState = Locked(TcpFlowMaintenanceState())
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
    var egressReadError: Error?
    /// Writer pumps retained until terminal teardown so we can
    /// cancel them from dispatcher-owned close paths.
    var clientWritePump: TcpClientWritePump?
    var egressWritePump: NwTcpConnectionWritePump?
    /// Egress `NWConnection` reached `.ready`. Set on `flowQueue`; read
    /// off-queue by maintenance and wake reconciliation through the locked
    /// maintenance snapshot.
    var egressReady: Bool {
        get { maintenanceState.withLock { $0.egressReady } }
        set { maintenanceState.withLock { $0.egressReady = newValue } }
    }
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
    /// `flowQueue`; read off-queue by `checkDeadPath` (same relaxation
    /// as `egressReady`).
    var lastPathViable = true
    /// A settle-delayed dead-path re-check (post-wake reconcile or
    /// mid-session viability-loss trigger) is already scheduled for this
    /// flow — coalesces a burst of triggers into one outstanding verdict.
    /// Set / cleared on `flowQueue`, like `lastPathViable`.
    var deadPathRecheckPending = false
    /// A terminal close signal (server EOF / egress close, `viaRust` mode) was
    /// observed. The egress read pump publishes it at the transport boundary
    /// before entering Rust so promotion cannot overtake the one-shot close
    /// callback; ordinary close handlers and the promoted forwarder also set
    /// it on `flowQueue`. Read off-queue by the maintenance watchdog through
    /// the locked snapshot, together with `drainClosePending`.
    var terminalSignalled: Bool {
        get { maintenanceState.withLock { $0.terminalSignalled } }
        set { maintenanceState.withLock { $0.terminalSignalled = newValue } }
    }
    /// A promoted or Rust-backed write drain is still outstanding. Unlike
    /// `terminalSignalled`, this clears only after every concurrently pending
    /// writer drain finishes and is read from the maintenance queue.
    var drainClosePending: Bool {
        get { maintenanceState.withLock { $0.drainClosePending } }
        set { maintenanceState.withLock { $0.drainClosePending = newValue } }
    }
    /// A post-ready egress `.waiting` tolerance timer is currently armed
    /// (`TcpFlowSession.handleEgressWaiting` armed it; cleared when it fires,
    /// is cancelled on `.ready` recovery, or on teardown). That timer is the
    /// PRECISE per-flow recovery budget for a path loss, so while it is armed
    /// the coarser mid-session viability re-check must defer to it rather than
    /// preempt it (see `handleEgressViabilityLoss` / `defaultViabilityLossRecheckMs`).
    /// Set / cleared on `flowQueue`, like the other lifecycle flags.
    var postReadyWaitingArmed = false
    /// Effective graceful-close linger budget for this flow (from the
    /// egress connect options, else `defaultLingerCloseMs`). Set once by
    /// `TcpFlowSession.startEgressConnection`; read by
    /// `beginPromoteCutover` to size the promoted forwarder's drain
    /// backstop so it matches the `viaRust` path's
    /// `TcpFlowSession.armTerminalDrainBackstop` budget.
    var lingerCloseMs: UInt32 {
        get { maintenanceState.withLock { $0.lingerCloseMs } }
        set { maintenanceState.withLock { $0.lingerCloseMs = newValue } }
    }
    /// Mode of the per-flow data path. Mutated only on the
    /// per-flow `DispatchQueue`. See [`TcpFlowMode`].
    var mode: TcpFlowMode {
        get { maintenanceState.withLock { $0.mode } }
        set { maintenanceState.withLock { $0.mode = newValue } }
    }
    /// Active when `mode == .promoted`. Owns the kernel ↔
    /// NWConnection direct read/write loops + cutover
    /// buffer.
    var directForwarder: TcpDirectForwarder?
    /// Monotonic timestamp (`DispatchTime`, mach-uptime — pauses during
    /// system sleep, like the engine's tokio idle timers) of the last byte
    /// observed on either data path. The via-Rust read/write pumps and the
    /// promoted forwarder bump it on `flowQueue`; maintenance reads it
    /// through the locked snapshot. A promoted flow idle past
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
    var lastActivityAt: DispatchTime {
        get { maintenanceState.withLock { $0.lastActivityAt } }
        set { maintenanceState.withLock { $0.lastActivityAt = newValue } }
    }

    /// Linearize a producer's accepted-byte activity against the pressure
    /// reaper's final commit. `false` means teardown already won and the
    /// producer must report the destination closed instead of accepting data.
    func recordActivityUnlessPressureEvicted() -> Bool {
        maintenanceState.withLock { state in
            guard !state.pressureEvictionCommitted else { return false }
            state.lastActivityAt = .now()
            return true
        }
    }

    func maintenanceSnapshot() -> TcpFlowMaintenanceState {
        maintenanceState.withLock { $0 }
    }

    func retirementIdentity() -> ResourceRetirementIdentity {
        maintenanceState.withLock { state in
            if let identity = state.resourceRetirementIdentity {
                return identity
            }
            let identity = ResourceRetirementIdentity()
            state.resourceRetirementIdentity = identity
            return identity
        }
    }

    /// Saturating idle age at one lock-defined instant. Activity may publish
    /// after the caller captures `nowNs`; that is age zero, not unsigned wrap.
    func idleMs(
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> UInt64 {
        maintenanceState.withLock { state in
            let lastNs = state.lastActivityAt.uptimeNanoseconds
            guard lastNs <= nowNs else { return 0 }
            return (nowNs - lastNs) / 1_000_000
        }
    }

    /// Run a final pressure-eviction decision while activity publication is
    /// excluded. The caller may atomically claim its external reservation in
    /// this closure: activity that wins this lock is observed and spares the
    /// flow; activity after the claim loses to an already-committed teardown.
    func withMaintenanceStateLocked<T>(
        _ body: (inout TcpFlowMaintenanceState) -> T
    ) -> T {
        maintenanceState.withLock { body(&$0) }
    }
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
    /// Admission token for a pre-ready egress start. Set before
    /// `NWConnection.start`, cleared when the start reaches `.ready` or any
    /// pre-open cleanup path fires. Lets the core maintain an exact in-flight
    /// start gauge and start-to-ready latency window.
    var admissionToken: TcpAdmissionToken?
    /// Engine lifecycle that created this flow. Removal callbacks carry it
    /// back to the core so stale teardown work from a detached engine cannot
    /// alter a newly attached engine's pressure episode.
    var engineGeneration: UInt64?
    /// Sticky one-shot teardown guard. Mutated and read only on
    /// `flowQueue` (single-threaded by construction), so it needs no lock.
    private(set) var isDone = false
    /// Each `NEAppProxyTCPFlow` half has one terminal close operation. Keep
    /// those edges separate from whole-flow teardown so a later aggregate
    /// terminal cannot repeat a close or replace its original error.
    private var clientReadClosed = false
    private var clientWriteClosed = false

    init() {
    }

    /// Called only on the flow queue, like the close transitions it describes.
    /// Each event appears at most once, including a duplicate terminal callback.
    func logDiagnostic(_ event: DiagnosticEvent, error: Error? = nil) {
        if let record = diagnosticRecord(for: event, error: error) {
            RamaLog.debugPublic(record)
        }
    }

    func diagnosticRecord(for event: DiagnosticEvent, error: Error? = nil) -> String? {
        let mask: UInt8 = 1 << event.rawValue
        guard reportedDiagnosticEvents & mask == 0 else { return nil }
        reportedDiagnosticEvents |= mask
        let errorKind: String
        let errorCode: Int
        if let networkError = error as? NWError {
            switch networkError {
            case .posix(let code): (errorKind, errorCode) = ("posix", Int(code.rawValue))
            case .dns(let code): (errorKind, errorCode) = ("dns", Int(code))
            case .tls(let code): (errorKind, errorCode) = ("tls", Int(code))
            default: (errorKind, errorCode) = ("network", (networkError as NSError).code)
            }
        } else if let error {
            let value = error as NSError
            switch value.domain {
            case NSPOSIXErrorDomain: errorKind = "posix"
            case NSURLErrorDomain: errorKind = "url"
            case NEAppProxyErrorDomain: errorKind = "app_proxy"
            default: errorKind = "other"
            }
            errorCode = value.code
        } else {
            (errorKind, errorCode) = ("none", 0)
        }
        return "tcp_terminal diagnostic_id=\(diagnosticId) engine_generation=\(engineGeneration ?? 0) "
            + "event=\(event.name) mode=\(mode == .viaRust ? "via_rust" : "promoted") "
            + "egress_ready=\(egressReady ? 1 : 0) done=\(isDone ? 1 : 0) "
            + "error_kind=\(errorKind) error_code=\(errorCode)"
    }

    func closeClientReadOnce(_ error: Error?) {
        guard !clientReadClosed else { return }
        clientReadClosed = true
        flow?.closeReadWithError(error)
    }

    func closeClientWriteOnce(_ error: Error?) {
        guard !clientWriteClosed else { return }
        clientWriteClosed = true
        logDiagnostic(.kernelWriteClose, error: error)
        flow?.closeWriteWithError(error)
    }

    // MARK: - Teardown
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
        if let token = admissionToken {
            core?.finishTcpStart(token, outcome: .failed)
            admissionToken = nil
        }
        let err = tcpUpstreamUnavailableError()
        closeClientReadOnce(err)
        closeClientWriteOnce(err)
        connection?.cancelAndDetach()
        connection = nil
        session?.cancel()
        if let flowId {
            core?.removeTcpFlow(
                flowId,
                context: self,
                engineGeneration: engineGeneration)
        }
    }

    // MARK: Post-open writer-self-terminal

    /// Either write pump exhausted its retry budget or hit a non-transient
    /// error. Cancel both writers before closing either transport: a Rust
    /// callback already inside `callback_active` may concurrently enqueue to
    /// the sibling writer, and it must observe `.closed` rather than schedule a
    /// kernel write after the transport has been closed.
    func applyWriterTerminal(_ error: Error) {
        applyFullTeardown(error: error, driveForwarder: true)
    }

    // MARK: Post-open natural close

    /// `onServerClosed → closeWhenDrained` completion: the Rust session
    /// signalled server EOF and the client write pump drained. Close the
    /// kernel flow with the egress read error when present, clean (`nil`) when
    /// it was opened, else with `upstreamUnavailable`. Does NOT cancel the Rust
    /// session — it already drove the terminal event.
    func applyDrainedClose(wasOpened: Bool, error: Error? = nil) {
        guard !isDone else { return }
        isDone = true
        if let error {
            closeClientReadOnce(error)
            closeClientWriteOnce(error)
        } else if wasOpened {
            closeClientReadOnce(nil)
            closeClientWriteOnce(nil)
        } else {
            let error = tcpUpstreamUnavailableError()
            closeClientReadOnce(error)
            closeClientWriteOnce(error)
        }
        connection?.cancelAndDetach()
        connection = nil
        if let flowId {
            core?.removeTcpFlow(
                flowId,
                context: self,
                engineGeneration: engineGeneration)
        }
    }

    /// Clean server→client half-close. Keep accepting client→server bytes
    /// until Rust independently closes and drains the egress writer.
    func applyClientWriteHalfClose() {
        guard !isDone else { return }
        closeClientWriteOnce(nil)
    }

    /// Both Rust write directions have drained. The client write half was
    /// already closed when its drain completed, so close only the remaining
    /// read half before releasing the connection and registry ownership.
    func applyFullyDrainedClose() {
        guard !isDone else { return }
        isDone = true
        closeClientReadOnce(nil)
        connection?.cancelAndDetach()
        connection = nil
        if let flowId {
            core?.removeTcpFlow(
                flowId,
                context: self,
                engineGeneration: engineGeneration)
        }
    }

    /// Publish terminal accounting; the forwarder then releases the drained
    /// connection through the write pump on this same flow queue.
    func applyPromotedTerminal() {
        guard !isDone else { return }
        isDone = true
        // Move this flow from reclaimable registry occupancy into the hard-cap
        // retirement ledger before its async registry removal can expose a
        // replacement slot. The write pump releases the token only at the
        // connection's actual `cancelAndDetach` point.
        if let core, let egressWritePump {
            let identity = retirementIdentity()
            let release: @Sendable () -> Void
            if let flowId {
                release = core.transferRegisteredResourceToRetirement(
                    flowId: flowId,
                    contextId: ObjectIdentifier(self),
                    engineGeneration: engineGeneration,
                    identity: identity)
            } else {
                // Defensive engine-less fallback: without a registry key there
                // is no ownership overlap to transfer, but the live connection
                // must still consume retirement capacity until cancellation.
                release = core.beginResourceRetirement()
            }
            egressWritePump.installTerminalResourceRelease(release)
        }
        closeClientReadOnce(nil)
        closeClientWriteOnce(nil)
        connection?.stateUpdateHandler = nil
        connection?.viabilityUpdateHandler = nil
        connection = nil
        if let flowId {
            core?.removeTcpFlow(
                flowId,
                context: self,
                engineGeneration: engineGeneration)
        }
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

    /// The flow-pressure backstop evicted this flow: the combined live flow
    /// count crossed the soft cap and this was among the most-idle flows of
    /// EITHER mode (idle past the pressure floor — nexus pressure is global, and
    /// both `viaRust` and `.promoted` carry an accurate `lastActivityAt`),
    /// chosen LRU to free a kernel nexus-flow slot for subsequent flows —
    /// rather than let the per-process allocation exhaust and freeze ALL
    /// proxied networking. Full teardown so BOTH the ingress kernel flow and
    /// the egress NWConnection slots are released. Idempotent via `isDone`. The
    /// caller re-checks idleness on `flowQueue` first, so a flow that just
    /// became active is never evicted. See `TransparentProxyCore.reapIdleUnderPressure`.
    func applyPressureEvicted() {
        let err = NSError(
            domain: "rama.tproxy.pressure-evicted", code: -1,
            userInfo: [
                NSLocalizedDescriptionKey:
                    "idle flow evicted under nexus-flow pressure; flow force-dropped"
            ])
        applyFullTeardown(error: err, driveForwarder: true)
    }

    /// The settle-delayed dead-path re-check (post-wake reconcile, or the
    /// mid-session viability-loss trigger) found this established flow's
    /// egress path no longer viable: the path was torn down across a
    /// network change but the NWConnection stayed `.ready`, so neither
    /// `.waiting` nor `.failed` fired. Reset it so the client reconnects
    /// instead of hanging until an idle reaper.
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
        if let token = admissionToken {
            core?.finishTcpStart(token, outcome: .failed)
            admissionToken = nil
        }
        clientWritePump?.cancel()
        closeClientReadOnce(error)
        closeClientWriteOnce(error)
        connection?.cancelAndDetach()
        connection = nil
        egressReadPump?.cancel()
        egressReadPump = nil
        egressWritePump?.cancel()
        clientReadPump = nil
        if driveForwarder {
            directForwarder?.cancel()
            directForwarder = nil
        }
        // `cancel()` waits for Rust callbacks already inside callback_active.
        // Keep both callback-visible writer slots intact until that barrier
        // returns; the callbacks see synchronously canceled pumps and report
        // `.closed`, never a racing ARC load versus a nil store.
        session?.cancel()
        egressWritePump = nil
        clientWritePump = nil
        if let flowId {
            core?.removeTcpFlow(
                flowId,
                context: self,
                engineGeneration: engineGeneration)
        }
    }
}
