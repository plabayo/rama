import Foundation
import Network
import NetworkExtension

/// Type-erased anchor `TransparentProxyCore` retains for each intercepted
/// TCP flow. Mirror of `UdpFlowSessionAnchor`: lets the core own the
/// generic `TcpFlowSession<F>` without knowing its flow type, reaching the
/// per-flow `ctx` for the registry walks (detach / wake / watchdog).
protocol TcpFlowSessionAnchor: AnyObject {
    var ctx: TcpFlowContext { get }
    func retireWriterAdmissionForEngineDetach()
}

/// Per-TCP-flow state machine.
///
/// Replaces the body of `TransparentProxyCore.handleTcpFlow`.
/// All mutable state is queue-confined to `flowQueue`; methods
/// are individually testable via `@testable import`.
///
/// Ownership: `TransparentProxyCore` retains this session (via
/// `TcpFlowSessionAnchor`) for the flow's lifetime; the session owns its
/// `ctx`, pumps, and `RamaTcpSessionHandle`. The egress `NWConnection`'s
/// handlers capture the session weakly, so registry membership — not a
/// closure capture — is what keeps the flow alive. `removeTcpFlow` drops
/// the entry and the session deallocates; `deinit` cancels the connection
/// as a backstop so it can't outlive the session.
final class TcpFlowSession<F: TcpFlowLike>: TcpFlowSessionAnchor, @unchecked Sendable {
    private struct WriterAdmissionRefs {
        var client: TcpClientWritePump?
        var egress: NwTcpConnectionWritePump?
    }

    weak var core: TransparentProxyCore?
    let flow: F
    let meta: RamaTransparentProxyFlowMetaBridge
    let flowId: ObjectIdentifier
    let flowQueue: DispatchQueue
    let ctx: TcpFlowContext

    // Egress lifecycle state — queue-confined.
    var egressReady = false
    var timeoutWork: DispatchWorkItem?
    var waitingWork: DispatchWorkItem?
    var terminalDrainBackstop: DispatchWorkItem?
    /// Rust can close both bridge directions in the same unwind. Keep each
    /// writer drain represented until its own completion; otherwise a fast
    /// egress FIN can disarm the backstop protecting a stuck client write.
    private enum TerminalDrain: Hashable {
        case clientWriter
        case egressWriter
    }
    private var pendingTerminalDrains: Set<TerminalDrain> = []
    private var completedTerminalDrains: Set<TerminalDrain> = []
    private struct ClientDrainClose {
        let wasOpened: Bool
        let error: Error?
    }
    /// The client-writer result owns final session teardown, but only after
    /// every simultaneously announced writer drain has completed.
    private var pendingClientDrainClose: ClientDrainClose?

    // Late-bound: only set once the engine decision is .intercept.
    var sessionHandle: RamaTcpSessionHandle?
    private var engineGeneration: UInt64?
    /// Installed from the engine lease before any pump or FFI callback is
    /// created. Value semantics keep this generation's behavior stable while
    /// a replacement engine starts and the old flow retires.
    private var runtimePolicy: TransparentProxyRuntimePolicy?
    /// Lazy keeps engine-less phase tests ergonomic without allocating a
    /// throwaway atomic/coordinator for every production flow before its lease
    /// installs the generation-owned budget.
    private lazy var writerMemoryBudget =
        core?.writerMemoryBudgetForPumpComposition() ?? WriterMemoryBudget()
    /// Stable cross-thread handles used only at the synchronous detach
    /// boundary. Payload state remains flow-queue-confined; these calls retire
    /// only waiter/pregrant admission before a replacement generation starts.
    private let writerAdmissionRefs = Locked(WriterAdmissionRefs())
    private var effectiveRuntimePolicy: TransparentProxyRuntimePolicy {
        runtimePolicy ?? .testDefaultsSnapshot
    }
    #if DEBUG || RAMA_TESTING
        var testRuntimePolicy: TransparentProxyRuntimePolicy? { runtimePolicy }
        var testWriterMemoryBudget: WriterMemoryBudget { writerMemoryBudget }
    #endif

    // Configured by `start`; defaults applied here so phase methods
    // can run in tests without going through the engine decision.
    var lingerCloseMs: UInt32 = defaultLingerCloseMs
    var egressEofGraceMs: UInt32 = defaultEgressEofGraceMs

    init(core: TransparentProxyCore, flow: F, meta: RamaTransparentProxyFlowMetaBridge) {
        self.core = core
        self.flow = flow
        self.meta = meta
        self.flowId = ObjectIdentifier(flow)
        self.flowQueue = DispatchQueue(
            label: "rama.tproxy.tcp.flow.\(UInt(bitPattern: ObjectIdentifier(flow)))",
            qos: .utility)
        self.ctx = TcpFlowContext()
        self.ctx.flowQueue = self.flowQueue
        // The context owns its own teardown (folded in from the former
        // `TcpFlowTeardown`); give it what those methods need.
        self.ctx.flow = flow
        self.ctx.core = core
        self.ctx.flowId = flowId
    }

    func retireWriterAdmissionForEngineDetach() {
        let pumps = writerAdmissionRefs.withLock { ($0.client, $0.egress) }
        pumps.0?.retireAdmissionForEngineDetach()
        pumps.1?.retireAdmissionForEngineDetach()
    }

    deinit {
        // Backstop: the registry is this session's sole owner, so we land
        // here once it drops us. If no teardown cancelled the egress
        // connection first, cancel it so the `NWConnection` + its NECP entry
        // can't outlive us.
        //
        // Touch `ctx.connection` ON `flowQueue`, not on whatever thread
        // released us. `removeTcpFlow` (the common path) is `stateQueue.async`
        // AFTER the teardown already nilled `connection` on `flowQueue`, so a
        // direct touch would be a safe no-op there — but `detachEngine` drops
        // the registry ref via a synchronous `removeAll()` on `stateQueue`
        // while that flow's `applyEngineDetached` is still queued on
        // `flowQueue`, and touching `connection` here would race that write.
        // Hopping keeps the access confined and FIFO-ordered after any queued
        // teardown (which nils `connection`, making this a no-op).
        // `cancelAndDetach` also drops the handlers so no stale `.cancelled`
        // callback fires in the gap. Capture `ctx` (not `self`) so it outlives
        // the deinit; engine-less test contexts with no `flowQueue` cancel
        // inline (single-threaded, no race).
        let ctx = self.ctx
        if let queue = ctx.flowQueue {
            queue.async {
                ctx.connection?.cancelAndDetach()
                ctx.connection = nil
            }
        } else {
            ctx.connection?.cancelAndDetach()
        }
    }

    /// Entry point. Returns `true` if the flow was claimed
    /// (intercepted or blocked), `false` if the engine
    /// decided to pass through.
    func start() -> Bool {
        guard let lease = core?.engineLeaseForNewFlow() else {
            core?.logDebug("handleNewFlow tcp engine unavailable; bypassing")
            return false
        }
        installEngineLease(lease)
        buildClientWritePump()

        guard let decision = requestEngineSession(using: lease) else {
            core?.logDebug("handleNewFlow tcp engine unavailable; bypassing")
            return false
        }

        switch decision {
        case .intercept(let session):
            sessionHandle = session
            ctx.session = session
            guard let core else {
                ctx.applyPreReadyFailure()
                return true
            }
            guard let engineGeneration,
                let admission = core.admitTcpStart(
                    flowId: flowId,
                    meta: meta,
                    engineGeneration: engineGeneration)
            else {
                session.cancel()
                return false
            }
            guard case .admit(let token) = admission else {
                let reason: String
                let appId: String
                let persist: Bool
                if case .reject(let r, let id, let p) = admission {
                    reason = r
                    appId = id
                    persist = p
                } else {
                    reason = "unavailable"
                    appId = "unknown"
                    persist = true
                }
                // `app=` in the clear: the source bundle id is already public
                // in Apple's own per-flow NE log lines on the same machine, and
                // it is the first thing a post-incident read needs. Past the
                // per-tick budget the line goes to debug only — see
                // `TcpAdmissionDecision.reject(persist:)`; the tick carries
                // the counts and the top refusing apps.
                let line =
                    "tcp admission rejected: \(reason); "
                    + effectiveRuntimePolicy.flowRefusal.logDescription
                    + " app=\(appId)"
                if persist { core.logLifecycle(line) } else { core.logDebug(line) }
                if effectiveRuntimePolicy.flowRefusal.isPassthrough {
                    session.cancel()
                    return false
                }
                let error = tcpUpstreamUnavailableError()
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                session.cancel()
                return true
            }
            ctx.admissionToken = token
            guard
                core.registerTcpFlowAndScheduleStartup(
                    flowId,
                    anchor: self,
                    appId: token.appId,
                    admissionToken: token,
                    engineGeneration: engineGeneration,
                    runtimePolicy: effectiveRuntimePolicy,
                    on: flowQueue,
                    body: { [self, session] in
                        guard !ctx.isDone else { return }
                        _ = startEgressConnection(session: session)
                    })
            else {
                core.finishTcpStart(token, outcome: .failed)
                ctx.admissionToken = nil
                session.cancel()
                return false
            }
            return true
        case .passthrough:
            // Declining hands the flow to the direct route (documented for
            // NETransparentProxyProvider; only the NEAppProxyProvider base
            // class closes declined flows). Never claim passthrough flows:
            // each claimed flow costs an egress NWConnection, and NECP makes
            // every connection start pay for all live ones.
            core?.logDebug("handleNewFlow tcp bypassed by rust flow policy")
            return false
        case .blocked:
            core?.logLifecycle("handleNewFlow tcp blocked by rust flow policy")
            let error = blockedFlowError()
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
            return true
        }
    }

    // MARK: - Phase: client write pump

    func buildClientWritePump() {
        let writer = TcpClientWritePump(
            flow: flow,
            queue: flowQueue,
            logger: { [weak core] message in core?.logFlowMessage(message) },
            onTerminalError: { [weak ctx] error in
                ctx?.applyWriterTerminal(error)
            },
            onDrained: { [weak ctx] in
                // Always wake the Rust ingress bridge first: during the
                // promote cutover window Rust may still be draining
                // buffered S→C bytes through this pump and parked on a
                // `.paused`, while the forwarder direction is still
                // `.buffering` (its drain hook no-ops until `.active`).
                // Swallowing the edge would stall Rust until its
                // paused-drain timeout and then drop the in-flight
                // chunk. Harmless once Rust has unwound (no waiter).
                // Post-cutover the forwarder additionally owns the
                // `.paused` replay it buffered.
                ctx?.session?.signalServerDrain()
                ctx?.directForwarder?.onClientPumpDrained()
            },
            // S→C byte progress on `flowQueue` — the flow-pressure backstop's
            // activity signal. Fires for BOTH viaRust and promoted (the
            // forwarder flushes through this pump too), so an actively
            // transferring flow of EITHER mode is never reaped as "idle".
            onActivity: { [weak ctx] in
                ctx?.recordActivityUnlessPressureEvicted() ?? false
            },
            writerMemoryBudget: writerMemoryBudget,
            writePolicy: effectiveRuntimePolicy.tcpWritePump
        )
        ctx.clientWritePump = writer
        writerAdmissionRefs.withLock { $0.client = writer }
    }

    // MARK: - Phase: engine session

    #if DEBUG || RAMA_TESTING
        func requestEngineSession() -> RamaTransparentProxyTcpSessionDecision? {
            guard let lease = core?.engineLeaseForNewFlow() else { return nil }
            installEngineLease(lease)
            return requestEngineSession(using: lease)
        }
    #endif

    private func installEngineLease(_ lease: TransparentProxyCore.EngineFlowLease) {
        runtimePolicy = lease.runtimePolicy
        writerMemoryBudget = lease.writerMemoryBudget
        engineGeneration = lease.generation
        ctx.engineGeneration = lease.generation
    }

    private func requestEngineSession(
        using lease: TransparentProxyCore.EngineFlowLease
    ) -> RamaTransparentProxyTcpSessionDecision? {
        guard let clientWritePump = ctx.clientWritePump else { return nil }
        let decision = lease.engine.newTcpSession(
            meta: meta,
            // Capture the writer itself: Rust invokes this closure on an
            // arbitrary worker, while teardown mutates ctx slots on
            // `flowQueue`. Re-reading `ctx.clientWritePump` here would race
            // Swift ARC's load with that nil store. The retained pump is
            // synchronously marked closed before teardown cancels Rust.
            onServerBytes: { [clientWritePump] data in
                clientWritePump.enqueue(data)
            },
            onClientReadDemand: { [weak self] in
                // The pump's queue-specific resume fast path makes this the
                // sole normalization hop from an arbitrary Rust worker.
                self?.flowQueue.async { [weak self] in
                    self?.ctx.clientReadPump?.resume()
                }
            },
            onServerClosed: { [weak self] in
                self?.flowQueue.async { [weak self] in
                    guard let self else { return }
                    self.ctx.logDiagnostic(.rustServerClosed)
                    if self.ctx.mode != .viaRust {
                        self.ctx.directForwarder?.markRustS2CDone()
                        return
                    }
                    self.closeClientAfterRustDrain()
                }
            },
            flowRefusalPolicy: effectiveRuntimePolicy.flowRefusal
        )
        return decision
    }

    /// Execute one asynchronous transport transition only while this
    /// session's engine generation is still attached. Production sessions
    /// always carry a generation; the fallback keeps phase-level unit tests
    /// that construct a session without engine admission usable.
    private func withActiveEngineGeneration(_ body: () -> Void) {
        guard let engineGeneration else {
            body()
            return
        }
        guard let core else { return }
        core.withActiveEngineGeneration(engineGeneration, body)
    }

    // MARK: - Phase: egress connection

    func startEgressConnection(session: RamaTcpSessionHandle) -> Bool {
        guard let remoteHost = meta.remoteHost, meta.remotePort > 0 else {
            core?.logDebug("handleTcpFlow: missing remote endpoint; rejecting flow")
            // Reject (close the claimed flow) rather than strand the app's
            // connect — see `TcpFlowContext.applyPreOpenCleanup`.
            ctx.applyPreReadyFailure()
            return true
        }

        let egressOpts = session.getEgressConnectOptions()
        let requestedConnectTimeoutMs = egressOpts?.connectTimeoutMs ?? 10_000
        let connectTimeoutMs =
            core?.tcpConnectTimeoutMs(
                base: requestedConnectTimeoutMs,
                engineGeneration: engineGeneration) ?? requestedConnectTimeoutMs
        lingerCloseMs = egressOpts?.lingerCloseMs ?? defaultLingerCloseMs
        egressEofGraceMs = egressOpts?.egressEofGraceMs ?? defaultEgressEofGraceMs
        // Mirror the linger budget onto the ctx so a later promote
        // cutover can size the forwarder's drain backstop identically
        // to this flow's `armTerminalDrainBackstop`.
        ctx.lingerCloseMs = lingerCloseMs
        let nwParams = makeTcpNwParameters(egressOpts)

        if egressOpts?.parameters.preserve_original_meta_data ?? true {
            flow.applyMetadata(to: nwParams)
        }

        guard let factory = core?.nwConnectionFactory,
            let connection = factory(remoteHost, meta.remotePort, nwParams)
        else {
            core?.logDebug(
                "handleTcpFlow: invalid remote port \(meta.remotePort); rejecting flow")
            // Reject the claimed flow (no connection built) — as above.
            ctx.applyPreReadyFailure()
            return true
        }
        ctx.connection = connection

        installConnectTimeout(connectTimeoutMs: connectTimeoutMs, remoteHost: remoteHost)
        installEgressStateHandler(connection: connection)
        connection.start(queue: flowQueue)
        return true
    }

    func installConnectTimeout(connectTimeoutMs: UInt32, remoteHost: String) {
        let work = DispatchWorkItem { [weak self] in
            // `egressReady` is a reliable signal now that `stateUpdateHandler`
            // runs in FIFO order (no re-dispatch hop): a `.ready` arriving
            // before this deadline flips `egressReady` and cancels this timer
            // before it can fire.
            guard let self, !self.egressReady else { return }
            self.core?.logDebug(
                "egress NWConnection timed out for tcp flow remote=\(remoteHost):\(self.meta.remotePort)"
            )
            if let token = self.ctx.admissionToken {
                self.core?.finishTcpStart(token, outcome: .timeout)
                self.ctx.admissionToken = nil
            }
            self.ctx.applyConnectTimeout()
        }
        timeoutWork = work
        flowQueue.asyncAfter(deadline: .now() + .milliseconds(Int(connectTimeoutMs)), execute: work)
    }

    /// Backstop for the graceful close path.
    ///
    /// `onServerClosed` / `onCloseEgress` hand the flow to
    /// `closeWhenDrained`, whose completion is gated on the write pump's
    /// queue draining. A peer that has stopped reading leaves the
    /// in-flight `flow.write` / `connection.send` completion deferred
    /// indefinitely, so the drain never finishes, the drain-gated
    /// teardown (`applyDrainedClose`) never runs, and the whole per-flow
    /// graph orphans — the egress write pump's queued `Data`, its
    /// dispatch continuations, the `flowQueue`, and the egress
    /// `NWConnection` leak permanently (they outlive even the 15-min Rust
    /// idle timeout, whose drop re-enters this same wedged drain).
    ///
    /// Bound the close by progress, not wall clock: `onCloseEgress` fires at
    /// every ordinary client half-close while the opposite direction may
    /// still stream for a long time, so a blind deadline would truncate live
    /// transfers. The work item re-checks the flow's activity clock and
    /// re-arms while bytes still move; only a quiet close (the wedged drain
    /// this backstop exists for) is force-torn-down. Idempotent via the
    /// sticky `done` flag. Setting `terminalSignalled` lets the maintenance
    /// watchdog reap the same wedge if this queue starves; it applies the
    /// same idle gate, so the two reapers agree.
    func armTerminalDrainBackstop() {
        ctx.terminalSignalled = true
        ctx.drainClosePending = true
        guard terminalDrainBackstop == nil, ctx.isDone != true,
            ctx.drainClosePending
        else { return }
        scheduleDrainBackstopCheck(afterMs: UInt64(lingerCloseMs))
    }

    private func scheduleDrainBackstopCheck(afterMs: UInt64) {
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.ctx.isDone == false,
                self.ctx.drainClosePending
            else { return }
            let idleMs = self.ctx.idleMs()
            if idleMs < UInt64(self.lingerCloseMs) {
                // Still moving bytes (live half-close) — check again once the
                // current linger window could have elapsed quietly.
                self.scheduleDrainBackstopCheck(
                    afterMs: max(UInt64(self.lingerCloseMs) - idleMs, 50))
                return
            }
            self.core?.logDebug(
                "tcp flow drain backstop fired; forcing teardown (peer not draining)")
            self.ctx.applyDrainBackstop()
        }
        terminalDrainBackstop = work
        flowQueue.asyncAfter(deadline: .now() + .milliseconds(Int(afterMs)), execute: work)
    }

    private func beginTerminalDrain(_ drain: TerminalDrain) -> Bool {
        guard !ctx.isDone else { return false }
        guard !completedTerminalDrains.contains(drain) else { return false }
        let inserted = pendingTerminalDrains.insert(drain).inserted
        guard inserted else { return false }
        ctx.terminalSignalled = true
        ctx.drainClosePending = true
        return true
    }

    private func finishTerminalDrain(_ drain: TerminalDrain) {
        guard !ctx.isDone else { return }
        pendingTerminalDrains.remove(drain)
        completedTerminalDrains.insert(drain)

        if drain == .clientWriter, let close = pendingClientDrainClose {
            if !close.wasOpened || close.error != nil {
                pendingClientDrainClose = nil
                terminalDrainBackstop?.cancel()
                terminalDrainBackstop = nil
                ctx.drainClosePending = false
                ctx.applyDrainedClose(
                    wasOpened: close.wasOpened,
                    error: close.error)
                return
            }
            ctx.applyClientWriteHalfClose()
        }

        let bothFinished = completedTerminalDrains.count == 2
        // A completed clean half-close may wait indefinitely for its
        // independent sibling direction. That is a valid half-open TCP flow,
        // not a wedged writer drain, so it must not retain the drain backstop.
        ctx.drainClosePending = !pendingTerminalDrains.isEmpty
        guard bothFinished, pendingTerminalDrains.isEmpty,
            pendingClientDrainClose != nil
        else {
            if !ctx.drainClosePending {
                terminalDrainBackstop?.cancel()
                terminalDrainBackstop = nil
            }
            return
        }
        pendingClientDrainClose = nil
        terminalDrainBackstop?.cancel()
        terminalDrainBackstop = nil
        ctx.drainClosePending = false
        ctx.applyFullyDrainedClose()
    }

    func closeClientAfterRustDrain() {
        guard beginTerminalDrain(.clientWriter) else { return }
        ctx.clientWritePump?.closeWhenDrained { [weak self] wasOpened in
            guard let self else { return }
            self.pendingClientDrainClose = ClientDrainClose(
                wasOpened: wasOpened,
                error: self.ctx.egressReadError)
            self.finishTerminalDrain(.clientWriter)
        }
        armTerminalDrainBackstop()
    }

    func installEgressStateHandler(connection: any NwConnectionLike) {
        // `[weak self]`: the registry owns the session (see the class doc),
        // so the handler no longer needs to anchor it — and capturing
        // strongly would re-create the connection → handler → session →
        // ctx.connection → connection cycle this inversion removes.
        //
        // No re-dispatch hop: NWConnection delivers this on the queue passed
        // to `start(queue:)` — which is `flowQueue` — so we're already
        // serialised here. Running `handleEgressState` directly (instead of
        // posting a fresh `flowQueue.async` item) keeps the state transition
        // in FIFO order with any timer armed on `flowQueue`, so a `.ready`
        // that arrives just before a connect/waiting deadline cancels that
        // timer BEFORE it fires — no reordering, no recovered-flow reset.
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            self.withActiveEngineGeneration {
                self.handleEgressState(state)
            }
        }
        // Cache path viability so the post-wake reconcile can read a plain
        // Bool (`ctx.lastPathViable`) instead of polling `currentPath`,
        // which leaks ~32B per read. `[weak self]` for the same reason as
        // `stateUpdateHandler`.
        //
        // Assign DIRECTLY — do NOT re-dispatch via `flowQueue.async`.
        // NWConnection delivers this on the queue passed to `start(queue:)`,
        // which IS `flowQueue`, so we're already serialised here. A second
        // hop would re-order this write to AFTER work already queued ahead
        // of it: e.g. a recovery `viable=true` arriving just before a due
        // `checkDeadPath` would land BEHIND the check, so the check
        // reads a stale `false` and resets a flow whose path just came back.
        // Direct assignment lands the value in FIFO order with the callback.
        connection.viabilityUpdateHandler = { [weak self] viable in
            guard let self else { return }
            self.withActiveEngineGeneration {
                self.ctx.lastPathViable = viable
                // Mid-session loss (roam / interface switch / VPN toggle):
                // schedule the settle-delayed dead-path re-check now instead
                // of waiting for a wake that never comes.
                if !viable { self.core?.handleEgressViabilityLoss(self.ctx) }
            }
        }
    }

    // MARK: - Phase: egress state transitions

    func handleEgressState(_ state: NWConnection.State) {
        guard let connection = ctx.connection else { return }
        switch state {
        case .ready: handleEgressReady(connection: connection)
        case .failed(let err): handleEgressFailed(err)
        case .waiting(let err): handleEgressWaiting(err)
        case .cancelled: handleEgressCancelled()
        default: break
        }
    }

    func handleEgressReady(connection: any NwConnectionLike) {
        if egressReady {
            // Duplicate `.ready` after a recovered `.waiting`. Cancel
            // any pending tolerance timer.
            waitingWork?.cancel()
            waitingWork = nil
            ctx.postReadyWaitingArmed = false
            ctx.egressWritePump?.connectionBecameReady()
            return
        }
        egressReady = true
        ctx.egressReady = true
        // Reaching ready is progress: start the idle clock here, not at
        // creation, so a flow that connected slowly does not enter the
        // pressure reaper's eligible set already aged — the rescan bound
        // in `collectPressureVictimsLocked` counts on that.
        ctx.lastActivityAt = .now()
        if let token = ctx.admissionToken {
            core?.finishTcpStart(token, outcome: .ready)
            ctx.admissionToken = nil
        }
        timeoutWork?.cancel()
        timeoutWork = nil
        // Cancel any pre-ready waiting budget so it can't tear a
        // now-healthy connection down.
        waitingWork?.cancel()
        waitingWork = nil
        ctx.postReadyWaitingArmed = false
        // The egress reached `.ready`, but `viabilityUpdateHandler` fires only
        // on CHANGE: if the path was already non-viable when we connected, it
        // will NOT re-fire, so this established-but-non-viable flow would have
        // no mid-session re-check and could strand until a wake/idle reaper —
        // exactly the hang the re-check exists to prevent. Arm it now. No-op
        // when the path is viable or the feature is disabled.
        if !ctx.lastPathViable { core?.handleEgressViabilityLoss(ctx) }

        guard let session = sessionHandle else { return }

        buildEgressWritePump(connection: connection)
        let egressWritePump = ctx.egressWritePump
        let readPump = buildEgressReadPump(connection: connection, session: session)

        // Register the Rust→Swift promote callback BEFORE
        // `session.activate(...)` hands the BridgeIo to the service
        // task. The service can call `PromoteHandle::into_passthrough`
        // on its very first poll; if no callback is registered at
        // the moment `fire()` dispatches, the Rust side returns
        // `EgressUnavailable` and `PromoteLayer` silently falls
        // through to the in-Rust data path. Registering here closes
        // that race window — the FFI registration completes
        // synchronously before activate's `bridge_tx.send(...)`.
        //
        // The callback body still hops to `flowQueue` and guards on
        // ctx state, so a promote firing before `flow.open` finishes
        // is observed by `beginPromoteCutover`'s `clientReadPump != nil`
        // gate and confirmed-failed cleanly. See `armPromoteCallback`.
        armPromoteCallback()

        session.activate(
            // As above, keep a stable callback-visible writer reference rather
            // than racing an arbitrary Rust worker against ctx teardown.
            onWriteToEgress: { [egressWritePump] data in
                egressWritePump?.enqueue(data) ?? .closed
            },
            onEgressReadDemand: { [weak self] in
                // As above, `resume()` runs inline once this sole hop reaches
                // the flow queue instead of posting a second queue item.
                self?.flowQueue.async { [weak self] in
                    self?.ctx.egressReadPump?.resume()
                }
            },
            onCloseEgress: { [weak self] in
                self?.flowQueue.async { [weak self] in
                    guard let self else { return }
                    if self.ctx.mode != .viaRust {
                        self.ctx.directForwarder?.markRustC2SDone()
                        return
                    }
                    self.closeEgressAfterRustDrain()
                }
            }
        )

        openKernelFlow(connection: connection, readPump: readPump, session: session)
    }

    func closeEgressAfterRustDrain() {
        guard beginTerminalDrain(.egressWriter) else { return }
        ctx.egressWritePump?.closeWhenDrained { [weak self] in
            self?.finishTerminalDrain(.egressWriter)
        }
        armTerminalDrainBackstop()
    }

    func handleEgressFailed(_ error: NWError?) {
        if !egressReady {
            timeoutWork?.cancel()
            timeoutWork = nil
            // Cancel any pre-ready waiting budget too.
            waitingWork?.cancel()
            waitingWork = nil
            core?.logDebug(
                "egress NWConnection failed before flow opened: \(String(describing: error))"
            )
            if case .posix(.ENOMEM)? = error {
                // A pre-ready ENOMEM is the provider-visible signature that
                // allocating the outbound NECP/NWConnection flow failed. Keep
                // this public, structured marker distinct from generic DNS,
                // TLS, origin, and socket-backpressure failures so the signed
                // ceiling probe can corroborate rather than infer exhaustion.
                core?.logLifecycleError(
                    "kernel flow allocation exhausted: resource=necp "
                        + "errno=ENOMEM protocol=tcp phase=connect_pre_ready")
            }
            ctx.applyPreReadyFailure()
        } else {
            core?.logDebug(
                "egress NWConnection failed after flow opened: \(String(describing: error))"
            )
            applyPostReadyTeardown(error: error)
        }
    }

    func handleEgressWaiting(_ error: NWError?) {
        // One timer at a time.
        if waitingWork != nil { return }

        if egressReady {
            // Post-ready: established connection lost its path. Tolerate
            // a brief blip, then tear down as failed.
            core?.logDebug(
                "egress NWConnection waiting after flow opened: \(String(describing: error))"
            )
            // `.ready` recovery is delivered via `stateUpdateHandler` in FIFO
            // order (no re-dispatch hop), so a path that comes back cancels
            // this timer (`handleEgressReady` → `waitingWork?.cancel()`)
            // before it fires — no stale-timer reset of a recovered flow.
            let work = DispatchWorkItem { [weak self] in
                self?.ctx.postReadyWaitingArmed = false
                self?.applyPostReadyTeardown(error: error)
            }
            waitingWork = work
            // Mark the precise recovery budget as armed so the coarser
            // mid-session viability re-check defers to it instead of
            // preempting it (see `handleEgressViabilityLoss`).
            ctx.postReadyWaitingArmed = true
            flowQueue.asyncAfter(
                deadline: .now() + .milliseconds(Int(defaultEgressWaitingToleranceMs)),
                execute: work
            )
            return
        }

        // Pre-ready: connect never established, path is down (boot,
        // wake, VPN transition). Fail fast so the app can retry the
        // moment the path returns; the timer is cancelled on `.ready`.
        core?.logDebug(
            "egress NWConnection waiting before ready (path down): \(String(describing: error))"
        )
        let work = DispatchWorkItem { [weak self] in
            // FIFO `stateUpdateHandler` makes `egressReady` reliable: a
            // `.ready` arriving before this budget expires flips it and
            // cancels this timer first.
            guard let self, !self.egressReady else { return }
            self.core?.logDebug(
                "egress NWConnection pre-ready waiting exceeded budget; failing fast "
                    + "remote=\(self.meta.remoteHost ?? "?"):\(self.meta.remotePort)"
            )
            self.ctx.applyPreReadyWaitingTimeout()
        }
        waitingWork = work
        flowQueue.asyncAfter(
            deadline: .now() + .milliseconds(Int(defaultEgressPreReadyWaitingBudgetMs)),
            execute: work
        )
    }

    func handleEgressCancelled() {
        waitingWork?.cancel()
        waitingWork = nil
        // Network.framework has already cancelled it; assigning handlers or
        // cancelling again violates its terminal-state contract.
        ctx.connection = nil
        if egressReady {
            ctx.applyPostReadyFailure(nil)
        } else {
            ctx.applyPreReadyFailure()
        }
    }

    private func applyPostReadyTeardown(error: NWError?) {
        waitingWork?.cancel()
        waitingWork = nil
        ctx.applyPostReadyFailure(error)
    }

    // MARK: - Phase: egress pump construction

    // Registers the egress write pump into `ctx.egressWritePump`; enqueue-driven.
    private func buildEgressWritePump(connection: any NwConnectionLike) {
        let pump = NwTcpConnectionWritePump(
            connection: connection,
            queue: flowQueue,
            onDrained: { [weak self] in
                guard let self else { return }
                // Always wake the Rust egress bridge first; the
                // forwarder additionally owns its `.paused` replay
                // post-cutover. See `buildClientWritePump` for why
                // swallowing this edge during the cutover window
                // would stall Rust and drop a chunk.
                self.ctx.session?.signalEgressDrain()
                self.ctx.directForwarder?.onEgressPumpDrained()
            },
            onTerminal: { [weak self] error in
                guard let self else { return }
                // Preserve terminal send failures in both modes. In promoted
                // mode the forwarder's natural terminal is intentionally
                // clean, so the errorful context teardown must win before we
                // cancel the forwarder and let that clean callback run.
                if self.ctx.mode != .viaRust {
                    self.ctx.applyWriterTerminal(error)
                    self.ctx.directForwarder?.cancel()
                } else {
                    self.terminalDrainBackstop?.cancel()
                    self.terminalDrainBackstop = nil
                    self.ctx.drainClosePending = false
                    self.ctx.applyWriterTerminal(error)
                }
            },
            onFinComplete: { [weak ctx] error in
                ctx?.logDiagnostic(.egressFin, error: error)
            },
            // C→S byte progress on `flowQueue` — see `buildClientWritePump`.
            onActivity: { [weak self] in
                self?.ctx.recordActivityUnlessPressureEvicted() ?? false
            },
            writerMemoryBudget: writerMemoryBudget,
            writePolicy: effectiveRuntimePolicy.tcpWritePump
        )
        ctx.egressWritePump = pump
        writerAdmissionRefs.withLock { $0.egress = pump }
    }

    func buildEgressReadPump(
        connection: any NwConnectionLike,
        session: RamaTcpSessionHandle
    ) -> NwTcpConnectionReadPump {
        let pump = NwTcpConnectionReadPump(
            connection: connection,
            session: session,
            queue: flowQueue,
            eofGraceDeadline: .milliseconds(Int(egressEofGraceMs)),
            onTerminalObserved: { [weak ctx] in
                ctx?.terminalSignalled = true
            },
            onReadError: { [weak ctx] error in ctx?.egressReadError = error },
            onAbnormalStop: { [weak ctx] error in
                guard let ctx else {
                    connection.cancelAndDetach()
                    return
                }
                ctx.applyReadHardError(error)
            },
            onActivity: { [weak ctx] in
                _ = ctx?.recordActivityUnlessPressureEvicted()
            },
            writerMemoryBudget: writerMemoryBudget
        )
        ctx.egressReadPump = pump
        return pump
    }

    // MARK: - Phase: open kernel flow

    func openKernelFlow(
        connection: any NwConnectionLike,
        readPump: NwTcpConnectionReadPump,
        session: RamaTcpSessionHandle
    ) {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            self?.flowQueue.async { [weak self] in
                guard let self else { return }
                self.ctx.logDiagnostic(.kernelOpen, error: error)
                self.withActiveEngineGeneration {
                    if let error {
                        self.core?.logDebug("flow.open error after egress ready: \(error)")
                        self.ctx.applyFlowOpenFailure(error)
                        return
                    }
                    // Teardown may have raced ahead while flow.open was in
                    // flight; `ctx.connection == nil` is the local signal.
                    guard self.ctx.connection != nil else {
                        self.core?.logTrace(
                            "flow.open completion observed teardown; dropping")
                        return
                    }
                    self.core?.logTrace("flow.open ok (tcp, egress pre-connected)")
                    let finishOpen: @Sendable () -> Void = { [weak self] in
                        guard let self else { return }
                        self.withActiveEngineGeneration {
                            // `markOpened` can synchronously finish a clean
                            // drain that arrived while `flow.open` was pending.
                            // Re-check after that transition before starting
                            // either read pump against torn-down transports.
                            guard !self.ctx.isDone,
                                self.ctx.connection != nil
                            else { return }
                            readPump.start()
                            self.armReadTerminal(session: session)
                            self.ctx.clientReadPump?.requestRead()
                        }
                    }
                    if let clientWritePump = self.ctx.clientWritePump {
                        clientWritePump.markOpened(finishOpen)
                    } else {
                        self.flowQueue.async(execute: finishOpen)
                    }
                }
            }
        }
    }

    func armReadTerminal(session: RamaTcpSessionHandle) {
        let flow = self.flow
        let terminal = TcpReadTerminal(
            // Client upload half-close (SHUT_WR → kernel readData EOF):
            // forward EOF to the egress, but do NOT issue a redundant
            // provider read-close or cancel the egress read pump — the
            // server→client direction must keep flowing until the server
            // closes. Cancelling it here truncated downloads on every
            // half-close and matched the Rust engine's asymmetric
            // on_client_eof / on_egress_eof contract incorrectly.
            onNaturalEof: { [weak self, weak session] in
                guard let self, !self.ctx.isDone else { return }
                self.core?.logTrace(
                    "tcp client read EOF (half-close): forward to egress, keep download open")
                self.ctx.logDiagnostic(.clientEof)
                session?.onClientEof()
            },
            onHardError: { [weak self] err in
                self?.ctx.applyReadHardError(err)
            }
        )
        let flowReadPump = TcpClientReadPump(
            flow: flow,
            session: session,
            queue: flowQueue,
            logger: { [weak core] message in core?.logFlowMessage(message) },
            onTerminal: { error in terminal.dispatch(error) },
            onActivity: { [weak ctx] in
                _ = ctx?.recordActivityUnlessPressureEvicted()
            },
            writerMemoryBudget: writerMemoryBudget
        )
        ctx.clientReadPump = flowReadPump
    }

    func armPromoteCallback() {
        guard let session = sessionHandle else { return }
        let flow = self.flow
        // Weak self: the Rust session holds this closure for its whole
        // lifetime. A strong capture would make the Rust session's box pin
        // the Swift session, defeating the registry-owns-the-session model
        // (the session must die when `removeTcpFlow` drops it, not when Rust
        // releases the box). Weak self resolves as long as the session is
        // registered, which is exactly when a promote can still fire.
        session.registerPromoteCallback { [weak self] in
            self?.flowQueue.async { [weak self] in
                guard let self else { return }
                self.core?.beginPromoteCutover(
                    ctx: self.ctx,
                    flow: flow,
                    flowQueue: self.flowQueue,
                    flowId: self.flowId
                )
            }
        }
    }
}
