import Foundation
import Network
import NetworkExtension

/// Type-erased anchor `TransparentProxyCore` retains for each intercepted
/// TCP flow. Mirror of `UdpFlowSessionAnchor`: lets the core own the
/// generic `TcpFlowSession<F>` without knowing its flow type, reaching the
/// per-flow `ctx` for the registry walks (detach / wake / watchdog).
protocol TcpFlowSessionAnchor: AnyObject {
    var ctx: TcpFlowContext { get }
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

    // Late-bound: only set once the engine decision is .intercept.
    var sessionHandle: RamaTcpSessionHandle?

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
        buildClientWritePump()

        guard let decision = requestEngineSession() else {
            core?.logDebug("handleNewFlow tcp engine unavailable; bypassing")
            return false
        }

        switch decision {
        case .intercept(let session):
            sessionHandle = session
            ctx.session = session
            let occupancy = core?.registerTcpFlow(flowId, anchor: self) ?? 0
            // Admit unconditionally — the flow-pressure backstop NEVER refuses
            // or delays a new flow. If admitting this one reached the soft cap,
            // ask the core to reap idle promoted flows asynchronously (off this
            // delivery thread) to free slots for SUBSEQUENT flows.
            let admitted = startEgressConnection(session: session)
            if defaultFlowPressureSoftCap > 0, occupancy >= Int(defaultFlowPressureSoftCap) {
                core?.reapIdleUnderPressure()
            }
            return admitted
        case .passthrough:
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
            onActivity: { [weak ctx] in ctx?.lastActivityAt = .now() }
        )
        ctx.clientWritePump = writer
    }

    // MARK: - Phase: engine session

    func requestEngineSession() -> RamaTransparentProxyTcpSessionDecision? {
        guard let engine = core?.engine else { return nil }
        return engine.newTcpSession(
            meta: meta,
            onServerBytes: { [weak ctx] data in
                ctx?.clientWritePump?.enqueue(data) ?? .closed
            },
            onClientReadDemand: { [weak self] in
                self?.flowQueue.async { [weak self] in
                    self?.ctx.clientReadPump?.resume()
                }
            },
            onServerClosed: { [weak self] in
                self?.flowQueue.async { [weak self] in
                    guard let self else { return }
                    if self.ctx.mode != .viaRust {
                        self.ctx.directForwarder?.markRustS2CDone()
                        return
                    }
                    self.ctx.clientWritePump?.closeWhenDrained { [weak self] wasOpened in
                        self?.ctx.applyDrainedClose(wasOpened: wasOpened)
                    }
                    self.armTerminalDrainBackstop()
                }
            }
        )
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
        let connectTimeoutMs = egressOpts?.connectTimeoutMs ?? 10_000
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
    /// Once a terminal signal is observed the flow IS ending, so bound
    /// the wait: force a full teardown if the graceful close hasn't
    /// completed within `lingerCloseMs`. Idempotent — `applyFullTeardown`'s
    /// sticky `done` flag makes this a no-op when the graceful path won,
    /// and the nil-guard arms the timer at most once. Cost is one timer
    /// per flow close (no hot-path impact), mirroring
    /// `installConnectTimeout`. Setting `terminalSignalled` lets the
    /// on-`stateQueue` maintenance watchdog reap the same wedge even when
    /// this flow's own queue is starved (the failure mode that watchdog
    /// exists for) — see `TransparentProxyCore.collectMaintenanceKicksLocked`.
    func armTerminalDrainBackstop() {
        ctx.terminalSignalled = true
        guard terminalDrainBackstop == nil, ctx.isDone != true else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.ctx.isDone == false else { return }
            self.core?.logDebug(
                "tcp flow drain backstop fired; forcing teardown (peer not draining)")
            self.ctx.applyDrainBackstop()
        }
        terminalDrainBackstop = work
        flowQueue.asyncAfter(
            deadline: .now() + .milliseconds(Int(lingerCloseMs)), execute: work)
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
            self?.handleEgressState(state)
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
            self.ctx.lastPathViable = viable
            // Mid-session loss (roam / interface switch / VPN toggle):
            // schedule the settle-delayed dead-path re-check now instead of
            // waiting for a wake that never comes. No-op while
            // `defaultViabilityLossRecheckMs == 0` (the shipped default).
            if !viable { self.core?.handleEgressViabilityLoss(self.ctx) }
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
            return
        }
        egressReady = true
        ctx.egressReady = true
        timeoutWork?.cancel()
        timeoutWork = nil
        // Cancel any pre-ready waiting budget so it can't tear a
        // now-healthy connection down.
        waitingWork?.cancel()
        waitingWork = nil
        guard let session = sessionHandle else { return }

        let writePump = buildEgressWritePump(connection: connection)
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
            onWriteToEgress: { [weak ctx] data in
                ctx?.egressWritePump?.enqueue(data) ?? .closed
            },
            onEgressReadDemand: { [weak self] in
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
                    self.ctx.egressWritePump?.closeWhenDrained()
                    self.armTerminalDrainBackstop()
                }
            }
        )

        openKernelFlow(connection: connection, readPump: readPump, session: session)
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
                self?.applyPostReadyTeardown(error: error)
            }
            waitingWork = work
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
        // A `.cancelled` reaching us is an EXTERNAL terminal event:
        // self-initiated teardown uses `cancelAndDetach()`, which nils
        // the state handler and suppresses this callback. So tear the
        // flow down (idempotent via the teardown's sticky `done` flag)
        // instead of leaking the session, registry entry, and
        // connection slot.
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

    private func buildEgressWritePump(connection: any NwConnectionLike) -> NwTcpConnectionWritePump
    {
        let pump = NwTcpConnectionWritePump(
            connection: connection,
            queue: flowQueue,
            lingerCloseDeadline: .milliseconds(Int(lingerCloseMs)),
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
            onTerminal: { [weak self] _ in
                guard let self else { return }
                // Promoted mode only: the forwarder owns teardown, so
                // drive it to terminal — its onTerminal closes the
                // kernel flow + drops the registry entry. (The
                // connection is already force-cancelled by the pump.)
                // In viaRust mode the egress write pump's `.closed`
                // return propagates to Rust on its next write, which
                // unwinds the bridge — so no action is needed (and
                // routing through teardown here would just race that).
                guard self.ctx.mode != .viaRust else { return }
                self.ctx.directForwarder?.cancel()
            },
            // C→S byte progress on `flowQueue` — see `buildClientWritePump`.
            onActivity: { [weak self] in self?.ctx.lastActivityAt = .now() }
        )
        ctx.egressWritePump = pump
        return pump
    }

    private func buildEgressReadPump(
        connection: any NwConnectionLike,
        session: RamaTcpSessionHandle
    ) -> NwTcpConnectionReadPump {
        let pump = NwTcpConnectionReadPump(
            connection: connection,
            session: session,
            queue: flowQueue,
            eofGraceDeadline: .milliseconds(Int(egressEofGraceMs))
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
                if let error {
                    self.core?.logDebug("flow.open error after egress ready: \(error)")
                    self.ctx.applyFlowOpenFailure(error)
                    return
                }
                // Teardown may have raced ahead while flow.open
                // was in flight; `ctx.connection == nil` is the
                // canonical signal.
                guard self.ctx.connection != nil else {
                    self.core?.logTrace("flow.open completion observed teardown; dropping")
                    return
                }
                self.core?.logTrace("flow.open ok (tcp, egress pre-connected)")
                self.ctx.clientWritePump?.markOpened()
                readPump.start()
                self.armReadTerminal(session: session)
                // `armPromoteCallback()` was moved to `handleEgressReady`
                // (before `session.activate`) to close the registration
                // race with the service task — see the comment there.
                self.ctx.clientReadPump?.requestRead()
            }
        }
    }

    func armReadTerminal(session: RamaTcpSessionHandle) {
        let flow = self.flow
        let terminal = TcpReadTerminal(
            // Client upload half-close (SHUT_WR → kernel readData EOF):
            // close our read side of the kernel flow and forward EOF to
            // the egress, but do NOT cancel the egress read pump — the
            // server→client direction must keep flowing until the server
            // closes. Cancelling it here truncated downloads on every
            // half-close and matched the Rust engine's asymmetric
            // on_client_eof / on_egress_eof contract incorrectly.
            onNaturalEof: { [weak self, weak session] in
                self?.core?.logTrace(
                    "tcp client read EOF (half-close): forward to egress, keep download open")
                flow.closeReadWithError(nil)
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
            onTerminal: terminal.dispatch
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
