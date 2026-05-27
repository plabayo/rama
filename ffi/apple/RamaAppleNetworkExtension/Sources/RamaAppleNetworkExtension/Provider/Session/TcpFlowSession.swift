import Foundation
import Network
import NetworkExtension

/// Per-TCP-flow state machine.
///
/// Replaces the body of `TransparentProxyCore.handleTcpFlow`.
/// All mutable state is queue-confined to `flowQueue`; methods
/// are individually testable via `@testable import`.
final class TcpFlowSession<F: TcpFlowLike>: @unchecked Sendable {
    weak var core: TransparentProxyCore?
    let flow: F
    let meta: RamaTransparentProxyFlowMetaBridge
    let flowId: ObjectIdentifier
    let flowQueue: DispatchQueue
    let ctx: TcpFlowContext
    let teardown: TcpFlowTeardown

    // Egress lifecycle state — queue-confined.
    var egressReady = false
    var timeoutWork: DispatchWorkItem?
    var waitingWork: DispatchWorkItem?

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
        self.teardown = TcpFlowTeardown(ctx: ctx, core: core, flow: flow, flowId: flowId)
        self.ctx.teardown = teardown
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
            core?.registerTcpFlow(flowId, session: session, context: ctx)
            return startEgressConnection(session: session)
        case .passthrough:
            core?.logDebug("handleNewFlow tcp bypassed by rust flow policy")
            return false
        case .blocked:
            core?.logInfo("handleNewFlow tcp blocked by rust flow policy")
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
                ctx?.teardown?.applyWriterTerminal(error)
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
            }
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
                        self?.ctx.teardown?.applyDrainedClose(wasOpened: wasOpened)
                    }
                }
            }
        )
    }

    // MARK: - Phase: egress connection

    func startEgressConnection(session: RamaTcpSessionHandle) -> Bool {
        guard let remoteHost = meta.remoteHost, meta.remotePort > 0 else {
            core?.logDebug("handleTcpFlow: missing remote endpoint; cancelling session")
            session.cancel()
            core?.removeTcpFlow(flowId)
            return true
        }

        let egressOpts = session.getEgressConnectOptions()
        let connectTimeoutMs = egressOpts?.connectTimeoutMs ?? 30_000
        lingerCloseMs = egressOpts?.lingerCloseMs ?? defaultLingerCloseMs
        egressEofGraceMs = egressOpts?.egressEofGraceMs ?? defaultEgressEofGraceMs
        let nwParams = makeTcpNwParameters(egressOpts)

        if egressOpts?.parameters.preserve_original_meta_data ?? true {
            flow.applyMetadata(to: nwParams)
        }

        guard let factory = core?.nwConnectionFactory,
            let connection = factory(remoteHost, meta.remotePort, nwParams)
        else {
            core?.logDebug("handleTcpFlow: invalid remote port \(meta.remotePort); cancelling session")
            session.cancel()
            core?.removeTcpFlow(flowId)
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
            guard let self, !self.egressReady else { return }
            self.core?.logDebug(
                "egress NWConnection timed out for tcp flow remote=\(remoteHost):\(self.meta.remotePort)"
            )
            self.ctx.teardown?.applyConnectTimeout()
        }
        timeoutWork = work
        flowQueue.asyncAfter(deadline: .now() + .milliseconds(Int(connectTimeoutMs)), execute: work)
    }

    func installEgressStateHandler(connection: any NwConnectionLike) {
        // Strong self: the handler IS the lifetime anchor for the
        // session. `handleTcpFlow` constructs the session and lets
        // its local ref go out of scope; without this strong
        // capture the session would deallocate and every later
        // callback (promote, late-`.failed`, etc.) would no-op.
        // The retain cycle (connection → handler → session →
        // ctx.connection → connection) is broken by
        // `cancelAndDetach()` on teardown, which sets the handler
        // to nil.
        connection.stateUpdateHandler = { state in
            self.flowQueue.async {
                self.handleEgressState(state)
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
            ctx.teardown?.applyPreReadyFailure()
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
            guard let self, !self.egressReady else { return }
            self.core?.logDebug(
                "egress NWConnection pre-ready waiting exceeded budget; failing fast "
                    + "remote=\(self.meta.remoteHost ?? "?"):\(self.meta.remotePort)"
            )
            self.ctx.teardown?.applyPreReadyWaitingTimeout()
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
            ctx.teardown?.applyPostReadyFailure(nil)
        } else {
            ctx.teardown?.applyPreReadyFailure()
        }
    }

    private func applyPostReadyTeardown(error: NWError?) {
        waitingWork?.cancel()
        waitingWork = nil
        ctx.teardown?.applyPostReadyFailure(error)
    }

    // MARK: - Phase: egress pump construction

    private func buildEgressWritePump(connection: any NwConnectionLike) -> NwTcpConnectionWritePump {
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
            }
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
                    self.ctx.teardown?.applyFlowOpenFailure(error)
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
                self?.core?.logTrace("tcp client read EOF (half-close): forward to egress, keep download open")
                flow.closeReadWithError(nil)
                session?.onClientEof()
            },
            onHardError: { [weak self] err in
                self?.ctx.teardown?.applyReadHardError(err)
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
        // Weak self: the Rust session keeps this closure alive until
        // session.cancel() runs, which doesn't happen on the
        // cutover-happy-path (the forwarder's onTerminal just closes
        // the flow + removeTcpFlow). Strong self here would pin the
        // session past every other anchor, leaking flow + connection.
        // The state handler's strong self is sufficient: if the
        // connection is alive, session is alive, weak self resolves.
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
