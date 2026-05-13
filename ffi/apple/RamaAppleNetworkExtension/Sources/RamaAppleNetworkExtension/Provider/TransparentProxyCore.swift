import Foundation
import Network
import RamaAppleNEFFI

/// Apple-framework-free home of the transparent-proxy per-flow state
/// machine, the engine handle ownership, and the session / context
/// registration maps.
///
/// `RamaTransparentProxyProvider` is the type the Apple system-extension
/// runtime instantiates and calls into; that subclass requirement is the
/// only reason it exists. The actual logic — receiving an intercepted
/// flow, wiring its read / write pumps to a Rust session, observing
/// `NWConnection` state transitions, cleaning up on terminal events —
/// has no reason to live in a `NETransparentProxyProvider` subclass and
/// historically just did so because it grew there.
///
/// Splitting that logic into this core type lets:
///
/// * unit tests drive the full per-flow lifecycle against a mock flow
///   (`MockTcpFlow` / `MockUdpFlow`) and a mock NWConnection
///   (`MockNwConnection`) without standing up a system extension or
///   real socket;
/// * end-to-end tests exercise the *real* Rust engine with mocked
///   Apple-framework surface, verifying byte flow + cleanup + memory
///   bounds under realistic scheduling;
/// * the provider become a thin (~150-line) adapter that delegates
///   every override to a method on the core, keeping the
///   Apple-specific boundary in one place.
///
/// The core has no `import NetworkExtension` dependency. Everything it
/// touches is either Rust-FFI (`Ram*Handle`), the `Network` framework
/// (which is testable), or its own protocols (`TcpFlowLike`,
/// `UdpFlowLike`, `NwConnectionLike`). The provider passes flow
/// metadata in via the `RamaTransparentProxyFlowMetaBridge` struct so
/// the core never has to access `NEFlowMetaData`.
final class TransparentProxyCore {
    // MARK: - Owned state

    private(set) var engine: RamaTransparentProxyEngineHandle?
    private let stateQueue = DispatchQueue(label: "rama.tproxy.core.state")
    private var tcpSessions: [ObjectIdentifier: RamaTcpSessionHandle] = [:]
    private var tcpContexts: [ObjectIdentifier: TcpFlowContext] = [:]
    private var udpSessions: [ObjectIdentifier: RamaUdpSessionHandle] = [:]
    private var udpContexts: [ObjectIdentifier: UdpFlowContext] = [:]

    /// Factory used to construct egress `NWConnection`s for intercepted
    /// flows. Production leaves this at the default (a real
    /// `NWConnection`); tests assign a mock factory so the per-flow
    /// state machine can be driven without a real socket.
    var nwConnectionFactory: NwConnectionFactoryFn = defaultNwConnectionFactory

    /// Timer that emits a per-protocol live-flow count every 60s.
    /// Operator-visible signal that catches accumulation regressions
    /// — a registered-flow leak would show up as `tcp_flows` /
    /// `udp_flows` growing without bound in `log show` — before
    /// users notice degradation. `nil` outside of `attachEngine` /
    /// `detachEngine` brackets.
    private var flowCountReportingTimer: DispatchSourceTimer?

    // MARK: - Engine lifecycle

    /// Hand a freshly-built engine to the core. The provider's
    /// `startProxy` override does the Apple-framework configuration
    /// dance (reading `protocolConfiguration`, building
    /// `NETransparentProxyNetworkSettings`, calling
    /// `setTunnelNetworkSettings`) and then publishes the resulting
    /// engine here. Per-flow handling becomes available only after
    /// this is called.
    func attachEngine(_ engine: RamaTransparentProxyEngineHandle) {
        // Single-shot in production (`startProxy` calls us once per
        // lifecycle), but defensively detach any previous engine
        // first so a future caller that double-attaches doesn't
        // strand the original engine's Rust runtime + bridge tasks
        // alive without anyone holding a way to stop them.
        if self.engine != nil {
            detachEngine(reason: 0)
        }
        self.engine = engine
        startFlowCountReporting()
    }

    /// Symmetric counterpart of `attachEngine` invoked from
    /// `stopProxy`. Stops the engine, clears all per-flow registrations.
    /// Idempotent — safe to call twice.
    func detachEngine(reason: Int32) {
        stopFlowCountReporting()
        self.engine?.stop(reason: reason)
        self.engine = nil
        stateQueue.sync {
            self.tcpSessions.removeAll(keepingCapacity: false)
            self.tcpContexts.removeAll(keepingCapacity: false)
            self.udpSessions.removeAll(keepingCapacity: false)
            self.udpContexts.removeAll(keepingCapacity: false)
        }
    }

    // MARK: - Periodic flow-count telemetry

    /// Interval between live-flow-count reports. 60s is short enough
    /// to surface accumulation regressions within minutes of onset
    /// and long enough that the resulting log volume is negligible.
    private static let flowCountReportingInterval: DispatchTimeInterval = .seconds(60)

    private func startFlowCountReporting() {
        stopFlowCountReporting()
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.schedule(
            deadline: .now() + Self.flowCountReportingInterval,
            repeating: Self.flowCountReportingInterval
        )
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            // `stateQueue.sync` not needed — the timer fires ON
            // `stateQueue`, so direct access to the maps is already
            // serialised correctly.
            let tcp = self.tcpContexts.count
            let udp = self.udpContexts.count
            self.logDebug("tproxy live-flow counts tcp=\(tcp) udp=\(udp)")
        }
        timer.resume()
        flowCountReportingTimer = timer
    }

    private func stopFlowCountReporting() {
        flowCountReportingTimer?.cancel()
        flowCountReportingTimer = nil
    }

    // MARK: - App-message routing

    func handleAppMessage(_ messageData: Data) -> Data? {
        logDebug("handleAppMessage bytes=\(messageData.count)")
        guard let engine else {
            logDebug("handleAppMessage ignored because engine is unavailable")
            return nil
        }
        return engine.handleAppMessage(messageData)
    }

    // MARK: - Registration maps

    func registerTcpFlow(
        _ flowId: ObjectIdentifier,
        session: RamaTcpSessionHandle,
        context: TcpFlowContext
    ) {
        stateQueue.sync {
            self.tcpSessions[flowId] = session
            self.tcpContexts[flowId] = context
        }
    }

    func registerUdpFlow(
        _ flowId: ObjectIdentifier,
        session: RamaUdpSessionHandle,
        context: UdpFlowContext
    ) {
        stateQueue.sync {
            self.udpSessions[flowId] = session
            self.udpContexts[flowId] = context
        }
    }

    func removeTcpFlow(_ flowId: ObjectIdentifier) {
        stateQueue.sync {
            self.tcpSessions.removeValue(forKey: flowId)
            self.tcpContexts.removeValue(forKey: flowId)
        }
    }

    func removeUdpFlow(_ flowId: ObjectIdentifier) {
        stateQueue.sync {
            self.udpSessions.removeValue(forKey: flowId)
            self.udpContexts.removeValue(forKey: flowId)
        }
    }

    /// Count of currently-registered TCP flows. Test-only signal for
    /// leak / churn assertions.
    var tcpFlowCount: Int {
        stateQueue.sync { self.tcpContexts.count }
    }

    /// Count of currently-registered UDP flows. Test-only signal.
    var udpFlowCount: Int {
        stateQueue.sync { self.udpContexts.count }
    }

    // MARK: - Logging helpers

    // Identical to the helpers the provider used to expose; consolidated
    // here so closures that capture `self` (the core) from inside the
    // moved flow-handling methods still have the same surface available.

    func logTrace(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_TRACE.rawValue),
            message: message
        )
    }

    func logDebug(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
            message: message
        )
    }

    func logInfo(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_INFO.rawValue),
            message: message
        )
    }

    func logError(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_ERROR.rawValue),
            message: message
        )
    }

    func logFlowMessage(_ message: FlowLogMessage) {
        switch message.level {
        case .trace: logTrace(message.text)
        case .debug: logDebug(message.text)
        case .error: logError(message.text)
        }
    }

    // MARK: - Per-flow handling (TCP)

    /// Handle one intercepted TCP flow end-to-end.
    ///
    /// Generic over `TcpFlowLike` so the adapter can pass a real
    /// `NEAppProxyTCPFlow` and tests can pass a `MockTcpFlow`. The
    /// metadata snapshot is extracted at the adapter boundary (where
    /// `NEFlowMetaData` is available) and passed in so this method
    /// itself never has to reach into Apple framework types.
    ///
    /// Returns `true` if the flow has been claimed (intercepted or
    /// blocked), `false` if the engine decided to pass through (no
    /// session was created, the flow will be handled by the kernel
    /// directly).
    func handleTcpFlow<F: TcpFlowLike>(
        _ flow: F, meta: RamaTransparentProxyFlowMetaBridge
    ) -> Bool {
        let flowId = ObjectIdentifier(flow)
        let flowQueue = DispatchQueue(
            label: "rama.tproxy.tcp.flow.\(UInt(bitPattern: ObjectIdentifier(flow)))",
            qos: .utility)
        let ctx = TcpFlowContext()

        let writer = TcpClientWritePump(
            flow: flow,
            queue: flowQueue,
            logger: { [weak self] message in
                self?.logFlowMessage(message)
            },
            onTerminalError: { [weak self, weak ctx] error in
                // [weak ctx] keeps the writer's onTerminalError closure
                // from pinning the per-flow context graph alive after
                // the session is removed.
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                ctx?.connection?.cancel()
                ctx?.session?.cancel()
                self?.removeTcpFlow(flowId)
            },
            onDrained: { [weak ctx] in
                ctx?.session?.signalServerDrain()
            }
        )
        ctx.clientWritePump = writer

        let decision =
            engine?.newTcpSession(
                meta: meta,
                onServerBytes: { [weak ctx] data in
                    // Reach the writer through ctx so the Rust callback
                    // box can't keep the writer alive past dispatcher
                    // teardown. `.closed` tells the Rust bridge to stop
                    // producing.
                    ctx?.clientWritePump?.enqueue(data) ?? .closed
                },
                onClientReadDemand: { [weak ctx] in
                    // Rust → Swift: the per-flow ingress channel has space
                    // again, so we may resume `flow.readData`. Hop onto the
                    // flow's queue before touching `ctx`, since this fires
                    // from a Rust worker thread.
                    flowQueue.async { [weak ctx] in
                        ctx?.clientReadPump?.resume()
                    }
                },
                onServerClosed: { [weak self, weak ctx] in
                    ctx?.clientWritePump?.closeWhenDrained { wasOpened in
                        if wasOpened {
                            flow.closeReadWithError(nil)
                            flow.closeWriteWithError(nil)
                        } else {
                            let error = tcpUpstreamUnavailableError()
                            flow.closeReadWithError(error)
                            flow.closeWriteWithError(error)
                        }
                        ctx?.connection?.cancel()
                        self?.removeTcpFlow(flowId)
                    }
                }
            ) ?? .passthrough

        let session: RamaTcpSessionHandle
        switch decision {
        case .intercept(let createdSession):
            session = createdSession
        case .passthrough:
            logDebug("handleNewFlow tcp bypassed by rust flow policy")
            return false
        case .blocked:
            logInfo("handleNewFlow tcp blocked by rust flow policy")
            let error = blockedFlowError()
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
            return true
        }

        ctx.session = session
        // Publish the flow state before any callback that may observe it can fire.
        registerTcpFlow(flowId, session: session, context: ctx)

        // ── Phase 2: pre-connect egress NWConnection before opening the flow ──
        guard let remoteHost = meta.remoteHost, meta.remotePort > 0 else {
            logDebug("handleTcpFlow: missing remote endpoint; cancelling session")
            session.cancel()
            removeTcpFlow(flowId)
            return true
        }

        let egressOpts = session.getEgressConnectOptions()
        let connectTimeoutMs = egressOpts.flatMap { $0.has_connect_timeout_ms ? $0.connect_timeout_ms : nil } ?? 30_000
        let lingerCloseMs = egressOpts.flatMap { $0.has_linger_close_ms ? $0.linger_close_ms : nil } ?? defaultLingerCloseMs
        let egressEofGraceMs = egressOpts.flatMap {
            $0.has_egress_eof_grace_ms ? $0.egress_eof_grace_ms : nil
        } ?? defaultEgressEofGraceMs
        let nwParams = makeTcpNwParameters(egressOpts)

        // Stamp the intercepted flow's NEFlowMetaData (source app identifier,
        // audit token, …) onto the egress NWParameters when the handler asks
        // for it (default true). Downstream NEAppProxyProviders that
        // intercept our egress see the original app rather than this
        // extension. Must run before the NWConnection is constructed from
        // these params.
        //
        // The core delegates to the protocol's `applyMetadata(to:)` so
        // it never has to know what `NEFlowMetaData` is — Apple-framework
        // surface stays on the adapter side via the conformance.
        if egressOpts?.parameters.preserve_original_meta_data ?? true {
            flow.applyMetadata(to: nwParams)
        }

        guard let connection = nwConnectionFactory(remoteHost, meta.remotePort, nwParams)
        else {
            logDebug(
                "handleTcpFlow: invalid remote port \(meta.remotePort); cancelling session"
            )
            session.cancel()
            removeTcpFlow(flowId)
            return true
        }
        ctx.connection = connection

        // Track whether the egress connection succeeded before flow.open was called.
        var egressReady = false

        // Timeout: cancel if NWConnection doesn't reach .ready in time.
        let timeoutMs = Int(connectTimeoutMs)
        let timeoutWork = DispatchWorkItem { [weak self, weak ctx] in
            guard !egressReady else { return }
            self?.logDebug("egress NWConnection timed out for tcp flow remote=\(remoteHost):\(meta.remotePort)")
            ctx?.connection?.cancel()
            ctx?.session?.cancel()
            self?.removeTcpFlow(flowId)
        }
        flowQueue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs), execute: timeoutWork)

        // Post-ready `.waiting(_)` tolerance — a Wi-Fi roam or other
        // transient path change can take the connection briefly back
        // into `.waiting` after it reached `.ready`. We allow a short
        // window for the path to recover; staying in `.waiting` past
        // the window means the path is gone and the flow must be torn
        // down so the macOS NWConnection registration is released.
        let egressWaitingToleranceMs = defaultEgressWaitingToleranceMs
        var waitingWork: DispatchWorkItem?

        // Post-ready teardown shared between the `.failed` arm and the
        // `.waiting` tolerance timer. Idempotent — every step is safe
        // to invoke twice, so a concurrent teardown path (the egress
        // read pump's EOF backstop, the flow's hard-error terminal,
        // an external `engine.stop`) that races with this closure
        // does not corrupt state.
        // Not `@Sendable` because it mutates `waitingWork`; all
        // invocation sites run on `flowQueue` so single-threaded
        // mutation is safe.
        let tearDownPostReady: (Error?) -> Void = { [weak self, weak ctx] err in
            waitingWork?.cancel()
            waitingWork = nil
            let nsErr =
                err
                ?? NSError(
                    domain: "rama.tproxy.tcp",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "egress NWConnection terminated post-ready"]
                )
            flow.closeReadWithError(nsErr)
            flow.closeWriteWithError(nsErr)
            ctx?.connection?.cancel()
            ctx?.connection = nil
            ctx?.egressReadPump?.cancel()
            ctx?.egressReadPump = nil
            ctx?.egressWritePump?.cancel()
            ctx?.egressWritePump = nil
            ctx?.clientReadPump = nil
            ctx?.clientWritePump?.cancel()
            ctx?.clientWritePump = nil
            ctx?.session?.cancel()
            self?.removeTcpFlow(flowId)
        }

        connection.stateUpdateHandler = { [weak self, weak ctx] (state: NWConnection.State) in
            flowQueue.async { [weak self, weak ctx] in
                guard let ctx, let connection = ctx.connection else { return }
                switch state {
                case .ready:
                    if egressReady {
                        // A duplicate `.ready` after a recovered
                        // `.waiting` — cancel any pending tolerance
                        // timer so it does not fire on the now-healthy
                        // connection.
                        waitingWork?.cancel()
                        waitingWork = nil
                        return
                    }
                    egressReady = true
                    timeoutWork.cancel()

                    let writePump = NwTcpConnectionWritePump(
                        connection: connection,
                        queue: flowQueue,
                        lingerCloseDeadline: .milliseconds(Int(lingerCloseMs)),
                        onDrained: { [weak ctx] in
                            ctx?.session?.signalEgressDrain()
                        }
                    )
                    ctx.egressWritePump = writePump
                    let readPump = NwTcpConnectionReadPump(
                        connection: connection,
                        session: session,
                        queue: flowQueue,
                        eofGraceDeadline: .milliseconds(Int(egressEofGraceMs))
                    )
                    ctx.egressReadPump = readPump

                    session.activate(
                        onWriteToEgress: { [weak ctx] data in
                            ctx?.egressWritePump?.enqueue(data) ?? .closed
                        },
                        onEgressReadDemand: { [weak ctx] in
                            flowQueue.async { [weak ctx] in
                                ctx?.egressReadPump?.resume()
                            }
                        },
                        onCloseEgress: { [weak ctx] in
                            ctx?.egressWritePump?.closeWhenDrained()
                        }
                    )

                    flow.open(withLocalEndpoint: nil) { [weak self, weak ctx] error in
                        flowQueue.async {
                            if let error {
                                self?.logDebug("flow.open error after egress ready: \(error)")
                                connection.cancel()
                                ctx?.connection = nil
                                readPump.cancel()
                                ctx?.egressReadPump = nil
                                ctx?.egressWritePump?.cancel()
                                ctx?.egressWritePump = nil
                                ctx?.clientWritePump?.cancel()
                                ctx?.clientWritePump = nil
                                session.cancel()
                                self?.removeTcpFlow(flowId)
                                return
                            }
                            self?.logTrace("flow.open ok (tcp, egress pre-connected)")
                            writer.markOpened()
                            readPump.start()

                            // Natural-EOF and hard-error paths
                            // intentionally diverge — see
                            // `TcpReadTerminal`. The natural-EOF
                            // path defers write-side teardown to
                            // the writer pump's drain so queued
                            // response bytes reach the originating
                            // app; closing the write side or
                            // calling `session.cancel()` here
                            // would truncate them. Weak captures
                            // keep this closure graph from pinning
                            // the per-flow context alive.
                            let terminal = TcpReadTerminal(
                                onNaturalEof: {
                                    [weak self, weak readPump, weak session] in
                                    self?.logTrace(
                                        "tcp natural EOF: deferring teardown to closeWhenDrained"
                                    )
                                    flow.closeReadWithError(nil)
                                    readPump?.cancel()
                                    session?.onClientEof()
                                },
                                onHardError: {
                                    [weak self, weak ctx, weak readPump, weak session] err in
                                    flow.closeReadWithError(err)
                                    flow.closeWriteWithError(err)
                                    ctx?.connection?.cancel()
                                    ctx?.connection = nil
                                    readPump?.cancel()
                                    ctx?.clientWritePump?.cancel()
                                    ctx?.egressWritePump?.cancel()
                                    session?.cancel()
                                    ctx?.clientReadPump = nil
                                    ctx?.egressReadPump = nil
                                    ctx?.clientWritePump = nil
                                    ctx?.egressWritePump = nil
                                    self?.removeTcpFlow(flowId)
                                }
                            )
                            let flowReadPump = TcpClientReadPump(
                                flow: flow,
                                session: session,
                                queue: flowQueue,
                                logger: { [weak self] message in self?.logFlowMessage(message) },
                                onTerminal: terminal.dispatch
                            )
                            ctx?.clientReadPump = flowReadPump
                            flowReadPump.requestRead()
                        }
                    }

                case .failed(let error):
                    if !egressReady {
                        // Pre-ready failure — flow was never opened,
                        // pumps were never wired, session has no
                        // bridges to drain. The minimal cleanup is
                        // enough.
                        timeoutWork.cancel()
                        self?.logDebug(
                            "egress NWConnection failed before flow opened: \(String(describing: error))"
                        )
                        // Explicit cancel() releases the kernel NECP flow slot.
                        connection.cancel()
                        session.cancel()
                        self?.removeTcpFlow(flowId)
                    } else {
                        // Post-ready failure — peer RST, TLS abort,
                        // NECP path drop, or anything else that takes
                        // an established `NWConnection` to `.failed`.
                        // Without this branch the connection sits
                        // registered until some other path (read pump
                        // error, idle timeout, max-flow lifetime)
                        // eventually catches it, which is exactly the
                        // accumulation that turns into the
                        // path-evaluator slowdown.
                        self?.logDebug(
                            "egress NWConnection failed after flow opened: \(String(describing: error))"
                        )
                        tearDownPostReady(error)
                    }

                case .waiting(let error):
                    if !egressReady {
                        // Pre-ready waiting is handled by
                        // `connect_timeout` already; we leave it
                        // alone here so two timers cannot race.
                        break
                    }
                    // Post-ready waiting — start the tolerance timer
                    // if one is not already pending. Returning to
                    // `.ready` cancels it; staying in `.waiting` past
                    // the tolerance triggers teardown via the same
                    // path as `.failed`.
                    if waitingWork != nil { break }
                    self?.logDebug(
                        "egress NWConnection waiting after flow opened: \(String(describing: error))"
                    )
                    let work = DispatchWorkItem {
                        tearDownPostReady(error)
                    }
                    waitingWork = work
                    flowQueue.asyncAfter(
                        deadline: .now() + .milliseconds(Int(egressWaitingToleranceMs)),
                        execute: work
                    )

                case .cancelled:
                    // We initiated this cancel via one of the
                    // teardown paths above (or the linger / EOF
                    // backstops in the pumps). Nothing to do here
                    // beyond making sure any pending `.waiting`
                    // tolerance timer is invalidated.
                    waitingWork?.cancel()
                    waitingWork = nil

                default:
                    // `.preparing`, `.setup`, and future cases —
                    // nothing actionable at the core level.
                    break
                }
            }
        }

        connection.start(queue: flowQueue)
        return true
    }

    // MARK: - Per-flow handling (UDP)

    /// Handle one intercepted UDP flow end-to-end. Mirror of the TCP
    /// counterpart: generic over `UdpFlowLike`, takes a metadata
    /// snapshot extracted at the adapter boundary, so the same logic
    /// is exercised by production (`NEAppProxyUDPFlow`) and by tests
    /// (`MockUdpFlow`).
    func handleUdpFlow<F: UdpFlowLike>(
        _ flow: F, meta bootMeta: RamaTransparentProxyFlowMetaBridge
    ) -> Bool {
        let flowId = ObjectIdentifier(flow)
        let flowQueue = DispatchQueue(
            label: "rama.tproxy.udp.flow.\(UInt(bitPattern: ObjectIdentifier(flow)))",
            qos: .utility)
        let ctx = UdpFlowContext()

        ctx.terminate = { [weak self, weak ctx] error in
            // Re-`[weak ctx]` at the nested closure boundary; see
            // `requestRead` for why.
            flowQueue.async { [weak self, weak ctx] in
                guard let ctx, ctx.readState != .closed else { return }
                ctx.readState = .closed
                ctx.egressReadPump?.cancel()
                ctx.egressReadPump = nil
                ctx.writer?.close()
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                ctx.connection?.cancel()
                ctx.connection = nil
                ctx.session?.onClientClose()
                self?.removeUdpFlow(flowId)
            }
        }

        ctx.writer = UdpClientWritePump(
            flow: flow,
            queue: flowQueue,
            logger: { [weak self] message in
                self?.logFlowMessage(message)
            },
            onTerminalError: { [weak ctx] error in
                // Route through `[weak ctx]` so this closure (held
                // by the writer) does not strong-capture `terminate`
                // — terminate transitively reaches the writer via
                // `ctx.writer`, so a strong link in either direction
                // would close a writer ↔ terminate cycle.
                ctx?.terminate?(error)
            }
        )

        ctx.requestRead = { [weak self, weak ctx] in
            // Re-`[weak ctx]` at every nested-closure boundary.
            // A `guard let ctx` here would make `ctx` strong for
            // every closure further down, re-introducing a strong
            // capture path back through this chain.
            flowQueue.async { [weak ctx] in
                guard let ctx, ctx.readState != .closed else { return }
                // If a read is already in flight (or demand is already
                // queued), record / keep the demand flag and return —
                // the completion handler will re-trigger.  The check
                // covers both .reading and .readingWithDemand so that
                // a third rapid demand does not issue a concurrent
                // second readDatagrams call while the first is still
                // in flight.
                if ctx.readState == .reading || ctx.readState == .readingWithDemand {
                    ctx.readState = .readingWithDemand
                    return
                }
                ctx.readState = .reading
                flow.readDatagrams { [weak self, weak ctx] datagrams, endpoints, error in
                    flowQueue.async { [weak ctx] in
                        guard let ctx, ctx.readState != .closed else { return }
                        let hadPendingDemand = ctx.readState == .readingWithDemand
                        ctx.readState = .idle
                        if let error {
                            self?.logFlowMessage(
                                classifyFlowCallbackError(error, operation: "udp flow.read")
                            )
                            ctx.terminate?(error)
                            return
                        }

                        guard let datagrams, !datagrams.isEmpty else {
                            self?.logTrace("flow.readDatagrams eof")
                            ctx.terminate?(nil)
                            return
                        }

                        // Per-batch endpoint extraction. A multi-
                        // endpoint batch (rare; sendto() to multiple
                        // peers on an unconnected UDP socket) gets
                        // collapsed because the egress side has one
                        // NWConnection per flow; within-batch peer
                        // variation is logged so operators see the
                        // single-peer assumption being violated.
                        let endpoint = endpoints?.first
                        if let endpoints, endpoints.count > 1,
                            !endpoints.dropFirst().allSatisfy({ $0 == endpoints[0] })
                        {
                            self?.logDebug(
                                "udp flow.readDatagrams returned mixed peer endpoints in one batch (\(endpoints.count) entries); single-peer assumption violated"
                            )
                        }
                        ctx.writer?.setSentByEndpoint(endpoint)

                        guard let session = ctx.session else {
                            self?.logDebug(
                                "udp flow read received but session no longer active; closing flow"
                            )
                            ctx.terminate?(nil)
                            return
                        }

                        for datagram in datagrams where !datagram.isEmpty {
                            session.onClientDatagram(datagram)
                        }

                        if hadPendingDemand {
                            ctx.requestRead?()
                        }
                    }
                }
            }
        }

        let decision = engine?.newUdpSession(
            meta: bootMeta,
            // Rust-held closures route through `[weak ctx]` so the
            // callback box (Rust) does not strong-pin the per-flow
            // pumps. The box is dropped on `_session_free`, so once
            // `removeUdpFlow` releases the session-handle these
            // closures stop firing — no late-arrival hazard.
            onServerDatagram: { [weak ctx] data in ctx?.writer?.enqueue(data) },
            onClientReadDemand: { [weak ctx] in ctx?.requestRead?() },
            onServerClosed: { [weak ctx] in ctx?.terminate?(nil) }
        ) ?? .passthrough

        let session: RamaUdpSessionHandle
        switch decision {
        case .intercept(let createdSession):
            session = createdSession
        case .passthrough:
            logDebug("handleNewFlow udp bypassed by rust flow policy")
            return false
        case .blocked:
            logInfo("handleNewFlow udp blocked by rust flow policy")
            let error = blockedFlowError()
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
            return true
        }

        ctx.session = session
        // Publish the flow state before any callback that may observe it can fire.
        registerUdpFlow(flowId, session: session, context: ctx)

        // ── Phase 2: pre-connect egress NWConnection before opening the flow ──
        guard let remoteHost = bootMeta.remoteHost, bootMeta.remotePort > 0 else {
            logDebug("handleUdpFlow: missing remote endpoint; cancelling session")
            session.onClientClose()
            removeUdpFlow(flowId)
            return true
        }

        let egressOpts = session.getEgressConnectOptions()
        let nwParams = makeUdpNwParameters(egressOpts)
        let connectTimeoutMs: UInt32 =
            egressOpts.flatMap { $0.has_connect_timeout_ms ? $0.connect_timeout_ms : nil } ?? 30_000

        // See TCP path for rationale; same metadata-propagation behavior.
        // The protocol's `applyMetadata(to:)` keeps the core ignorant of
        // `NEFlowMetaData`.
        if egressOpts?.parameters.preserve_original_meta_data ?? true {
            flow.applyMetadata(to: nwParams)
        }

        guard let connection = nwConnectionFactory(remoteHost, bootMeta.remotePort, nwParams)
        else {
            logDebug(
                "handleUdpFlow: invalid remote port \(bootMeta.remotePort); cancelling session"
            )
            session.onClientClose()
            removeUdpFlow(flowId)
            return true
        }
        ctx.connection = connection

        var egressReady = false

        // Wall-clock cap on the NWConnection.stateUpdateHandler reaching
        // `.ready`. Configurable via `NwUdpConnectOptions.connect_timeout`;
        // default 30s when the handler does not override.
        let timeoutWork = DispatchWorkItem { [weak self, weak ctx] in
            guard !egressReady else { return }
            self?.logDebug(
                "egress NWConnection timed out for udp flow remote=\(remoteHost):\(bootMeta.remotePort)"
            )
            ctx?.connection?.cancel()
            ctx?.connection = nil
            ctx?.session?.onClientClose()
            self?.removeUdpFlow(flowId)
        }
        flowQueue.asyncAfter(
            deadline: .now() + .milliseconds(Int(connectTimeoutMs)), execute: timeoutWork)

        // Mirror of the TCP path's `.waiting(_)` tolerance: a brief
        // post-ready dip back into `.waiting` should be tolerated;
        // sitting in `.waiting` past the window means the path is
        // gone and the flow must be torn down.
        let udpEgressWaitingToleranceMs = defaultEgressWaitingToleranceMs
        var udpWaitingWork: DispatchWorkItem?

        connection.stateUpdateHandler = { [weak self, weak ctx] (state: NWConnection.State) in
            flowQueue.async { [weak self, weak ctx] in
                guard let ctx, let connection = ctx.connection else { return }
                switch state {
                case .ready:
                    if egressReady {
                        udpWaitingWork?.cancel()
                        udpWaitingWork = nil
                        return
                    }
                    egressReady = true
                    timeoutWork.cancel()

                    let readPump = NwUdpConnectionReadPump(
                        connection: connection,
                        session: session,
                        queue: flowQueue,
                        // Same anti-cycle pattern as the writer's
                        // `onTerminalError`: weak forwarder so the
                        // read pump doesn't strong-pin `terminate`.
                        onTerminate: { [weak ctx] error in ctx?.terminate?(error) }
                    )
                    ctx.egressReadPump = readPump

                    session.activate(onSendToEgress: { [weak ctx] data in
                        // Surface send failures: the completion
                        // closure runs on NWConnection's scheduler,
                        // hop back onto `flowQueue` so `terminate`
                        // sees flow-scoped state single-threaded.
                        //
                        // `isComplete: true` is the correct datagram
                        // boundary marker on a UDP `NWConnection`; the
                        // value is set explicitly here because the
                        // injectable protocol surface has no default
                        // arguments.
                        connection.send(
                            content: data,
                            contentContext: .defaultMessage,
                            isComplete: true,
                            completion: .contentProcessed({ error in
                                if let error {
                                    flowQueue.async { ctx?.terminate?(error) }
                                }
                            })
                        )
                    })

                    flow.open(withLocalEndpoint: nil) { [weak self, weak ctx] error in
                        flowQueue.async {
                            if let error {
                                self?.logDebug("udp flow.open error after egress ready: \(error)")
                                connection.cancel()
                                readPump.cancel()
                                ctx?.egressReadPump = nil
                                ctx?.connection = nil
                                session.onClientClose()
                                self?.removeUdpFlow(flowId)
                                return
                            }
                            self?.logTrace("flow.open ok (udp, egress pre-connected)")
                            ctx?.writer?.markOpened()
                            readPump.start()
                            ctx?.requestRead?()
                        }
                    }

                case .failed(let error):
                    if !egressReady {
                        timeoutWork.cancel()
                        self?.logDebug(
                            "egress NWConnection failed before udp flow opened: \(String(describing: error))"
                        )
                        // See TCP path: explicit cancel() returns the kernel flow slot.
                        connection.cancel()
                        ctx.connection = nil
                        session.onClientClose()
                        self?.removeUdpFlow(flowId)
                    } else {
                        // Post-ready failure — route through the
                        // shared `terminate` closure so the flow
                        // teardown is consistent with all other UDP
                        // failure paths (egress read pump, flow-side
                        // read error, NWConnection send failure).
                        udpWaitingWork?.cancel()
                        udpWaitingWork = nil
                        self?.logDebug(
                            "egress NWConnection failed after udp flow opened: \(String(describing: error))"
                        )
                        ctx.terminate?(error)
                    }

                case .waiting(let error):
                    if !egressReady {
                        break
                    }
                    if udpWaitingWork != nil { break }
                    self?.logDebug(
                        "egress NWConnection waiting after udp flow opened: \(String(describing: error))"
                    )
                    let work = DispatchWorkItem { [weak ctx] in
                        ctx?.terminate?(error)
                    }
                    udpWaitingWork = work
                    flowQueue.asyncAfter(
                        deadline: .now() + .milliseconds(Int(udpEgressWaitingToleranceMs)),
                        execute: work
                    )

                case .cancelled:
                    udpWaitingWork?.cancel()
                    udpWaitingWork = nil

                default:
                    break
                }
            }
        }

        connection.start(queue: flowQueue)
        return true
    }
}
