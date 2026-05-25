import Foundation
import Network
import NetworkExtension
import RamaAppleNEFFI

/// Home of the transparent-proxy per-flow state machine, the engine
/// handle ownership, and the session / context registration maps.
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
/// * the provider become a thin adapter that delegates every override
///   to a method on the core, keeping `NETransparentProxyProvider`-
///   subclass-specific concerns (the runtime contract) in one place.
///
/// Frameworks consumed here:
///
/// * `RamaAppleNEFFI` — the Rust engine FFI.
/// * `Network` — for `NWConnection` (egress on TCP flows) and
///   `NWParameters`.
/// * `NetworkExtension` — for `NWHostEndpoint` /
///   `NetworkExtension.NWEndpoint` (kernel-supplied flow endpoints
///   on the UDP read path) and for `NEAppProxyUDPFlow` /
///   `NEAppProxyTCPFlow` typing on the `UdpFlowLike` /
///   `TcpFlowLike` protocols' real-flow implementations. Concrete
///   `NEAppProxyFlow` subclasses and `NEFlowMetaData` extraction
///   live in the provider, not the core; the core never reaches
///   into a real flow's framework innards.
///
/// `@unchecked Sendable` because mutable state is either confined to
/// `stateQueue` (registration maps, engine handle, flow-count timer)
/// or set once at construction and only mutated via documented
/// single-threaded entry points (`nwConnectionFactory` from tests
/// before any flow handling starts). Swift can't see the runtime
/// invariants; the annotation tells the type system to trust them.
final class TransparentProxyCore: @unchecked Sendable {
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

    #if DEBUG
        /// Test-only accessor for the writer pump bound to a flow.
        /// Returns `nil` if the flow is not registered (or never
        /// had a writer attached). Used by per-flow unit tests
        /// that need to inspect cache state mutated by the read
        /// loop. Gated on `#if DEBUG` so production builds carry
        /// no test-only surface on `TransparentProxyCore`.
        func testInspectUdpWriter(for flow: AnyObject) -> UdpClientWritePump? {
            stateQueue.sync { self.udpContexts[ObjectIdentifier(flow)]?.writer }
        }

        /// Test-only accessor for the per-flow TCP context. Used by
        /// the promote-cutover integration tests to drive
        /// `beginPromoteCutover` directly + inspect the resulting
        /// state (mode transition, forwarder presence). Same
        /// gating rationale as the UDP accessor above.
        func testInspectTcpContext(for flow: AnyObject) -> TcpFlowContext? {
            stateQueue.sync { self.tcpContexts[ObjectIdentifier(flow)] }
        }
    #endif

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
        TcpFlowSession(core: self, flow: flow, meta: meta).start()
    }


    // MARK: - Promote cutover orchestration

    /// Coordinate a service-initiated promote: cancel the
    /// Rust-bound read pumps with carryover routed into a fresh
    /// `TcpDirectForwarder`, then ACK Rust so its in-flight
    /// service drains and exits.
    ///
    /// Runs on the per-flow `flowQueue`. Assumes all four pumps,
    /// the kernel flow, and the egress `NWConnection` are live
    /// (the promote callback is registered only after that
    /// point in `handleTcpFlow`).
    ///
    /// Failure modes that ACK `.failed` instead of `.ok`:
    ///   * Mode already advanced past `.viaRust` (e.g. double-
    ///     fire). Idempotent: subsequent calls are no-ops.
    ///   * Connection or pumps already torn down (a fast hard-
    ///     error path raced ahead). Confirm with a diagnostic
    ///     reason so the service falls through to the in-Rust
    ///     data path.
    ///
    /// `internal` (not `private`) so the integration tests in
    /// `PromoteCutoverIntegrationTests` can call this directly
    /// with mock flows / connections — exercising the full
    /// cutover sequence without needing a real Rust service to
    /// invoke `into_passthrough` from the engine side.
    func beginPromoteCutover<F: TcpFlowLike>(
        ctx: TcpFlowContext?,
        flow: F,
        flowQueue: DispatchQueue,
        flowId: ObjectIdentifier
    ) {
        guard let ctx else { return }
        guard ctx.mode == .viaRust else {
            // Idempotent: a later promote-callback invocation
            // (e.g. test-only manual fire) lands here. No-op.
            return
        }
        guard let session = ctx.session,
              let connection = ctx.connection,
              let clientWritePump = ctx.clientWritePump,
              let egressWritePump = ctx.egressWritePump
        else {
            logDebug(
                "promote: flow not in a promotable state (missing session/connection/pumps); confirming failed"
            )
            ctx.session?.confirmPromoted(
                .failed, reason: "egress not ready")
            return
        }

        ctx.mode = .promoted
        logTrace("promote: cutover begin")

        let forwarder = TcpDirectForwarder(
            flow: flow,
            connection: connection,
            clientWritePump: clientWritePump,
            egressWritePump: egressWritePump,
            queue: flowQueue,
            logger: { [weak self] message in self?.logFlowMessage(message) },
            onTerminal: { [weak self, weak flow] in
                // Both direct directions done. Close the
                // kernel flow read+write sides + drop the
                // per-flow registry entry. The egress
                // NWConnection's lifecycle is owned by
                // egressWritePump (drain → FIN → linger).
                flow?.closeReadWithError(nil)
                flow?.closeWriteWithError(nil)
                self?.removeTcpFlow(flowId)
            }
        )
        ctx.directForwarder = forwarder

        // Cancel the Rust-bound read pumps. Their in-flight
        // bytes (the `.paused` replay buffer plus any
        // outstanding `readData` / `receive` result) are
        // routed into the forwarder's per-direction
        // buffers, to be flushed FIFO after Rust's tail
        // when the corresponding Rust-done signal arrives.
        //
        // `onComplete` fires the read-drain barrier: only
        // then can the forwarder issue its own
        // `flow.readData` / `connection.receive` without
        // racing the in-flight kernel-side request.
        ctx.clientReadPump?.cancelForPromote(
            onCarryover: { [weak forwarder] data in
                forwarder?.acceptClientCarryover(data)
            },
            onComplete: { [weak forwarder] in
                forwarder?.markClientReadDrained()
            })
        ctx.egressReadPump?.cancelForPromote(
            onCarryover: { [weak forwarder] data in
                forwarder?.acceptEgressCarryover(data)
            },
            onComplete: { [weak forwarder] in
                forwarder?.markEgressReadDrained()
            })

        // ACK the cutover. Rust drops its ingress + egress
        // senders; the service drains its read loops + writes
        // its responses to the existing write pumps. Once
        // Rust signals `onServerClosed` / `onCloseEgress`,
        // the mode-aware handlers transition the forwarder's
        // per-direction state to `.active`.
        session.confirmPromoted(.ok)
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
                ctx.writer?.close()
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
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
                    flowQueue.async { [weak self, weak ctx] in
                        guard let ctx, ctx.readState != .closed else { return }
                        let hadPendingDemand = ctx.readState == .readingWithDemand
                        ctx.readState = .idle
                        if let error {
                            let msg = classifyFlowCallbackError(
                                error,
                                operation: "udp flow.read"
                            )
                            self?.logFlowMessage(msg)
                            ctx.terminate?(error)
                            return
                        }

                        guard let datagrams, !datagrams.isEmpty else {
                            self?.logTrace("flow.readDatagrams eof")
                            ctx.terminate?(nil)
                            return
                        }

                        guard let session = ctx.session else {
                            self?.logDebug(
                                "udp flow read received but session no longer active; closing flow"
                            )
                            ctx.terminate?(nil)
                            return
                        }

                        // Forward each datagram tagged with its
                        // per-datagram peer. `flow.readDatagrams`
                        // returns parallel arrays (`datagrams[i]`
                        // paired with `endpoints[i]`); we honour
                        // that pairing so a multi-peer flow (DNS
                        // stub resolver, NTP, gaming) faithfully
                        // proxies each datagram to its intended
                        // peer instead of collapsing to a single
                        // bootstrap endpoint. RFC 768: zero-length
                        // datagrams are valid; forward unchanged.
                        let endpointMismatch =
                            endpoints != nil
                            && (endpoints?.count ?? 0) != datagrams.count
                        if endpointMismatch && !ctx.endpointMismatchLogged {
                            ctx.endpointMismatchLogged = true
                            self?.logDebug(
                                "udp flow.readDatagrams returned mismatched array lengths (datagrams=\(datagrams.count), endpoints=\(endpoints?.count ?? 0)); surplus datagrams will be forwarded with peer = nil. First-occurrence-only log per flow."
                            )
                        }
                        for (index, datagram) in datagrams.enumerated() {
                            // Strict parallel-array semantics: Apple
                            // documents `readDatagrams` as returning
                            // `[Data]` paired with `[NWEndpoint]`
                            // element-for-element. If the endpoint
                            // array is missing or shorter than the
                            // datagrams array, the surplus entries
                            // get `nil` peer — we do NOT fabricate
                            // attribution from `eps.first`, which on
                            // a multi-peer flow would actively
                            // misroute every reply past the first
                            // index back to the first observed peer.
                            // `ramaUdpPeer(from:)` does the
                            // NWHostEndpoint fast path + macOS-15
                            // NWConcreteHostEndpoint KVC fallback.
                            //
                            // Element type inferred from
                            // `endpoints: [NWEndpoint]?` (NetworkExtension's
                            // legacy class); writing it explicitly conflicts
                            // with the modern `Network.NWEndpoint` enum
                            // imported elsewhere in this file.
                            let endpoint = endpoints.flatMap { eps in
                                index < eps.count ? eps[index] : nil
                            }
                            let peer = endpoint.flatMap(ramaUdpPeer(from:))
                            // Update the writer pump's cached
                            // "latest peer" — the fallback for
                            // outbound datagrams that arrive
                            // without explicit `sentBy`. Rebuild
                            // from the parsed `RamaUdpPeer` so the
                            // cache is always a kernel-acceptable
                            // `NWHostEndpoint`, regardless of which
                            // concrete `NWEndpoint` subclass the
                            // kernel surfaced.
                            if let peer {
                                ctx.writer?.setSentByEndpoint(
                                    peer.toNetworkExtensionEndpoint()
                                )
                            }
                            session.onClientDatagram(datagram, peer: peer)
                        }

                        if hadPendingDemand {
                            ctx.requestRead?()
                        }
                    }
                }
            }
        }

        let decision =
            engine?.newUdpSession(
                meta: bootMeta,
                // Rust-held closures route through `[weak ctx]` so the
                // callback box (Rust) does not strong-pin the per-flow
                // pumps. The box is dropped on `_session_free`, so once
                // `removeUdpFlow` releases the session-handle these
                // closures stop firing — no late-arrival hazard.
                onServerDatagram: { [weak ctx] data, peer in
                    // `peer` is the source the reply came from; thread it
                    // into the writer pump as the `sentBy` endpoint so
                    // `flow.writeDatagrams` tags the kernel-bound write
                    // correctly per datagram, even when the flow has been
                    // talking to multiple peers.
                    ctx?.writer?.enqueue(data, sentBy: peer?.toNetworkExtensionEndpoint())
                },
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

        // ── Phase 2: open the flow and hand control to Rust ──
        //
        // Egress lives on the Rust side, owned by the handler's
        // service: the service opens its own socket(s),
        // routes by per-datagram peer, and writes replies back via
        // `flow.send`. The pre-ready NWConnection state machine that
        // once gated `flow.open` is gone — as soon as Rust says
        // "intercept" we open the flow and arm the session.
        //
        // Trade-off: a downstream `NEAppProxyProvider` no longer sees
        // the egress flow as an `NEAppProxyFlow` carrying the original
        // `NEFlowMetaData` (BSD socket sits below NE attribution). This
        // matches stacked-provider behavior under any direct-socket
        // egress; downstream `NEFilterPacketProvider` policies already
        // saw the extension PID. Audit-token attribution to the
        // ORIGINATING app is preserved end-to-end via Rust's
        // `TransparentProxyFlowMeta`.
        flow.open(withLocalEndpoint: nil) { [weak self, weak ctx] error in
            flowQueue.async { [weak self, weak ctx] in
                guard let ctx else { return }
                if let error {
                    self?.logDebug("udp flow.open error: \(error)")
                    ctx.terminate?(error)
                    return
                }
                self?.logTrace("flow.open ok (udp; egress on Rust-owned BSD socket)")
                ctx.writer?.markOpened()
                ctx.session?.activate()
                ctx.requestRead?()
            }
        }
        return true
    }
}
