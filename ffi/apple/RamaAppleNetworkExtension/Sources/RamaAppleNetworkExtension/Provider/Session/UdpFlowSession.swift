import Foundation
@preconcurrency import NetworkExtension

/// Type-erased anchor that `TransparentProxyCore` retains for each
/// intercepted UDP flow.
///
/// The core needs to keep the per-flow session alive while the flow
/// is open (so its closures stay callable and the Rust session
/// handle isn't dropped from under the running engine), but it
/// shouldn't have to know about the session's generic flow type
/// (`UdpFlowSession<NEAppProxyUDPFlow>` in production,
/// `UdpFlowSession<MockUdpFlow>` in tests). This protocol is the
/// minimal surface the core actually uses: the per-flow `ctx`,
/// reached on sleep to fire `terminate`.
///
/// Replaces the previous `UdpFlowContext.lifetimeAnchor` cycle —
/// the context no longer holds the session; the core holds the
/// session, the session holds the context. One-way ownership, no
/// cycle to break.
protocol UdpFlowSessionAnchor: AnyObject {
    var ctx: UdpFlowContext { get }
}

/// Per-UDP-flow state machine.
///
/// Replaces the body of `TransparentProxyCore.handleUdpFlow`.
/// Simpler than its TCP counterpart: no NWConnection (egress is
/// Rust-owned BSD socket), no pumps beyond the client writer, no
/// promote cutover.
final class UdpFlowSession<F: UdpFlowLike>: UdpFlowSessionAnchor, @unchecked Sendable {
    weak var core: TransparentProxyCore?
    let flow: F
    let meta: RamaTransparentProxyFlowMetaBridge
    let flowId: ObjectIdentifier
    let flowQueue: DispatchQueue
    let ctx: UdpFlowContext

    var sessionHandle: RamaUdpSessionHandle?

    /// Wall-clock cap on per-flow idle (no datagrams in either
    /// direction). 0 disables the watchdog. Defaults to
    /// `defaultUdpIdleTimeoutMs`; override in tests by setting
    /// this on the session before calling `start()`.
    var idleTimeoutMs: UInt32 = defaultUdpIdleTimeoutMs

    /// Pending one-shot idle work item, queue-confined.
    /// `armIdleTimer` cancels and reschedules; the terminate
    /// closure cancels and nils it. Tracked separately from
    /// `ctx` so unit tests can observe whether the watchdog
    /// has been armed without poking at internal state.
    var idleWork: DispatchWorkItem?

    init(core: TransparentProxyCore, flow: F, meta: RamaTransparentProxyFlowMetaBridge) {
        self.core = core
        self.flow = flow
        self.meta = meta
        self.flowId = ObjectIdentifier(flow)
        self.flowQueue = DispatchQueue(
            label: "rama.tproxy.udp.flow.\(UInt(bitPattern: ObjectIdentifier(flow)))",
            qos: .utility)
        self.ctx = UdpFlowContext()
    }

    /// Entry point. Returns `true` if the flow was claimed.
    ///
    /// Ownership model: this session is owned by its caller's local
    /// variable for the duration of `start()`. The only path that
    /// transfers ownership to the core is `.intercept`, via
    /// `registerUdpFlow(_:anchor:)`. Every other path returns
    /// without registering — the local variable goes out of scope
    /// at the caller, the session deallocates, and the
    /// `ctx`/`writer`/closure graph hanging off it deallocates with
    /// it. No cycle to break, no anchor to clear.
    func start() -> Bool {
        installTerminate()
        buildClientWritePump()
        installRequestRead()

        guard let decision = requestEngineSession() else {
            core?.logDebug("handleNewFlow udp engine unavailable; bypassing")
            return false
        }

        switch decision {
        case .intercept(let session):
            sessionHandle = session
            ctx.session = session
            let occupancy = core?.registerUdpFlow(flowId, anchor: self) ?? 0
            openKernelFlow()
            // Nexus pressure is global (tcp+udp). A UDP burst can approach the
            // kernel ceiling too, so drive the same backstop TCP admission does
            // — it reaps idle TCP slots to free room. NEVER refuses/delays this
            // flow (the reap is async, off this delivery thread, for SUBSEQUENT
            // flows). No-op when the soft cap is disabled or unmet.
            if defaultFlowPressureSoftCap > 0, occupancy >= Int(defaultFlowPressureSoftCap) {
                core?.reapIdleUnderPressure()
            }
            return true
        case .passthrough:
            core?.logDebug("handleNewFlow udp bypassed by rust flow policy")
            return false
        case .blocked:
            core?.logLifecycle("handleNewFlow udp blocked by rust flow policy")
            let error = blockedFlowError()
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
            return true
        }
    }

    // MARK: - Phases

    func installTerminate() {
        // The stored capture stays weak (no permanent cycle), but the
        // dispatched block holds ctx strongly: `detachEngine` drops the
        // registry anchors right after dispatching, and a weak capture in
        // the block would dealloc ctx mid-flight and skip the kernel-flow
        // close and the Rust `onClientClose`. The one-shot block releases
        // its captures on return. Mirrors the TCP walk.
        let flow = self.flow
        let flowQueue = self.flowQueue
        let flowId = self.flowId
        ctx.terminate = { [weak ctx, weak core = self.core, weak self] error in
            guard let ctx else { return }
            let core = core
            let session = self
            flowQueue.async {
                guard ctx.readState != .closed else { return }
                ctx.readState = .closed
                session?.idleWork?.cancel()
                session?.idleWork = nil
                ctx.writer?.close()
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                ctx.session?.onClientClose()
                core?.removeUdpFlow(flowId)
            }
        }
    }

    /// Cancel any pending idle work item and arm a fresh one. Called
    /// after `flow.open` succeeds and on every datagram in either
    /// direction. When the work item fires, it terminates the flow
    /// so the session leaves the core's map and deallocates.
    ///
    /// Apple's `NEAppProxyUDPFlow` gives the extension no terminal
    /// signal for an idle peer (UDP has no FIN; the kernel's
    /// `flow.readDatagrams` callback only observes errors / EOF on
    /// explicit close). Without this watchdog a flow that completes
    /// a few request/response datagrams and goes quiet stays
    /// registered until the engine-side `udp_max_flow_lifetime`
    /// cap fires.
    ///
    /// Must run on `flowQueue`. `idleTimeoutMs == 0` disables the
    /// watchdog (used in tests that exercise other code paths).
    func armIdleTimer() {
        idleWork?.cancel()
        idleWork = nil
        let timeout = idleTimeoutMs
        guard timeout > 0 else { return }
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            // Observe the latest readState — a terminate that
            // raced ahead between fire and execution would have
            // cleared idleWork, but a fresh re-arm could have
            // landed in between. Guarding here keeps the
            // watchdog harmless against double-fire.
            guard self.ctx.readState != .closed else { return }
            self.core?.logDebug("udp flow idle for \(timeout) ms; closing")
            self.ctx.terminate?(nil)
        }
        idleWork = work
        flowQueue.asyncAfter(deadline: .now() + .milliseconds(Int(timeout)), execute: work)
    }

    func buildClientWritePump() {
        ctx.writer = UdpClientWritePump(
            flow: flow,
            queue: flowQueue,
            logger: { [weak core] message in core?.logFlowMessage(message) },
            onTerminalError: { [weak ctx] error in
                // [weak ctx] avoids a writer ↔ terminate cycle —
                // terminate reaches the writer via `ctx.writer`.
                ctx?.terminate?(error)
            }
        )
    }

    func installRequestRead() {
        let flow = self.flow
        let flowQueue = self.flowQueue
        // Use a weak self capture only on the readDatagrams
        // completion — that's the only branch that needs to call
        // back into the session's `handleReadCompletion`. If self
        // is gone by then the flow is being torn down and
        // dropping the bytes is safe (the read pump is closed).
        ctx.requestRead = { [weak ctx, weak self] in
            flowQueue.async { [weak ctx, weak self] in
                guard let ctx, ctx.readState != .closed else { return }
                if ctx.readState == .reading || ctx.readState == .readingWithDemand {
                    ctx.readState = .readingWithDemand
                    return
                }
                ctx.readState = .reading
                flow.readDatagrams { [weak self] datagrams, endpoints, error in
                    self?.handleReadCompletion(
                        datagrams: datagrams, endpoints: endpoints, error: error)
                }
            }
        }
    }

    func handleReadCompletion(datagrams: [Data]?, endpoints: [NWEndpoint]?, error: Error?) {
        flowQueue.async { [weak self] in
            guard let self else { return }
            let ctx = self.ctx
            guard ctx.readState != .closed else { return }
            let hadPendingDemand = ctx.readState == .readingWithDemand
            ctx.readState = .idle

            if let error {
                let msg = classifyFlowCallbackError(error, operation: "udp flow.read")
                self.core?.logFlowMessage(msg)
                ctx.terminate?(error)
                return
            }
            guard let datagrams, !datagrams.isEmpty else {
                self.core?.logTrace("flow.readDatagrams eof")
                ctx.terminate?(nil)
                return
            }
            guard let session = ctx.session else {
                self.core?.logDebug(
                    "udp flow read received but session no longer active; closing flow")
                ctx.terminate?(nil)
                return
            }

            // Reset the idle deadline — Apple just gave us datagrams,
            // the flow is alive.
            self.armIdleTimer()
            self.forwardDatagrams(datagrams: datagrams, endpoints: endpoints, session: session)
            if hadPendingDemand { ctx.requestRead?() }
        }
    }

    /// Forward each datagram tagged with its per-datagram peer.
    /// Apple's `readDatagrams` returns parallel arrays; we honour
    /// the pairing so a multi-peer flow proxies each datagram to
    /// its intended peer. Surplus datagrams get `peer = nil`
    /// rather than a fabricated attribution to `eps.first`.
    func forwardDatagrams(
        datagrams: [Data], endpoints: [NWEndpoint]?, session: RamaUdpSessionHandle
    ) {
        let mismatch = endpoints != nil && (endpoints?.count ?? 0) != datagrams.count
        if mismatch && !ctx.endpointMismatchLogged {
            ctx.endpointMismatchLogged = true
            core?.logDebug(
                "udp flow.readDatagrams returned mismatched array lengths (datagrams=\(datagrams.count), endpoints=\(endpoints?.count ?? 0)); surplus datagrams will be forwarded with peer = nil. First-occurrence-only log per flow."
            )
        }
        for (index, datagram) in datagrams.enumerated() {
            let endpoint = endpoints.flatMap { eps in
                index < eps.count ? eps[index] : nil
            }
            let peer = endpoint.flatMap(ramaUdpPeer(from:))
            if let peer {
                ctx.writer?.setSentByEndpoint(peer.toNetworkExtensionEndpoint())
            }
            session.onClientDatagram(datagram, peer: peer)
        }
    }

    func requestEngineSession() -> RamaTransparentProxyUdpSessionDecision? {
        guard let engine = core?.engine else { return nil }
        return engine.newUdpSession(
            meta: meta,
            onServerDatagram: { [weak ctx, weak self] data, peer in
                // Push the datagram synchronously (writer.enqueue is
                // queue-internal) AND hop to flowQueue to bump the
                // idle deadline. The hop is a few microseconds of
                // additional latency on the rare path where the
                // Rust → Swift datagram is the only liveness signal;
                // worth it to avoid a UAF on `self.idleWork` from a
                // background scheduler thread.
                ctx?.writer?.enqueue(data, sentBy: peer?.toNetworkExtensionEndpoint())
                self?.flowQueue.async { [weak self] in
                    self?.armIdleTimer()
                }
            },
            onClientReadDemand: { [weak ctx] in ctx?.requestRead?() },
            onServerClosed: { [weak ctx] in ctx?.terminate?(nil) }
        )
    }

    func openKernelFlow() {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            self?.flowQueue.async { [weak self] in
                guard let self else { return }
                if let error {
                    self.core?.logDebug("udp flow.open error: \(error)")
                    self.ctx.terminate?(error)
                    return
                }
                self.core?.logTrace("flow.open ok (udp; egress on Rust-owned BSD socket)")
                self.ctx.writer?.markOpened()
                self.ctx.session?.activate()
                // Arm the idle watchdog. Subsequent datagrams in
                // either direction push the deadline forward; an
                // idle peer (DNS that's answered and gone quiet,
                // NAT-binding probe with no response, …) trips the
                // watchdog and we terminate cleanly. Without this,
                // the session stays registered until the engine-
                // side `udp_max_flow_lifetime` cap fires (15 min
                // by default).
                self.armIdleTimer()
                self.ctx.requestRead?()
            }
        }
    }
}
