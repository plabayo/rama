import Foundation
import NetworkExtension

/// Per-UDP-flow state machine.
///
/// Replaces the body of `TransparentProxyCore.handleUdpFlow`.
/// Simpler than its TCP counterpart: no NWConnection (egress is
/// Rust-owned BSD socket), no pumps beyond the client writer, no
/// promote cutover.
final class UdpFlowSession<F: UdpFlowLike>: @unchecked Sendable {
    weak var core: TransparentProxyCore?
    let flow: F
    let meta: RamaTransparentProxyFlowMetaBridge
    let flowId: ObjectIdentifier
    let flowQueue: DispatchQueue
    let ctx: UdpFlowContext

    var sessionHandle: RamaUdpSessionHandle?

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
            core?.registerUdpFlow(flowId, session: session, context: ctx)
            openKernelFlow()
            return true
        case .passthrough:
            core?.logDebug("handleNewFlow udp bypassed by rust flow policy")
            return false
        case .blocked:
            core?.logInfo("handleNewFlow udp blocked by rust flow policy")
            let error = blockedFlowError()
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
            return true
        }
    }

    // MARK: - Phases

    func installTerminate() {
        let flow = self.flow
        ctx.terminate = { [weak self, weak ctx] error in
            self?.flowQueue.async { [weak self, weak ctx] in
                guard let ctx, ctx.readState != .closed else { return }
                ctx.readState = .closed
                ctx.writer?.close()
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                ctx.session?.onClientClose()
                self?.core?.removeUdpFlow(self?.flowId ?? ObjectIdentifier(flow))
            }
        }
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
        ctx.requestRead = { [weak self, weak ctx] in
            self?.flowQueue.async { [weak self, weak ctx] in
                guard let ctx, ctx.readState != .closed else { return }
                if ctx.readState == .reading || ctx.readState == .readingWithDemand {
                    ctx.readState = .readingWithDemand
                    return
                }
                ctx.readState = .reading
                flow.readDatagrams { [weak self, weak ctx] datagrams, endpoints, error in
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
            onServerDatagram: { [weak ctx] data, peer in
                ctx?.writer?.enqueue(data, sentBy: peer?.toNetworkExtensionEndpoint())
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
                self.ctx.requestRead?()
            }
        }
    }
}
