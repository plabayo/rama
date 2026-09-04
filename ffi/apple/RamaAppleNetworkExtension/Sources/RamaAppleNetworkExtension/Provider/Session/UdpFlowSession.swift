import Foundation
import RamaAppleNEFFI
@preconcurrency import NetworkExtension

func udpIdleTimeoutNanoseconds(_ timeoutMs: UInt64) -> UInt64 {
    timeoutMs > UInt64.max / 1_000_000
        ? UInt64.max
        : timeoutMs * 1_000_000
}

/// Type-erased anchor that `TransparentProxyCore` retains for each
/// intercepted UDP flow.
///
/// The core needs to keep the per-flow session alive while the flow
/// is open (so its closures stay callable and the Rust session
/// handle isn't dropped from under the running engine), but it
/// shouldn't have to know about the session's generic flow type
/// (`UdpFlowSession<NEAppProxyUDPFlow>` in production,
/// `UdpFlowSession<MockUdpFlow>` in tests). This protocol is the
/// minimal surface the core actually uses: the per-flow `ctx`, plus the
/// asynchronous detach teardown used to account for physical resource release.
///
/// Replaces the previous `UdpFlowContext.lifetimeAnchor` cycle —
/// the context no longer holds the session; the core holds the
/// session, the session holds the context. One-way ownership, no
/// cycle to break.
protocol UdpFlowSessionAnchor: AnyObject {
    var ctx: UdpFlowContext { get }
}

extension UdpFlowSessionAnchor {
    /// Queue one detach teardown and acknowledge resource release only after
    /// the already-queued `terminate` block has closed the kernel flow and Rust
    /// session. FIFO ordering provides the completion without synchronously
    /// waiting on a potentially blocked flow queue.
    func terminateForEngineDetach(
        _ error: Error,
        onResourceReleased: @escaping @Sendable () -> Void
    ) {
        guard let terminate = ctx.terminate else {
            onResourceReleased()
            return
        }
        terminate(error)
        if let flowQueue = ctx.flowQueue {
            flowQueue.async(execute: onResourceReleased)
        } else {
            onResourceReleased()
        }
    }
}

private struct UdpIdleActivityState {
    var closed = false
    var lastUptimeNs: UInt64?
}

private struct UdpReadDemandGate {
    var closed = false
    /// One credit starts a read; the second preserves the single follow-up
    /// represented by `UdpFlowReadState.readingWithDemand`.
    var credits: UInt8 = 0
    var runnerQueued = false
    #if DEBUG
        var runnerSchedules: UInt64 = 0
    #endif
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
    private let flowQueueKey = DispatchSpecificKey<UInt8>()

    var sessionHandle: RamaUdpSessionHandle?
    private var engineGeneration: UInt64?
    private var runtimePolicy: TransparentProxyRuntimePolicy?
    private var effectiveRuntimePolicy: TransparentProxyRuntimePolicy {
        runtimePolicy ?? .testDefaultsSnapshot
    }
    #if DEBUG
        var testRuntimePolicy: TransparentProxyRuntimePolicy? { runtimePolicy }
    #endif
    /// Queue-confined lifecycle gates. Natural server completion first enters
    /// a draining phase; errors and detach skip directly to teardown.
    private var gracefulServerCloseStarted = false
    private var teardownFinished = false

    /// Bounded allowance for already-accepted kernel-bound replies after the
    /// Rust service completes naturally. Tests override this with a short
    /// deterministic interval.
    var gracefulDrainTimeoutMs: UInt32 = 2_000

    /// Wall-clock cap on per-flow idle (no datagrams in either
    /// direction). 0 disables the watchdog. Defaults to
    /// the attached engine policy; tests may override it before `start()`.
    private var idleTimeoutMsStorage: UInt64 = 60_000
    private var idleTimeoutWasExplicitlySet = false
    var idleTimeoutMs: UInt64 {
        get { idleTimeoutMsStorage }
        set {
            idleTimeoutMsStorage = newValue
            idleTimeoutWasExplicitlySet = true
        }
    }

    /// Pending one-shot idle work item and monotonic activity time,
    /// with the timer queue-confined and the timestamp lock-protected.
    /// Datagram activity can originate on the Rust callback thread and only
    /// updates the timestamp. The outstanding timer observes it when it fires
    /// and re-arms once for any remaining idle interval.
    var idleWork: DispatchWorkItem?
    private let idleActivity = Locked(UdpIdleActivityState())
    /// Cross-thread demand is saturated before dispatch so one Rust callback
    /// per datagram cannot allocate one flow-queue block per datagram.
    private let readDemand = Locked(UdpReadDemandGate())

    #if DEBUG
        /// Test-only count of actual queue schedules, not activity
        /// observations. Pins that a datagram burst creates no timers
        /// without adding field storage or increments in Release.
        private(set) var idleTimerScheduleCount: UInt64 = 0
    #endif

    init(core: TransparentProxyCore, flow: F, meta: RamaTransparentProxyFlowMetaBridge) {
        self.core = core
        self.flow = flow
        self.meta = meta
        self.flowId = ObjectIdentifier(flow)
        self.flowQueue = DispatchQueue(
            label: "rama.tproxy.udp.flow.\(UInt(bitPattern: ObjectIdentifier(flow)))",
            qos: .utility)
        self.ctx = UdpFlowContext()
        self.ctx.flowQueue = self.flowQueue
        self.flowQueue.setSpecific(key: self.flowQueueKey, value: 1)
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
        startWithDecision().callbackReturnValue
    }

    /// Rich form of `start()` used by the Network Extension adapter so it can
    /// log Rama's exact policy result before converting it to Apple's Bool.
    func startWithDecision() -> UdpFlowHandlingDecision {
        guard let lease = core?.engineLeaseForNewFlow() else {
            ctx.registrationGate.abandon()
            core?.logDebug("handleNewFlow udp engine unavailable; bypassing")
            return .passthrough
        }
        installEngineLease(lease)
        installTerminate()
        buildClientWritePump()
        installRequestRead()

        guard let decision = requestEngineSession(using: lease) else {
            ctx.registrationGate.abandon()
            core?.logDebug("handleNewFlow udp engine unavailable; bypassing")
            return .passthrough
        }

        switch decision {
        case .intercept(let session):
            let initialRemote = meta.remoteHost.map {
                EndpointHostPort(host: $0, port: meta.remotePort).description
            } ?? "<missing>"
            core?.logDebug(
                "udp_flow_handling=started",
                privateMetadata: "initial_remote=\(initialRemote)"
            )
            installEngineSession(session)
            guard let engineGeneration, let core else {
                ctx.registrationGate.abandon()
                session.onClientClose()
                return .passthrough
            }
            let appId = meta.sourceAppBundleIdentifier
                ?? meta.sourceAppSigningIdentifier
                ?? meta.sourceAppPid.map { "pid:\($0)" }
                ?? "pid:unknown"
            let registration = core.registerUdpFlowAndScheduleStartupDecision(
                    flowId,
                    anchor: self,
                    appId: appId,
                    engineGeneration: engineGeneration,
                    runtimePolicy: effectiveRuntimePolicy,
                    on: flowQueue,
                    body: { [self] in
                        guard ctx.readState != .closed else { return }
                        openKernelFlow()
                    },
                    pendingServerClose: { [self] in
                        replayPendingServerCloseBeforeStartup()
                    })
            switch registration {
            case .started:
                return .intercept
            case .unavailable:
                session.onClientClose()
                return .passthrough
            case .capacityRefused(let reason, let persist):
                let line =
                    "udp admission rejected: \(reason); "
                    + effectiveRuntimePolicy.flowRefusal.logDescription
                    + " app=\(appId)"
                if persist { core.logLifecycle(line) } else { core.logDebug(line) }
                session.onClientClose()
                if effectiveRuntimePolicy.flowRefusal.isPassthrough { return .passthrough }
                let error = blockedFlowError()
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                return .blocked
            }
        case .passthrough:
            ctx.registrationGate.abandon()
            core?.logDebug("handleNewFlow udp bypassed by rust flow policy")
            return .passthrough
        case .blocked:
            ctx.registrationGate.abandon()
            core?.logLifecycle("handleNewFlow udp blocked by rust flow policy")
            let error = blockedFlowError()
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
            return .blocked
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
            // Error callbacks already normalized onto the flow queue must
            // commit teardown before a later graceful-close block. Adding a
            // second hop here would let that clean close overtake and suppress
            // the originating kernel error. Off-queue callers still dispatch
            // so Rust callbacks can unwind before Swift closes their handle.
            if let session,
                DispatchQueue.getSpecific(key: session.flowQueueKey) != nil
            {
                session.terminateImmediately(error, retainedCore: core)
                return
            }
            flowQueue.async {
                if let session {
                    session.terminateImmediately(error, retainedCore: core)
                    return
                }

                // Defensive fallback if the session anchor was already lost.
                // The strong `ctx` capture still guarantees kernel teardown.
                guard ctx.readState != .closed else { return }
                ctx.readState = .closed
                ctx.defersRegistryRemovalForGracefulDrain = false
                ctx.writer?.close()
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                ctx.session?.onClientClose()
                core?.removeUdpFlow(flowId, engineGeneration: ctx.engineGeneration)
            }
        }
    }

    private func closeActivityGates() {
        closeReadDemandGate()
        idleWork?.cancel()
        idleWork = nil
        idleActivity.withLock { state in
            state.closed = true
            state.lastUptimeNs = nil
        }
    }

    /// Error, detach, and explicit client close remain immediate. This method
    /// also wins a race against an in-progress graceful drain.
    private func terminateImmediately(
        _ error: Error?, retainedCore: TransparentProxyCore?
    ) {
        guard !teardownFinished else { return }
        teardownFinished = true
        ctx.defersRegistryRemovalForGracefulDrain = false
        let readWasOpen = ctx.readState != .closed
        ctx.readState = .closed
        closeActivityGates()
        ctx.writer?.close()
        if readWasOpen { flow.closeReadWithError(error) }
        flow.closeWriteWithError(error)
        ctx.session?.onClientClose()
        retainedCore?.removeUdpFlow(flowId, engineGeneration: ctx.engineGeneration)
    }

    /// Called directly by the Rust callback thread. Before ownership is
    /// decided the gate records only; after claim, admission is stopped
    /// synchronously before dispatch so callbacks racing behind the natural
    /// close cannot add work to the drain set.
    func requestGracefulServerClose() {
        guard ctx.registrationGate.recordServerClose() else { return }
        ctx.writer?.stopAcceptingForDrain()
        flowQueue.async { [self] in beginGracefulServerClose() }
    }

    /// Replay a close which arrived before core admission claimed this flow.
    /// Core calls this synchronously on `flowQueue` after publishing the
    /// registry anchor. There cannot be an activated Rust service yet, but use
    /// the ordinary graceful path so any defensively pre-accepted writer work
    /// remains retained and bounded until its completion/backstop.
    func replayPendingServerCloseBeforeStartup() {
        dispatchPrecondition(condition: .onQueue(flowQueue))
        ctx.writer?.stopAcceptingForDrain()
        beginGracefulServerClose()
    }

    private func beginGracefulServerClose() {
        guard !teardownFinished, !gracefulServerCloseStarted else { return }
        gracefulServerCloseStarted = true
        ctx.defersRegistryRemovalForGracefulDrain = true
        ctx.readState = .closed
        closeActivityGates()
        flow.closeReadWithError(nil)
        // Stops Rust callbacks/read demand while preserving payloads already
        // copied into the writer's accepted/in-flight set.
        ctx.session?.onClientClose()

        guard let writer = ctx.writer else {
            finishGracefulServerClose(drained: true)
            return
        }
        writer.closeWhenDrained(timeoutMs: gracefulDrainTimeoutMs) { [weak self] drained in
            self?.finishGracefulServerClose(drained: drained)
        }
    }

    private func finishGracefulServerClose(drained: Bool) {
        guard gracefulServerCloseStarted, !teardownFinished else { return }
        teardownFinished = true
        gracefulServerCloseStarted = false
        ctx.defersRegistryRemovalForGracefulDrain = false
        if !drained {
            core?.logDebug(
                "udp graceful server-close drain exceeded \(gracefulDrainTimeoutMs) ms; forcing write-side close"
            )
        }
        flow.closeWriteWithError(nil)
        core?.removeUdpFlow(flowId, engineGeneration: ctx.engineGeneration)
    }

    /// Start the idle watchdog after `flow.open` succeeds. Repeated
    /// calls only record activity while a timer is already pending.
    /// When the timer fires, it either re-arms for the time remaining
    /// since the latest datagram or terminates the flow.
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
    func armIdleTimer(
        nowUptimeNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) {
        let timeout = idleTimeoutMs
        guard timeout > 0 else {
            idleWork?.cancel()
            idleWork = nil
            idleActivity.withLock { $0.lastUptimeNs = nil }
            return
        }
        let active = idleActivity.withLock { state in
            guard !state.closed else { return false }
            state.lastUptimeNs = max(state.lastUptimeNs ?? 0, nowUptimeNs)
            return true
        }
        guard active else { return }
        guard idleWork == nil else { return }
        scheduleIdleTimer(afterNs: udpIdleTimeoutNanoseconds(timeout))
    }

    /// Record one datagram in either direction. This thread-safe operation is
    /// deliberately only a monotonic timestamp update: high-rate traffic must
    /// not cancel, allocate, or enqueue timer work. Taking the maximum keeps
    /// out-of-order callback threads from moving the clock backward.
    func recordIdleActivity(
        nowUptimeNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) {
        guard idleTimeoutMs > 0 else { return }
        idleActivity.withLock { state in
            guard !state.closed else { return }
            state.lastUptimeNs = max(state.lastUptimeNs ?? 0, nowUptimeNs)
        }
    }

    private func scheduleIdleTimer(afterNs delayNs: UInt64) {
        let boundedDelay = min(delayNs, UInt64(Int.max))
        let work = DispatchWorkItem { [weak self] in
            self?.handleIdleTimerFire()
        }
        idleWork = work
        #if DEBUG
            idleTimerScheduleCount &+= 1
        #endif
        flowQueue.asyncAfter(
            deadline: .now() + .nanoseconds(Int(boundedDelay)),
            execute: work
        )
    }

    /// Reconcile a timer fire with the most recent activity. The
    /// explicit timestamp keeps the state transition deterministic
    /// in tests; production uses the monotonic dispatch clock.
    func handleIdleTimerFire(
        nowUptimeNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) {
        idleWork = nil
        guard ctx.readState != .closed else { return }
        let timeout = idleTimeoutMs
        guard timeout > 0 else {
            idleActivity.withLock { $0.lastUptimeNs = nil }
            return
        }
        let lastActivityAt = idleActivity.withLock { $0.lastUptimeNs }
        guard let lastActivityAt else {
            armIdleTimer(nowUptimeNs: nowUptimeNs)
            return
        }

        let timeoutNs = udpIdleTimeoutNanoseconds(timeout)
        let idleNs = nowUptimeNs >= lastActivityAt
            ? nowUptimeNs - lastActivityAt
            : 0
        guard idleNs >= timeoutNs else {
            scheduleIdleTimer(afterNs: timeoutNs - idleNs)
            return
        }

        core?.logDebug("udp flow idle for \(timeout) ms; closing")
        ctx.terminate?(nil)
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
            },
            onActivity: { [weak self] in
                self?.recordIdleActivity()
            }
        )
    }

    func installRequestRead() {
        ctx.requestRead = { [weak self] in
            self?.enqueueReadDemand()
        }
    }

    private func enqueueReadDemand() {
        readDemand.withLock { state in
            guard !state.closed else { return }
            state.credits = min(2, state.credits &+ 1)
            guard !state.runnerQueued else { return }
            state.runnerQueued = true
            #if DEBUG
                state.runnerSchedules &+= 1
            #endif
            flowQueue.async { [weak self] in self?.runReadDemand() }
        }
    }

    private func runReadDemand() {
        let credits = readDemand.withLock { state -> UInt8 in
            guard !state.closed else {
                state.credits = 0
                state.runnerQueued = false
                return 0
            }
            let credits = state.credits
            state.credits = 0
            state.runnerQueued = false
            return credits
        }
        guard credits > 0 else { return }

        switch ctx.readState {
        case .idle:
            ctx.readState = credits > 1 ? .readingWithDemand : .reading
            flow.readDatagrams { [weak self] datagrams, endpoints, error in
                self?.handleReadCompletion(
                    datagrams: datagrams, endpoints: endpoints, error: error)
            }
        case .reading:
            ctx.readState = .readingWithDemand
        case .readingWithDemand:
            break
        case .closed:
            closeReadDemandGate()
        }
    }

    private func closeReadDemandGate() {
        readDemand.withLock { state in
            state.closed = true
            state.credits = 0
            state.runnerQueued = false
        }
    }

    func handleReadCompletion(datagrams: [Data]?, endpoints: [NWEndpoint]?, error: Error?) {
        // Timestamp ingress at callback entry. The flow queue can be delayed
        // behind an already-due idle timer; recording only inside its block
        // would let that timer reap a datagram that arrived first.
        if let datagrams, !datagrams.isEmpty {
            recordIdleActivity()
        }
        flowQueue.async { [weak self] in
            guard let self else { return }
            let ctx = self.ctx
            guard ctx.readState != .closed else { return }
            let hadPendingDemand = ctx.readState == .readingWithDemand
            ctx.readState = .idle

            if let error {
                let msg = classifyFlowCallbackError(error, operation: "udp flow.read")
                self.core?.logFlowMessage(msg)
                self.closeReadDemandGate()
                ctx.terminate?(error)
                return
            }
            guard let datagrams, !datagrams.isEmpty else {
                self.core?.logTrace("flow.readDatagrams eof")
                self.closeReadDemandGate()
                ctx.terminate?(nil)
                return
            }
            guard let session = ctx.session else {
                self.core?.logDebug(
                    "udp flow read received but session no longer active; closing flow")
                self.closeReadDemandGate()
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
            if peer != nil {
                // Preserve Apple's original endpoint object. Reconstructing it
                // from the Rama peer adds parsing/allocation on every packet
                // and can discard endpoint representation details.
                ctx.writer?.setSentByEndpoint(endpoint)
            }
            session.onClientDatagram(datagram, peer: peer)
        }
    }

    func requestEngineSession() -> RamaTransparentProxyUdpSessionDecision? {
        guard let lease = core?.engineLeaseForNewFlow() else { return nil }
        installEngineLease(lease)
        return requestEngineSession(using: lease)
    }

    private func installEngineLease(_ lease: TransparentProxyCore.EngineFlowLease) {
        runtimePolicy = lease.runtimePolicy
        if !idleTimeoutWasExplicitlySet {
            idleTimeoutMsStorage = lease.runtimePolicy.udpIdleTimeoutMs
        }
        // Publish identity before entering FFI: the Rust max-lifetime task can
        // win immediately and invoke `onServerClosed` before this call returns.
        // That callback touches only the registration gate until core claims
        // ownership, and the claim lock then supplies the publication edge to
        // subsequent teardown.
        engineGeneration = lease.generation
        ctx.engineGeneration = lease.generation
    }

    private func requestEngineSession(
        using lease: TransparentProxyCore.EngineFlowLease
    ) -> RamaTransparentProxyUdpSessionDecision? {
        let decision = lease.engine.newUdpSession(
            meta: meta,
            onServerDatagram: { [weak ctx] view, peerView in
                // The writer records activity at callback entry before it
                // materializes these borrowed views, without adding a second
                // dispatch for the idle watchdog.
                ctx?.writer?.enqueueBorrowed(view, peerView: peerView)
            },
            onClientReadDemand: { [weak ctx] in ctx?.requestRead?() },
            onServerClosed: { [weak self] in self?.requestGracefulServerClose() },
            flowRefusalPolicy: effectiveRuntimePolicy.flowRefusal
        )
        return decision
    }

    /// The handle and its weak context view are flow-queue-confined once
    /// installed. A pre-claim Rust close records only in `registrationGate`,
    /// so this synchronous publication cannot be overtaken by teardown.
    private func installEngineSession(_ session: RamaUdpSessionHandle) {
        let install = {
            self.sessionHandle = session
            self.ctx.session = session
        }
        if DispatchQueue.getSpecific(key: flowQueueKey) != nil {
            install()
        } else {
            flowQueue.sync(execute: install)
        }
    }

    /// Execute one asynchronous open completion only while this session's
    /// engine generation is still attached. The fallback is for phase-level
    /// tests that construct a session without engine admission.
    private func withActiveEngineGeneration(_ body: () -> Void) {
        guard let engineGeneration else {
            body()
            return
        }
        guard let core else { return }
        core.withActiveEngineGeneration(engineGeneration, body)
    }

    func openKernelFlow() {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            self?.flowQueue.async { [weak self] in
                guard let self else { return }
                self.withActiveEngineGeneration {
                    guard self.ctx.readState != .closed else { return }
                    if let error {
                        let message = classifyFlowCallbackError(
                            error,
                            operation: "udp flow.open"
                        )
                        self.core?.logFlowMessage(message)
                        self.ctx.terminate?(error)
                        return
                    }
                    self.core?.logTrace(
                        "flow.open ok (udp; egress on Rust-owned BSD socket)")
                    self.ctx.writer?.markOpened()
                    self.ctx.session?.activate()
                    // Arm the idle watchdog. Subsequent datagrams in either
                    // direction push the deadline forward. Without this, the
                    // session stays registered until Rust's max-lifetime cap.
                    self.armIdleTimer()
                    // Rust's first `UdpFlow.recv()` supplies the first read
                    // credit. Do not prefetch here: a service that has not
                    // asked for ingress must not fill its bounded queue, and
                    // activation plus the first recv must not create two
                    // credits for one consumer request.
                }
            }
        }
    }

    #if DEBUG
        var testReadDemandSnapshot: (
            closed: Bool, credits: UInt8, runnerQueued: Bool, runnerSchedules: UInt64
        ) {
            readDemand.withLock { state in
                (state.closed, state.credits, state.runnerQueued, state.runnerSchedules)
            }
        }

        var testIdleActivitySnapshot: (closed: Bool, lastUptimeNs: UInt64?) {
            idleActivity.withLock { ($0.closed, $0.lastUptimeNs) }
        }
    #endif
}
