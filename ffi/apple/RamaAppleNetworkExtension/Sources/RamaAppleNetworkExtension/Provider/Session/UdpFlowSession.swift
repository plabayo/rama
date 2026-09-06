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
    /// Thread-safe pressure-state cancellation used by detach before queuing
    /// teardown onto a flow queue which may remain stalled indefinitely.
    func closeIngressStagingForEngineDetach()
}

extension UdpFlowSessionAnchor {
    func closeIngressStagingForEngineDetach() {}

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
    var firstProbeId: UInt64 = 0
    var secondProbeId: UInt64 = 0
    var runnerQueued = false
    #if DEBUG || RAMA_TESTING
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
    /// Production installs the generation budget before first access. The lazy
    /// fallback exists only for phase-level tests constructed without a lease.
    private lazy var writerMemoryBudget = WriterMemoryBudget()
    private var effectiveRuntimePolicy: TransparentProxyRuntimePolicy {
        runtimePolicy ?? .testDefaultsSnapshot
    }
    #if DEBUG || RAMA_TESTING
        var testRuntimePolicy: TransparentProxyRuntimePolicy? { runtimePolicy }
        var testWriterMemoryBudget: WriterMemoryBudget { writerMemoryBudget }
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
    /// Production assigns the shared budget before publishing the flow. Keep
    /// the standalone test fallback lazy so new flows do not allocate and
    /// immediately discard a private coordinator, atomics, and lease timer.
    private lazy var ingressStaging = UdpIngressFlowStaging(
        generation: UdpIngressGenerationStagingBudget(policy: .testDefaults))
    /// Queue-confined replacement read held behind Swift staging capacity.
    /// It is logically `.reading`, so one additional Rust demand continues to
    /// coalesce in `pendingReadProbeId` without issuing another Apple read.
    private var stagingCapacityWaiting = false
    private var stagingWaitProbeId: UInt64 = 0

    #if DEBUG || RAMA_TESTING
        /// Test-only count of actual queue schedules, not activity
        /// observations. Pins that a datagram burst creates no timers
        /// without adding field storage or increments in Release.
        private(set) var idleTimerScheduleCount: UInt64 = 0
        var testProbeAcknowledger: ((UInt64) -> Void)?
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
                let publicLine =
                    "udp admission rejected: \(reason); "
                    + effectiveRuntimePolicy.flowRefusal.logDescription
                let privateMetadata = "app=\(appId)"
                if persist {
                    core.logLifecycle(publicLine, privateMetadata: privateMetadata)
                } else {
                    core.logDebug(publicLine, privateMetadata: privateMetadata)
                }
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
        ingressStaging.close()
        idleWork?.cancel()
        idleWork = nil
        idleActivity.withLock { state in
            state.closed = true
            state.lastUptimeNs = nil
        }
    }

    func closeIngressStagingForEngineDetach() {
        ingressStaging.close()
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
    /// registered indefinitely. Rust defaults the independent maximum
    /// lifetime to `None` for long-lived QUIC/H3; deployments may still opt
    /// into an absolute cap explicitly.
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
        #if DEBUG || RAMA_TESTING
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
            },
            writerMemoryBudget: writerMemoryBudget
        )
    }

    func installRequestRead() {
        #if DEBUG || RAMA_TESTING
            ctx.requestRead = { [weak self] in
                self?.enqueueReadDemand(probeId: 0)
            }
        #endif
        ctx.requestReadWithProbe = { [weak self] probeId in
            self?.enqueueReadDemand(probeId: probeId)
        }
    }

    private func enqueueReadDemand(probeId: UInt64) {
        var rejectedProbeId: UInt64 = 0
        readDemand.withLock { state in
            guard !state.closed else {
                rejectedProbeId = probeId
                return
            }
            if state.credits == 0 {
                state.firstProbeId = probeId
                state.credits = 1
            } else if state.credits == 1 {
                state.secondProbeId = probeId
                state.credits = 2
            } else {
                rejectedProbeId = probeId
            }
            guard !state.runnerQueued else { return }
            state.runnerQueued = true
            #if DEBUG || RAMA_TESTING
                state.runnerSchedules &+= 1
            #endif
            flowQueue.async { [weak self] in self?.runReadDemand() }
        }
        let probeToAck = rejectedProbeId
        if probeToAck != 0 {
            // This method is entered synchronously from Rust while its demand
            // lifetime gate is held. Never re-enter FFI here: close may be
            // draining that gate. Queue-confined ACK also keeps overload
            // callback work bounded to the existing serial runner domain.
            flowQueue.async { [weak self] in
                self?.acknowledgeProbe(probeToAck)
            }
        }
    }

    private func runReadDemand() {
        let demands = readDemand.withLock { state -> (UInt8, UInt64, UInt64) in
            guard !state.closed else {
                state.credits = 0
                let first = state.firstProbeId
                let second = state.secondProbeId
                state.firstProbeId = 0
                state.secondProbeId = 0
                state.runnerQueued = false
                return (0, first, second)
            }
            let credits = state.credits
            let first = state.firstProbeId
            let second = state.secondProbeId
            state.credits = 0
            state.firstProbeId = 0
            state.secondProbeId = 0
            state.runnerQueued = false
            return (credits, first, second)
        }
        let (credits, firstProbeId, secondProbeId) = demands
        guard credits > 0 else {
            acknowledgeProbe(firstProbeId)
            acknowledgeProbe(secondProbeId)
            return
        }

        switch ctx.readState {
        case .idle:
            ctx.readState = credits > 1 ? .readingWithDemand : .reading
            if credits > 1 { ctx.pendingReadProbeId = secondProbeId }
            flow.readDatagrams { [weak self] datagrams, endpoints, error in
                self?.handleReadCompletion(
                    datagrams: datagrams,
                    endpoints: endpoints,
                    error: error,
                    probeId: firstProbeId)
            }
        case .reading:
            ctx.readState = .readingWithDemand
            ctx.pendingReadProbeId = firstProbeId
            if credits > 1 { acknowledgeProbe(secondProbeId) }
        case .readingWithDemand:
            acknowledgeProbe(firstProbeId)
            if credits > 1 { acknowledgeProbe(secondProbeId) }
        case .closed:
            acknowledgeProbe(firstProbeId)
            if credits > 1 { acknowledgeProbe(secondProbeId) }
            closeReadDemandGate()
        }
    }

    private func closeReadDemandGate() {
        let pending = readDemand.withLock { state -> (UInt8, UInt64, UInt64) in
            let pending = (state.credits, state.firstProbeId, state.secondProbeId)
            state.closed = true
            state.credits = 0
            state.firstProbeId = 0
            state.secondProbeId = 0
            state.runnerQueued = false
            return pending
        }
        if pending.0 > 0 { acknowledgeProbe(pending.1) }
        if pending.0 > 1 { acknowledgeProbe(pending.2) }
        acknowledgeProbe(ctx.pendingReadProbeId)
        ctx.pendingReadProbeId = 0
        acknowledgeProbe(stagingWaitProbeId)
        stagingWaitProbeId = 0
        stagingCapacityWaiting = false
    }

    private func acknowledgeProbe(_ probeId: UInt64) {
        guard probeId != 0 else { return }
        #if DEBUG || RAMA_TESTING
            testProbeAcknowledger?(probeId)
        #endif
        sessionHandle?.completeClientRead(probeId: probeId)
    }

    func handleReadCompletion(
        datagrams: [Data]?,
        endpoints: [NWEndpoint]?,
        error: Error?,
        probeId: UInt64 = 0,
        stagingGrantTicket: UInt64 = 0
    ) {
        // Timestamp ingress at callback entry. The flow queue can be delayed
        // behind an already-due idle timer; recording only inside its block
        // would let that timer reap a datagram that arrived first.
        if let datagrams, !datagrams.isEmpty {
            recordIdleActivity()
        }
        // Reserve before capturing into the queue. The original Apple arrays
        // remain framework-transient; only this admissible prefix survives the
        // callback return. ACK after that decision, without queue delay.
        let hadKernelDatagrams = datagrams?.isEmpty == false
        if error != nil || datagrams == nil {
            ingressStaging.completeWithoutStaging(grantTicket: stagingGrantTicket)
        }
        let stagingOutcome = error == nil
            ? datagrams.map {
                ingressStaging.stage(
                    datagrams: $0,
                    endpoints: endpoints,
                    grantTicket: stagingGrantTicket)
            }
            : nil
        let staged = stagingOutcome?.batch
        if let sample = stagingOutcome?.dropSample {
            // Keep the signed-soak parser's legacy `generation_*` keys stable;
            // their values now describe the process-global staging envelope.
            core?.logLifecycle(
                "UDP Swift ingress staging dropped datagrams reason=\"\(sample.reason.rawValue)\" "
                    + "cumulative_drop_events=\(sample.cumulativeDropEvents) "
                    + "cumulative_dropped_items=\(sample.cumulativeDroppedItems) "
                    + "cumulative_dropped_bytes_lower_bound=\(sample.cumulativeDroppedBytesLowerBound) "
                    + "generation_retained_items=\(sample.generationRetainedItems) "
                    + "generation_max_retained_items=\(sample.generationMaxRetainedItems) "
                    + "generation_retained_bytes=\(sample.generationRetainedBytes) "
                    + "generation_max_retained_bytes=\(sample.generationMaxRetainedBytes)"
            )
        }
        acknowledgeProbe(probeId)
        flowQueue.async { [weak self] in
            guard let self else { return }
            let ctx = self.ctx
            guard ctx.readState != .closed else { return }
            let hadPendingDemand = ctx.readState == .readingWithDemand
            let pendingProbeId = ctx.pendingReadProbeId
            ctx.pendingReadProbeId = 0
            ctx.readState = .idle

            if let error {
                if hadPendingDemand { self.acknowledgeProbe(pendingProbeId) }
                let msg = classifyFlowCallbackError(error, operation: "udp flow.read")
                self.core?.logFlowMessage(msg)
                self.closeReadDemandGate()
                ctx.terminate?(error)
                return
            }
            guard hadKernelDatagrams else {
                if hadPendingDemand { self.acknowledgeProbe(pendingProbeId) }
                self.core?.logTrace("flow.readDatagrams eof")
                self.closeReadDemandGate()
                ctx.terminate?(nil)
                return
            }
            guard let staged else {
                guard hadKernelDatagrams,
                    let blockedReason = stagingOutcome?.blockedReason,
                    blockedReason != .closed
                else {
                    if hadPendingDemand { self.acknowledgeProbe(pendingProbeId) }
                    return
                }
                if blockedReason == .oversizedBytes {
                    if hadPendingDemand { self.acknowledgeProbe(pendingProbeId) }
                    let datagramBytes = stagingOutcome?.neededBytes ?? 0
                    self.core?.logLifecycle(
                        "UDP Swift ingress staging rejected nonretryable datagram; "
                            + "terminating flow reason=\"\(blockedReason.rawValue)\" "
                            + "datagram_bytes=\(datagramBytes)"
                    )
                    self.closeReadDemandGate()
                    ctx.terminate?(
                        NSError(
                            domain: NSPOSIXErrorDomain,
                            code: Int(EMSGSIZE),
                            userInfo: [
                                NSLocalizedDescriptionKey:
                                    "UDP datagram exceeds Swift ingress staging capacity"
                            ]))
                    return
                }
                // No payload crossed into Rust, but retrying immediately while
                // the staging budget is full creates a hot Apple read loop.
                // Keep exactly one logical read outstanding and let the
                // process-global/per-flow capacity coordinator grant its restart.
                ctx.readState = .reading
                self.stagingCapacityWaiting = true
                self.stagingWaitProbeId = hadPendingDemand ? pendingProbeId : 0
                let armed = self.ingressStaging.waitForCapacity(
                    reason: blockedReason,
                    neededItems: stagingOutcome?.neededItems ?? 1,
                    neededBytes: stagingOutcome?.neededBytes ?? 0
                ) { [weak self] ticket in
                    self?.resumeReadAfterStagingCapacity(grantTicket: ticket)
                }
                if !armed {
                    let strandedProbeId = self.stagingWaitProbeId
                    self.stagingWaitProbeId = 0
                    self.stagingCapacityWaiting = false
                    ctx.readState = .idle
                    self.acknowledgeProbe(strandedProbeId)
                }
                return
            }
            guard let session = ctx.session else {
                if hadPendingDemand { self.acknowledgeProbe(pendingProbeId) }
                self.core?.logDebug(
                    "udp flow read received but session no longer active; closing flow")
                self.closeReadDemandGate()
                ctx.terminate?(nil)
                return
            }

            #if DEBUG || RAMA_TESTING
                let mismatch = staged.forward(
                    to: session,
                    onMatchedEndpoint: { endpoint in
                        // Explicit test observation seam for strict endpoint
                        // pairing. Production Release omits this cache mutation.
                        ctx.writer?.setSentByEndpoint(endpoint)
                    })
            #else
                let mismatch = staged.forward(to: session)
            #endif
            if let mismatch, !ctx.endpointMismatchLogged {
                ctx.endpointMismatchLogged = true
                self.core?.logDebug(
                    "udp flow.readDatagrams returned mismatched array lengths (datagrams=\(mismatch.datagrams), endpoints=\(mismatch.endpoints)); surplus datagrams will be forwarded with peer = nil. First-occurrence-only log per flow."
                )
            }
            if hadPendingDemand { self.enqueueReadDemand(probeId: pendingProbeId) }
        }
    }

    private func resumeReadAfterStagingCapacity(grantTicket: UInt64) {
        flowQueue.async { [weak self] in
            guard let self else { return }
            guard self.ctx.readState != .closed, self.stagingCapacityWaiting else { return }
            self.stagingCapacityWaiting = false
            let probeId = self.stagingWaitProbeId
            self.stagingWaitProbeId = 0
            self.flow.readDatagrams { [weak self] datagrams, endpoints, error in
                self?.handleReadCompletion(
                    datagrams: datagrams,
                    endpoints: endpoints,
                    error: error,
                    probeId: probeId,
                    stagingGrantTicket: grantTicket)
            }
        }
    }

    #if DEBUG || RAMA_TESTING
        func requestEngineSession() -> RamaTransparentProxyUdpSessionDecision? {
            guard let lease = core?.engineLeaseForNewFlow() else { return nil }
            installEngineLease(lease)
            return requestEngineSession(using: lease)
        }
    #endif

    private func installEngineLease(_ lease: TransparentProxyCore.EngineFlowLease) {
        runtimePolicy = lease.runtimePolicy
        writerMemoryBudget = lease.writerMemoryBudget
        ingressStaging = UdpIngressFlowStaging(
            generation: lease.udpIngressStagingBudget,
            policy: lease.runtimePolicy.udpIngressStaging)
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
            onClientReadDemand: { [weak ctx] probeId in
                ctx?.requestReadWithProbe?(probeId)
            },
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
                    // a quiet session stays registered indefinitely (Rust's
                    // active-flow-safe max-lifetime default is `None`).
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

    #if DEBUG || RAMA_TESTING
        var testReadDemandSnapshot: (
            closed: Bool, credits: UInt8, firstProbeId: UInt64,
            secondProbeId: UInt64, runnerQueued: Bool, runnerSchedules: UInt64
        ) {
            readDemand.withLock { state in
                (
                    state.closed, state.credits, state.firstProbeId,
                    state.secondProbeId, state.runnerQueued, state.runnerSchedules
                )
            }
        }

        func testCloseIngressStaging() { ingressStaging.close() }

        func testFillGlobalIngressStaging() -> UdpIngressStagedBatch? {
            let flowPolicy = effectiveRuntimePolicy.udpIngressStaging
            let policy = UdpIngressStagingPolicy(
                maxItemsPerFlow: flowPolicy.maxItemsPerFlow,
                maxItemsPerGeneration: flowPolicy.maxItemsPerFlow,
                maxBytesPerFlow: flowPolicy.maxBytesPerFlow,
                maxBytesPerGeneration: flowPolicy.maxBytesPerFlow)
            let budget = UdpIngressGenerationStagingBudget(policy: policy)
            ingressStaging = UdpIngressFlowStaging(generation: budget)
            let holder = UdpIngressFlowStaging(generation: budget)
            return holder.stage(
                datagrams: [Data(count: flowPolicy.maxBytesPerFlow)],
                endpoints: nil
            ).batch
        }

        func testWaitForIngressStagingCapacity(
            neededItems: Int,
            neededBytes: Int,
            onReady: @escaping @Sendable (UInt64) -> Void
        ) -> Bool {
            ingressStaging.waitForCapacity(
                reason: .generationBytes,
                neededItems: neededItems,
                neededBytes: neededBytes,
                onReady: onReady)
        }

        var testStagingCapacityWaiting: Bool { stagingCapacityWaiting }

        var testIdleActivitySnapshot: (closed: Bool, lastUptimeNs: UInt64?) {
            idleActivity.withLock { ($0.closed, $0.lastUptimeNs) }
        }
    #endif
}
