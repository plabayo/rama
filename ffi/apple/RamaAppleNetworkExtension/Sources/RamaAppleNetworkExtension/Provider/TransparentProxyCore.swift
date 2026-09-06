import Foundation
import Network
import NetworkExtension
import RamaAppleNEFFI

enum UdpFlowRegistrationDecision {
    case started(occupancy: Int)
    case unavailable
    case capacityRefused(reason: String, persist: Bool)
}

private enum UdpFlowRegistrationPlan {
    case started(occupancy: Int, pendingServerClose: Bool)
    case unavailable
    case capacityRefused(reason: String, persist: Bool)

    var decision: UdpFlowRegistrationDecision {
        switch self {
        case .started(let occupancy, _): return .started(occupancy: occupancy)
        case .unavailable: return .unavailable
        case .capacityRefused(let reason, let persist):
            return .capacityRefused(reason: reason, persist: persist)
        }
    }
}

/// Stable identity for one underlying kernel/network resource while ownership
/// moves between the live registry, detach teardown, and a promoted FIN linger.
/// The accounting ledger retains this tiny object while claims are live, so
/// allocator reuse of a flow/context address cannot conflate two resources.
final class ResourceRetirementIdentity: Hashable, @unchecked Sendable {
    static func == (lhs: ResourceRetirementIdentity, rhs: ResourceRetirementIdentity) -> Bool {
        lhs === rhs
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(self))
    }
}

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

    private let stateQueue = DispatchQueue(label: "rama.tproxy.core.state")
    private let lifecycleLock = NSRecursiveLock()
    private let flowLifecycleGroup = DispatchGroup()
    private var engineStorage: RamaTransparentProxyEngineHandle?
    /// Published and cleared in the same `stateQueue` transaction as the
    /// matching engine. Sessions copy this through `EngineFlowLease`, so
    /// retiring callbacks never consult a replacement generation's policy.
    private var runtimePolicyStorage: TransparentProxyRuntimePolicy?
    /// Process/core-lifetime Apple callback staging envelope. Retiring batches,
    /// current flows, and replacement generations all charge this one object,
    /// so a stalled retired flow cannot stack another global allowance on each
    /// attach. Attach reconfigures only its global caps; flow-local caps remain
    /// immutable in each lease/session snapshot.
    private let udpIngressStagingBudgetStorage = UdpIngressGenerationStagingBudget(
        policy: .testDefaults)
    /// Process/core-lifetime aggregate budget for every Swift writer. It is
    /// deliberately retained across engine replacement so stalled retirees
    /// and new-generation flows share one physical memory envelope.
    private var writerMemoryBudgetStorage: WriterMemoryBudget?
    private var engineGeneration: UInt64 = 0
    /// Queue-confined and intentionally never reset across detach/attach.
    /// Combined with the engine generation, this identifies one admission
    /// operation even when an ObjectIdentifier is reused.
    private var nextTcpAdmissionNonce: UInt64 = 0
    private var acceptingFlows = false

    struct EngineFlowLease {
        let engine: RamaTransparentProxyEngineHandle
        let generation: UInt64
        let runtimePolicy: TransparentProxyRuntimePolicy
        let udpIngressStagingBudget: UdpIngressGenerationStagingBudget
        let writerMemoryBudget: WriterMemoryBudget
    }

    /// Queue-confined policy lookup. Engine-less tests retain their historical
    /// ability to tune module defaults before invoking a core helper directly;
    /// production always has an explicitly attached policy.
    private func runtimePolicyLocked() -> TransparentProxyRuntimePolicy {
        runtimePolicyStorage ?? .testDefaultsSnapshot
    }

    /// Narrow fallback snapshots keep legacy tests ergonomic without making an
    /// asynchronous pressure callback read unrelated unsafe test knobs (for
    /// example the refusal action while another test is restoring it).
    private func flowPressurePolicyLocked() -> FlowPressurePolicy {
        runtimePolicyStorage?.flowPressure ?? .testDefaultsSnapshot
    }

    private func tcpStartAdmissionPolicyLocked() -> TcpStartAdmissionPolicy {
        runtimePolicyStorage?.tcpStartAdmission ?? .testDefaultsSnapshot
    }

    var engine: RamaTransparentProxyEngineHandle? {
        stateQueue.sync { engineStorage }
    }
    /// Per-TCP-flow session registry (mirror of `udpSessions`). The
    /// registry OWNS the session (type-erased via `TcpFlowSessionAnchor`);
    /// the session owns its `ctx` and everything under it. So registry
    /// membership IS the flow's liveness — the egress `NWConnection`'s
    /// handlers capture the session weakly, so they no longer anchor it
    /// and there is no retain cycle to break by hand. Dropping the entry
    /// via `removeTcpFlow` deallocates the session (and its `deinit`
    /// cancels the connection as a backstop).
    private var tcpSessions: [ObjectIdentifier: TcpFlowSessionAnchor] = [:]
    /// Per-UDP-flow session registry. Same one-way ownership: the
    /// registry holds the per-flow `UdpFlowSession` (type-erased via
    /// `UdpFlowSessionAnchor`); the session owns its context, so dropping
    /// the entry via `removeUdpFlow` deallocates the whole graph.
    private var udpSessions: [ObjectIdentifier: UdpFlowSessionAnchor] = [:]

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

    /// One coalesced pressure wake-up for expiring victim selections whose
    /// flow queue has not started them. No-headroom suppression is deliberately
    /// trigger-driven: it bounds admission/accounting scans without turning an
    /// over-cap, all-active population into a perpetual polling loop.
    /// Queue-confined to `stateQueue`.
    private var pressureRecheckWork: DispatchWorkItem?
    private var pressureRecheckDeadlineNs: UInt64 = 0
    private var pressureRecheckToken: UInt64 = 0
    private enum PressureRepairState: Equatable {
        case idle
        /// A spare or expiry removed promised capacity. Scan once after every
        /// active reservation in that batch settles.
        case scanWhenBatchSettles
        /// A terminal tombstone may hide the remaining headroom. Its queued
        /// closure is the next event; do not poll or scan after each removal.
        case waitingForTombstoneAck
    }
    private var pressureRepairState: PressureRepairState = .idle
    // MARK: - Engine lifecycle

    /// Hand a freshly-built engine to the core. The provider's
    /// `startProxy` override does the Apple-framework configuration
    /// dance (reading `protocolConfiguration`, building
    /// `NETransparentProxyNetworkSettings`, calling
    /// `setTunnelNetworkSettings`) and then publishes the resulting
    /// engine here. Per-flow handling becomes available only after
    /// this is called.
    @discardableResult
    func attachEngine(
        _ engine: RamaTransparentProxyEngineHandle,
        runtimePolicy: TransparentProxyRuntimePolicy
    ) -> UInt64 {
        attachEngineForLifecycle(engine, runtimePolicy: runtimePolicy)
    }

    #if DEBUG || RAMA_TESTING
    /// Test-only legacy entry point. Tests that directly tune module defaults
    /// can omit a policy and retain their per-helper snapshot behavior.
    @discardableResult
    func attachEngine(_ engine: RamaTransparentProxyEngineHandle) -> UInt64 {
        attachEngineForLifecycle(engine, runtimePolicy: nil)
    }
    #endif

    private func attachEngineForLifecycle(
        _ engine: RamaTransparentProxyEngineHandle,
        runtimePolicy: TransparentProxyRuntimePolicy?
    ) -> UInt64 {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        // Single-shot in production (`startProxy` calls us once per
        // lifecycle), but defensively detach any previous engine
        // first so a future caller that double-attaches doesn't
        // strand the original engine's Rust runtime + bridge tasks
        // alive without anyone holding a way to stop them.
        if self.engine != nil {
            detachEngine(reason: 0)
        }
        let generation = stateQueue.sync {
            self.engineGeneration &+= 1
            self.engineStorage = engine
            self.runtimePolicyStorage = runtimePolicy
            let effectivePolicy = runtimePolicy ?? .testDefaultsSnapshot
            self.udpIngressStagingBudgetStorage.reconfigure(
                policy: effectivePolicy.udpIngressStaging)
            if let writerMemoryBudgetStorage = self.writerMemoryBudgetStorage {
                writerMemoryBudgetStorage.reconfigure(policy: effectivePolicy.writerMemory)
            } else {
                self.writerMemoryBudgetStorage = WriterMemoryBudget(
                    policy: effectivePolicy.writerMemory)
            }
            self.acceptingFlows = true
            self.pressureVictimState.withLock {
                $0.activeEngineGeneration = self.engineGeneration
            }
            return self.engineGeneration
        }
        startFlowCountReporting()
        return generation
    }

    /// Symmetric counterpart of `attachEngine` invoked from
    /// `stopProxy`. Stops the engine, clears all per-flow registrations.
    /// Idempotent — safe to call twice.
    func detachEngine(reason: Int32) {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        // Close admission, snapshot ownership, clear both registries, and
        // invalidate maintenance state in one serial transaction. A flow that
        // acquired the old engine just before this point carries its generation
        // into admission/registration and is rejected after this transaction;
        // it cannot escape the teardown snapshot into the next lifecycle.
        let detached = stateQueue.sync {
            self.acceptingFlows = false
            self.engineGeneration &+= 1
            let engine = self.engineStorage
            self.engineStorage = nil
            // Reserve retirement capacity before dropping registry ownership.
            // TCP uses its stable resource identity so a promoted linger which
            // races this detach becomes a second claimant, not a second slot.
            // Admission is closed throughout this state-queue transaction.
            let tcp = self.tcpSessions.values.map {
                (
                    session: $0,
                    release: self.beginResourceRetirement(
                        identity: $0.ctx.retirementIdentity())
                )
            }
            let udp = self.udpSessions.values.map {
                (session: $0, release: self.beginResourceRetirement())
            }
            self.tcpSessions.removeAll(keepingCapacity: false)
            self.udpSessions.removeAll(keepingCapacity: false)
            self.pauseFlowCountReportingLocked()
            // Invalidate victim tokens and classify the active episode in the
            // same transaction that closes admission and clears ownership.
            // An old flow-queue acknowledgement must not slip into the later
            // lifecycle-group wait and relabel an interrupted episode ended.
            self.resetMaintenanceStateLocked()
            self.runtimePolicyStorage = nil
            return (engine: engine, tcp: tcp, udp: udp)
        }
        // Admission is closed under lifecycleLock. Entrants must be short,
        // nonblocking, and never reenter the lifecycle lock: detach holds it
        // while waiting here. Drain their pressure triggers before teardown.
        flowLifecycleGroup.wait()
        stateQueue.sync { self.resetMaintenanceStateLocked() }
        // The snapshots retain every context/session until its teardown has
        // been dispatched, so clearing registry ownership above cannot orphan
        // the egress connection even though Rust callbacks are about to stop.
        for retired in detached.tcp {
            // A stalled retiring flow queue must not carry a waiter/pregrant
            // into the replacement generation. This synchronous edge leaves
            // real queued/in-flight payload charges intact for their physical
            // queue/completion retirement.
            retired.session.retireWriterAdmissionForEngineDetach()
            let ctx = retired.session.ctx
            let release = retired.release
            runFlowTeardown(ctx) {
                ctx.applyEngineDetached()
                release()
            }
        }
        for retired in detached.udp {
            // Cancel the shared-budget waiter synchronously. The physical flow
            // teardown remains asynchronous and may sit behind user work, but
            // one stalled retired queue cannot retain a cross-generation FIFO
            // entry or its provisional grant.
            retired.session.closeIngressStagingForEngineDetach()
            retired.session.terminateForEngineDetach(
                engineDetachedError(), onResourceReleased: retired.release)
        }
        detached.engine?.stop(reason: reason)
    }

    /// Begin accounting for one unique resource which has no overlapping live
    /// registry owner. Used by UDP detach and test-created independent
    /// retirements. The returned closure is idempotent.
    func beginResourceRetirement() -> @Sendable () -> Void {
        beginResourceRetirement(identity: ResourceRetirementIdentity())
    }

    /// Add one claimant to a stable physical resource. Detach and promoted
    /// terminal can both claim the same TCP connection; only the last release
    /// restores hard-cap capacity.
    private func beginResourceRetirement(
        identity: ResourceRetirementIdentity
    ) -> @Sendable () -> Void {
        let token = pressureVictimState.withLock {
            $0.acquireRetirementClaim(for: identity)
        }
        return retirementReleaseClosure(for: token)
    }

    /// Atomically publish a promoted connection's registry removal intent and
    /// its retirement claim. Direct admission subtracts the recorded overlap;
    /// pressure projection uses the matching removal credit plus retirement.
    func transferRegisteredResourceToRetirement(
        flowId: ObjectIdentifier,
        contextId: ObjectIdentifier?,
        engineGeneration: UInt64?,
        identity: ResourceRetirementIdentity
    ) -> @Sendable () -> Void {
        let token = pressureVictimState.withLock { state in
            let token = state.acquireRetirementClaim(for: identity)
            let announcement = state.announceRemoval(
                flowId: flowId,
                contextId: contextId,
                engineGeneration: engineGeneration,
                mayCancelSelectedVictim: true,
                providesPhysicalRelief: false)
            if announcement.announced {
                state.markRegisteredRetirementOverlap(
                    flowId: flowId,
                    identity: identity)
            }
            return token
        }
        return retirementReleaseClosure(for: token)
    }

    private func retirementReleaseClosure(
        for token: UInt64?
    ) -> @Sendable () -> Void {
        guard let token else { return {} }
        return { [weak self] in
            guard let self else { return }
            let result = self.pressureVictimState.withLock { pressureState in
                let released = pressureState.releaseRetirementClaim(token)
                guard released else { return (released: false, canceled: false) }
                return (
                    released: true,
                    canceled: pressureState.cancelHardCapReplacementSelected())
            }
            guard result.released, result.canceled else { return }
            self.stateQueue.async {
                self.drainPressureVictimOutcomesLocked()
                self.reschedulePressureRecheckLocked()
            }
        }
    }

    private var retiringResourceCount: Int {
        pressureVictimState.withLock { $0.retiringResourceCount }
    }

    private func retirementOccupancySnapshot() -> (retiring: Int, overlap: Int) {
        pressureVictimState.withLock {
            ($0.retiringResourceCount, $0.registeredRetirementOverlapCount)
        }
    }

    /// Exact physical occupancy for direct hard-cap admission. Registered
    /// retirement overlaps are counted once; pending TCP starts remain unique
    /// reservations until registration transfers their exact admission token.
    /// MUST run on `stateQueue`.
    private func liveResourceOccupancyLocked(registered: Int) -> Int {
        let retirement = retirementOccupancySnapshot()
        return max(registered - retirement.overlap, 0)
            + overload.liveFlowReservations.count
            + retirement.retiring
    }

    /// Detach only the engine published by one asynchronous provider start.
    /// The generation check and detach are one lifecycle-lock transaction, so
    /// a stale settings callback can never tear down a newer engine.
    @discardableResult
    func detachEngine(ifGeneration generation: UInt64, reason: Int32) -> Bool {
        lifecycleLock.lock()
        defer { lifecycleLock.unlock() }
        let isCurrent = stateQueue.sync {
            acceptingFlows && engineStorage != nil && engineGeneration == generation
        }
        guard isCurrent else { return false }
        detachEngine(reason: reason)
        return true
    }

    func engineLeaseForNewFlow() -> EngineFlowLease? {
        stateQueue.sync {
            guard acceptingFlows,
                let engine = engineStorage,
                let writerMemoryBudget = writerMemoryBudgetStorage
            else { return nil }
            return EngineFlowLease(
                engine: engine,
                generation: engineGeneration,
                runtimePolicy: runtimePolicyLocked(),
                udpIngressStagingBudget: udpIngressStagingBudgetStorage,
                writerMemoryBudget: writerMemoryBudget)
        }
    }

    /// Stable process-lifetime envelope for the few test/composition paths
    /// which construct a writer before requesting an engine lease. Production
    /// `TcpFlowSession.start()` installs the exact object from its lease before
    /// building either writer; exposing this stable identity here keeps early
    /// construction from manufacturing a second, unbounded envelope.
    func writerMemoryBudgetForPumpComposition() -> WriterMemoryBudget? {
        stateQueue.sync { writerMemoryBudgetStorage }
    }

    /// Linearize an asynchronous transport callback with engine detach.
    /// Callers enter while the generation is current, then perform only their
    /// short queue-confined state transition. Detach closes admission under
    /// the same lock and waits for all entrants before dispatching teardown or
    /// stopping Rust. A callback arriving after that boundary is discarded.
    /// The body must not block or reenter a lifecycle operation, including
    /// this method; detach holds lifecycleLock while waiting for it to leave.
    @discardableResult
    func withActiveEngineGeneration(
        _ generation: UInt64,
        _ body: () -> Void
    ) -> Bool {
        lifecycleLock.lock()
        guard acceptingFlows,
            engineStorage != nil,
            engineGeneration == generation
        else {
            lifecycleLock.unlock()
            return false
        }
        flowLifecycleGroup.enter()
        lifecycleLock.unlock()
        defer { flowLifecycleGroup.leave() }
        body()
        return true
    }

    /// Run a teardown for a registered flow on its own `flowQueue`
    /// when it has one — production contexts always do (set by
    /// `TcpFlowSession.init`), and routing there keeps the teardown
    /// single-threaded with that flow's kernel / NWConnection
    /// callbacks (the `done` flag + slots are flow-queue-confined).
    /// A context with no queue (engine-less unit-test contexts, or
    /// any that never got one) runs inline: better to tear it down
    /// than to silently skip it.
    private func runFlowTeardown(
        _ ctx: TcpFlowContext, _ body: @escaping @Sendable () -> Void
    ) {
        if let queue = ctx.flowQueue {
            queue.async(execute: body)
        } else {
            body()
        }
    }

    // MARK: - System sleep / wake

    /// Apple's `sleep(completionHandler:)` is a brief pause-and-return
    /// hook: do minimal work and complete promptly.
    ///
    /// We deliberately do NOT tear flows down or block on an engine drain
    /// here. A blocking drain can be wedged by any non-yielding engine
    /// task (e.g. an in-flight handler fetch over a link that dies across
    /// the suspend); it then times out and — worse — leaves the proxy
    /// intercepting traffic it can no longer forward after wake. Flows
    /// that don't survive the suspend are reaped post-wake by the per-flow
    /// `.failed` path (`handleSystemWake` + `applyPostReadyFailure`), the
    /// same route any mid-flight connection failure already takes.
    func handleSystemSleep(completion: @escaping () -> Void) {
        pauseFlowCountReporting()
        engine?.notifySystemSleep()
        logLifecycle("system sleep")
        completion()
    }

    /// On wake, restart telemetry and reconcile every TCP flow:
    ///
    ///   * Still-connecting (`!egressReady`): its NECP path is gone and it
    ///     won't recover — reap now so it doesn't burn its connect timer.
    ///   * Established (`egressReady`): the egress `NWConnection` can
    ///     silently lose its path across a network-changing sleep yet stay
    ///     `.ready` — neither `.waiting` nor `.failed` fires, so the
    ///     per-flow `handleEgressState` reaper never runs and the flow
    ///     wedges (peer unreachable → graceful drain never completes) until
    ///     the 60s maintenance watchdog. Re-check viability after a short
    ///     settle (`defaultPostWakePathRecheckMs`) and reset the ones whose
    ///     path didn't come back, so a stale long-lived connection (e.g.
    ///     Chrome reusing an HTTP/2 connection to a Google host) is reset
    ///     promptly instead of hanging. A no-op (Power-Nap) sleep leaves the
    ///     path viable, so those flows are kept.
    func handleSystemWake() {
        engine?.notifySystemWake()
        // Reconcile on each flow's own queue: the `egressReady` /
        // `lastPathViable` reads and the teardown all run there, so they
        // stay single-threaded with that flow's kernel / NWConnection
        // callbacks instead of racing them.
        let all: [TcpFlowContext] = stateQueue.sync { self.tcpSessions.values.map { $0.ctx } }
        for ctx in all {
            runFlowTeardown(ctx) { [weak self] in
                // `hasReachedReady`, NOT `egressReady`: this reconcile block
                // can be queued AHEAD of a `.ready` callback that's still
                // pending on `flowQueue`, so `egressReady` may be stale here
                // even though NW already reached `.ready`. FIFO doesn't help
                // a read (only a timer-cancel) — consult live state so we
                // don't pre-open-cleanup a flow that just connected.
                guard ctx.hasReachedReady else {
                    ctx.applySystemWake()
                    return
                }
                // Established: defer the verdict to a settle-delayed
                // viability re-check (see `checkDeadPath`). Needs a
                // `flowQueue` to schedule on; production contexts always
                // have one (engine-less test contexts that don't are left
                // to the per-flow `.failed`/watchdog paths, as before).
                self?.scheduleDeadPathRecheck(
                    ctx, afterMs: defaultPostWakePathRecheckMs, trigger: "wake")
            }
        }
        logLifecycle("system wake")
        resumeFlowCountReportingIfAttached()
    }

    private func resumeFlowCountReportingIfAttached() {
        stateQueue.sync {
            guard acceptingFlows, engineStorage != nil else { return }
            startFlowCountReportingLocked()
        }
    }

    /// Schedule the settle-delayed dead-path re-check for one flow on its
    /// own `flowQueue`. Shared by the post-wake reconcile and the
    /// mid-session viability-loss trigger; coalesced via
    /// `deadPathRecheckPending` so a burst of triggers (viability flapping
    /// across a roam, wake + path change overlapping) keeps at most one
    /// outstanding verdict per flow. Call on `flowQueue` (both triggers
    /// do). No-op without a `flowQueue` (engine-less test contexts), as
    /// before.
    ///
    /// Coalescing is across triggers, not just within one: if a viability
    /// loss already armed a re-check, an overlapping `handleSystemWake` finds
    /// `deadPathRecheckPending` set and rides the in-flight one rather than
    /// scheduling its own. The verdict is identical either way (`checkDeadPath`
    /// only reads `lastPathViable`/`egressReady`/`isDone`), so the only effect
    /// is timing: the FIRST-scheduled trigger's settle wins, so the reset can
    /// land up to `max(afterMs)` out — still far inside the idle reapers. Tests
    /// that exercise ONE trigger in isolation pin the other's tunable to 0.
    private func scheduleDeadPathRecheck(
        _ ctx: TcpFlowContext, afterMs: UInt32, trigger: String
    ) {
        guard let queue = ctx.flowQueue else { return }
        guard !ctx.deadPathRecheckPending else { return }
        ctx.deadPathRecheckPending = true
        queue.asyncAfter(
            deadline: .now() + .milliseconds(Int(afterMs))
        ) { [weak self, weak ctx] in
            // Clear the coalescing flag even if the core died — a stuck
            // `true` would suppress every future re-check for this flow.
            guard let ctx else { return }
            ctx.deadPathRecheckPending = false
            guard let self else { return }
            self.checkDeadPath(ctx, trigger: trigger)
        }
    }

    /// Mid-session counterpart of the post-wake reconcile, fired by the
    /// egress `viabilityUpdateHandler` reporting `false` while the
    /// connection stays `.ready` — the silent strand a Wi-Fi roam /
    /// interface switch / VPN toggle leaves behind, where neither
    /// `.waiting` nor `.failed` ever fires. Schedules the same
    /// settle-delayed verdict as wake: a path that recovers in the window
    /// is spared, and pre-ready flows are spared by the verdict's
    /// `egressReady` guard (the connect timeout / pre-ready waiting budget
    /// own those). Disabled when `defaultViabilityLossRecheckMs == 0`.
    func handleEgressViabilityLoss(_ ctx: TcpFlowContext) {
        let settleMs = defaultViabilityLossRecheckMs
        guard settleMs > 0 else { return }
        // Defer to the precise per-flow `.waiting` tolerance timer when it is
        // armed: that timer is the deliberately-chosen recovery budget for this
        // exact path loss, and the coarser viability re-check must not preempt
        // it (a shorter settle would reset a flow still inside its budget). The
        // re-check still owns the silent-strand case where `.waiting` never
        // fires. Belt-and-suspenders on top of the default being == the
        // tolerance; this also holds if an operator misconfigures it lower.
        guard !ctx.postReadyWaitingArmed else { return }
        scheduleDeadPathRecheck(ctx, afterMs: settleMs, trigger: "path change")
    }

    /// Settle re-check for one established flow. MUST run on the flow's
    /// own `flowQueue` so the `egressReady` / `lastPathViable` reads stay
    /// single-threaded with the flow's other callbacks. Reached from two
    /// triggers — the post-wake reconcile and a mid-session viability loss
    /// — with the same verdict: reset iff the egress path is no longer
    /// viable (the `viabilityUpdateHandler` last reported `false` and it
    /// didn't recover during the settle window). Idempotent: if the flow
    /// already tore down in the settle window (its NWConnection reported
    /// `.failed` / `.waiting`, or it closed gracefully) the teardown's
    /// sticky `done` flag makes this a no-op; if the path recovered,
    /// `lastPathViable` is `true` again and it is left alone.
    private func checkDeadPath(_ ctx: TcpFlowContext, trigger: String) {
        guard ctx.egressReady, ctx.connection != nil else { return }
        // Don't act on a flow whose teardown already ran/started — it may
        // still be observable here during the window before its async
        // `removeTcpFlow` lands (e.g. a promoted flow that hit
        // `applyPromotedTerminal`). `applyWakeDeadPath` would no-op on a
        // `done` teardown anyway, but bailing here also avoids the
        // misleading "resetting established flow" log line.
        guard ctx.isDone != true else { return }
        guard !ctx.lastPathViable else { return }
        logLifecycle(
            "\(trigger): egress path not viable after settle; resetting established flow")
        ctx.applyWakeDeadPath()
    }

    private func engineDetachedError() -> NSError {
        NSError(
            domain: "rama.tproxy.engine-detached", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "engine detached; flow dropped"])
    }

    // MARK: - Periodic maintenance (flow-count telemetry + stale-flow watchdog)

    /// Interval between maintenance ticks. 60s is short enough to surface
    /// accumulation regressions and to bound how long a wedged flow can
    /// sit in the registry, while long enough that the resulting log
    /// volume is negligible.
    private static let periodicMaintenanceInterval: DispatchTimeInterval = .seconds(60)
    private static let periodicMaintenanceIntervalSeconds: Double = 60.0

    /// TCP flow IDs observed pre-`egressReady` on the previous
    /// maintenance tick. On the NEXT tick, any flow still in this set
    /// AND still pre-`egressReady` has been stuck for at least one
    /// tick interval (≥ 60s) and is force-torn-down — the per-flow
    /// connect-timeout timer fires on the flow's own dispatch queue,
    /// so when that queue is starved (the post-wake / tokio-backlog
    /// failure mode this watchdog exists for) the per-flow timer is
    /// also queued behind backlog. The watchdog runs on `stateQueue`
    /// which has its own thread, so it makes progress even when every
    /// per-flow queue is in catch-up.
    ///
    /// Only mutated from `stateQueue` (the maintenance timer fires
    /// there); no lock needed.
    private var stuckPreReadyFlowIds: Set<ObjectIdentifier> = []

    /// TCP flow IDs that had signalled a terminal close
    /// (`ctx.terminalSignalled`) yet were still in the registry on the
    /// previous maintenance tick. A flow present here AND still
    /// closing-but-registered on the NEXT tick has a wedged graceful
    /// drain (peer stopped reading → the in-flight write completion never
    /// fired → `closeWhenDrained` never finished → the drain-gated
    /// teardown never ran). The per-flow `armTerminalDrainBackstop` timer
    /// normally reaps it within `lingerCloseMs`; this set is the
    /// stateQueue-driven safety net for when that flow queue is starved.
    ///
    /// Only mutated from `stateQueue`; no lock needed.
    private var stuckClosingFlowIds: Set<ObjectIdentifier> = []

    /// High-water mark of the COMBINED (TCP + UDP) live flow count, for
    /// observability of nexus-slot pressure against `defaultFlowPressureSoftCap`
    /// / the kernel ceiling. Updated + reported on the maintenance tick. Only
    /// mutated from `stateQueue`.
    private var flowCountHighWater = 0

    /// Coalesces a burst of `reapIdleUnderPressure` triggers (one per
    /// admission while over the soft cap) into one outstanding scan. Set
    /// on the triggering thread at enqueue and cleared by the scan block,
    /// so it must be locked rather than `stateQueue`-confined: a flag that
    /// lives only inside the serial block is never visible to the block
    /// queued behind it, and every admission would enqueue its own
    /// O(n log n) scan — behind which the next admission's
    /// `registerTcpFlow.sync` on the NE delivery thread would block.
    private struct PressureReapSlot {
        var nextToken: UInt64 = 0
        var outstandingToken: UInt64?
        /// A hard-cap refusal may need one replaceable slot even while the
        /// registered population is below the ordinary soft-pressure trigger.
        /// Production requests retain their engine generation so a delayed
        /// old-generation refusal cannot target a replacement engine.
        var hardCapReplacementGeneration: UInt64?
        /// Engine-less compatibility tests have no generation to attach. This
        /// bit is accepted only while no explicit production policy is bound.
        var unscopedHardCapReplacementRequested = false
        /// Kept separate from hard-cap work so rejecting a stale scoped hard
        /// request cannot manufacture an ordinary scan in the new generation.
        var ordinaryPressureRequested = false
        /// Every TCP admission represented by the coalesced scan. A single
        /// latest-ID slot lets the same scan evict an earlier admission when
        /// the configured idle floor is zero.
        var protectedFlowIds: Set<ObjectIdentifier> = []
    }
    private let pressureReapSlot = Locked(PressureReapSlot())

    /// Admissions protected by the current pressure-selection cycle. Pending
    /// IDs close the register-to-trigger window; active IDs survive immediate
    /// spare/lease replacement scans. Both are `stateQueue`-confined.
    private var pendingPressureProtectedFlowIds: Set<ObjectIdentifier> = []
    private var activePressureProtectedFlowIds: Set<ObjectIdentifier> = []

    /// Monotonic deadline (uptime ns) before which a pressure scan is
    /// skipped outright. Armed by a no-headroom scan: nothing was idle
    /// past the floor, and idle age only grows, so no flow can qualify
    /// before the closest one crosses it. Under a churn burst — every
    /// flow seconds old against a 120s floor — this turns dozens of
    /// futile full scans per second into none. Cleared by a successful
    /// reap and whenever a completed batch brings occupancy below the cap.
    /// Only mutated on `stateQueue`.
    private var pressureRescanSuppressedUntilNs: UInt64 = 0
    /// Coalesced delayed rescan armed when a settled batch drops its
    /// admission-protection set. Ordinary no-headroom suppression does not
    /// poll, but this protection transition must receive one wake or the last
    /// burst can remain over cap forever with no later admission to trigger it.
    private var pressureProtectionRetryToken: UInt64 = 0
    private var pressureProtectionRetryWork: DispatchWorkItem?
    private var pressureProtectionRetryDeadlineNs: UInt64 = 0
    #if DEBUG || RAMA_TESTING
        private var pressureProtectionRetrySchedules = 0
        private var pressureProtectionRetryBodyRuns = 0
        private let beforeTcpHardCapReplacementPublish =
            Locked<(@Sendable () -> Void)?>(nil)
    #endif

    /// Bounds on that suppression. The upper one caps how long a stale
    /// view can outlive a change the idle-age argument doesn't cover
    /// (flows leaving the registry, a knob being lowered); the lower one
    /// keeps the corner where something is idle past the floor yet
    /// ineligible for a non-idle reason (such as a pending drain without a
    /// terminal signal) from degrading back into a scan per admission.
    private static let pressureRescanMaxSuppressMs: UInt64 = 5_000
    private static let pressureRescanMinSuppressMs: UInt64 = 250
    /// A selection that cannot even start on its flow queue inside this
    /// window is not useful as released-capacity credit. Expire its token and
    /// let the next scan try a responsive victim instead.
    private var pressureVictimDispatchLeaseMs: UInt64 = 250

    /// Reaper counters, monotonic; the tick reports the deltas so a bundle
    /// shows coalescing (triggers ≫ scans) and suppression (skipped) at work.
    /// `triggers` and `scans` are locked, not `stateQueue`-confined: the
    /// first is bumped on the triggering thread, the second is read by
    /// tests while they hold the queue.
    private let pressureTriggersTotal = Locked(0)
    private let pressureScansTotal = Locked(0)
    private var pressureSkipsTotal = 0
    /// A flow is counted once per cycle in which it is selected.
    private var pressureSelectionsTotal = 0
    /// Selections whose `flowQueue` re-check committed pressure teardown.
    private var pressureEvictedTotal = 0
    /// Selections whose `flowQueue` re-check declined teardown.
    private var pressureSparedTotal = 0
    /// Selections invalidated because another teardown or current occupancy
    /// made them unnecessary before pressure teardown committed.
    private var pressureCanceledTotal = 0
    /// Selections whose flow queue did not start within the dispatch lease.
    private var pressureExpiredTotal = 0
    private var pressureStatsAtLastTick = (
        triggers: 0, scans: 0, skips: 0, selections: 0, evicted: 0, spared: 0,
        canceled: 0, expired: 0)

    enum PressureVictimPhase: Equatable {
        case selected
        case committed
        case spareAwaitingAccounting
        case canceled
        case expired
    }

    enum PressureVictimGoal: Equatable {
        case lowWater
        case hardCapReplacement
    }

    struct PressureVictimReservation {
        let token: UInt64
        let selectedAtNs: UInt64
        let flowId: ObjectIdentifier
        let goal: PressureVictimGoal
        var phase: PressureVictimPhase
    }

    private struct PressureSelectionRef {
        let id: ObjectIdentifier
        let token: UInt64
    }

    struct PressureVictim {
        let ctx: TcpFlowContext
        let token: UInt64
        let goal: PressureVictimGoal
    }

    private struct PressureExpiryCounts {
        var lowWater = 0
        var hardCapReplacement = 0

        var total: Int { lowWater + hardCapReplacement }
    }

    private struct PressureOutcomeCounts {
        var evicted = 0
        var spared = 0
        var canceled = 0
        var episodeEvicted = 0
        var episodeSpared = 0
        var episodeCanceled = 0

        var isEmpty: Bool {
            evicted == 0 && spared == 0 && canceled == 0
        }
    }

    /// Tokenized reservations close three races at once. A selected victim is
    /// excluded from another scan, but only for a bounded dispatch lease. Its
    /// flow queue must atomically claim the exact token before teardown, so a
    /// cancellation, expiry, detach, or later selection cannot be acted on by
    /// stale queued work. A flow queue moves `selected → committed` only after
    /// its final local re-check. Canceled/expired tombstones stay excluded
    /// until their already-queued closure acknowledges the token, preventing
    /// retry work from accumulating behind a permanently starved queue.
    ///
    /// The lock is intentional: flow queues only perform the tiny
    /// `selected → committed/spareAwaitingAccounting` transition.
    /// Selection, expiry, reconciliation, and telemetry remain serialized on
    /// `stateQueue`.
    private struct PressureVictimState {
        private struct RetirementRecord {
            var claimCount: Int
            var overlappingFlowId: ObjectIdentifier?
            /// The physical resource was released while its asynchronous
            /// registry removal was still pending. Keep this tombstone until
            /// registry ownership ends so detach cannot resurrect the slot.
            var resourceReleased: Bool
        }

        var reservations: [ObjectIdentifier: PressureVictimReservation] = [:]
        /// Token order for selected reservations. Phase changes leave lazy
        /// tombstones here; pruning from either end is amortized O(1), avoiding
        /// a full reservation-map walk for every deadline or cancellation.
        private var selectionOrder: [PressureSelectionRef] = []
        private var selectionHead = 0
        /// At most one hard-cap replacement is live. Keep its selection ref
        /// directly so retirement release cancels it in O(1), not by scanning
        /// the ordinary low-water batch.
        private var hardCapSelection: PressureSelectionRef?
        private(set) var hasOutstandingHardCapReplacement = false
        /// Cached phase counts keep the admission-trigger skip path O(1).
        /// They are updated under this same lock as every phase transition.
        var victimCreditCount = 0
        var unresolvedReservationCount = 0
        var activeEngineGeneration: UInt64?
        /// Registry membership mirrored under the same lock as removal intent.
        /// Consuming an ID here proves a removal can actually provide capacity
        /// before it retires another selected victim. This makes duplicate and
        /// unknown removals pressure-accounting no-ops.
        var registeredFlowIds: Set<ObjectIdentifier> = []
        /// Registry removals announce themselves before their async
        /// `stateQueue` hop. Sharing this lock with reservation commits lets a
        /// natural removal retire one still-selected eviction before it can
        /// commit, even while `stateQueue` is backlogged.
        /// Value is `true` when the removal supplies capacity independently
        /// of a pressure victim; `false` when it is that victim's own removal.
        var pendingRemovalFlowIds: [ObjectIdentifier: Bool] = [:]
        var naturalReliefCount = 0
        /// Retirement lives under this same lock as removal credit. A
        /// registered-to-retiring transfer and every pressure projection
        /// therefore observe either the old pair or the new pair, never a torn
        /// mix.
        private var nextRetirementClaimToken: UInt64 = 0
        private var retirementClaims: [UInt64: ResourceRetirementIdentity] = [:]
        private var retirementRecords: [ResourceRetirementIdentity: RetirementRecord] = [:]
        private var registeredRetirementByFlow:
            [ObjectIdentifier: ResourceRetirementIdentity] = [:]
        private(set) var retiringResourceCount = 0
        var registeredRetirementOverlapCount: Int {
            registeredRetirementByFlow.count
        }
        /// Outcome decisions made off `stateQueue`, waiting to be folded into
        /// the queue-confined lifecycle counters. Keeping this tiny ledger
        /// under the reservation lock makes detach an exactly-once boundary:
        /// it can atomically drain decisions and invalidate every token.
        private var unreportedOutcomes = PressureOutcomeCounts()

        mutating func insertReservation(
            _ reservation: PressureVictimReservation,
            for id: ObjectIdentifier
        ) {
            if let old = reservations.updateValue(reservation, forKey: id) {
                removeCounts(for: old.phase)
            }
            addCounts(for: reservation.phase)
            if reservation.phase == .selected {
                let ref = PressureSelectionRef(id: id, token: reservation.token)
                selectionOrder.append(ref)
                if reservation.goal == .hardCapReplacement {
                    precondition(!hasOutstandingHardCapReplacement)
                    hardCapSelection = ref
                    hasOutstandingHardCapReplacement = true
                }
            }
        }

        mutating func setPhase(
            _ phase: PressureVictimPhase,
            for id: ObjectIdentifier
        ) {
            guard var reservation = reservations[id] else { return }
            removeCounts(for: reservation.phase)
            if reservation.phase == .selected,
                reservation.goal == .hardCapReplacement
            {
                hardCapSelection = nil
                if phase == .canceled || phase == .expired {
                    hasOutstandingHardCapReplacement = false
                }
            }
            reservation.phase = phase
            reservations[id] = reservation
            addCounts(for: phase)
        }

        @discardableResult
        mutating func removeReservation(
            for id: ObjectIdentifier
        ) -> PressureVictimReservation? {
            guard let reservation = reservations.removeValue(forKey: id) else {
                return nil
            }
            if reservation.phase == .selected,
                reservation.goal == .hardCapReplacement
            {
                hardCapSelection = nil
            }
            if reservation.goal == .hardCapReplacement,
                reservation.phase == .selected || reservation.phase == .committed
            {
                hasOutstandingHardCapReplacement = false
            }
            removeCounts(for: reservation.phase)
            return reservation
        }

        mutating func insertPendingRemoval(
            _ providesRelief: Bool,
            for id: ObjectIdentifier
        ) {
            pendingRemovalFlowIds[id] = providesRelief
            if providesRelief { naturalReliefCount += 1 }
        }

        mutating func removePendingRemoval(for id: ObjectIdentifier) {
            if pendingRemovalFlowIds.removeValue(forKey: id) == true {
                naturalReliefCount -= 1
            }
        }

        mutating func announceRemoval(
            flowId: ObjectIdentifier,
            contextId: ObjectIdentifier?,
            engineGeneration: UInt64?,
            mayCancelSelectedVictim: Bool,
            providesPhysicalRelief: Bool = true
        ) -> (announced: Bool, canceled: Bool) {
            if let engineGeneration {
                guard activeEngineGeneration == engineGeneration else {
                    return (false, false)
                }
            }
            guard pendingRemovalFlowIds[flowId] == nil,
                registeredFlowIds.remove(flowId) != nil
            else {
                return (false, false)
            }
            let providesRelief: Bool
            switch contextId.flatMap({ reservations[$0]?.phase }) {
            case .some(.selected), .some(.committed):
                providesRelief = false
            case .some(.spareAwaitingAccounting), .some(.canceled),
                .some(.expired), .none:
                providesRelief = true
            }
            insertPendingRemoval(providesRelief, for: flowId)
            guard providesRelief, mayCancelSelectedVictim else {
                return (true, false)
            }
            // A registered-to-linger transfer relieves registry-based soft
            // pressure but still owns the same physical resource. Preserve a
            // hard-cap replacement until capacity actually leaves the ledger.
            return (
                true,
                cancelNewestSelected(includeHardCapReplacement: providesPhysicalRelief))
        }

        /// Add one claimant for a physical resource. Multiple detach/promoted
        /// claimants share one resource count and release it only when the last
        /// claim completes. `nil` means that resource was already physically
        /// released while a stale registry owner remained.
        mutating func acquireRetirementClaim(
            for identity: ResourceRetirementIdentity
        ) -> UInt64? {
            if retirementRecords[identity]?.resourceReleased == true {
                return nil
            }
            precondition(
                nextRetirementClaimToken < .max,
                "retiring-resource token space exhausted")
            nextRetirementClaimToken += 1
            let token = nextRetirementClaimToken
            retirementClaims[token] = identity
            if var record = retirementRecords[identity] {
                record.claimCount += 1
                retirementRecords[identity] = record
            } else {
                retirementRecords[identity] = RetirementRecord(
                    claimCount: 1,
                    overlappingFlowId: nil,
                    resourceReleased: false)
                retiringResourceCount += 1
            }
            return token
        }

        /// Returns true only when this claim released physical capacity.
        mutating func releaseRetirementClaim(_ token: UInt64) -> Bool {
            guard let identity = retirementClaims.removeValue(forKey: token),
                var record = retirementRecords[identity]
            else {
                return false
            }
            precondition(record.claimCount > 0)
            record.claimCount -= 1
            guard record.claimCount == 0 else {
                retirementRecords[identity] = record
                return false
            }
            retiringResourceCount -= 1
            if record.overlappingFlowId != nil {
                record.resourceReleased = true
                retirementRecords[identity] = record
            } else {
                retirementRecords.removeValue(forKey: identity)
            }
            return true
        }

        mutating func markRegisteredRetirementOverlap(
            flowId: ObjectIdentifier,
            identity: ResourceRetirementIdentity
        ) {
            guard var record = retirementRecords[identity] else {
                preconditionFailure("retirement overlap without a resource record")
            }
            if let oldIdentity = registeredRetirementByFlow[flowId] {
                precondition(oldIdentity === identity)
                return
            }
            precondition(record.overlappingFlowId == nil)
            record.overlappingFlowId = flowId
            retirementRecords[identity] = record
            registeredRetirementByFlow[flowId] = identity
        }

        mutating func endRegisteredRetirementOverlap(for flowId: ObjectIdentifier) {
            guard let identity = registeredRetirementByFlow.removeValue(forKey: flowId),
                var record = retirementRecords[identity]
            else {
                return
            }
            precondition(record.overlappingFlowId == flowId)
            record.overlappingFlowId = nil
            if record.claimCount == 0 {
                retirementRecords.removeValue(forKey: identity)
            } else {
                retirementRecords[identity] = record
            }
        }

        private mutating func endAllRegisteredRetirementOverlaps() {
            let overlaps = registeredRetirementByFlow
            registeredRetirementByFlow.removeAll(keepingCapacity: false)
            for (flowId, identity) in overlaps {
                guard var record = retirementRecords[identity] else { continue }
                precondition(record.overlappingFlowId == flowId)
                record.overlappingFlowId = nil
                if record.claimCount == 0 {
                    retirementRecords.removeValue(forKey: identity)
                } else {
                    retirementRecords[identity] = record
                }
            }
        }

        mutating func recordOutcome(
            _ phase: PressureVictimPhase,
            goal: PressureVictimGoal
        ) {
            switch phase {
            case .committed:
                unreportedOutcomes.evicted += 1
                if goal == .lowWater { unreportedOutcomes.episodeEvicted += 1 }
            case .spareAwaitingAccounting:
                unreportedOutcomes.spared += 1
                if goal == .lowWater { unreportedOutcomes.episodeSpared += 1 }
            case .canceled:
                unreportedOutcomes.canceled += 1
                if goal == .lowWater { unreportedOutcomes.episodeCanceled += 1 }
            case .selected, .expired:
                break
            }
        }

        mutating func takeUnreportedOutcomes() -> PressureOutcomeCounts {
            let outcomes = unreportedOutcomes
            unreportedOutcomes = PressureOutcomeCounts()
            return outcomes
        }

        mutating func reset() -> PressureOutcomeCounts {
            let outcomes = takeUnreportedOutcomes()
            reservations.removeAll(keepingCapacity: false)
            selectionOrder.removeAll(keepingCapacity: false)
            selectionHead = 0
            hardCapSelection = nil
            hasOutstandingHardCapReplacement = false
            pendingRemovalFlowIds.removeAll(keepingCapacity: false)
            registeredFlowIds.removeAll(keepingCapacity: false)
            victimCreditCount = 0
            unresolvedReservationCount = 0
            naturalReliefCount = 0
            activeEngineGeneration = nil
            // Detach clears both registries in the same `stateQueue`
            // transaction. Claims survive into the next generation, but no
            // old registry owner remains to overlap them.
            endAllRegisteredRetirementOverlaps()
            return outcomes
        }

        mutating func earliestSelectedDeadline(leaseNs: UInt64) -> UInt64? {
            while selectionHead < selectionOrder.count {
                let ref = selectionOrder[selectionHead]
                if let reservation = reservations[ref.id],
                    reservation.token == ref.token,
                    reservation.phase == .selected,
                    pendingRemovalFlowIds[reservation.flowId] == nil
                {
                    compactSelectionOrderIfNeeded()
                    return reservation.selectedAtNs &+ leaseNs
                }
                selectionHead += 1
            }
            compactSelectionOrderIfNeeded()
            return nil
        }

        mutating func expireSelected(
            nowNs: UInt64,
            leaseNs: UInt64
        ) -> PressureExpiryCounts {
            var expired = PressureExpiryCounts()
            while selectionHead < selectionOrder.count {
                let ref = selectionOrder[selectionHead]
                guard let reservation = reservations[ref.id],
                    reservation.token == ref.token,
                    reservation.phase == .selected,
                    pendingRemovalFlowIds[reservation.flowId] == nil
                else {
                    selectionHead += 1
                    continue
                }
                guard reservation.selectedAtNs &+ leaseNs <= nowNs else { break }
                setPhase(.expired, for: ref.id)
                selectionHead += 1
                switch reservation.goal {
                case .lowWater: expired.lowWater += 1
                case .hardCapReplacement: expired.hardCapReplacement += 1
                }
            }
            compactSelectionOrderIfNeeded()
            return expired
        }

        mutating func cancelNewestSelected(includeHardCapReplacement: Bool = true) -> Bool {
            // At most one hard-cap replacement exists. Temporarily skipping
            // its ref lets a registry-only removal cancel an older low-water
            // victim while retaining the hard-cap ticket for expiry checks.
            var preservedHardCap: PressureSelectionRef?
            defer {
                if let preservedHardCap { selectionOrder.append(preservedHardCap) }
            }
            while selectionOrder.count > selectionHead {
                let ref = selectionOrder.removeLast()
                guard let reservation = reservations[ref.id],
                    reservation.token == ref.token,
                    reservation.phase == .selected,
                    pendingRemovalFlowIds[reservation.flowId] == nil
                else { continue }
                if !includeHardCapReplacement, reservation.goal == .hardCapReplacement {
                    preservedHardCap = ref
                    continue
                }
                setPhase(.canceled, for: ref.id)
                recordOutcome(.canceled, goal: reservation.goal)
                compactSelectionOrderIfNeeded()
                return true
            }
            compactSelectionOrderIfNeeded()
            return false
        }

        mutating func cancelHardCapReplacementSelected() -> Bool {
            guard let ref = hardCapSelection,
                let reservation = reservations[ref.id],
                reservation.token == ref.token,
                reservation.phase == .selected,
                pendingRemovalFlowIds[reservation.flowId] == nil
            else {
                hardCapSelection = nil
                return false
            }
            setPhase(.canceled, for: ref.id)
            recordOutcome(.canceled, goal: reservation.goal)
            return true
        }

        private mutating func compactSelectionOrderIfNeeded() {
            guard selectionHead > 0 else { return }
            if selectionHead == selectionOrder.count {
                selectionOrder.removeAll(keepingCapacity: true)
                selectionHead = 0
            } else if selectionHead >= 256,
                selectionHead * 2 >= selectionOrder.count
            {
                selectionOrder.removeFirst(selectionHead)
                selectionHead = 0
            }
        }

        private mutating func addCounts(for phase: PressureVictimPhase) {
            switch phase {
            case .selected, .committed:
                victimCreditCount += 1
                unresolvedReservationCount += 1
            case .spareAwaitingAccounting:
                unresolvedReservationCount += 1
            case .canceled, .expired:
                break
            }
        }

        private mutating func removeCounts(for phase: PressureVictimPhase) {
            switch phase {
            case .selected, .committed:
                victimCreditCount -= 1
                unresolvedReservationCount -= 1
            case .spareAwaitingAccounting:
                unresolvedReservationCount -= 1
            case .canceled, .expired:
                break
            }
        }
    }
    private let pressureVictimState = Locked(PressureVictimState())
    private var nextPressureVictimToken: UInt64 = 0

    /// One ordinary soft-pressure stretch, from the first at-cap scan until
    /// registered occupancy reaches the normalized low-water target. One-slot
    /// hard-cap replacements are deliberately excluded. Summarised in a lifecycle
    /// line at its end — the shape of a burst (how long, how high, what the
    /// reaper managed) is what a post-incident bundle needs and what the
    /// 60s tick is too coarse to show. An episode cut short by a provider
    /// restart is emitted as `interrupted`, after atomically folding any
    /// committed, spared, or canceled decisions that have not reached their
    /// normal state-queue accounting callbacks yet.
    /// Only mutated on `stateQueue`.
    private struct PressureEpisode {
        var startNs: UInt64
        var startEpochUs: UInt64
        var peakOccupancy: UInt64
        /// Snapshot the generation's threshold for trustworthy interrupted
        /// summaries after detach atomically clears the attached policy.
        var softCap: UInt32
        var scans = 0
        var skips = 0
        var selections = 0
        var evicted = 0
        var spared = 0
        var canceled = 0
        var expired = 0
    }
    private var pressureEpisode: PressureEpisode?

    #if DEBUG || RAMA_TESTING
        /// Test-only: the suppression most recently armed, in ms. Lets a
        /// test assert the derived bound itself instead of racing the
        /// clock for what remains of it. Only mutated on `stateQueue`.
        private var pressureRescanLastArmedMs: UInt64 = 0
        /// Test-only: eviction closures that reached a victim `flowQueue`,
        /// spared or not. One per unique selection is the invariant.
        private let pressureEvictionBodyRuns = Locked(0)
    #endif

    /// Rate-limits the "over cap but nothing idle to reap" lifecycle log to once
    /// per pressure episode (re-armed when occupancy reaches low-water or a
    /// reap actually fires). A sustained over-cap population — notably
    /// UDP-dominated occupancy, where the TCP-only reap can never reach
    /// low-water — would otherwise emit a persisted os_log on EVERY admission.
    /// Only mutated on `stateQueue`.
    private var pressureNoHeadroomLogged = false
    /// Separate rate limit for hard-cap replacement scans. Such a scan does
    /// not open an ordinary low-water episode, so it needs its own lifecycle.
    private var hardCapNoHeadroomLogged = false

    /// Admission / overload counters for TCP egress starts. Only touched on
    /// `stateQueue`, alongside the flow registries it summarizes.
    private var overload = TcpOverloadState()

    /// Per-tick teardown work split by disposition: pre-ready flows get
    /// `applyConnectTimeout`, wedged-closing flows get `applyDrainBackstop`,
    /// idle promoted flows get `applyIdleTimeout`.
    private struct MaintenanceKicks {
        var preReadyStuck: [TcpFlowContext] = []
        var closingStuck: [TcpFlowContext] = []
        var idleStuck: [TcpFlowContext] = []
        var isEmpty: Bool {
            preReadyStuck.isEmpty && closingStuck.isEmpty && idleStuck.isEmpty
        }
    }

    /// True when a promoted flow has gone without byte activity for at least
    /// `defaultPromotedIdleTimeoutMs`. `0` disables the reaper. Uses the
    /// monotonic `DispatchTime` clock (mach-uptime; pauses during system
    /// sleep, matching the engine's tokio idle timers) so a flow is never
    /// reaped merely for having spanned a sleep — that population is handled
    /// by the wake reconcile + egress keepalive. Read off `flowQueue` from the
    /// maintenance tick (same relaxation as `egressReady`); re-checked on
    /// `flowQueue` before the teardown actually fires.
    private static func promotedFlowIsIdle(_ ctx: TcpFlowContext) -> Bool {
        promotedFlowIsIdle(ctx.maintenanceSnapshot())
    }

    private static func promotedFlowIsIdle(_ state: TcpFlowMaintenanceState) -> Bool {
        let timeoutMs = defaultPromotedIdleTimeoutMs
        guard timeoutMs > 0 else { return false }
        return flowIdleMs(state) > UInt64(timeoutMs)
    }

    private static func elapsedMs(nowNs: UInt64, sinceNs: UInt64) -> UInt64 {
        guard sinceNs <= nowNs else { return 0 }
        return (nowNs - sinceNs) / 1_000_000
    }

    private static func wallClockEpochUs() -> UInt64 {
        UInt64(max(Date().timeIntervalSince1970 * 1_000_000, 0))
    }

    private static func pressureLowWater(_ policy: FlowPressurePolicy) -> UInt64 {
        UInt64(policy.lowWater)
    }

    private static func flowIdleMs(
        _ state: TcpFlowMaintenanceState,
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> UInt64 {
        elapsedMs(nowNs: nowNs, sinceNs: state.lastActivityAt.uptimeNanoseconds)
    }

    /// A drain is wedged only while its close is still pending and no bytes
    /// have moved for the linger budget. `terminalSignalled` is sticky across
    /// a completed half-close, so it cannot identify a pending drain alone.
    private static func flowIsDrainWedged(_ ctx: TcpFlowContext) -> Bool {
        flowIsDrainWedged(ctx.maintenanceSnapshot())
    }

    private static func flowIsDrainWedged(
        _ state: TcpFlowMaintenanceState,
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> Bool {
        guard state.terminalSignalled, state.drainClosePending else { return false }
        return flowIdleMs(state, nowNs: nowNs) > UInt64(state.lingerCloseMs)
    }

    /// Selection and fire-time re-check share this exact lifecycle policy.
    /// A completed half-close (`terminalSignalled` with no pending drain) is
    /// still eligible once idle. A drain in progress is protected until it is
    /// genuinely wedged, including the defensive pending-without-terminal
    /// state.
    private static func flowPressureAllowsEviction(
        _ state: TcpFlowMaintenanceState,
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> Bool {
        return !state.drainClosePending || flowIsDrainWedged(state, nowNs: nowNs)
    }

    /// Flow-pressure backstop. Called asynchronously after an admission reaches
    /// the soft cap, and after a hard-cap refusal needs one replaceable slot.
    /// Reaps idle TCP flows past
    /// `defaultFlowPressureIdleFloorMs`, oldest-idle first (LRU), down to
    /// `defaultFlowPressureLowWater`, to free nexus slots for SUBSEQUENT flows.
    /// Coalesced via `pressureReapSlot` so a burst is a single scan, and
    /// victims with live capacity reservations count as gone, so
    /// a trigger landing in their window costs O(1).
    ///
    /// Guarantees (see the tunable doc for the policy rationale):
    ///   * The just-admitted flow is NEVER the victim and is never delayed —
    ///     this runs after admission, asynchronously.
    ///   * Mode-agnostic (nexus pressure is global): BOTH `viaRust` and
    ///     `.promoted` flows are eligible. Both bump `lastActivityAt` from
    ///     their read and write pumps, so an actively-transferring flow of
    ///     either mode is excluded by the idle-floor check and never selected.
    ///   * No activity-blind eviction: if nothing is idle past the floor we log
    ///     and do nothing (admit-and-ride) rather than reset a live connection.
    ///   * Each eviction re-checks idleness ON the victim's `flowQueue` before
    ///     firing, closing the select-then-teardown race; teardown is
    ///     idempotent via `isDone`.
    func reapIdleUnderPressure(
        protecting flowId: ObjectIdentifier? = nil,
        flowPressurePolicy: FlowPressurePolicy? = nil,
        hardCapReplacement: Bool = false,
        engineGeneration: UInt64? = nil
    ) {
        // Production callers pass their engine lease's immutable policy. The
        // fallback preserves engine-less pressure-test ergonomics only.
        guard
            (flowPressurePolicy
                ?? TransparentProxyRuntimePolicy.testDefaultsSnapshot.flowPressure).softCap > 0
        else {
            return
        }
        // Claim the single outstanding scan slot BEFORE dispatching; a
        // trigger that finds it taken rides the scan already queued, which
        // re-reads occupancy when it runs. Never `stateQueue.sync` here —
        // this is the delivery thread that just admitted the flow.
        pressureTriggersTotal.withLock { $0 += 1 }
        let scanToken = pressureReapSlot.withLock { slot -> UInt64? in
            if let flowId { slot.protectedFlowIds.insert(flowId) }
            if hardCapReplacement {
                if let engineGeneration {
                    if let current = slot.hardCapReplacementGeneration {
                        slot.hardCapReplacementGeneration = max(
                            current, engineGeneration)
                    } else {
                        slot.hardCapReplacementGeneration = engineGeneration
                    }
                } else {
                    slot.unscopedHardCapReplacementRequested = true
                }
            } else {
                slot.ordinaryPressureRequested = true
            }
            guard slot.outstandingToken == nil else { return nil }
            slot.nextToken &+= 1
            slot.outstandingToken = slot.nextToken
            return slot.nextToken
        }
        guard let scanToken else { return }
        stateQueue.async {
            // Release the slot first so a trigger landing mid-scan gets a
            // fresh scan afterwards instead of being dropped.
            let request = self.pressureReapSlot.withLock {
                slot -> (Set<ObjectIdentifier>, UInt64?, Bool, Bool)? in
                guard slot.outstandingToken == scanToken else { return nil }
                slot.outstandingToken = nil
                let protected = slot.protectedFlowIds
                let hardCapGeneration = slot.hardCapReplacementGeneration
                let unscopedHardCap = slot.unscopedHardCapReplacementRequested
                let ordinaryPressure = slot.ordinaryPressureRequested
                slot.protectedFlowIds.removeAll(keepingCapacity: true)
                slot.hardCapReplacementGeneration = nil
                slot.unscopedHardCapReplacementRequested = false
                slot.ordinaryPressureRequested = false
                return (
                    protected, hardCapGeneration, unscopedHardCap,
                    ordinaryPressure)
            }
            guard let request else { return }
            let validScopedHardCap = request.1.map {
                self.acceptingFlows && $0 == self.engineGeneration
            } ?? false
            let hardCapReplacement = validScopedHardCap
                || (request.2 && self.runtimePolicyStorage == nil)
            guard hardCapReplacement || request.3 else { return }
            let victims = self.collectPressureVictimsIfDueLocked(
                continuation: hardCapReplacement ? .hardCapReplacement : .newEpisode,
                excluding: request.0)
            // `fire` only DISPATCHES teardowns to each victim's `flowQueue`,
            // so nothing heavy runs while on `stateQueue`.
            self.firePressureEvictions(victims)
        }
    }

    /// Suppression gate in front of `collectPressureVictimsLocked`. MUST be
    /// called on `stateQueue`. Only an over-cap scan is expensive, so only
    /// that is what the deadline skips; under the cap the scan is O(1) and
    /// is what clears the gate and re-arms the episode log. "Over cap" is
    /// measured net of pending victims, like the scan itself.
    private func collectPressureVictimsIfDueLocked(
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds,
        continuation: PressureContinuation = .newEpisode,
        excluding protectedFlowIds: Set<ObjectIdentifier> = []
    ) -> [PressureVictim] {
        let pressurePolicy = flowPressurePolicyLocked()
        mergePressureProtectionsLocked(protectedFlowIds)
        let occupancy = self.tcpSessions.count + self.udpSessions.count
        if var episode = pressureEpisode {
            episode.peakOccupancy = max(episode.peakOccupancy, UInt64(occupancy))
            pressureEpisode = episode
        }
        let pressure = pressureVictimState.withLock { state in
            (
                credited: state.victimCreditCount + state.naturalReliefCount,
                hardCapReplacement: state.hasOutstandingHardCapReplacement,
                retiring: state.retiringResourceCount)
        }
        let projected = max(occupancy - pressure.credited, 0)
        let selectionGoal: PressureVictimGoal
        switch continuation {
        case .newEpisode:
            guard projected >= Int(pressurePolicy.softCap) else {
                clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
                return []
            }
            selectionGoal = .lowWater
        case .aboveSoftCap:
            guard pressureEpisode != nil,
                projected >= Int(pressurePolicy.softCap)
            else {
                clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
                return []
            }
            selectionGoal = .lowWater
        case .towardLowWater:
            guard pressureEpisode != nil,
                projected > Int(Self.pressureLowWater(pressurePolicy))
            else {
                clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
                return []
            }
            selectionGoal = .lowWater
        case .hardCapReplacement:
            if projected >= Int(pressurePolicy.softCap) {
                selectionGoal = .lowWater
            } else {
                guard !pressure.hardCapReplacement else {
                    clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
                    return []
                }
                let hardCap = Int(pressurePolicy.liveHardCap)
                let projectedLive = projected
                    + self.overload.liveFlowReservations.count
                    + pressure.retiring
                guard hardCap > 0, projected > 0, projectedLive >= hardCap else {
                    clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
                    return []
                }
                selectionGoal = .hardCapReplacement
            }
        }
        guard nowNs >= pressureRescanSuppressedUntilNs else {
            pressureSkipsTotal += 1
            if selectionGoal == .lowWater, var episode = pressureEpisode {
                episode.skips += 1
                episode.peakOccupancy = max(episode.peakOccupancy, UInt64(occupancy))
                pressureEpisode = episode
            }
            clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
            return []
        }
        return collectPressureVictimsLocked(
            nowNs: nowNs,
            goal: selectionGoal)
    }

    /// Victim selection. MUST be called on `stateQueue`. Re-reads live occupancy
    /// (it may have changed since the triggering admission). Eligible:
    /// established (`egressReady`), not in a healthy pending drain,
    /// not already reserved, idle past the floor —
    /// ranked oldest-idle first (true LRU). Ordinary pressure selects toward
    /// low-water; a below-soft hard-cap refusal selects at most one replacement.
    /// MODE-AGNOSTIC:
    /// both `viaRust` and `.promoted` flows are evictable (nexus pressure is
    /// global and both carry an accurate `lastActivityAt`). Eviction is
    /// TCP-only because UDP flows
    /// self-bound via `defaultUdpIdleTimeoutMs`; a UDP-driven burst still TRIGGERS
    /// this (via `registerUdpFlow` occupancy), reaping idle TCP slots to relieve
    /// the global ceiling. Empty result = nothing to do (under cap, or no idle
    /// headroom).
    private func collectPressureVictimsLocked(
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds,
        excluding protectedFlowIds: Set<ObjectIdentifier> = [],
        goal: PressureVictimGoal = .lowWater
    ) -> [PressureVictim] {
        let pressurePolicy = flowPressurePolicyLocked()
        mergePressureProtectionsLocked(protectedFlowIds)
        let protectedFlowIds = activePressureProtectedFlowIds
        let softCap = pressurePolicy.softCap
        guard softCap > 0 else {
            activePressureProtectedFlowIds.removeAll(keepingCapacity: true)
            return []
        }
        let lowWater = Self.pressureLowWater(pressurePolicy)
        let floorMs = UInt64(pressurePolicy.idleFloorMs)
        let occupancy = UInt64(self.tcpSessions.count + self.udpSessions.count)
        if goal == .lowWater {
            if var episode = pressureEpisode {
                episode.peakOccupancy = max(episode.peakOccupancy, occupancy)
                pressureEpisode = episode
            }
            guard occupancy >= UInt64(softCap) || pressureEpisode != nil else {
                // Outside an active episode and below the cap: re-arm the log
                // episode, and drop any rescan suppression so the next one is
                // never skipped on the strength of a stale view.
                pressureNoHeadroomLogged = false
                pressureRescanSuppressedUntilNs = 0
                reschedulePressureRecheckLocked(nowNs: nowNs)
                clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
                return []
            }
        }
        // Pending victims are leaving: measure against what remains. Until
        // that reaches the cap again a trigger in their window is O(1) here.
        let pressureState = pressureVictimState.withLock {
            (reservations: $0.reservations,
             pendingRemovalFlowIds: Set($0.pendingRemovalFlowIds.keys),
             victimCreditCount: $0.victimCreditCount,
             naturalReliefCount: $0.naturalReliefCount,
             retiringResourceCount: $0.retiringResourceCount)
        }
        let reservations = pressureState.reservations
        let pending = UInt64(pressureState.victimCreditCount)
        let naturalRelief = UInt64(pressureState.naturalReliefCount)
        let credited = pending &+ naturalRelief
        let projected = occupancy > credited ? occupancy - credited : 0
        let want: Int
        switch goal {
        case .lowWater:
            guard projected > lowWater else {
                clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
                return []
            }
            want = Int(projected - lowWater)
        case .hardCapReplacement:
            let hardCap = UInt64(pressurePolicy.liveHardCap)
            let projectedLive = projected
                &+ UInt64(self.overload.liveFlowReservations.count)
                &+ UInt64(pressureState.retiringResourceCount)
            guard hardCap > 0, projected > 0, projectedLive >= hardCap else {
                clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
                return []
            }
            want = 1
        }
        pressureScansTotal.withLock { $0 += 1 }
        if goal == .lowWater {
            var episode = pressureEpisode
                ?? PressureEpisode(
                    startNs: nowNs,
                    startEpochUs: Self.wallClockEpochUs(),
                    peakOccupancy: occupancy,
                    softCap: softCap)
            episode.scans += 1
            episode.peakOccupancy = max(episode.peakOccupancy, occupancy)
            pressureEpisode = episode
        }
        // Snapshot the LRU sort key (`lastActivityAt`) and a single `now` into
        // immutable locals BEFORE filtering/sorting. `lastActivityAt` is mutated
        // on each flow's own `flowQueue` (onActivity), so sorting the live
        // objects would read a key that another thread is changing mid-sort — a
        // data race and an unstable comparator. Snapshotting makes the ordering
        // self-consistent; the fire-loop re-check on `flowQueue` remains the
        // authority on whether a chosen victim is actually still idle.
        typealias Candidate = (
            ctx: TcpFlowContext, state: TcpFlowMaintenanceState, lastNs: UInt64
        )
        let reservedIds = Set(reservations.keys)
        let candidates: [Candidate] = self.tcpSessions.values.compactMap { session in
            let id = ObjectIdentifier(session.ctx)
            let flowId = session.ctx.flowId ?? id
            guard !reservedIds.contains(id),
                !pressureState.pendingRemovalFlowIds.contains(flowId)
            else {
                return nil
            }
            let state = session.ctx.maintenanceSnapshot()
            return (
                ctx: session.ctx,
                state: state,
                lastNs: state.lastActivityAt.uptimeNanoseconds
            )
        }
        // Mode-agnostic idle-floor check: BOTH modes carry an accurate
        // `lastActivityAt` (bumped by both read and write pumps), so
        // an actively-transferring flow of either mode is never selected.
        // Closing flows become eligible once genuinely drain-wedged.
        let idleCandidates: [Candidate] = candidates.filter { candidate in
            let id = ObjectIdentifier(candidate.ctx)
            let flowId = candidate.ctx.flowId ?? id
            guard !protectedFlowIds.contains(flowId) else { return false }
            let lifecycleAllowsEviction = Self.flowPressureAllowsEviction(
                candidate.state,
                nowNs: nowNs)
            let idleMs = Self.elapsedMs(nowNs: nowNs, sinceNs: candidate.lastNs)
            return candidate.state.egressReady && lifecycleAllowsEviction && idleMs > floorMs
        }
        let sortedCandidates = idleCandidates.sorted { lhs, rhs in
            lhs.lastNs < rhs.lastNs
        }
        let eligible: [TcpFlowContext] = sortedCandidates.map { $0.ctx }
        if eligible.isEmpty {
            // Nothing idle past the floor, and idle age only grows: no flow
            // can qualify before the closest established one crosses it.
            // Skip rescans until then (bounded) instead of re-sorting the
            // registry on every admission of a burst that, by construction,
            // has nothing to give. Pre-ready flows are excluded — they
            // become eligible via a state change, not via age, and one
            // that turns ready inside the window enters at idle age 0
            // (`handleEgressReady` resets the clock), so it cannot beat
            // this bound; the cap covers the rest. `+ 1`: eligibility is
            // strictly past the floor.
            let untilEligibleMs = candidates.lazy.compactMap { candidate -> UInt64? in
                guard candidate.state.egressReady else { return nil }
                let idleMs = Self.elapsedMs(nowNs: nowNs, sinceNs: candidate.lastNs)
                let idleWaitMs = floorMs >= idleMs ? floorMs - idleMs + 1 : 0
                let lifecycleWaitMs: UInt64
                if candidate.state.drainClosePending {
                    guard candidate.state.terminalSignalled else { return nil }
                    let lingerMs = UInt64(candidate.state.lingerCloseMs)
                    lifecycleWaitMs = lingerMs >= idleMs ? lingerMs - idleMs + 1 : 0
                } else {
                    lifecycleWaitMs = 0
                }
                return max(idleWaitMs, lifecycleWaitMs)
            }.min() ?? Self.pressureRescanMaxSuppressMs
            let suppressMs = min(
                max(untilEligibleMs, Self.pressureRescanMinSuppressMs),
                Self.pressureRescanMaxSuppressMs)
            pressureRescanSuppressedUntilNs = nowNs &+ suppressMs &* 1_000_000
            reschedulePressureRecheckLocked(nowNs: nowNs)
            #if DEBUG || RAMA_TESTING
                pressureRescanLastArmedMs = suppressMs
            #endif
            if goal == .lowWater, !pressureNoHeadroomLogged {
                self.logLifecycle(
                    "flow pressure: occupancy \(occupancy), soft cap \(softCap), but no "
                        + "flow idle past \(floorMs)ms floor; admitting without reap"
                )
                pressureNoHeadroomLogged = true
            } else if goal == .hardCapReplacement, !hardCapNoHeadroomLogged {
                self.logLifecycle(
                    "flow pressure: live hard cap \(pressurePolicy.liveHardCap), but no "
                        + "TCP flow idle past \(floorMs)ms floor; refusing without reap"
                )
                hardCapNoHeadroomLogged = true
            }
            clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
            return []
        }
        if goal == .lowWater {
            pressureNoHeadroomLogged = false
        } else {
            hardCapNoHeadroomLogged = false
        }
        pressureRescanSuppressedUntilNs = 0
        if goal == .lowWater { cancelPressureProtectionRetryLocked() }
        var victims: [PressureVictim] = []
        victims.reserveCapacity(min(want, eligible.count))
        pressureVictimState.withLock { state in
            // Removal intent can arrive while candidate snapshots are being
            // collected. Recompute the budget under its shared lock before
            // inserting reservations so that intent cannot slip between the
            // projection above and selection here.
            let currentCredit = state.victimCreditCount + state.naturalReliefCount
            let currentProjected = max(Int(occupancy) - currentCredit, 0)
            let currentWant: Int
            switch goal {
            case .lowWater:
                currentWant = max(currentProjected - Int(lowWater), 0)
            case .hardCapReplacement:
                let currentLive = currentProjected
                    + self.overload.liveFlowReservations.count
                    + state.retiringResourceCount
                let hardCap = Int(pressurePolicy.liveHardCap)
                currentWant = !state.hasOutstandingHardCapReplacement
                    && hardCap > 0 && currentLive >= hardCap ? 1 : 0
            }
            let stillEligible = eligible.filter { ctx in
                let id = ObjectIdentifier(ctx)
                let flowId = ctx.flowId ?? id
                return state.reservations[id] == nil
                    && state.pendingRemovalFlowIds[flowId] == nil
            }
            for ctx in stillEligible.prefix(currentWant) {
                nextPressureVictimToken &+= 1
                let token = nextPressureVictimToken
                state.insertReservation(
                    PressureVictimReservation(
                        token: token,
                        selectedAtNs: nowNs,
                        flowId: ctx.flowId ?? ObjectIdentifier(ctx),
                        goal: goal,
                        phase: .selected),
                    for: ObjectIdentifier(ctx))
                victims.append(PressureVictim(ctx: ctx, token: token, goal: goal))
            }
        }
        reschedulePressureRecheckLocked(nowNs: nowNs)
        pressureSelectionsTotal += victims.count
        if goal == .lowWater { pressureEpisode?.selections += victims.count }
        let pendingCount = pressureVictimCreditCount()
        if goal == .lowWater {
            self.logLifecycle(
                "flow pressure: occupancy \(occupancy) over soft cap \(softCap); selected "
                    + "\(victims.count) idle flow(s) toward low-water \(lowWater) "
                    + "(\(pendingCount) pending teardown)"
            )
        } else {
            self.logLifecycle(
                "flow pressure: live hard cap \(pressurePolicy.liveHardCap); selected "
                    + "\(victims.count) idle TCP replacement(s) "
                    + "(\(pendingCount) pending teardown)"
            )
        }
        if victims.isEmpty { clearPressureProtectionsIfIdleLocked(nowNs: nowNs) }
        return victims
    }

    /// Fold admissions observed since the previous selection into the current
    /// retry cycle. A cycle retains them only while live victim work exists;
    /// once a scan finds no replacement they become ordinary older flows.
    private func mergePressureProtectionsLocked(
        _ additional: Set<ObjectIdentifier> = []
    ) {
        activePressureProtectedFlowIds.formUnion(pendingPressureProtectedFlowIds)
        activePressureProtectedFlowIds.formUnion(additional)
        pendingPressureProtectedFlowIds.removeAll(keepingCapacity: true)
    }

    private func clearPressureProtectionsIfIdleLocked(nowNs: UInt64) {
        let hasActiveWork = pressureVictimState.withLock {
            $0.unresolvedReservationCount > 0
        }
        // A terminal tombstone excludes its own context without carrying live
        // work or projected-capacity credit. Once a batch has settled, retaining
        // admission protections until that tombstone's starved flow queue runs
        // can shield every responsive replacement forever. Keep protections only
        // while the batch is actively settling; waiting for acknowledgement is a
        // safe release boundary because tombstones remain independently reserved.
        guard !hasActiveWork, pressureRepairState != .scanWhenBatchSettles,
            !activePressureProtectedFlowIds.isEmpty
        else { return }
        activePressureProtectedFlowIds.removeAll(keepingCapacity: true)
        // Releases share one bounded state-transition wake. A later deadline
        // rides an earlier work item; an earlier deadline replaces it. A
        // no-op retry preserves ordinary suppression without polling.
        scheduleReleasedProtectionRetryIfNeededLocked(nowNs: nowNs)
    }

    /// A live-cap refusal adds no registry state, so it only needs to publish a
    /// trigger when the same queue-confined guards would let the reaper do work.
    /// This avoids one extra `stateQueue` block per sequential refusal while a
    /// no-headroom deadline is live or existing relief already covers pressure.
    /// MUST be called on `stateQueue`.
    private func shouldWakePressureReaperAfterLiveCapRefusalLocked(
        registered: Int,
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> Bool {
        let pressurePolicy = flowPressurePolicyLocked()
        let softCap = Int(pressurePolicy.softCap)
        guard softCap > 0, nowNs >= pressureRescanSuppressedUntilNs else {
            return false
        }
        let pressure = pressureVictimState.withLock {
            (
                credited: $0.victimCreditCount + $0.naturalReliefCount,
                hardCapReplacement: $0.hasOutstandingHardCapReplacement,
                retiring: $0.retiringResourceCount)
        }
        let projectedRegistered = max(registered - pressure.credited, 0)
        if projectedRegistered >= softCap { return true }
        guard !pressure.hardCapReplacement else { return false }
        let hardCap = Int(pressurePolicy.liveHardCap)
        guard hardCap > 0, projectedRegistered > 0 else { return false }
        let projectedLive = projectedRegistered
            + overload.liveFlowReservations.count
            + pressure.retiring
        return projectedLive >= hardCap
    }

    /// Arm one continuation for the moment a released protected candidate can
    /// first be reconsidered. This is a state-transition wake, not periodic
    /// no-headroom polling: if current occupancy no longer needs a scan at fire
    /// time, the work stops without clearing ordinary suppression.
    private func cancelPressureProtectionRetryLocked() {
        pressureProtectionRetryToken &+= 1
        pressureProtectionRetryWork?.cancel()
        pressureProtectionRetryWork = nil
        pressureProtectionRetryDeadlineNs = 0
    }

    private func schedulePressureProtectionRetryLocked(
        deadlineNs: UInt64,
        nowNs: UInt64
    ) {
        if pressureProtectionRetryWork != nil,
            pressureProtectionRetryDeadlineNs <= deadlineNs
        {
            return
        }
        cancelPressureProtectionRetryLocked()
        let token = pressureProtectionRetryToken
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.pressureProtectionRetryToken == token else { return }
            self.pressureProtectionRetryToken &+= 1
            self.pressureProtectionRetryWork = nil
            self.pressureProtectionRetryDeadlineNs = 0
            #if DEBUG || RAMA_TESTING
                self.pressureProtectionRetryBodyRuns += 1
            #endif
            guard self.pressureProtectionRetryNeededLocked() else { return }
            self.pressureRescanSuppressedUntilNs = 0
            let victims = self.collectPressureVictimsIfDueLocked(
                continuation: .towardLowWater)
            self.firePressureEvictions(victims)
        }
        pressureProtectionRetryWork = work
        pressureProtectionRetryDeadlineNs = deadlineNs
        #if DEBUG || RAMA_TESTING
            pressureProtectionRetrySchedules += 1
        #endif
        let delayNs = deadlineNs > nowNs ? deadlineNs - nowNs : 0
        stateQueue.asyncAfter(deadline: .now() + .nanoseconds(Int(delayNs)), execute: work)
    }

    private func pressureProtectionRetryNeededLocked() -> Bool {
        guard pressureEpisode != nil else { return false }
        let pressurePolicy = flowPressurePolicyLocked()
        guard pressurePolicy.softCap > 0 else { return false }
        let occupancy = tcpSessions.count + udpSessions.count
        let projected = pressureVictimState.withLock {
            max(occupancy - $0.victimCreditCount - $0.naturalReliefCount, 0)
        }
        let needsRetry: Bool
        if pressureRepairState == .waitingForTombstoneAck {
            // Tombstone repair continues through the hysteresis band;
            // otherwise releasing the only responsive candidate's protection
            // below soft-cap can strand the episode forever above low-water.
            needsRetry = projected > Int(Self.pressureLowWater(pressurePolicy))
        } else {
            // A successful ordinary batch deliberately stops once it falls
            // below soft-cap. Do not chase admissions that were hidden behind
            // pending victim credit down to low-water one batch at a time.
            needsRetry = projected >= Int(pressurePolicy.softCap)
        }
        return needsRetry
    }

    private func scheduleReleasedProtectionRetryIfNeededLocked(nowNs: UInt64) {
        guard pressureProtectionRetryNeededLocked() else { return }
        let minimumDeadlineNs = nowNs &+
            Self.pressureRescanMinSuppressMs &* 1_000_000
        let deadlineNs = max(pressureRescanSuppressedUntilNs, minimumDeadlineNs)
        schedulePressureProtectionRetryLocked(
            deadlineNs: deadlineNs,
            nowNs: nowNs)
    }

    /// Fire the evictions selected by `collectPressureVictimsLocked`. Hops to
    /// each victim's `flowQueue` (off `stateQueue`) and re-checks idleness
    /// THERE before tearing down — a byte may have moved (bumping
    /// `lastActivityAt`) between selection and here, and `mode`/`isDone` may
    /// have advanced. `applyPressureEvicted` has no internal gate, so this
    /// re-check is its protection; teardown is idempotent via `isDone`. A
    /// spared victim is handed back via `pressureVictimSpared`; an evicted
    /// one resolves through `removeTcpFlow`.
    private func firePressureEvictions(_ victims: [PressureVictim]) {
        let floorMs = UInt64(flowPressurePolicyLocked().idleFloorMs)
        enum FireDecision {
            case committed
            case spare
            case retired
        }
        for victim in victims {
            let ctx = victim.ctx
            runFlowTeardown(ctx) { [weak self] in
                #if DEBUG || RAMA_TESTING
                    self?.pressureEvictionBodyRuns.withLock { $0 += 1 }
                #endif
                let nowNs = DispatchTime.now().uptimeNanoseconds
                // Every path that wins `isDone` also queues registry removal;
                // let that removal classify this still-selected ticket as
                // canceled rather than racing it into the spare bucket.
                guard !ctx.isDone else { return }
                let decision = ctx.withMaintenanceStateLocked { state -> FireDecision in
                    guard state.egressReady,
                        Self.flowPressureAllowsEviction(state, nowNs: nowNs),
                        Self.flowIdleMs(state, nowNs: nowNs) > floorMs
                    else { return .spare }
                    guard self?.commitPressureVictim(victim) == true else {
                        return .retired
                    }
                    state.pressureEvictionCommitted = true
                    return .committed
                }
                switch decision {
                case .spare:
                    if self?.markPressureVictimSpared(victim) == true {
                        self?.pressureVictimSpared(victim)
                    } else {
                        self?.pressureVictimAcknowledged(
                            victim, wasEligibleAtFire: false)
                    }
                    return
                case .retired:
                    self?.pressureVictimAcknowledged(
                        victim, wasEligibleAtFire: true)
                    return
                case .committed:
                    ctx.applyPressureEvicted()
                }
            }
        }
    }

    /// Linearize a failed final eligibility check against cancellation and
    /// expiry before its state-queue accounting hop.
    private func markPressureVictimSpared(_ victim: PressureVictim) -> Bool {
        pressureVictimState.withLock { state in
            let id = ObjectIdentifier(victim.ctx)
            guard let reservation = state.reservations[id],
                reservation.token == victim.token,
                reservation.phase == .selected
            else { return false }
            state.setPhase(.spareAwaitingAccounting, for: id)
            state.recordOutcome(.spareAwaitingAccounting, goal: reservation.goal)
            return true
        }
    }

    /// Commit only the exact reservation that just passed the flow-local
    /// eligibility check. A detach or alternate teardown that invalidated the
    /// token in that narrow window wins and makes this closure a no-op.
    private func commitPressureVictim(_ victim: PressureVictim) -> Bool {
        let committed = pressureVictimState.withLock { state in
            let id = ObjectIdentifier(victim.ctx)
            guard let reservation = state.reservations[id],
                reservation.token == victim.token,
                reservation.phase == .selected
            else { return false }
            state.setPhase(.committed, for: id)
            state.recordOutcome(.committed, goal: reservation.goal)
            return true
        }
        return committed
    }

    /// A selected victim failed its `flowQueue` re-check. Drop it from the
    /// reservation and re-evaluate. Async hop, never `sync`: this runs on the
    /// victim's `flowQueue`.
    private func pressureVictimSpared(_ victim: PressureVictim) {
        stateQueue.async {
            self.drainPressureVictimOutcomesLocked()
            let id = ObjectIdentifier(victim.ctx)
            guard self.resolvePressureVictimLocked(id, token: victim.token) else { return }
            if victim.goal == .hardCapReplacement {
                if self.pressureRepairState != .idle {
                    self.settlePressureVictimBatchLocked()
                } else {
                    self.clearPressureProtectionsIfIdleLocked(
                        nowNs: DispatchTime.now().uptimeNanoseconds)
                }
                self.reschedulePressureRecheckLocked()
                return
            }
            self.pressureRepairState = .scanWhenBatchSettles
            self.pressureRescanSuppressedUntilNs = 0
            self.settlePressureVictimBatchLocked()
        }
    }

    /// A queued closure observed that its token was retired before commit.
    /// Remove the tombstone so a later cycle may consider the flow again.
    private func pressureVictimAcknowledged(
        _ victim: PressureVictim,
        wasEligibleAtFire: Bool
    ) {
        stateQueue.async {
            self.drainPressureVictimOutcomesLocked()
            guard let phase = self.acknowledgePressureVictimLocked(
                ObjectIdentifier(victim.ctx), token: victim.token)
            else { return }

            if victim.goal == .hardCapReplacement {
                if self.pressureRepairState != .idle {
                    self.settlePressureVictimBatchLocked()
                } else {
                    self.clearPressureProtectionsIfIdleLocked(
                        nowNs: DispatchTime.now().uptimeNanoseconds)
                }
                self.reschedulePressureRecheckLocked()
                self.endPressureEpisodeIfAtLowWaterLocked()
                return
            }

            let occupancy = self.tcpSessions.count + self.udpSessions.count
            let projected = self.pressureVictimState.withLock {
                max(occupancy - $0.victimCreditCount - $0.naturalReliefCount, 0)
            }
            let needsRepair = (phase == .expired || phase == .canceled)
                && self.pressureEpisode != nil
                && projected
                    > Int(Self.pressureLowWater(self.flowPressurePolicyLocked()))
            let terminalTombstones = self.pressureVictimState.withLock {
                $0.reservations.count - $0.unresolvedReservationCount
            }
            var rearmed = false
            if needsRepair, wasEligibleAtFire {
                if self.pressureRepairState == .idle {
                    self.pressureRepairState = .waitingForTombstoneAck
                }
                if let replacement = self.rearmAcknowledgedPressureVictimLocked(victim) {
                    rearmed = true
                    self.firePressureEvictions([replacement])
                }
            }
            if needsRepair, !rearmed {
                if terminalTombstones > 0 {
                    if self.pressureRepairState == .idle {
                        self.pressureRepairState = .waitingForTombstoneAck
                    }
                } else {
                    self.pressureRepairState = .scanWhenBatchSettles
                    self.pressureRescanSuppressedUntilNs = 0
                    self.settlePressureVictimBatchLocked()
                }
            } else if !rearmed,
                self.pressureRepairState == .waitingForTombstoneAck,
                terminalTombstones == 0
            {
                self.settlePressureVictimBatchLocked()
            }
            self.reschedulePressureRecheckLocked()
            self.endPressureEpisodeIfAtLowWaterLocked()
        }
    }

    /// A recovered flow queue has just performed the expensive, flow-local
    /// eligibility check. Re-arm that exact context in O(1) instead of sorting
    /// the whole registry. Its new closure still re-checks locally before
    /// commit, preserving the activity race guarantee.
    private func rearmAcknowledgedPressureVictimLocked(
        _ victim: PressureVictim,
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) -> PressureVictim? {
        guard pressureRepairState != .idle, pressureEpisode != nil else {
            return nil
        }
        let id = ObjectIdentifier(victim.ctx)
        let flowId = victim.ctx.flowId ?? id
        guard tcpSessions[flowId]?.ctx === victim.ctx,
            !activePressureProtectedFlowIds.contains(flowId)
        else { return nil }
        let occupancy = tcpSessions.count + udpSessions.count
        var replacement: PressureVictim?
        pressureVictimState.withLock { state in
            let projected = max(
                occupancy - state.victimCreditCount - state.naturalReliefCount,
                0)
            guard projected > Int(Self.pressureLowWater(flowPressurePolicyLocked())),
                state.reservations[id] == nil,
                state.pendingRemovalFlowIds[flowId] == nil
            else { return }
            nextPressureVictimToken &+= 1
            let token = nextPressureVictimToken
            state.insertReservation(
                PressureVictimReservation(
                    token: token,
                    selectedAtNs: nowNs,
                    flowId: flowId,
                    goal: .lowWater,
                    phase: .selected),
                for: id)
            replacement = PressureVictim(
                ctx: victim.ctx,
                token: token,
                goal: .lowWater)
        }
        guard let replacement else { return nil }
        pressureNoHeadroomLogged = false
        pressureRescanSuppressedUntilNs = 0
        pressureSelectionsTotal += 1
        pressureEpisode?.selections += 1
        reschedulePressureRecheckLocked(nowNs: nowNs)
        return replacement
    }

    private func pressureVictimCreditCount() -> Int {
        pressureVictimState.withLock { $0.victimCreditCount }
    }

    /// Remove a terminal tombstone without charging a second outcome.
    /// MUST be called on `stateQueue`.
    @discardableResult
    private func acknowledgePressureVictimLocked(
        _ id: ObjectIdentifier, token: UInt64
    ) -> PressureVictimPhase? {
        let removed = pressureVictimState.withLock { state -> PressureVictimPhase? in
            guard let reservation = state.reservations[id], reservation.token == token,
                reservation.phase == .canceled || reservation.phase == .expired
            else { return nil }
            state.removeReservation(for: id)
            return reservation.phase
        }
        if removed == .expired || removed == .canceled {
            // A terminal tombstone excluded this flow from any scan that
            // armed suppression. Once acknowledged, the flow is newly
            // eligible; do not retain that stale view.
            pressureRescanSuppressedUntilNs = 0
        }
        return removed
    }

    /// Resolve one exact reservation after its already-ledgered spare outcome
    /// reaches `stateQueue`. MUST be called on `stateQueue`.
    @discardableResult
    private func resolvePressureVictimLocked(
        _ id: ObjectIdentifier, token: UInt64
    ) -> Bool {
        let reservation: PressureVictimReservation? = pressureVictimState.withLock {
            state in
            guard let current = state.reservations[id], current.token == token,
                current.phase == .spareAwaitingAccounting
            else {
                return nil
            }
            return state.removeReservation(for: id)
        }
        return reservation != nil
    }

    /// Schedule the earliest outstanding pressure deadline. One token guards
    /// against a cancelled work item already dequeued when a newer deadline
    /// replaces it. MUST be called on `stateQueue`.
    private func reschedulePressureRecheckLocked(
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) {
        let leaseNs = pressureVictimDispatchLeaseMs &* 1_000_000
        let selectionDeadline = pressureVictimState.withLock {
            $0.earliestSelectedDeadline(leaseNs: leaseNs)
        }
        guard let deadline = selectionDeadline else {
            pressureRecheckWork?.cancel()
            pressureRecheckWork = nil
            pressureRecheckDeadlineNs = 0
            pressureRecheckToken &+= 1
            return
        }
        if pressureRecheckWork != nil, pressureRecheckDeadlineNs <= deadline { return }
        pressureRecheckWork?.cancel()
        pressureRecheckToken &+= 1
        let token = pressureRecheckToken
        pressureRecheckDeadlineNs = deadline
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.pressureRecheckToken == token else { return }
            self.pressureRecheckWork = nil
            self.pressureRecheckDeadlineNs = 0
            self.runPressureRecheckLocked()
        }
        pressureRecheckWork = work
        let delayNs = deadline > nowNs ? deadline - nowNs : 0
        stateQueue.asyncAfter(deadline: .now() + .nanoseconds(Int(delayNs)), execute: work)
    }

    /// Expire dispatch-starved selections, then run the due rescan. An expired
    /// victim remains a tombstone until its queued closure acknowledges the
    /// token, so the rescan can try a different flow without piling work onto
    /// the same starved queue. MUST run on `stateQueue`.
    private func runPressureRecheckLocked(
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds
    ) {
        let leaseNs = pressureVictimDispatchLeaseMs &* 1_000_000
        let expiredCount = pressureVictimState.withLock { state in
            state.expireSelected(nowNs: nowNs, leaseNs: leaseNs)
        }
        if expiredCount.total > 0 {
            pressureExpiredTotal += expiredCount.total
        }
        if expiredCount.lowWater > 0 {
            pressureEpisode?.expired += expiredCount.lowWater
            pressureRepairState = .scanWhenBatchSettles
            pressureRescanSuppressedUntilNs = 0
            settlePressureVictimBatchLocked(nowNs: nowNs)
        }
        if expiredCount.hardCapReplacement > 0 {
            clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
            endPressureEpisodeIfAtLowWaterLocked()
        }
        reschedulePressureRecheckLocked(nowNs: nowNs)
    }

    private func startFlowCountReporting() {
        stateQueue.sync { self.startFlowCountReportingLocked() }
    }

    private func startFlowCountReportingLocked() {
        pauseFlowCountReportingLocked()
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.schedule(
            deadline: .now() + Self.periodicMaintenanceInterval,
            repeating: Self.periodicMaintenanceInterval
        )
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let toKick = self.collectMaintenanceKicksLocked()
            guard !toKick.isEmpty else { return }
            // Keep teardown work off the registry queue so maintenance stays short.
            DispatchQueue.global(qos: .utility).async {
                self.fireWatchdogKicks(toKick)
            }
        }
        timer.resume()
        flowCountReportingTimer = timer
    }

    private func pauseFlowCountReporting() {
        stateQueue.sync { self.pauseFlowCountReportingLocked() }
    }

    private func pauseFlowCountReportingLocked() {
        flowCountReportingTimer?.cancel()
        flowCountReportingTimer = nil
    }

    /// Fold off-queue terminal decisions into queue-confined telemetry once.
    /// Reservation cleanup is deliberately separate: a committed victim still
    /// carries projected-capacity credit until its registry removal lands.
    private func drainPressureVictimOutcomesLocked() {
        let outcomes = pressureVictimState.withLock {
            $0.takeUnreportedOutcomes()
        }
        applyPressureVictimOutcomesLocked(outcomes)
    }

    private func applyPressureVictimOutcomesLocked(
        _ outcomes: PressureOutcomeCounts
    ) {
        guard !outcomes.isEmpty else { return }
        pressureEvictedTotal += outcomes.evicted
        pressureSparedTotal += outcomes.spared
        pressureCanceledTotal += outcomes.canceled
        pressureEpisode?.evicted += outcomes.episodeEvicted
        pressureEpisode?.spared += outcomes.episodeSpared
        pressureEpisode?.canceled += outcomes.episodeCanceled
    }

    private func resetMaintenanceStateLocked() {
        pressureReapSlot.withLock { slot in
            slot.nextToken &+= 1
            slot.outstandingToken = nil
            slot.hardCapReplacementGeneration = nil
            slot.unscopedHardCapReplacementRequested = false
            slot.ordinaryPressureRequested = false
            slot.protectedFlowIds.removeAll(keepingCapacity: false)
        }
        // Clear watchdog state so a future `attachEngine` doesn't
        // inherit stale "stuck" IDs from the previous lifecycle.
        self.stuckPreReadyFlowIds.removeAll(keepingCapacity: false)
        self.stuckClosingFlowIds.removeAll(keepingCapacity: false)
        self.flowCountHighWater = 0
        self.overload = TcpOverloadState()
        self.pressureRescanSuppressedUntilNs = 0
        self.cancelPressureProtectionRetryLocked()
        self.pressureNoHeadroomLogged = false
        self.hardCapNoHeadroomLogged = false
        // Drain and invalidate under one lock. A flow-queue decision either
        // linearizes first and is included below, or loses its stale token.
        let finalOutcomes = self.pressureVictimState.withLock {
            $0.reset()
        }
        self.applyPressureVictimOutcomesLocked(finalOutcomes)
        if let episode = self.pressureEpisode {
            self.logPressureEpisodeLocked(episode, outcome: "interrupted")
        }
        self.pressureEpisode = nil
        self.pressureRepairState = .idle
        self.pendingPressureProtectedFlowIds.removeAll(keepingCapacity: false)
        self.activePressureProtectedFlowIds.removeAll(keepingCapacity: false)
        self.pressureRecheckWork?.cancel()
        self.pressureRecheckWork = nil
        self.pressureRecheckDeadlineNs = 0
        self.pressureRecheckToken &+= 1
        let triggers = self.pressureTriggersTotal.withLock { $0 }
        let scans = self.pressureScansTotal.withLock { $0 }
        self.pressureStatsAtLastTick = (
            triggers, scans, self.pressureSkipsTotal, self.pressureSelectionsTotal,
            self.pressureEvictedTotal, self.pressureSparedTotal,
            self.pressureCanceledTotal, self.pressureExpiredTotal)
    }

    /// One maintenance tick, on-`stateQueue` half: emit flow-count
    /// telemetry, run the stale-pre-ready bookkeeping, and return the
    /// list of contexts that crossed the "stuck for ≥ one tick"
    /// threshold so the off-queue half can drive their teardowns.
    ///
    /// MUST be called on `stateQueue` — both the timer handler and
    /// the test hook satisfy that.
    private func collectMaintenanceKicksLocked() -> MaintenanceKicks {
        let flowPressurePolicy = flowPressurePolicyLocked()
        let tcpStartAdmissionPolicy = tcpStartAdmissionPolicyLocked()
        drainPressureVictimOutcomesLocked()
        // `stateQueue.sync` is unnecessary inside — the timer fires ON
        // `stateQueue`, so direct access to the maps is already
        // serialised correctly.
        let tcp = self.tcpSessions.count
        let udp = self.udpSessions.count
        let retirement = self.retirementOccupancySnapshot()
        let retiring = retirement.retiring
        let retirementOverlap = retirement.overlap
        let total = max(tcp + udp - retirementOverlap, 0) + retiring
        if total > self.flowCountHighWater { self.flowCountHighWater = total }
        // Tick-driven breaker pass: catches the state where pressure arrived
        // through admissions under the soft cap after a slow completion, so
        // neither event evaluated with both conditions true. Cannot close on
        // its own — in-flight only drops on completion, which evaluates
        // itself. Also keeps the `breaker=` field below fresh.
        self.updateTcpAdmissionBreakerLocked(trigger: "tick")
        // Combined total is what matters for the kernel nexus ceiling (global
        // across the flowswitch). `cap`/`peak` make pressure visible in soak.
        let topShedApps = self.overload.topShedAppSummary()
        let overloadSnapshot = self.overload.snapshotAndResetRates(
            intervalSeconds: Self.periodicMaintenanceIntervalSeconds)
        let topApps = self.overload.topAppSummary()
        let admissionRate = String(format: "%.2f", overloadSnapshot.admissionRate)
        let timeoutRate = String(format: "%.2f", overloadSnapshot.timeoutRate)
        let shedRate = String(format: "%.2f", overloadSnapshot.shedRate)
        let breaker = overloadSnapshot.breakerOpen ? "open" : "closed"
        let appSummary = topApps.isEmpty ? "-" : topApps
        let shedAppSummary = topShedApps.isEmpty ? "-" : topShedApps
        let latencySummary =
            "p50=\(overloadSnapshot.p50StartMs),p95=\(overloadSnapshot.p95StartMs),"
            + "p99=\(overloadSnapshot.p99StartMs)"
        let countSummary =
            "tproxy live-flow counts tcp=\(tcp) udp=\(udp) total=\(total) "
            + "peak=\(self.flowCountHighWater) softCap=\(flowPressurePolicy.softCap) "
            + "hardCap=\(flowPressurePolicy.liveHardCap) retiring=\(retiring) "
            + "retirementOverlap=\(retirementOverlap)"
        let overloadSummary =
            "tcpStartsInFlight=\(overloadSnapshot.startsInFlight) "
            + "tcpStartsInFlightPeak=\(overloadSnapshot.startsInFlightPeak) "
            + "hardCap=\(tcpStartAdmissionPolicy.hardCap) "
            + "admissionRate=\(admissionRate)/s timeoutRate=\(timeoutRate)/s "
            + "shedRate=\(shedRate)/s shedHardCap=\(overloadSnapshot.shedHardCap) "
            + "shedBreaker=\(overloadSnapshot.shedBreaker) "
            + "shedLiveCapTcp=\(overloadSnapshot.shedLiveCapTcp) "
            + "shedLiveCapUdp=\(overloadSnapshot.shedLiveCapUdp) "
            + "shedApps=\(shedAppSummary) "
            + "startLatencyMs[\(latencySummary)] breaker=\(breaker)"
        let triggers = self.pressureTriggersTotal.withLock { $0 }
        let scans = self.pressureScansTotal.withLock { $0 }
        let pending = pressureVictimCreditCount()
        let pressureSummary =
            "pressure[triggers=\(triggers - pressureStatsAtLastTick.triggers) "
            + "scans=\(scans - pressureStatsAtLastTick.scans) "
            + "skipped=\(pressureSkipsTotal - pressureStatsAtLastTick.skips) "
            + "selected=\(pressureSelectionsTotal - pressureStatsAtLastTick.selections) "
            + "evicted=\(pressureEvictedTotal - pressureStatsAtLastTick.evicted) "
            + "spared=\(pressureSparedTotal - pressureStatsAtLastTick.spared) "
            + "canceled=\(pressureCanceledTotal - pressureStatsAtLastTick.canceled) "
            + "expired=\(pressureExpiredTotal - pressureStatsAtLastTick.expired) "
            + "pending=\(pending)]"
        pressureStatsAtLastTick = (
            triggers, scans, pressureSkipsTotal, pressureSelectionsTotal,
            pressureEvictedTotal, pressureSparedTotal, pressureCanceledTotal,
            pressureExpiredTotal
        )
        // Bundle ids are in the clear: Apple's own `com.apple.networkextension`
        // subsystem logs the source app of every flow publicly on the same
        // machine, so redacting them here only hides them from our own
        // post-incident reads.
        self.logLifecycle(
            "\(countSummary) \(overloadSummary) \(pressureSummary) topApps=\(appSummary)")

        // Track two cross-tick "stuck" sets. An ID present in both the
        // previous AND the current set has been stuck for ≥ one tick
        // interval and gets force-torn-down — driven from here (on
        // `stateQueue`, its own thread) so it survives the per-flow queue
        // being starved.
        //
        //   * Pre-`egressReady`: still connecting → `applyConnectTimeout`,
        //     the same teardown the per-flow connect timer would fire.
        //   * Post-ready + `terminalSignalled`: a terminal close was
        //     signalled but the flow never left the registry → its
        //     graceful drain wedged → `applyDrainBackstop`, mirroring the
        //     per-flow `armTerminalDrainBackstop` timer.
        var nowStuckPreReady: Set<ObjectIdentifier> = []
        var nowStuckClosing: Set<ObjectIdentifier> = []
        var kicks = MaintenanceKicks()
        for (id, anchor) in tcpSessions {
            let ctx = anchor.ctx
            let state = ctx.maintenanceSnapshot()
            if !state.egressReady {
                nowStuckPreReady.insert(id)
                if stuckPreReadyFlowIds.contains(id) {
                    kicks.preReadyStuck.append(ctx)
                }
            } else if Self.flowIsDrainWedged(state) {
                // Genuinely drain-wedged (viaRust: terminalSignalled; promoted:
                // a direction stuck in `.finishing`). A clean half-close whose
                // opposite direction is still actively transferring is NOT
                // wedged — `flowIsDrainWedged` excludes it, so it falls through
                // to the idle reaper below and is reaped only if it later goes
                // quiet, never force-reset while live.
                nowStuckClosing.insert(id)
                if stuckClosingFlowIds.contains(id) {
                    kicks.closingStuck.append(ctx)
                }
            } else if state.mode == .promoted, Self.promotedFlowIsIdle(state) {
                // Promoted-path idle reaper. The `viaRust` path has the Rust
                // engine's own DEFAULT_TCP_IDLE_TIMEOUT; promotion drops it
                // (the Rust task exits at cutover), so an established promoted
                // flow gone silent would otherwise pin its egress
                // NWConnection's nexus-flow slot until the process exhausts its
                // NECP allocation. No cross-tick "stuck set" is needed here:
                // the multi-minute idle deadline far exceeds one tick, so the
                // duration check is its own hysteresis, and an actively
                // transferring flow keeps bumping `lastActivityAt` and is
                // never selected.
                kicks.idleStuck.append(ctx)
            }
        }
        stuckPreReadyFlowIds = nowStuckPreReady
        stuckClosingFlowIds = nowStuckClosing
        return kicks
    }

    /// Fire collected teardowns outside the registry queue.
    private func fireWatchdogKicks(_ kicks: MaintenanceKicks) {
        guard !kicks.isEmpty else { return }
        if !kicks.preReadyStuck.isEmpty {
            logLifecycle(
                "watchdog: force-tearing down \(kicks.preReadyStuck.count) stale pre-ready flow(s)"
            )
            for ctx in kicks.preReadyStuck {
                // Re-check via `hasReachedReady` ON `flowQueue`, NOT plain
                // `egressReady`. This kick block can be queued AHEAD of a
                // pending `.ready` callback, so `egressReady` may be stale
                // `false` here even though NW reached `.ready` — FIFO orders
                // the `.ready` handler, not this read. Consulting live state
                // spares a connection that just came up. `applyConnectTimeout`
                // has no internal ready-check, so this gate is its protection.
                runFlowTeardown(ctx) {
                    guard !ctx.hasReachedReady else { return }
                    ctx.applyConnectTimeout()
                }
            }
        }
        if !kicks.closingStuck.isEmpty {
            logLifecycle(
                "watchdog: force-tearing down \(kicks.closingStuck.count) wedged closing flow(s)"
            )
            for ctx in kicks.closingStuck {
                // Re-check drain-wedge ON `flowQueue`: between the off-queue
                // selection and here a `.finishing` direction may have drained
                // (reaching `.finished`) or the active opposite direction may
                // have advanced, so a flow that is no longer genuinely wedged
                // must be spared rather than force-reset while still live.
                // `applyDrainBackstop` has no internal wedge-check, so this gate
                // is its protection; it is idempotent via `isDone` regardless.
                runFlowTeardown(ctx) {
                    guard Self.flowIsDrainWedged(ctx) else { return }
                    ctx.applyDrainBackstop()
                }
            }
        }
        if !kicks.idleStuck.isEmpty {
            logLifecycle(
                "watchdog: force-tearing down \(kicks.idleStuck.count) idle promoted flow(s)"
            )
            for ctx in kicks.idleStuck {
                // Re-check idle ON `flowQueue`: a byte may have moved (bumping
                // `lastActivityAt`) between the off-queue selection and here,
                // and `mode` may have advanced if a teardown raced ahead.
                // `applyIdleTimeout` has no internal idle-check, so this gate
                // is its protection; it is idempotent via `isDone` regardless.
                runFlowTeardown(ctx) {
                    guard ctx.mode == .promoted, Self.promotedFlowIsIdle(ctx) else { return }
                    ctx.applyIdleTimeout()
                }
            }
        }
    }

    #if DEBUG || RAMA_TESTING
        /// Test hook: run one maintenance tick synchronously. Lets
        /// unit tests exercise the watchdog without waiting 60s for
        /// the production timer. Same `#if DEBUG` gating as the other
        /// `test*` surfaces above.
        func testRunPeriodicMaintenance() {
            let toKick = stateQueue.sync { self.collectMaintenanceKicksLocked() }
            // Outside `stateQueue.sync` on purpose — see
            // [`fireWatchdogKicks`] for the deadlock rationale.
            fireWatchdogKicks(toKick)
        }

        /// Test hook: run one maintenance tick with a caller-supplied mutation
        /// injected BETWEEN selection and the fire bodies. Lets a test revive a
        /// flow after it was selected as idle/stuck, exercising the
        /// on-`flowQueue` re-check that must then spare it.
        func testRunMaintenanceWithRevival(_ reviveBetweenSelectAndFire: () -> Void) {
            let toKick = stateQueue.sync { self.collectMaintenanceKicksLocked() }
            reviveBetweenSelectAndFire()
            fireWatchdogKicks(toKick)
        }
        /// Test hook: run one flow-pressure reap synchronously (selection on
        /// `stateQueue`, evictions fired outside it — same shape as
        /// `testRunPeriodicMaintenance`). Lets unit tests exercise the backstop
        /// without the production async dispatch or a live occupancy burst.
        func testReapIdleUnderPressure() {
            let victims = stateQueue.sync { self.collectPressureVictimsLocked() }
            firePressureEvictions(victims)
        }

        func testRequestHardCapReplacement() {
            reapIdleUnderPressure(hardCapReplacement: true)
        }

        func testSetBeforeTcpHardCapReplacementPublish(
            _ hook: (@Sendable () -> Void)?
        ) {
            beforeTcpHardCapReplacementPublish.withLock { $0 = hook }
        }

        /// Test hooks: the two halves of the pressure reap exposed separately so
        /// a test can inject a state change (e.g. a flow becoming active again)
        /// BETWEEN selection and the fire body, exercising the on-`flowQueue`
        /// re-check that protects a just-revived victim.
        func testCollectPressureVictims() -> [PressureVictim] {
            stateQueue.sync { self.collectPressureVictimsLocked() }
        }
        func testCollectPressureVictims(nowNs: UInt64) -> [PressureVictim] {
            stateQueue.sync { self.collectPressureVictimsLocked(nowNs: nowNs) }
        }
        func testFirePressureEvictions(_ victims: [PressureVictim]) {
            firePressureEvictions(victims)
        }

        func testCommitPressureVictim(_ victim: PressureVictim) -> Bool {
            commitPressureVictim(victim)
        }

        func testMarkPressureVictimSpared(_ victim: PressureVictim) -> Bool {
            markPressureVictimSpared(victim)
        }

        /// Test hook: the production trigger's on-queue half, rescan
        /// suppression included, run synchronously.
        /// `testReapIdleUnderPressure` bypasses the gate on purpose (it pins
        /// victim selection alone).
        func testReapIdleUnderPressureIfDue() {
            let victims = stateQueue.sync { self.collectPressureVictimsIfDueLocked() }
            firePressureEvictions(victims)
        }

        func testReapIdleUnderPressureIfDue(
            nowNs: UInt64,
            protecting flowId: ObjectIdentifier? = nil
        ) {
            let protected = flowId.map { Set([$0]) } ?? []
            let victims = stateQueue.sync {
                self.collectPressureVictimsIfDueLocked(
                    nowNs: nowNs,
                    excluding: protected)
            }
            firePressureEvictions(victims)
        }

        func testCollectPressureVictimsIfDue(nowNs: UInt64) -> [PressureVictim] {
            stateQueue.sync {
                self.collectPressureVictimsIfDueLocked(nowNs: nowNs)
            }
        }

        /// Test hook: full selection scans performed so far.
        var testPressureScanCount: Int { pressureScansTotal.withLock { $0 } }

        /// Test hook: production trigger publications, before slot coalescing.
        var testPressureTriggerCount: Int { pressureTriggersTotal.withLock { $0 } }

        /// Test hook: a scan is queued and has not started yet.
        var testPressureReapScheduled: Bool {
            pressureReapSlot.withLock { $0.outstandingToken != nil }
        }

        /// Lock-only diagnostics remain readable even when `stateQueue` is the
        /// queue that failed to make progress.
        var testPressureAsyncDiagnosticSnapshot: String {
            let slot = pressureReapSlot.withLock {
                (
                    scheduled: $0.outstandingToken != nil,
                    protected: $0.protectedFlowIds.count,
                    ordinary: $0.ordinaryPressureRequested,
                    hard: $0.hardCapReplacementGeneration != nil
                        || $0.unscopedHardCapReplacementRequested)
            }
            let victims = pressureVictimState.withLock {
                (
                    reservations: $0.reservations.count,
                    credit: $0.victimCreditCount,
                    unresolved: $0.unresolvedReservationCount,
                    pendingRemovals: $0.pendingRemovalFlowIds.count)
            }
            return "reapScheduled=\(slot.scheduled) protected=\(slot.protected) "
                + "ordinaryRequested=\(slot.ordinary) hardRequested=\(slot.hard) "
                + "reservations=\(victims.reservations) credit=\(victims.credit) "
                + "unresolved=\(victims.unresolved) "
                + "pendingRemovals=\(victims.pendingRemovals)"
        }

        /// Enqueue an observation after pressure work already submitted to
        /// `stateQueue`. Tests combine this with flow-queue barriers to drive
        /// dispatch handoffs deterministically; their timeout remains only a
        /// deadlock watchdog, not the signal that work should have settled.
        func testSchedulePressureStateObservation(
            _ observe: @escaping @Sendable () -> Void
        ) {
            stateQueue.async(execute: observe)
        }

        var testPressureRecheckScheduled: Bool {
            stateQueue.sync { self.pressureRecheckWork != nil }
        }

        var testFlowCountReportingScheduled: Bool {
            stateQueue.sync { self.flowCountReportingTimer != nil }
        }

        /// Test hook: total victim selections, including later spares.
        var testPressureSelectionsTotal: Int {
            stateQueue.sync { self.pressureSelectionsTotal }
        }

        /// Test hook: selections that committed pressure teardown.
        var testPressureEvictedTotal: Int {
            stateQueue.sync { self.pressureEvictedTotal }
        }

        /// Test hook: eviction closures that ran on a victim `flowQueue`.
        var testPressureEvictionBodyRuns: Int { pressureEvictionBodyRuns.withLock { $0 } }

        /// Test hook: selected victims whose teardown has not yet left the registry.
        var testPressurePendingVictimCount: Int {
            stateQueue.sync { self.pressureVictimCreditCount() }
        }

        /// Registry entries whose terminal removal has already linearized in
        /// pressure accounting but whose async map erase has not landed yet.
        var testPressurePendingRemovalCount: Int {
            pressureVictimState.withLock { $0.pendingRemovalFlowIds.count }
        }

        /// Test hook: selections the `flowQueue` re-check declined.
        var testPressureSparedTotal: Int { stateQueue.sync { self.pressureSparedTotal } }

        var testPressureCanceledTotal: Int { stateQueue.sync { self.pressureCanceledTotal } }

        var testPressureExpiredTotal: Int { stateQueue.sync { self.pressureExpiredTotal } }

        var testPendingPressureProtectionCount: Int {
            stateQueue.sync { self.pendingPressureProtectedFlowIds.count }
        }

        var testActivePressureProtectionCount: Int {
            stateQueue.sync { self.activePressureProtectedFlowIds.count }
        }

        var testPressureWaitingForTombstoneAck: Bool {
            stateQueue.sync { self.pressureRepairState == .waitingForTombstoneAck }
        }

        var testPressureProtectionRetryScheduleCount: Int {
            stateQueue.sync { self.pressureProtectionRetrySchedules }
        }

        var testPressureProtectionRetryBodyRunCount: Int {
            stateQueue.sync { self.pressureProtectionRetryBodyRuns }
        }

        func testSetPressureVictimDispatchLeaseMs(_ value: UInt64) {
            stateQueue.sync { self.pressureVictimDispatchLeaseMs = value }
        }

        /// Stop this test core, wait for every registered flow queue to apply
        /// teardown, then drain the resulting registry callbacks. Tests that
        /// temporarily mutate process-global policy must use this boundary
        /// before restoring it.
        func testDetachAndDrainFlowQueues() {
            let flowQueues: [DispatchQueue] = stateQueue.sync {
                tcpSessions.values.compactMap { $0.ctx.flowQueue }
                    + udpSessions.values.compactMap { $0.ctx.flowQueue }
            }
            detachEngine(reason: 0)
            for queue in flowQueues { queue.sync {} }
            stateQueue.sync {}
        }

        var testPressureVictimDispatchLeaseMs: UInt64 {
            stateQueue.sync { self.pressureVictimDispatchLeaseMs }
        }

        var testEngineGeneration: UInt64 {
            stateQueue.sync { self.engineGeneration }
        }

        /// Test hook: the suppression most recently armed, in ms.
        var testPressureRescanLastArmedMs: UInt64 {
            stateQueue.sync { self.pressureRescanLastArmedMs }
        }

        /// Test hook: remaining rescan suppression in ms (`0` = none).
        var testPressureRescanSuppressedForMs: UInt64 {
            stateQueue.sync {
                let now = DispatchTime.now().uptimeNanoseconds
                guard now < self.pressureRescanSuppressedUntilNs else { return 0 }
                return (self.pressureRescanSuppressedUntilNs - now) / 1_000_000
            }
        }

        /// Test hook: announce removal without immediately queueing the
        /// registry mutation, exposing the exact pending-accounting window.
        @discardableResult
        func testAnnouncePressureRemoval(
            flowId: ObjectIdentifier,
            context: TcpFlowContext?
        ) -> Bool {
            announcePressureRemoval(
                flowId: flowId,
                contextId: context.map(ObjectIdentifier.init),
                engineGeneration: nil)
        }

        /// Test hook: drive the lease recheck at a synthetic future instant.
        func testRunPressureRecheck(afterMs: UInt64) {
            let nowNs = DispatchTime.now().uptimeNanoseconds
            stateQueue.sync {
                self.runPressureRecheckLocked(
                    nowNs: nowNs &+ afterMs &* 1_000_000)
            }
        }

        /// Test hook: drive the lease recheck at an exact monotonic instant.
        func testRunPressureRecheck(nowNs: UInt64) {
            stateQueue.sync { self.runPressureRecheckLocked(nowNs: nowNs) }
        }

        /// Test hook: run exact-clock boundaries without allowing the real
        /// deadline work item to interleave between observations.
        func testRunPressureRechecks(nowNsValues: [UInt64]) -> [Int] {
            stateQueue.sync {
                nowNsValues.map { nowNs in
                    self.runPressureRecheckLocked(nowNs: nowNs)
                    return self.pressureExpiredTotal
                }
            }
        }

        /// Fire the currently scheduled released-protection continuation now.
        /// The work item's token makes its later real deadline a no-op.
        func testRunPressureProtectionRetry() {
            stateQueue.sync { self.pressureProtectionRetryWork?.perform() }
        }

        /// Test hook: park `stateQueue` until the returned semaphore is
        /// signalled, so a test can pile triggers up behind it. Do not call
        /// any `stateQueue.sync` hook while it is held.
        func testHoldStateQueue() -> DispatchSemaphore {
            let gate = DispatchSemaphore(value: 0)
            stateQueue.async { gate.wait() }
            return gate
        }

        /// Test hook: run the post-wake established-flow path re-check
        /// synchronously, skipping the `defaultPostWakePathRecheckMs`
        /// settle timer. Mirrors `testRunPeriodicMaintenance`.
        func testCheckWakeDeadPath(_ ctx: TcpFlowContext) {
            checkDeadPath(ctx, trigger: "wake")
        }

        /// Test hook: inspect the watchdog's "stuck since last tick" set.
        var testStuckPreReadyFlowIds: Set<ObjectIdentifier> {
            stateQueue.sync { self.stuckPreReadyFlowIds }
        }

        /// Test hook: inspect the watchdog's post-`.ready` "closing but
        /// not yet removed" tracking set.
        var testStuckClosingFlowIds: Set<ObjectIdentifier> {
            stateQueue.sync { self.stuckClosingFlowIds }
        }
    #endif

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

    /// Register the per-flow session as the owner-of-record for an
    /// intercepted TCP flow. Mirror of `registerUdpFlow`: the anchor is
    /// the only strong reference keeping the session alive while the flow
    /// is open; dropping it via `removeTcpFlow` deallocates the session
    /// and the `ctx`/pumps/`RamaTcpSessionHandle` graph it owns.
    /// Register a TCP flow and return the COMBINED (TCP + UDP) live flow count
    /// after insertion, so the caller can drive the flow-pressure backstop
    /// without a second `stateQueue.sync` on the delivery thread (the count is
    /// read inside the register sync that already happens). Combined because
    /// the kernel nexus ceiling is global across the flowswitch, not per-proto.
    @discardableResult
    func registerTcpFlow(
        _ flowId: ObjectIdentifier,
        anchor: TcpFlowSessionAnchor,
        appId: String? = nil,
        admissionToken: TcpAdmissionToken? = nil,
        engineGeneration: UInt64? = nil
    ) -> Int? {
        stateQueue.sync {
            let pressurePolicy = self.flowPressurePolicyLocked()
            if let engineGeneration {
                guard self.acceptingFlows,
                    engineGeneration == self.engineGeneration
                else { return nil }
            }
            let hadReservation: Bool
            if let admissionToken {
                let expectedGeneration = engineGeneration ?? self.engineGeneration
                guard admissionToken.flowId == flowId,
                    admissionToken.identity.engineGeneration == expectedGeneration,
                    self.overload.startsInFlight[flowId]?.identity == admissionToken.identity,
                    self.overload.liveFlowReservations[flowId] == admissionToken.identity
                else { return nil }
                self.overload.liveFlowReservations.removeValue(forKey: flowId)
                hadReservation = true
            } else {
                // An admitted start must transfer its exact reservation. A
                // tokenless direct registration remains available for tests
                // and internal registry fixtures that never reserved a slot.
                guard self.overload.liveFlowReservations[flowId] == nil else { return nil }
                hadReservation = false
            }
            let occupancyBefore = self.liveResourceOccupancyLocked(
                registered: self.tcpSessions.count + self.udpSessions.count)
            let hardCap = Int(pressurePolicy.liveHardCap)
            guard hadReservation || hardCap == 0 || occupancyBefore < hardCap else {
                return nil
            }
            self.tcpSessions[flowId] = anchor
            self.hardCapNoHeadroomLogged = false
            self.pressureVictimState.withLock {
                $0.registeredFlowIds.insert(flowId)
            }
            if let appId {
                self.overload.flowApps[flowId] = appId
                self.overload.perAppFlowCounts[appId, default: 0] += 1
            }
            let occupancy = self.tcpSessions.count + self.udpSessions.count
            if pressurePolicy.softCap > 0,
                occupancy >= Int(pressurePolicy.softCap)
                    || self.pressureEpisode != nil
            {
                self.pendingPressureProtectedFlowIds.insert(flowId)
            }
            return occupancy
        }
    }

    /// Register and bracket transport startup against detach. Registration and
    /// group entry are atomic under `lifecycleLock`; the short startup body then
    /// runs synchronously on its new per-flow queue. This preserves queue
    /// confinement and caller priority, while independent flows remain free to
    /// start concurrently. Detach closes admission under the same lock and
    /// waits for entrants before it dispatches teardown or stops the engine.
    func registerTcpFlowAndScheduleStartup(
        _ flowId: ObjectIdentifier,
        anchor: TcpFlowSessionAnchor,
        appId: String?,
        admissionToken: TcpAdmissionToken? = nil,
        engineGeneration: UInt64,
        runtimePolicy: TransparentProxyRuntimePolicy? = nil,
        on flowQueue: DispatchQueue,
        body: @escaping @Sendable () -> Void
    ) -> Bool {
        let pressurePolicy =
            (runtimePolicy ?? TransparentProxyRuntimePolicy.testDefaultsSnapshot).flowPressure
        lifecycleLock.lock()
        guard
            let occupancy = registerTcpFlow(
                flowId,
                anchor: anchor,
                appId: appId,
                admissionToken: admissionToken,
                engineGeneration: engineGeneration)
        else {
            lifecycleLock.unlock()
            return false
        }
        flowLifecycleGroup.enter()
        lifecycleLock.unlock()
        defer { flowLifecycleGroup.leave() }
        flowQueue.sync(execute: body)
        if pressurePolicy.softCap > 0,
            occupancy >= Int(pressurePolicy.softCap)
        {
            reapIdleUnderPressure(
                protecting: flowId,
                flowPressurePolicy: pressurePolicy)
        }
        return true
    }

    /// Register the per-flow session as the owner-of-record for an
    /// intercepted UDP flow. The anchor is the only strong reference
    /// keeping the session alive while the flow is open; dropping
    /// it via `removeUdpFlow` deallocates the session and the
    /// `ctx`/writer/closure graph it owns.
    ///
    /// Returns the COMBINED (TCP + UDP) live flow count after insertion so the
    /// caller can drive the flow-pressure backstop on UDP admission too: the
    /// kernel nexus ceiling is global across the flowswitch, so a UDP burst can
    /// approach it just as a TCP burst can. (The reap evicts idle TCP flows;
    /// UDP self-bounds via `defaultUdpIdleTimeoutMs`.)
    @discardableResult
    func registerUdpFlow(
        _ flowId: ObjectIdentifier,
        anchor: UdpFlowSessionAnchor,
        appId: String = "pid:unknown",
        engineGeneration: UInt64? = nil
    ) -> Int? {
        switch prepareUdpFlowRegistration(
            flowId,
            anchor: anchor,
            appId: appId,
            engineGeneration: engineGeneration)
        {
        case .started(let occupancy, let pendingServerClose):
            if pendingServerClose {
                if let terminate = anchor.ctx.terminate {
                    terminate(nil)
                } else {
                    removeUdpFlow(flowId, engineGeneration: engineGeneration)
                }
            }
            return occupancy
        case .unavailable, .capacityRefused: return nil
        }
    }

    private func prepareUdpFlowRegistration(
        _ flowId: ObjectIdentifier,
        anchor: UdpFlowSessionAnchor,
        appId: String,
        engineGeneration: UInt64?
    ) -> UdpFlowRegistrationPlan {
        let result: (
            plan: UdpFlowRegistrationPlan,
            wakePressureReaper: Bool,
            flowPressurePolicy: FlowPressurePolicy
        ) = stateQueue.sync {
            let pressurePolicy = self.flowPressurePolicyLocked()
            if let engineGeneration {
                guard self.acceptingFlows,
                    engineGeneration == self.engineGeneration
                else {
                    anchor.ctx.registrationGate.abandon()
                    return (
                        plan: .unavailable,
                        wakePressureReaper: false,
                        flowPressurePolicy: pressurePolicy)
                }
            }
            let registered = self.tcpSessions.count + self.udpSessions.count
            let projected = self.liveResourceOccupancyLocked(registered: registered)
            let hardCap = Int(pressurePolicy.liveHardCap)
            if hardCap > 0, projected >= hardCap {
                self.overload.shedLiveCapUdpSinceTick += 1
                let reason =
                    "combined live-flow hard cap reached projected=\(projected) hardCap=\(hardCap) protocol=udp"
                guard case .reject(_, _, let persist) = self.recordShedLocked(
                    reason: reason, appId: appId)
                else { preconditionFailure("shed recorder must reject") }
                anchor.ctx.registrationGate.abandon()
                return (
                    plan: .capacityRefused(reason: reason, persist: persist),
                    wakePressureReaper:
                        self.shouldWakePressureReaperAfterLiveCapRefusalLocked(
                            registered: registered),
                    flowPressurePolicy: pressurePolicy)
            }

            // `stateQueue -> registrationGate -> pressureVictimState` is the
            // sole publication order. A Rust close that sees `.claimed`
            // therefore cannot announce removal before both registry mirrors
            // exist. Conversely, a close already recorded while `.pending`
            // is published as leaving in this same transaction, retaining its
            // anchor for graceful drain without creating pressure overshoot.
            guard let claim = anchor.ctx.registrationGate.claim(
                publishing: { pendingServerClose in
                    self.udpSessions[flowId] = anchor
                    self.hardCapNoHeadroomLogged = false
                    self.pressureVictimState.withLock {
                        $0.registeredFlowIds.insert(flowId)
                    }
                    let occupancy = self.tcpSessions.count + self.udpSessions.count
                    if pendingServerClose {
                        _ = self.announcePressureRemoval(
                            flowId: flowId,
                            contextId: nil,
                            engineGeneration: engineGeneration,
                            mayCancelSelectedVictim: false)
                    }
                    return occupancy
                })
            else {
                return (
                    plan: .unavailable,
                    wakePressureReaper: false,
                    flowPressurePolicy: pressurePolicy)
            }
            return (
                plan: .started(
                    occupancy: claim.value,
                    pendingServerClose: claim.pendingServerClose),
                wakePressureReaper: false,
                flowPressurePolicy: pressurePolicy)
        }
        // A refused flow never reaches the post-registration pressure trigger.
        // Wake the trigger-driven reaper after leaving `stateQueue` so a TCP
        // flow that became idle while the live cap was closed can release a
        // slot. The reaper's outstanding-slot and suppression gates keep a
        // refusal storm bounded.
        if result.wakePressureReaper {
            reapIdleUnderPressure(
                flowPressurePolicy: result.flowPressurePolicy,
                hardCapReplacement: true,
                engineGeneration: engineGeneration)
        }
        return result.plan
    }

    /// UDP counterpart of `registerTcpFlowAndScheduleStartup`.
    func registerUdpFlowAndScheduleStartupDecision(
        _ flowId: ObjectIdentifier,
        anchor: UdpFlowSessionAnchor,
        appId: String,
        engineGeneration: UInt64,
        runtimePolicy: TransparentProxyRuntimePolicy? = nil,
        on flowQueue: DispatchQueue,
        body: @escaping @Sendable () -> Void,
        pendingServerClose: (@Sendable () -> Void)? = nil
    ) -> UdpFlowRegistrationDecision {
        let pressurePolicy =
            (runtimePolicy ?? TransparentProxyRuntimePolicy.testDefaultsSnapshot).flowPressure
        lifecycleLock.lock()
        let registration = prepareUdpFlowRegistration(
            flowId,
            anchor: anchor,
            appId: appId,
            engineGeneration: engineGeneration)
        guard case .started(let occupancy, let closePending) = registration else {
            lifecycleLock.unlock()
            return registration.decision
        }
        flowLifecycleGroup.enter()
        lifecycleLock.unlock()
        defer { flowLifecycleGroup.leave() }
        flowQueue.sync {
            if closePending {
                if let pendingServerClose {
                    pendingServerClose()
                } else if let terminate = anchor.ctx.terminate {
                    terminate(nil)
                } else {
                    self.removeUdpFlow(flowId, engineGeneration: engineGeneration)
                }
            } else {
                body()
            }
            // A Rust max-lifetime callback can close the session before Swift
            // finishes startup, and defensive/test teardown can still mark a
            // context closed independently of the ownership gate. Reconcile
            // after insertion, on the flow's queue, and use the admitting
            // generation so stale cleanup cannot touch a newly attached
            // engine's registry.
            if anchor.ctx.readState == .closed,
                !anchor.ctx.defersRegistryRemovalForGracefulDrain
            {
                self.removeUdpFlow(flowId, engineGeneration: engineGeneration)
            }
        }
        if pressurePolicy.softCap > 0,
            occupancy >= Int(pressurePolicy.softCap)
        {
            reapIdleUnderPressure(flowPressurePolicy: pressurePolicy)
        }
        return .started(occupancy: occupancy)
    }

    /// Compatibility-shaped test/helper entry point. Production uses the rich
    /// decision above so it can apply fail-open/fail-closed at the hard cap.
    func registerUdpFlowAndScheduleStartup(
        _ flowId: ObjectIdentifier,
        anchor: UdpFlowSessionAnchor,
        engineGeneration: UInt64,
        on flowQueue: DispatchQueue,
        body: @escaping @Sendable () -> Void
    ) -> Bool {
        if case .started = registerUdpFlowAndScheduleStartupDecision(
            flowId,
            anchor: anchor,
            appId: "pid:unknown",
            engineGeneration: engineGeneration,
            on: flowQueue,
            body: body)
        {
            return true
        }
        return false
    }

    func removeTcpFlow(
        _ flowId: ObjectIdentifier,
        context: TcpFlowContext? = nil,
        engineGeneration: UInt64? = nil
    ) {
        // `.async`, not `.sync`: this is called from per-flow teardown
        // running on the flow's own `flowQueue`. A synchronous hop here
        // blocks that flowQueue thread on the shared serial `stateQueue`;
        // under high concurrent churn many flowQueue threads block at once,
        // exhausting the GCD pool and starving OTHER flows' timers (the 5s
        // drain backstop) and data-path work — which is what pushed wedged
        // flows out to the 60s watchdog (60–130s stuck). Fire-and-forget is
        // safe: removal is the terminal step (the teardown's `done` flag is
        // already set), it returns nothing, and the mutation still
        // serializes on `stateQueue`, so the watchdog/reconcile see
        // consistent state. The map's strong ref also keeps the ctx alive
        // until the async lands, which only HELPS the ObjectIdentifier-reuse
        // guard below.
        _ = announcePressureRemoval(
            flowId: flowId,
            contextId: context.map(ObjectIdentifier.init),
            engineGeneration: engineGeneration)
        stateQueue.async {
            if let engineGeneration, engineGeneration != self.engineGeneration {
                return
            }
            self.drainPressureVictimOutcomesLocked()
            let removedAnchor = self.tcpSessions.removeValue(forKey: flowId)
            let reservation = self.pressureVictimState.withLock { state in
                state.removePendingRemoval(for: flowId)
                state.endRegisteredRetirementOverlap(for: flowId)
                return removedAnchor.map {
                    state.removeReservation(for: ObjectIdentifier($0.ctx))
                } ?? nil
            }
            let resolvedPressureReservation = reservation != nil
            if removedAnchor != nil {
                switch reservation?.phase {
                case .selected:
                    self.pressureCanceledTotal += 1
                    if reservation?.goal == .lowWater {
                        self.pressureEpisode?.canceled += 1
                    }
                case .committed, .spareAwaitingAccounting, .canceled, .expired, .none:
                    break
                }
            }
            if let appId = self.overload.flowApps.removeValue(forKey: flowId),
                let count = self.overload.perAppFlowCounts[appId]
            {
                if count <= 1 {
                    self.overload.perAppFlowCounts.removeValue(forKey: appId)
                } else {
                    self.overload.perAppFlowCounts[appId] = count - 1
                }
            }
            // Admissions can land while this batch's reservations count as
            // future relief. Re-evaluate once at the batch boundary, not once
            // per removal, so those hidden admissions are covered without
            // turning normal churn into a registry sort per callback.
            // Belt-and-suspenders against `ObjectIdentifier` reuse:
            // if a torn-down flow's pointer is recycled for a new ctx
            // within one maintenance tick, the new ctx would inherit
            // the old's "stuck" status and be kicked on its very
            // first observation. Removing here keeps the watchdog's
            // tracking set in lockstep with the registry.
            self.stuckPreReadyFlowIds.remove(flowId)
            self.stuckClosingFlowIds.remove(flowId)
            self.pendingPressureProtectedFlowIds.remove(flowId)
            self.activePressureProtectedFlowIds.remove(flowId)
            self.reschedulePressureRecheckLocked()
            self.settlePressureVictimBatchLocked(
                reevaluateAboveSoftCap: resolvedPressureReservation)
        }
    }

    // MARK: - TCP overload admission

    func admitTcpStart(
        flowId: ObjectIdentifier,
        meta: RamaTransparentProxyFlowMetaBridge,
        engineGeneration: UInt64? = nil
    ) -> TcpAdmissionDecision? {
        let result: (
            decision: TcpAdmissionDecision?,
            wakePressureReaper: Bool,
            flowPressurePolicy: FlowPressurePolicy
        ) = stateQueue.sync {
            let pressurePolicy = self.flowPressurePolicyLocked()
            let admissionPolicy = self.tcpStartAdmissionPolicyLocked()
            if let engineGeneration {
                guard self.acceptingFlows,
                    engineGeneration == self.engineGeneration
                else {
                    return (
                        decision: nil,
                        wakePressureReaper: false,
                        flowPressurePolicy: pressurePolicy)
                }
            }
            let appId = self.overload.appId(for: meta)
            let liveHardCap = Int(pressurePolicy.liveHardCap)
            let registered = self.tcpSessions.count + self.udpSessions.count
            let projectedLive = self.liveResourceOccupancyLocked(registered: registered)
            if liveHardCap > 0, projectedLive >= liveHardCap {
                self.overload.shedLiveCapTcpSinceTick += 1
                let reason =
                    "combined live-flow hard cap reached projected=\(projectedLive) "
                    + "hardCap=\(liveHardCap) protocol=tcp"
                return (
                    decision: self.recordShedLocked(reason: reason, appId: appId),
                    wakePressureReaper:
                        self.shouldWakePressureReaperAfterLiveCapRefusalLocked(
                            registered: registered),
                    flowPressurePolicy: pressurePolicy)
            }
            let hardCap = Int(admissionPolicy.hardCap)
            let softCap = Int(admissionPolicy.softCap)
            let inFlight = self.overload.startsInFlight.count
            // Evaluate on admission too, not only on completion, and BEFORE
            // the hard-cap branch: the latency window may already be bad
            // from completions that happened under the soft cap, and the
            // admission that brings pressure is the one that should open
            // the breaker — not the next completion, and not never, when
            // pinned at the hard cap.
            if !self.overload.breakerOpen, softCap > 0, inFlight >= softCap {
                self.updateTcpAdmissionBreakerLocked(trigger: "admission")
            }
            if hardCap > 0, inFlight >= hardCap {
                self.overload.shedHardCapSinceTick += 1
                return (
                    decision: self.recordShedLocked(
                        reason: "hard start cap reached inFlight=\(inFlight) hardCap=\(hardCap)",
                        appId: appId),
                    wakePressureReaper: false,
                    flowPressurePolicy: pressurePolicy)
            }
            if self.overload.breakerOpen, softCap > 0, inFlight >= softCap {
                self.overload.shedBreakerSinceTick += 1
                return (
                    decision: self.recordShedLocked(
                        reason: "latency breaker open inFlight=\(inFlight) softCap=\(softCap)",
                        appId: appId),
                    wakePressureReaper: false,
                    flowPressurePolicy: pressurePolicy)
            }
            precondition(
                self.nextTcpAdmissionNonce < .max,
                "tcp-admission nonce space exhausted")
            self.nextTcpAdmissionNonce += 1
            let token = TcpAdmissionToken(
                identity: TcpAdmissionIdentity(
                    engineGeneration: self.engineGeneration,
                    nonce: self.nextTcpAdmissionNonce),
                flowId: flowId,
                startedAt: .now(),
                appId: appId)
            self.overload.startsInFlight[flowId] = token
            self.overload.liveFlowReservations[flowId] = token.identity
            self.overload.admissionsSinceTick += 1
            self.overload.startsInFlightPeakSinceTick = max(
                self.overload.startsInFlightPeakSinceTick, self.overload.startsInFlight.count)
            return (
                decision: .admit(token),
                wakePressureReaper: false,
                flowPressurePolicy: pressurePolicy)
        }
        // The live-cap branch cannot rely on the ordinary post-registration
        // trigger because this flow was not registered. Run the wake outside
        // `stateQueue`; start-cap and latency-breaker refusals do not represent
        // live-flow pressure and deliberately do not trigger it.
        if result.wakePressureReaper {
            #if DEBUG || RAMA_TESTING
                beforeTcpHardCapReplacementPublish.withLock { $0 }?()
            #endif
            reapIdleUnderPressure(
                flowPressurePolicy: result.flowPressurePolicy,
                hardCapReplacement: true,
                engineGeneration: engineGeneration)
        }
        return result.decision
    }

    /// Count a refusal and decide whether its per-flow line may be
    /// persisted (first `persistedShedLinesPerTick` per window). MUST be
    /// called on `stateQueue`.
    private func recordShedLocked(reason: String, appId: String) -> TcpAdmissionDecision {
        self.overload.shedsSinceTick += 1
        self.overload.shedsByAppSinceTick[appId, default: 0] += 1
        let persist = self.overload.shedsSinceTick <= TcpOverloadState.persistedShedLinesPerTick
        return .reject(reason: reason, appId: appId, persist: persist)
    }

    func finishTcpStart(_ token: TcpAdmissionToken, outcome: TcpStartOutcome) {
        // Capture completion on the caller's queue. `stateQueue` serializes
        // accounting, but time spent waiting behind unrelated state work is
        // not connect/start latency and must not feed the overload breaker.
        let completedAtNs = DispatchTime.now().uptimeNanoseconds
        finishTcpStart(token, outcome: outcome, completedAtNs: completedAtNs)
    }

    private func finishTcpStart(
        _ token: TcpAdmissionToken,
        outcome: TcpStartOutcome,
        completedAtNs: UInt64
    ) {
        stateQueue.async {
            guard
                self.overload.startsInFlight[token.flowId]?.identity == token.identity
            else {
                return
            }
            self.overload.startsInFlight.removeValue(forKey: token.flowId)
            let releasedLiveReservation: Bool
            if self.overload.liveFlowReservations[token.flowId] == token.identity {
                self.overload.liveFlowReservations.removeValue(forKey: token.flowId)
                releasedLiveReservation = true
            } else {
                releasedLiveReservation = false
            }
            if releasedLiveReservation {
                self.hardCapNoHeadroomLogged = false
                let canceled = self.pressureVictimState.withLock {
                    $0.cancelHardCapReplacementSelected()
                }
                if canceled {
                    self.drainPressureVictimOutcomesLocked()
                    self.reschedulePressureRecheckLocked()
                }
            }
            // Use the caller's matching admission token and the completion
            // instant captured before this work was enqueued.
            let latencyMs =
                (completedAtNs &- token.startedAt.uptimeNanoseconds)
                / 1_000_000
            self.overload.insertLatency(latencyMs)
            if outcome == .timeout {
                self.overload.timeoutsSinceTick += 1
            }
            self.updateTcpAdmissionBreakerLocked(trigger: "completion")
        }
    }

    func tcpConnectTimeoutMs(
        base: UInt32,
        engineGeneration: UInt64? = nil
    ) -> UInt32 {
        stateQueue.sync {
            if let engineGeneration {
                guard acceptingFlows, engineGeneration == self.engineGeneration else {
                    return base
                }
            }
            let admissionPolicy = self.tcpStartAdmissionPolicyLocked()
            let inFlight = self.overload.startsInFlight.count
            let softCap = Int(admissionPolicy.softCap)
            if self.overload.breakerOpen, admissionPolicy.breakerConnectTimeoutMs > 0 {
                return min(base, admissionPolicy.breakerConnectTimeoutMs)
            }
            if softCap > 0, inFlight >= softCap,
                admissionPolicy.pressureConnectTimeoutMs > 0
            {
                return min(base, admissionPolicy.pressureConnectTimeoutMs)
            }
            return base
        }
    }

    /// Runs on start completion, on admission at/over the soft cap, and on
    /// the maintenance tick. Both inputs — the completed-latency window and
    /// the in-flight count — change only on admission or completion, so the
    /// tick is a backstop for the case where the last evaluation saw one
    /// condition but not the other and nothing has arrived since.
    private func updateTcpAdmissionBreakerLocked(trigger: String) {
        let admissionPolicy = tcpStartAdmissionPolicyLocked()
        let inFlight = self.overload.startsInFlight.count
        let softCap = Int(admissionPolicy.softCap)
        let openThreshold = UInt64(admissionPolicy.breakerOpenP95Ms)
        let closeThreshold = UInt64(admissionPolicy.breakerCloseP95Ms)
        guard softCap > 0, openThreshold > 0 else { return }
        let p95 = self.overload.percentile(0.95)
        if !self.overload.breakerOpen, inFlight >= softCap, p95 >= openThreshold {
            self.overload.breakerOpen = true
            self.logLifecycle(
                "tcp overload breaker open (on \(trigger)): p95StartMs=\(p95) "
                    + "inFlight=\(inFlight) softCap=\(softCap) openP95Ms=\(openThreshold)")
        } else if self.overload.breakerOpen, inFlight < softCap, p95 <= closeThreshold {
            self.overload.breakerOpen = false
            self.logLifecycle(
                "tcp overload breaker closed (on \(trigger)): p95StartMs=\(p95) "
                    + "inFlight=\(inFlight) softCap=\(softCap) closeP95Ms=\(closeThreshold)")
        }
    }

    func removeUdpFlow(
        _ flowId: ObjectIdentifier,
        engineGeneration: UInt64? = nil
    ) {
        // `.async` for the same reason as `removeTcpFlow` — never block a
        // per-flow teardown on the shared serial queue.
        _ = announcePressureRemoval(
            flowId: flowId,
            contextId: nil,
            engineGeneration: engineGeneration)
        stateQueue.async {
            if let engineGeneration, engineGeneration != self.engineGeneration {
                return
            }
            self.drainPressureVictimOutcomesLocked()
            self.pressureVictimState.withLock {
                $0.removePendingRemoval(for: flowId)
            }
            self.udpSessions.removeValue(forKey: flowId)
            self.reschedulePressureRecheckLocked()
            self.settlePressureVictimBatchLocked()
        }
    }

    /// Announce capacity that is already committed to leave before the
    /// asynchronous registry mutation reaches `stateQueue`. If this is a
    /// natural removal, retire one newest queued selection under the same lock
    /// its flow queue must acquire to commit. Whichever event wins the lock is
    /// the linearization point; a removal announced first cannot be followed by
    /// an avoidable pressure eviction that drives occupancy below low-water.
    private func announcePressureRemoval(
        flowId: ObjectIdentifier,
        contextId: ObjectIdentifier?,
        engineGeneration: UInt64?,
        mayCancelSelectedVictim: Bool = true
    ) -> Bool {
        pressureVictimState.withLock {
            $0.announceRemoval(
                flowId: flowId,
                contextId: contextId,
                engineGeneration: engineGeneration,
                mayCancelSelectedVictim: mayCancelSelectedVictim).canceled
        }
    }

    /// Keep an established pressure episode moving after a victim outcome
    /// removes projected-capacity credit without removing a flow. Registry
    /// removal calls this only after resolving the final active reservation in
    /// a batch: its occupancy decrement replaces that credit, while one
    /// batch-boundary scan accounts for enough admissions hidden by the batch
    /// to leave occupancy at or above the cap. Do not chase arrivals below the
    /// cap one by one; the next threshold crossing starts a fresh batch.
    /// MUST run on `stateQueue`.
    private enum PressureContinuation {
        case newEpisode
        case aboveSoftCap
        case towardLowWater
        case hardCapReplacement
    }

    /// Complete a reservation batch before ending its episode. A spare or
    /// expiry consumes promised relief without removing occupancy, so exactly
    /// one replacement scan repairs the whole settled batch. Terminal
    /// tombstones retain the debt until their queued closures acknowledge.
    private func settlePressureVictimBatchLocked(
        nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds,
        reevaluateAboveSoftCap: Bool = false
    ) {
        let activeReservations = pressureVictimState.withLock {
            $0.unresolvedReservationCount
        }
        guard activeReservations == 0 else { return }

        var victims: [PressureVictim] = []
        switch pressureRepairState {
        case .scanWhenBatchSettles:
            victims = collectPressureVictimsIfDueLocked(
                nowNs: nowNs,
                continuation: .towardLowWater)
            let state = pressureVictimState.withLock {
                (credit: $0.victimCreditCount + $0.naturalReliefCount,
                 terminalTombstones:
                    $0.reservations.count - $0.unresolvedReservationCount)
            }
            let occupancy = tcpSessions.count + udpSessions.count
            let projected = max(occupancy - state.credit, 0)
            if projected <= Int(Self.pressureLowWater(flowPressurePolicyLocked())) {
                pressureRepairState = .idle
            } else if state.terminalTombstones > 0 {
                pressureRepairState = .waitingForTombstoneAck
            } else {
                pressureRepairState = .idle
            }
        case .waitingForTombstoneAck:
            let state = pressureVictimState.withLock {
                (credit: $0.victimCreditCount + $0.naturalReliefCount,
                 terminalTombstones:
                    $0.reservations.count - $0.unresolvedReservationCount)
            }
            let occupancy = tcpSessions.count + udpSessions.count
            let projected = max(occupancy - state.credit, 0)
            if projected <= Int(Self.pressureLowWater(flowPressurePolicyLocked()))
                || state.terminalTombstones == 0
            {
                pressureRepairState = .idle
            }
        case .idle:
            if reevaluateAboveSoftCap {
                victims = collectPressureVictimsIfDueLocked(
                    nowNs: nowNs,
                    continuation: .aboveSoftCap)
            }
        }
        firePressureEvictions(victims)
        clearPressureProtectionsIfIdleLocked(nowNs: nowNs)
        endPressureEpisodeIfAtLowWaterLocked()
    }

    /// MUST be called on `stateQueue` after a registry removal or terminal
    /// victim outcome. Keep the episode and its suppression alive throughout
    /// the entire hysteresis band: ending at `softCap - 1` lets hostile churn
    /// alternate across the cap and force an O(n log n) scan on every arrival.
    /// Reaching normalized low-water proves the burst has actually settled.
    private func endPressureEpisodeIfAtLowWaterLocked() {
        let pressurePolicy = flowPressurePolicyLocked()
        let softCap = Int(pressurePolicy.softCap)
        guard softCap > 0 else { return }
        let lowWater = Int(Self.pressureLowWater(pressurePolicy))
        guard self.tcpSessions.count + self.udpSessions.count <= lowWater else {
            return
        }
        guard pressureRepairState == .idle else { return }
        let unresolved = pressureVictimState.withLock { state in
            !state.pendingRemovalFlowIds.isEmpty
                || state.unresolvedReservationCount > 0
        }
        guard !unresolved else { return }
        drainPressureVictimOutcomesLocked()
        pressureNoHeadroomLogged = false
        pressureRescanSuppressedUntilNs = 0
        cancelPressureProtectionRetryLocked()
        pendingPressureProtectedFlowIds.removeAll(keepingCapacity: true)
        activePressureProtectedFlowIds.removeAll(keepingCapacity: true)
        reschedulePressureRecheckLocked()
        if let episode = pressureEpisode {
            pressureEpisode = nil
            logPressureEpisodeLocked(episode, outcome: "ended")
        }
    }

    private func logPressureEpisodeLocked(
        _ episode: PressureEpisode,
        outcome: String
    ) {
        let durationMs = Self.elapsedMs(
            nowNs: DispatchTime.now().uptimeNanoseconds,
            sinceNs: episode.startNs)
        let startEpochMs = episode.startEpochUs / 1_000
        logLifecycle(
            "flow pressure episode \(outcome): startEpochMs=\(startEpochMs) "
                + "durationMs=\(durationMs) "
                + "peakOccupancy=\(episode.peakOccupancy) "
                + "softCap=\(episode.softCap) "
                + "scans=\(episode.scans) skipped=\(episode.skips) "
                + "selected=\(episode.selections) evicted=\(episode.evicted) "
                + "spared=\(episode.spared) canceled=\(episode.canceled) "
                + "expired=\(episode.expired) "
                + "startEpochUs=\(episode.startEpochUs)")
    }

    /// Count of currently-registered TCP flows. Test-only signal for
    /// leak / churn assertions.
    var tcpFlowCount: Int {
        stateQueue.sync { self.tcpSessions.count }
    }

    /// Count of currently-registered UDP flows. Test-only signal.
    var udpFlowCount: Int {
        stateQueue.sync { self.udpSessions.count }
    }

    #if DEBUG || RAMA_TESTING
        /// Test-only accessor for the writer pump bound to a flow.
        /// Returns `nil` if the flow is not registered (or never
        /// had a writer attached). Used by per-flow unit tests
        /// that need to inspect the Debug-only endpoint-pairing
        /// observation seam. Gated on `#if DEBUG` so Release builds carry no
        /// test-only surface or read-loop fallback-cache mutation.
        func testInspectUdpWriter(for flow: AnyObject) -> UdpClientWritePump? {
            stateQueue.sync { self.udpSessions[ObjectIdentifier(flow)]?.ctx.writer }
        }

        func testInspectUdpFlowQueue(for flow: AnyObject) -> DispatchQueue? {
            stateQueue.sync { self.udpSessions[ObjectIdentifier(flow)]?.ctx.flowQueue }
        }

        func testInspectUdpFlowReadState(for flow: AnyObject) -> UdpFlowReadState? {
            guard
                let ctx = stateQueue.sync(execute: {
                    self.udpSessions[ObjectIdentifier(flow)]?.ctx
                }),
                let flowQueue = ctx.flowQueue
            else { return nil }
            return flowQueue.sync { ctx.readState }
        }

        /// Test-only accessor for the per-flow TCP context. Used by
        /// the promote-cutover integration tests to drive
        /// `beginPromoteCutover` directly + inspect the resulting
        /// state (mode transition, forwarder presence). Same
        /// gating rationale as the UDP accessor above.
        func testInspectTcpContext(for flow: AnyObject) -> TcpFlowContext? {
            stateQueue.sync { self.tcpSessions[ObjectIdentifier(flow)]?.ctx }
        }

        /// Insert a TCP context into the registry directly, without
        /// going through `registerTcpFlow` (which requires a real
        /// `RamaTcpSessionHandle`). Wraps the bare ctx in a stub anchor so
        /// the registry's invariant (one anchor per flow) holds. Lets tests
        /// drive engine-less scenarios like the `detachEngine` / wake walks.
        func testInsertTcpContext(_ flowId: ObjectIdentifier, _ ctx: TcpFlowContext) {
            stateQueue.sync {
                self.tcpSessions[flowId] = _TestTcpFlowSessionAnchor(ctx: ctx)
                self.pressureVictimState.withLock {
                    $0.registeredFlowIds.insert(flowId)
                }
            }
        }

        func testAdmitTcpStart(
            flowId: ObjectIdentifier, meta: RamaTransparentProxyFlowMetaBridge
        ) -> TcpAdmissionDecision {
            admitTcpStart(flowId: flowId, meta: meta)!
        }

        func testFinishTcpStart(_ token: TcpAdmissionToken, outcome: TcpStartOutcome) {
            finishTcpStart(token, outcome: outcome)
        }

        func testFinishTcpStart(
            _ token: TcpAdmissionToken,
            outcome: TcpStartOutcome,
            latencyMs: UInt64
        ) {
            finishTcpStart(
                token,
                outcome: outcome,
                completedAtNs: token.startedAt.uptimeNanoseconds
                    &+ (latencyMs &* 1_000_000))
        }

        /// Insert a completed-start latency without consulting wall clock.
        /// Breaker tests use this to describe an exact latency distribution;
        /// production samples still enter only through `finishTcpStart`.
        func testInsertTcpStartLatencyMs(_ latencyMs: UInt64) {
            stateQueue.sync {
                self.overload.insertLatency(latencyMs)
                self.updateTcpAdmissionBreakerLocked(trigger: "test completion")
            }
        }

        var testRetiringResourceCount: Int { retiringResourceCount }

        var testRegisteredRetirementOverlapCount: Int {
            pressureVictimState.withLock { $0.registeredRetirementOverlapCount }
        }

        var testLiveResourceOccupancy: Int {
            stateQueue.sync {
                self.liveResourceOccupancyLocked(
                    registered: self.tcpSessions.count + self.udpSessions.count)
            }
        }

        var testTcpStartsInFlight: Int {
            stateQueue.sync { self.overload.startsInFlight.count }
        }

        var testTcpLiveFlowReservations: Int {
            stateQueue.sync { self.overload.liveFlowReservations.count }
        }

        var testTcpStartLatencySampleCount: Int {
            stateQueue.sync { self.overload.startLatencyMsWindow.count }
        }

        func testTcpStartLatencyPercentile(_ percentile: Double) -> UInt64 {
            stateQueue.sync { self.overload.percentile(percentile) }
        }

        var testTcpTimeoutsSinceTick: Int {
            stateQueue.sync { self.overload.timeoutsSinceTick }
        }

        var testTcpOverloadBreakerOpen: Bool {
            stateQueue.sync { self.overload.breakerOpen }
        }

        func testTcpConnectTimeoutMs(base: UInt32) -> UInt32 {
            tcpConnectTimeoutMs(base: base)
        }

        /// Symmetric for UDP. Wraps the bare ctx in a stub
        /// `UdpFlowSessionAnchor` so the production map's
        /// invariant (one anchor per registered flow) holds. The
        /// stub captures the ctx as the live session would, so
        /// `handleSystemSleep` reaches the same `ctx.terminate`
        /// path.
        func testInsertUdpContext(_ flowId: ObjectIdentifier, _ ctx: UdpFlowContext) {
            stateQueue.sync {
                self.udpSessions[flowId] = _TestUdpFlowSessionAnchor(ctx: ctx)
                self.pressureVictimState.withLock {
                    $0.registeredFlowIds.insert(flowId)
                }
            }
        }
    #endif

    // MARK: - Logging helpers

    func logTrace(_ message: String) {
        RamaLog.trace(message)
    }

    func logDebug(_ message: String) {
        RamaLog.debug(message)
    }

    func logDebug(_ publicMessage: String, privateMetadata: String) {
        RamaLog.debug(publicMessage, privateMetadata: privateMetadata)
    }

    func logInfo(_ message: String) {
        RamaLog.info(message)
    }

    func logError(_ message: String) {
        RamaLog.error(message)
    }

    /// Emit a lifecycle / critical event.
    ///
    /// Routed through `LifecycleLog`, a dedicated `os.Logger` sink that
    /// emits at `OS_LOG_TYPE_DEFAULT` so the message is always present
    /// in `log show` for post-incident debugging.
    func logLifecycle(_ message: String) {
        LifecycleLog.notice(message)
    }

    func logLifecycle(_ message: String, privateMetadata: String) {
        LifecycleLog.notice(message, privateMetadata: privateMetadata)
    }

    /// Lifecycle-error counterpart of [`logLifecycle`].
    func logLifecycleError(_ message: String) {
        LifecycleLog.error(message)
    }

    func logFlowMessage(_ message: FlowLogMessage) {
        if let publicText = message.publicText {
            switch message.level {
            case .trace: RamaLog.tracePublic(publicText)
            case .debug: RamaLog.debugPublic(publicText)
            case .info: LifecycleLog.notice(publicText)
            case .error: RamaLog.errorPublic(publicText)
            }
        }
        switch message.level {
        case .trace: logTrace(message.text)
        case .debug: logDebug(message.text)
        case .info: RamaLog.info(message.text)
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
        // A Rust close callback is one-shot. If either writer direction has
        // already entered its terminal drain, promoting now would create a
        // forwarder whose matching `markRust*Done` edge can never be replayed.
        // Keep the flow on the in-Rust path so the remaining close callback
        // can finish the existing two-sided drain.
        guard !ctx.terminalSignalled, !ctx.drainClosePending else {
            logDebug("promote: flow already closing; confirming failed")
            ctx.session?.confirmPromoted(
                .failed, reason: "flow already closing")
            return
        }
        // Note `clientReadPump`: installed by `armReadTerminal`, which
        // runs inside the `flow.open` completion callback. Its
        // presence is the canonical "kernel flow is open" signal —
        // the forwarder we build below issues `flow.readData` and
        // expects the kernel side to honor it. Promoting before
        // flow.open completes (only possible since we moved
        // `armPromoteCallback` ahead of `session.activate` to fix
        // the registration race) would start the forwarder on an
        // unopened flow; refuse cleanly and let the service fall
        // back to the in-Rust path.
        guard let session = ctx.session,
            let connection = ctx.connection,
            let clientWritePump = ctx.clientWritePump,
            let egressWritePump = ctx.egressWritePump,
            ctx.clientReadPump != nil
        else {
            logDebug(
                "promote: flow not in a promotable state (missing session/connection/pumps or flow.open not yet complete); confirming failed"
            )
            ctx.session?.confirmPromoted(
                .failed, reason: "egress not ready")
            return
        }

        ctx.mode = .promoted
        // Start the promoted-idle reaper clock at cutover, not context
        // creation — a flow may have spent time on the `viaRust` path first,
        // and only now loses the engine's in-Rust idle backstop.
        ctx.lastActivityAt = .now()
        logTrace("promote: cutover begin")

        let forwarder = makePromotedForwarder(
            ctx: ctx,
            flow: flow,
            connection: connection,
            clientWritePump: clientWritePump,
            egressWritePump: egressWritePump,
            flowQueue: flowQueue
        )

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
        ctx.clientReadPump?.cancelForPromoteWithReservations(
            onCarryover: { [weak forwarder] payload in
                forwarder?.acceptClientCarryoverCursor(payload)
            },
            onError: { [weak forwarder] error in
                forwarder?.acceptClientCarryoverError(error)
            },
            onComplete: { [weak forwarder] in
                forwarder?.markClientReadDrained()
            })
        ctx.egressReadPump?.cancelForPromoteWithReservations(
            onCarryover: { [weak forwarder] payload in
                forwarder?.acceptEgressCarryoverCursor(payload)
            },
            onError: { [weak forwarder] error in
                forwarder?.acceptEgressCarryoverError(error)
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

    /// Build the direct kernel↔egress forwarder for the `viaRust`→promote
    /// cutover. Wires the lifecycle callbacks onto `ctx` and stores it as
    /// `ctx.directForwarder`. The caller drives the cutover sequencing
    /// (read-pump carryover, then the Rust-done/read-drained signals).
    func makePromotedForwarder<F: TcpFlowLike>(
        ctx: TcpFlowContext,
        flow: F,
        connection: any NwConnectionLike,
        clientWritePump: TcpClientWritePump,
        egressWritePump: NwTcpConnectionWritePump,
        flowQueue: DispatchQueue
    ) -> TcpDirectForwarder {
        let forwarder = TcpDirectForwarder(
            flow: flow,
            connection: connection,
            clientWritePump: clientWritePump,
            egressWritePump: egressWritePump,
            writerMemoryBudget: clientWritePump.aggregateBudget,
            queue: flowQueue,
            logger: { [weak self] message in self?.logFlowMessage(message) },
            drainStallDeadline: .milliseconds(Int(ctx.lingerCloseMs)),
            drainIdleMs: { [weak ctx] in ctx?.idleMs() ?? .max },
            // Mark the ctx so the on-`stateQueue` maintenance watchdog can also
            // reap this promoted flow if `flowQueue` later starves — the same
            // `terminalSignalled` net the `viaRust` close path arms.
            onClosing: { [weak ctx] in ctx?.terminalSignalled = true },
            onDrainPendingChanged: { [weak ctx] pending in
                ctx?.drainClosePending = pending
            },
            // A finishing direction's drain wedged (peer stopped reading):
            // route through the shared full-teardown reaper. Idempotent via
            // the sticky `isDone`.
            onDrainStall: { [weak ctx] in ctx?.applyDrainBackstop() },
            onReadError: { [weak ctx] error in
                ctx?.applyReadHardError(error)
            },
            // Bump the promoted-idle reaper clock on every byte moved.
            onActivity: { [weak ctx] in
                ctx?.recordActivityUnlessPressureEvicted() ?? false
            },
            writeChunkLimit: clientWritePump.maxPendingBytes,
            // The forwarder's flow type has no close surface; hand it the
            // write-half close so the client app sees server EOF.
            closeClientWrite: { [weak ctx] error in
                ctx?.closeClientWriteOnce(error)
            },
            // Both directions done. Route through the shared teardown so the
            // close marks `done` and detaches handlers — WITHOUT cancelling the
            // egress NWConnection, whose FIN/linger the egress write pump owns.
            onTerminal: { [weak ctx] in ctx?.applyPromotedTerminal() }
        )
        ctx.directForwarder = forwarder
        return forwarder
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
        handleUdpFlowDecision(flow, meta: bootMeta).callbackReturnValue
    }

    /// Rich decision form used by the provider callbacks for observability.
    /// `handleUdpFlow` remains as the Bool facade used by existing callers.
    func handleUdpFlowDecision<F: UdpFlowLike>(
        _ flow: F, meta bootMeta: RamaTransparentProxyFlowMetaBridge
    ) -> UdpFlowHandlingDecision {
        UdpFlowSession(core: self, flow: flow, meta: bootMeta).startWithDecision()
    }

}

#if DEBUG || RAMA_TESTING
    /// Stub anchor used by `testInsertUdpContext` — wraps a bare
    /// `UdpFlowContext` so the production registry's
    /// `UdpFlowSessionAnchor` invariant holds in tests that drive the
    /// `detachEngine` registry walk without spinning up a full session.
    final class _TestUdpFlowSessionAnchor: UdpFlowSessionAnchor {
        let ctx: UdpFlowContext
        init(ctx: UdpFlowContext) { self.ctx = ctx }
    }

    /// TCP counterpart of `_TestUdpFlowSessionAnchor`: wraps a bare
    /// `TcpFlowContext` so `testInsertTcpContext` can populate the
    /// session registry without a real `TcpFlowSession` / engine.
    final class _TestTcpFlowSessionAnchor: TcpFlowSessionAnchor {
        let ctx: TcpFlowContext
        init(ctx: TcpFlowContext) { self.ctx = ctx }
        func retireWriterAdmissionForEngineDetach() {}
    }
#endif
