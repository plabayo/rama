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
        // Tear down live flows BEFORE stopping the engine and clearing
        // the registry. A live TcpFlowSession is lifetime-anchored by
        // its NWConnection.stateUpdateHandler, and once the engine is
        // stopped the Rust→Swift close callbacks are suppressed — so
        // just dropping the maps would leak each egress NWConnection
        // (and its kernel NECP entry) until process exit. Each teardown
        // cancels its connection + session and removes itself from the
        // registry; the removeAll below is then a no-op safety net.
        let tcp: [TcpFlowContext] = stateQueue.sync { self.tcpSessions.values.map { $0.ctx } }
        for ctx in tcp { runFlowTeardown(ctx) { ctx.applyEngineDetached() } }
        let udp: [UdpFlowSessionAnchor] = stateQueue.sync { Array(self.udpSessions.values) }
        for session in udp { session.ctx.terminate?(engineDetachedError()) }
        self.engine?.stop(reason: reason)
        self.engine = nil
        stateQueue.sync {
            self.tcpSessions.removeAll(keepingCapacity: false)
            self.udpSessions.removeAll(keepingCapacity: false)
        }
    }

    /// Run a teardown for a registered flow on its own `flowQueue`
    /// when it has one — production contexts always do (set by
    /// `TcpFlowSession.init`), and routing there keeps the teardown
    /// single-threaded with that flow's kernel / NWConnection
    /// callbacks (the `done` flag + slots are flow-queue-confined).
    /// A context with no queue (engine-less unit-test contexts, or
    /// any that never got one) runs inline: better to tear it down
    /// than to silently skip it.
    private func runFlowTeardown(_ ctx: TcpFlowContext, _ body: @escaping () -> Void) {
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
        stopFlowCountReporting()
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
        if self.engine != nil {
            startFlowCountReporting()
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

    /// Coalesces a burst of `reapIdleUnderPressure` triggers (one fires per
    /// admission while combined occupancy is over the soft cap) into a single
    /// outstanding selection scan. Only mutated on `stateQueue`. Without it,
    /// every over-cap admission enqueues a fresh O(n log n) selection on the
    /// serial `stateQueue`, behind which the next admission's
    /// `registerTcpFlow.sync` (on the NE delivery thread) head-of-line-blocks.
    private var pressureReapInFlight = false

    /// Rate-limits the "over cap but nothing idle to reap" lifecycle log to once
    /// per pressure episode (re-armed when occupancy drops back under the cap or
    /// a reap actually fires). A sustained over-cap population — notably
    /// UDP-dominated occupancy, where the TCP-only reap can never reach
    /// low-water — would otherwise emit a persisted os_log on EVERY admission.
    /// Only mutated on `stateQueue`.
    private var pressureNoHeadroomLogged = false

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
        let timeoutMs = defaultPromotedIdleTimeoutMs
        guard timeoutMs > 0 else { return false }
        return flowIdleMs(ctx) > UInt64(timeoutMs)
    }

    /// Milliseconds since this flow last moved an app byte, on the monotonic
    /// `DispatchTime` clock (mach-uptime; pauses during sleep). Bumped by the
    /// forwarder's `onActivity` for `.promoted` flows. Same off-`flowQueue`
    /// read relaxation as `egressReady`.
    private static func flowIdleMs(_ ctx: TcpFlowContext) -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds &- ctx.lastActivityAt.uptimeNanoseconds) / 1_000_000
    }

    /// Whether a closing flow is GENUINELY drain-wedged (its graceful close
    /// stalled) — the only state the closing-stuck watchdog should force-tear-
    /// down. `terminalSignalled` alone is NOT sufficient: for a `.promoted` flow
    /// it is set (and stays set — sticky) the moment the FIRST direction enters
    /// `.finishing`, so a flow that took a clean client half-close while the
    /// OPPOSITE direction is still actively streaming a long download would
    /// otherwise be wrongly reset ~1-2 ticks later (the pre-existing STUCK-1
    /// bug).
    ///
    /// Discriminator (race-free — uses ONLY already-`flowQueue`-relaxed fields,
    /// no forwarder-phase read which would widen the off-queue read surface):
    /// wedged means closing AND no byte progress past the linger budget, in
    /// both modes. A live half-close keeps bumping `lastActivityAt` on its
    /// still-active direction and is spared; `terminalSignalled` is sticky
    /// and fires at every ordinary half-close, so it can never count as a
    /// wedge on its own. Both write pumps bump the activity clock on the
    /// flow's queue, so it is accurate in `viaRust` too.
    ///
    /// The cross-tick "stuck for ≥1 tick" set adds ~one maintenance interval of
    /// hysteresis on top, so a merely bursty-but-alive flow is never selected.
    /// Read off `flowQueue` from the maintenance tick (same relaxation as
    /// `egressReady`); re-checked on `flowQueue` before the teardown fires.
    private static func flowIsDrainWedged(_ ctx: TcpFlowContext) -> Bool {
        guard ctx.terminalSignalled else { return false }
        return flowIdleMs(ctx) > UInt64(ctx.lingerCloseMs)
    }

    /// Flow-pressure backstop. Called (async, off the delivery thread) from
    /// `TcpFlowSession.start()` OR `UdpFlowSession.start()` when admitting a flow
    /// pushed the COMBINED (tcp+udp) live count to/over
    /// `defaultFlowPressureSoftCap`. Reaps idle TCP flows past
    /// `defaultFlowPressureIdleFloorMs`, oldest-idle first (LRU), down to
    /// `defaultFlowPressureLowWater`, to free nexus slots for SUBSEQUENT flows.
    /// Coalesced via `pressureReapInFlight` so a burst is a single scan.
    ///
    /// Guarantees (see the tunable doc for the policy rationale):
    ///   * The just-admitted flow is NEVER the victim and is never delayed —
    ///     this runs after admission, asynchronously.
    ///   * Mode-agnostic (nexus pressure is global): BOTH `viaRust` and
    ///     `.promoted` flows are eligible. Both bump `lastActivityAt` on the
    ///     shared write-pump flowQueue hop, so an actively-transferring flow of
    ///     either mode is excluded by the idle-floor check and never selected.
    ///   * No activity-blind eviction: if nothing is idle past the floor we log
    ///     and do nothing (admit-and-ride) rather than reset a live connection.
    ///   * Each eviction re-checks idleness ON the victim's `flowQueue` before
    ///     firing, closing the select-then-teardown race; teardown is
    ///     idempotent via `isDone`.
    func reapIdleUnderPressure() {
        guard defaultFlowPressureSoftCap > 0 else { return }
        // Selection on `stateQueue` ASYNC — never a second `stateQueue.sync` on
        // the delivery thread that admitted the flow (admission already
        // happened; a sync here could stall all flow delivery). `fire` only
        // DISPATCHES teardowns to each victim's `flowQueue`, so nothing heavy
        // runs while on `stateQueue`.
        stateQueue.async {
            // Coalesce a burst: if a selection scan is already outstanding this
            // trigger rides it rather than enqueuing another O(n log n) scan on
            // the serial queue behind the delivery thread's register `.sync`.
            // The flag guards selection + dispatch (the stateQueue-bound work);
            // the dispatched teardowns run independently on their flowQueues, and
            // a trigger arriving after dispatch correctly runs a fresh scan that
            // re-reads occupancy.
            guard !self.pressureReapInFlight else { return }
            self.pressureReapInFlight = true
            defer { self.pressureReapInFlight = false }
            let victims = self.collectPressureVictimsLocked()
            self.firePressureEvictions(victims)
        }
    }

    /// Victim selection. MUST be called on `stateQueue`. Re-reads live occupancy
    /// (it may have changed since the triggering admission). Eligible:
    /// established (`egressReady`), not already closing (`terminalSignalled`),
    /// idle past the floor — ranked oldest-idle first (true LRU), capped at the
    /// count needed to reach low-water. MODE-AGNOSTIC: both `viaRust` and
    /// `.promoted` flows are evictable (nexus pressure is global and both carry
    /// an accurate `lastActivityAt`). Eviction is TCP-only because UDP flows
    /// self-bound via `defaultUdpIdleTimeoutMs`; a UDP-driven burst still TRIGGERS
    /// this (via `registerUdpFlow` occupancy), reaping idle TCP slots to relieve
    /// the global ceiling. Empty result = nothing to do (under cap, or no idle
    /// headroom).
    private func collectPressureVictimsLocked() -> [TcpFlowContext] {
        let softCap = defaultFlowPressureSoftCap
        guard softCap > 0 else { return [] }
        let lowWater = max(UInt64(defaultFlowPressureLowWater), 1)
        let floorMs = UInt64(defaultFlowPressureIdleFloorMs)
        let occupancy = UInt64(self.tcpSessions.count + self.udpSessions.count)
        guard occupancy >= UInt64(softCap) else {
            // Back under the cap: re-arm the no-headroom log for the next episode.
            pressureNoHeadroomLogged = false
            return []
        }
        let want = occupancy > lowWater ? Int(occupancy - lowWater) : 0
        guard want > 0 else { return [] }
        // Snapshot the LRU sort key (`lastActivityAt`) and a single `now` into
        // immutable locals BEFORE filtering/sorting. `lastActivityAt` is mutated
        // on each flow's own `flowQueue` (onActivity), so sorting the live
        // objects would read a key that another thread is changing mid-sort — a
        // data race and an unstable comparator. Snapshotting makes the ordering
        // self-consistent; the fire-loop re-check on `flowQueue` remains the
        // authority on whether a chosen victim is actually still idle.
        let nowNs = DispatchTime.now().uptimeNanoseconds
        let eligible =
            self.tcpSessions.values
            .map { (ctx: $0.ctx, lastNs: $0.ctx.lastActivityAt.uptimeNanoseconds) }
            .filter {
                // Mode-agnostic idle-floor check: BOTH modes carry an accurate
                // `lastActivityAt` (bumped on the shared write-pump flowQueue
                // hop), so an actively-transferring flow of either mode is
                // excluded here and never selected.
                //
                // Closing flows are eligible once genuinely drain-wedged:
                // dead weight holding a nexus slot is the first thing to
                // sacrifice under pressure. The wedge test's idle gate keeps
                // a live half-close unreapable.
                $0.ctx.egressReady
                    && (!$0.ctx.terminalSignalled || Self.flowIsDrainWedged($0.ctx))
                    && (nowNs &- $0.lastNs) / 1_000_000 > floorMs
            }
            .sorted { $0.lastNs < $1.lastNs }
            .map { $0.ctx }
        if eligible.isEmpty {
            // Over the cap but nothing idle enough to sacrifice — admit and ride
            // rather than reset a live flow. Logged ONCE per episode (not per
            // admission): a sustained over-cap population — notably UDP-dominated
            // occupancy, where the TCP-only reap can never reach low-water —
            // would otherwise spam a persisted os_log on every new flow.
            if !pressureNoHeadroomLogged {
                self.logLifecycle(
                    "flow pressure: over soft cap (\(softCap)) at occupancy \(occupancy) but no "
                        + "flow idle past \(floorMs)ms floor; admitting without reap"
                )
                pressureNoHeadroomLogged = true
            }
            return []
        }
        pressureNoHeadroomLogged = false
        let victims = Array(eligible.prefix(want))
        self.logLifecycle(
            "flow pressure: occupancy \(occupancy) over soft cap \(softCap); reaping "
                + "\(victims.count) idle flow(s) toward low-water \(lowWater)"
        )
        return victims
    }

    /// Fire the evictions selected by `collectPressureVictimsLocked`. Hops to
    /// each victim's `flowQueue` (off `stateQueue`) and re-checks idleness
    /// THERE before tearing down — a byte may have moved (bumping
    /// `lastActivityAt`) between selection and here, and `mode`/`isDone` may
    /// have advanced. `applyPressureEvicted` has no internal gate, so this
    /// re-check is its protection; teardown is idempotent via `isDone`.
    private func firePressureEvictions(_ victims: [TcpFlowContext]) {
        let floorMs = UInt64(defaultFlowPressureIdleFloorMs)
        for ctx in victims {
            runFlowTeardown(ctx) {
                guard ctx.egressReady, !ctx.isDone,
                    !ctx.terminalSignalled || Self.flowIsDrainWedged(ctx),
                    Self.flowIdleMs(ctx) > floorMs
                else { return }
                ctx.applyPressureEvicted()
            }
        }
    }

    private func startFlowCountReporting() {
        stopFlowCountReporting()
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        timer.schedule(
            deadline: .now() + Self.periodicMaintenanceInterval,
            repeating: Self.periodicMaintenanceInterval
        )
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let toKick = self.collectMaintenanceKicksLocked()
            guard !toKick.isEmpty else { return }
            // Hop off `stateQueue` before firing teardowns. `removeTcpFlow`
            // is now `.async` so an inline teardown body (engine-less ctx
            // without a `flowQueue`) no longer sync-re-enters `stateQueue`
            // → the old deadlock is gone. Kept as belt-and-suspenders so we
            // never run a teardown body while holding `stateQueue`'s context
            // (keeps the maintenance tick short and the queue free for other
            // mutations). Costs one async per tick.
            DispatchQueue.global(qos: .utility).async {
                self.fireWatchdogKicks(toKick)
            }
        }
        timer.resume()
        flowCountReportingTimer = timer
    }

    private func stopFlowCountReporting() {
        flowCountReportingTimer?.cancel()
        flowCountReportingTimer = nil
        // Clear watchdog state so a future `attachEngine` doesn't
        // inherit stale "stuck" IDs from the previous lifecycle.
        stateQueue.sync {
            self.stuckPreReadyFlowIds.removeAll(keepingCapacity: false)
            self.stuckClosingFlowIds.removeAll(keepingCapacity: false)
            self.overload = TcpOverloadState()
        }
    }

    /// One maintenance tick, on-`stateQueue` half: emit flow-count
    /// telemetry, run the stale-pre-ready bookkeeping, and return the
    /// list of contexts that crossed the "stuck for ≥ one tick"
    /// threshold so the off-queue half can drive their teardowns.
    ///
    /// MUST be called on `stateQueue` — both the timer handler and
    /// the test hook satisfy that.
    private func collectMaintenanceKicksLocked() -> MaintenanceKicks {
        // `stateQueue.sync` is unnecessary inside — the timer fires ON
        // `stateQueue`, so direct access to the maps is already
        // serialised correctly.
        let tcp = self.tcpSessions.count
        let udp = self.udpSessions.count
        let total = tcp + udp
        if total > self.flowCountHighWater { self.flowCountHighWater = total }
        // Combined total is what matters for the kernel nexus ceiling (global
        // across the flowswitch). `cap`/`peak` make pressure visible in soak.
        let overloadSnapshot = self.overload.snapshotAndResetRates(
            intervalSeconds: Self.periodicMaintenanceIntervalSeconds)
        let topApps = self.overload.topAppSummary()
        let admissionRate = String(format: "%.2f", overloadSnapshot.admissionRate)
        let timeoutRate = String(format: "%.2f", overloadSnapshot.timeoutRate)
        let shedRate = String(format: "%.2f", overloadSnapshot.shedRate)
        let breaker = overloadSnapshot.breakerOpen ? "open" : "closed"
        let appSummary = topApps.isEmpty ? "-" : topApps
        let latencySummary =
            "p50=\(overloadSnapshot.p50StartMs),p95=\(overloadSnapshot.p95StartMs),"
            + "p99=\(overloadSnapshot.p99StartMs)"
        let countSummary =
            "tproxy live-flow counts tcp=\(tcp) udp=\(udp) total=\(total) "
            + "peak=\(self.flowCountHighWater) softCap=\(defaultFlowPressureSoftCap)"
        let overloadSummary =
            "tcpStartsInFlight=\(overloadSnapshot.startsInFlight) "
            + "admissionRate=\(admissionRate)/s timeoutRate=\(timeoutRate)/s "
            + "shedRate=\(shedRate)/s startLatencyMs[\(latencySummary)] "
            + "breaker=\(breaker) topApps=\(appSummary)"
        self.logLifecycle("\(countSummary) \(overloadSummary)")

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
            if !ctx.egressReady {
                nowStuckPreReady.insert(id)
                if stuckPreReadyFlowIds.contains(id) {
                    kicks.preReadyStuck.append(ctx)
                }
            } else if Self.flowIsDrainWedged(ctx) {
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
            } else if ctx.mode == .promoted, Self.promotedFlowIsIdle(ctx) {
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

    /// One maintenance tick, off-`stateQueue` half: actually fire the
    /// teardowns identified by [`collectMaintenanceKicksLocked`].
    ///
    /// Hopped off `stateQueue` deliberately. `removeTcpFlow` is `.async`
    /// now, so an inline teardown body (engine-less / test ctx without a
    /// `flowQueue`) no longer sync-re-enters `stateQueue` — kept as
    /// belt-and-suspenders so a teardown body never runs while holding the
    /// maintenance tick's `stateQueue` context. Costs nothing in production.
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

    #if DEBUG
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

        /// Test hooks: the two halves of the pressure reap exposed separately so
        /// a test can inject a state change (e.g. a flow becoming active again)
        /// BETWEEN selection and the fire body, exercising the on-`flowQueue`
        /// re-check that protects a just-revived victim.
        func testCollectPressureVictims() -> [TcpFlowContext] {
            stateQueue.sync { self.collectPressureVictimsLocked() }
        }
        func testFirePressureEvictions(_ victims: [TcpFlowContext]) {
            firePressureEvictions(victims)
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
    func registerTcpFlow(_ flowId: ObjectIdentifier, anchor: TcpFlowSessionAnchor, appId: String? = nil) -> Int {
        stateQueue.sync {
            self.tcpSessions[flowId] = anchor
            if let appId {
                self.overload.flowApps[flowId] = appId
                self.overload.perAppFlowCounts[appId, default: 0] += 1
            }
            return self.tcpSessions.count + self.udpSessions.count
        }
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
    func registerUdpFlow(_ flowId: ObjectIdentifier, anchor: UdpFlowSessionAnchor) -> Int {
        stateQueue.sync {
            self.udpSessions[flowId] = anchor
            return self.tcpSessions.count + self.udpSessions.count
        }
    }

    func removeTcpFlow(_ flowId: ObjectIdentifier) {
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
        stateQueue.async {
            self.tcpSessions.removeValue(forKey: flowId)
            if let appId = self.overload.flowApps.removeValue(forKey: flowId),
                let count = self.overload.perAppFlowCounts[appId]
            {
                if count <= 1 {
                    self.overload.perAppFlowCounts.removeValue(forKey: appId)
                } else {
                    self.overload.perAppFlowCounts[appId] = count - 1
                }
            }
            // Belt-and-suspenders against `ObjectIdentifier` reuse:
            // if a torn-down flow's pointer is recycled for a new ctx
            // within one maintenance tick, the new ctx would inherit
            // the old's "stuck" status and be kicked on its very
            // first observation. Removing here keeps the watchdog's
            // tracking set in lockstep with the registry.
            self.stuckPreReadyFlowIds.remove(flowId)
            self.stuckClosingFlowIds.remove(flowId)
        }
    }

    // MARK: - TCP overload admission

    func admitTcpStart(
        flowId: ObjectIdentifier, meta: RamaTransparentProxyFlowMetaBridge
    ) -> TcpAdmissionDecision {
        stateQueue.sync {
            let appId = self.overload.appId(for: meta)
            let hardCap = Int(defaultTcpStartInFlightHardCap)
            let softCap = Int(defaultTcpStartInFlightSoftCap)
            let inFlight = self.overload.startsInFlight.count
            if hardCap > 0, inFlight >= hardCap {
                self.overload.shedsSinceTick += 1
                return .reject(
                    "hard start cap reached inFlight=\(inFlight) hardCap=\(hardCap) app=\(appId)")
            }
            if self.overload.breakerOpen, softCap > 0, inFlight >= softCap {
                self.overload.shedsSinceTick += 1
                return .reject(
                    "latency breaker open inFlight=\(inFlight) softCap=\(softCap) app=\(appId)")
            }
            let token = TcpAdmissionToken(flowId: flowId, startedAt: .now(), appId: appId)
            self.overload.startsInFlight[flowId] = token
            self.overload.admissionsSinceTick += 1
            return .admit(token)
        }
    }

    func finishTcpStart(_ token: TcpAdmissionToken, outcome: TcpStartOutcome) {
        stateQueue.async {
            guard self.overload.startsInFlight.removeValue(forKey: token.flowId) != nil else {
                return
            }
            let latencyMs =
                (DispatchTime.now().uptimeNanoseconds &- token.startedAt.uptimeNanoseconds)
                / 1_000_000
            self.overload.insertLatency(latencyMs)
            if outcome == .timeout {
                self.overload.timeoutsSinceTick += 1
            }
            self.updateTcpAdmissionBreakerLocked()
        }
    }

    func tcpConnectTimeoutMs(base: UInt32) -> UInt32 {
        stateQueue.sync {
            let inFlight = self.overload.startsInFlight.count
            let softCap = Int(defaultTcpStartInFlightSoftCap)
            if self.overload.breakerOpen, defaultTcpBreakerConnectTimeoutMs > 0 {
                return min(base, defaultTcpBreakerConnectTimeoutMs)
            }
            if softCap > 0, inFlight >= softCap, defaultTcpPressureConnectTimeoutMs > 0 {
                return min(base, defaultTcpPressureConnectTimeoutMs)
            }
            return base
        }
    }

    private func updateTcpAdmissionBreakerLocked() {
        let p95 = self.overload.percentile(0.95)
        let inFlight = self.overload.startsInFlight.count
        let softCap = Int(defaultTcpStartInFlightSoftCap)
        let openThreshold = UInt64(defaultTcpStartLatencyBreakerP95Ms)
        let closeThreshold = UInt64(defaultTcpStartLatencyBreakerCloseP95Ms)
        guard softCap > 0, openThreshold > 0 else { return }
        if !self.overload.breakerOpen, inFlight >= softCap, p95 >= openThreshold {
            self.overload.breakerOpen = true
            self.logLifecycle(
                "tcp overload breaker open: p95StartMs=\(p95) inFlight=\(inFlight) softCap=\(softCap)")
        } else if self.overload.breakerOpen, inFlight < softCap, p95 <= closeThreshold {
            self.overload.breakerOpen = false
            self.logLifecycle(
                "tcp overload breaker closed: p95StartMs=\(p95) inFlight=\(inFlight) softCap=\(softCap)")
        }
    }

    func removeUdpFlow(_ flowId: ObjectIdentifier) {
        // `.async` for the same reason as `removeTcpFlow` — never block a
        // per-flow teardown on the shared serial queue.
        stateQueue.async { self.udpSessions.removeValue(forKey: flowId) }
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

    #if DEBUG
        /// Test-only accessor for the writer pump bound to a flow.
        /// Returns `nil` if the flow is not registered (or never
        /// had a writer attached). Used by per-flow unit tests
        /// that need to inspect cache state mutated by the read
        /// loop. Gated on `#if DEBUG` so production builds carry
        /// no test-only surface on `TransparentProxyCore`.
        func testInspectUdpWriter(for flow: AnyObject) -> UdpClientWritePump? {
            stateQueue.sync { self.udpSessions[ObjectIdentifier(flow)]?.ctx.writer }
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
            }
        }

        func testAdmitTcpStart(
            flowId: ObjectIdentifier, meta: RamaTransparentProxyFlowMetaBridge
        ) -> TcpAdmissionDecision {
            admitTcpStart(flowId: flowId, meta: meta)
        }

        func testFinishTcpStart(_ token: TcpAdmissionToken, outcome: TcpStartOutcome) {
            finishTcpStart(token, outcome: outcome)
        }

        var testTcpStartsInFlight: Int {
            stateQueue.sync { self.overload.startsInFlight.count }
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
            }
        }
    #endif

    // MARK: - Logging helpers

    // Identical to the helpers the provider used to expose; consolidated
    // here so closures that capture `self` (the core) from inside the
    // moved flow-handling methods still have the same surface available.

    func logTrace(_ message: String) {
        RamaLog.trace(message)
    }

    func logDebug(_ message: String) {
        RamaLog.debug(message)
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

    /// Lifecycle-error counterpart of [`logLifecycle`].
    func logLifecycleError(_ message: String) {
        LifecycleLog.error(message)
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
            queue: flowQueue,
            logger: { [weak self] message in self?.logFlowMessage(message) },
            drainStallDeadline: .milliseconds(Int(ctx.lingerCloseMs)),
            // Mark the ctx so the on-`stateQueue` maintenance watchdog can also
            // reap this promoted flow if `flowQueue` later starves — the same
            // `terminalSignalled` net the `viaRust` close path arms.
            onClosing: { [weak ctx] in ctx?.terminalSignalled = true },
            // A finishing direction's drain wedged (peer stopped reading):
            // route through the shared full-teardown reaper. Idempotent via
            // the sticky `isDone`.
            onDrainStall: { [weak ctx] in ctx?.applyDrainBackstop() },
            // Bump the promoted-idle reaper clock on every byte moved.
            onActivity: { [weak ctx] in ctx?.lastActivityAt = .now() },
            // The forwarder's flow type has no close surface; hand it the
            // write-half close so the client app sees server EOF.
            closeClientWrite: { [weak flow] error in
                flow?.closeWriteWithError(error)
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
        UdpFlowSession(core: self, flow: flow, meta: bootMeta).start()
    }

}

#if DEBUG
    /// Stub anchor used by `testInsertUdpContext` — wraps a bare
    /// `UdpFlowContext` so the production registry's
    /// `UdpFlowSessionAnchor` invariant holds in tests that drive the
    /// `detachEngine` registry walk without spinning up a full session.
    /// (System sleep no longer iterates the registry — it just stops the
    /// telemetry timer and notifies the engine.)
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
    }
#endif
