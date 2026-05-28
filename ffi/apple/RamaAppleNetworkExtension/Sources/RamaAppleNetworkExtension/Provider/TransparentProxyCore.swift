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
    /// Per-TCP-flow context registry. The session handle reaches
    /// into the context via `ctx.session` so there is no separate
    /// session map — one entry per active flow, removed exactly
    /// when teardown calls `removeTcpFlow`.
    private var tcpContexts: [ObjectIdentifier: TcpFlowContext] = [:]
    /// Per-UDP-flow session registry. Unlike the TCP side, this
    /// holds the per-flow `UdpFlowSession` (type-erased via
    /// `UdpFlowSessionAnchor`) rather than the bare context. The
    /// session owns the context as a `let` member, so registering
    /// the session keeps the whole graph (`ctx`, writer, closures,
    /// `RamaUdpSessionHandle`) alive while the flow is open and
    /// drops it deterministically when `removeUdpFlow` runs — no
    /// context→session back-reference, no retain cycle.
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
        let tcp: [TcpFlowContext] = stateQueue.sync { Array(self.tcpContexts.values) }
        for ctx in tcp { runFlowTeardown(ctx) { ctx.teardown?.applyEngineDetached() } }
        let udp: [UdpFlowSessionAnchor] = stateQueue.sync { Array(self.udpSessions.values) }
        for session in udp { session.ctx.terminate?(engineDetachedError()) }
        self.engine?.stop(reason: reason)
        self.engine = nil
        stateQueue.sync {
            self.tcpContexts.removeAll(keepingCapacity: false)
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

    /// Budget the engine drain blocks the sleep handler for. Apple's
    /// `sleepWithCompletionHandler:` grace is "seconds" — 5s is well
    /// within that and gives the Rust runtime enough time to unwind a
    /// stress-magnitude (~hundreds-of-flows) backlog cooperatively.
    /// Tasks that don't yield by then are signalled and will bail on
    /// next yield post-wake; they no longer block new-flow processing
    /// because new flows register against the fresh shutdown the
    /// drain installed.
    static let systemSleepEngineDrainBudgetMs: UInt32 = 5_000

    /// Drop every active flow on sleep, then block until the Rust
    /// engine confirms its spawned tasks have actually exited
    /// cooperatively (or until [`systemSleepEngineDrainBudgetMs`]
    /// elapses, whichever first).
    ///
    /// Each Swift-side TCP teardown is dispatched onto its own flow
    /// queue first (`runFlowTeardown`) so it runs single-threaded
    /// with that flow's kernel / NWConnection callbacks — the
    /// teardown's `done` flag and slot mutations are
    /// flow-queue-confined, so this avoids racing them. Then we drive
    /// `engine.drainForSleep`, which fires the engine-wide shutdown
    /// trigger; per-flow `Shutdown`s observe `parent_guard.cancelled()`
    /// on the engine guard chain and the cascade unwinds every
    /// in-Rust service / bridge / handler task. The drain blocks
    /// until either all tasks exit or the budget elapses.
    ///
    /// Apple may suspend the process the moment we call `completion`.
    /// Blocking on the drain BEFORE `completion` ensures the runtime
    /// is genuinely quiet at the suspension point: no half-cancelled
    /// service tasks, no hundreds of pending timer expirations to
    /// catch up on after wake.
    func handleSystemSleep(completion: @escaping () -> Void) {
        stopFlowCountReporting()
        let tcp: [TcpFlowContext] = stateQueue.sync { Array(self.tcpContexts.values) }
        for ctx in tcp { runFlowTeardown(ctx) { ctx.teardown?.applySystemSleep() } }
        let udp: [UdpFlowSessionAnchor] = stateQueue.sync { Array(self.udpSessions.values) }
        for session in udp { session.ctx.terminate?(systemSleepError()) }
        // Notify the handler's on_system_sleep hook FIRST so it has
        // a chance to start running before the drain's cancellation
        // cascades. The hook task is spawned through the engine's
        // graceful executor, so the drain still bounds it.
        engine?.notifySystemSleep()

        // Engine-side recoverable drain. Fires the engine-wide
        // shutdown trigger and blocks until all guards drop or the
        // budget expires. On wake a fresh shutdown is in place so
        // new flows are unaffected.
        let outcome = engine?.drainForSleep(maxWaitMs: Self.systemSleepEngineDrainBudgetMs)
            ?? .alreadyStopped
        logLifecycle(
            "system sleep: drained tcp=\(tcp.count) udp=\(udp.count) flows; engine=\(outcome)"
        )
        completion()
    }

    /// On wake, restart telemetry and reconcile any TCP flow whose
    /// egress never reached `.ready` — a still-connecting flow won't
    /// recover (its NECP path is gone) and would otherwise burn its
    /// connect timer. Established flows are left to the post-ready path
    /// so we don't kill ones the OS kept across a no-op sleep.
    func handleSystemWake() {
        engine?.notifySystemWake()
        // Reconcile on each flow's own queue: both the `egressReady`
        // read and the teardown run there, so they stay single-threaded
        // with that flow's kernel / NWConnection callbacks instead of
        // racing them (and reading `egressReady`, written on the flow
        // queue, off-queue). A still-connecting flow won't recover (its
        // NECP path is gone); established flows are left to the
        // post-ready path so we don't kill ones the OS kept across a
        // no-op sleep.
        let all: [TcpFlowContext] = stateQueue.sync { Array(self.tcpContexts.values) }
        for ctx in all {
            runFlowTeardown(ctx) {
                guard !ctx.egressReady else { return }
                ctx.teardown?.applySystemWake()
            }
        }
        logLifecycle("system wake")
        if self.engine != nil {
            startFlowCountReporting()
        }
    }

    private func systemSleepError() -> NSError {
        NSError(
            domain: "rama.tproxy.system-sleep", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "system entered sleep; flow dropped"])
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
            // Hop off `stateQueue` before firing teardowns. Today
            // every production ctx has its own `flowQueue` so the
            // teardown body runs there (no recursive sync). But if a
            // future code path ever inserts a ctx without one,
            // `runFlowTeardown` runs the body inline → the body's
            // `core?.removeTcpFlow(flowId)` `stateQueue.sync`s back
            // → deadlock. Hopping off here costs one async per tick
            // (per-flow watchdog) and makes the production path
            // robust to that regression. The test hook does the
            // same; this brings prod into line.
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
        stateQueue.sync { self.stuckPreReadyFlowIds.removeAll(keepingCapacity: false) }
    }

    /// One maintenance tick, on-`stateQueue` half: emit flow-count
    /// telemetry, run the stale-pre-ready bookkeeping, and return the
    /// list of contexts that crossed the "stuck for ≥ one tick"
    /// threshold so the off-queue half can drive their teardowns.
    ///
    /// MUST be called on `stateQueue` — both the timer handler and
    /// the test hook satisfy that.
    private func collectMaintenanceKicksLocked() -> [TcpFlowContext] {
        // `stateQueue.sync` is unnecessary inside — the timer fires ON
        // `stateQueue`, so direct access to the maps is already
        // serialised correctly.
        let tcp = self.tcpContexts.count
        let udp = self.udpSessions.count
        self.logDebug("tproxy live-flow counts tcp=\(tcp) udp=\(udp)")

        // Track the set of pre-`egressReady` IDs across ticks. An ID
        // present in both the previous AND the current set has been
        // stuck for ≥ one tick interval and gets force-torn-down via
        // `applyConnectTimeout` — the same teardown the per-flow
        // connect timer would fire, just driven from here so it
        // survives the per-flow queue being starved.
        var nowStuck: Set<ObjectIdentifier> = []
        var toKick: [TcpFlowContext] = []
        for (id, ctx) in tcpContexts where !ctx.egressReady {
            nowStuck.insert(id)
            if stuckPreReadyFlowIds.contains(id) {
                toKick.append(ctx)
            }
        }
        stuckPreReadyFlowIds = nowStuck
        return toKick
    }

    /// One maintenance tick, off-`stateQueue` half: actually fire the
    /// teardowns identified by [`collectMaintenanceKicksLocked`].
    ///
    /// Hopped off `stateQueue` deliberately. In production every ctx
    /// has its own `flowQueue` so `runFlowTeardown` dispatches there
    /// — but engine-less / test ctxs without a `flowQueue` run the
    /// teardown body inline, and that body calls
    /// `core?.removeTcpFlow(flowId)` which `stateQueue.sync`s back.
    /// Holding `stateQueue` across the body would deadlock there. The
    /// hop costs nothing in production and makes the watchdog robust
    /// to engine-less call paths.
    private func fireWatchdogKicks(_ toKick: [TcpFlowContext]) {
        guard !toKick.isEmpty else { return }
        logLifecycle(
            "watchdog: force-tearing down \(toKick.count) stale pre-ready flow(s)"
        )
        for ctx in toKick {
            // Re-check `egressReady` ON `flowQueue`. The decision to
            // kick was made on `stateQueue` from a `nonisolated`
            // read of `ctx.egressReady`; between that and us getting
            // here the flow may have raced into `.ready` (the
            // legitimate happy path catching up just in time). The
            // teardown's `applyConnectTimeout` has no internal
            // ready-check — it'd cancel a healthy NWConnection and
            // pop the registry. Mirror what `handleSystemWake`
            // already does for the same race.
            runFlowTeardown(ctx) {
                guard !ctx.egressReady else { return }
                ctx.teardown?.applyConnectTimeout()
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

        /// Test hook: inspect the watchdog's "stuck since last tick" set.
        var testStuckPreReadyFlowIds: Set<ObjectIdentifier> {
            stateQueue.sync { self.stuckPreReadyFlowIds }
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

    func registerTcpFlow(
        _ flowId: ObjectIdentifier,
        session: RamaTcpSessionHandle,
        context: TcpFlowContext
    ) {
        stateQueue.sync { self.tcpContexts[flowId] = context }
    }

    /// Register the per-flow session as the owner-of-record for an
    /// intercepted UDP flow. The anchor is the only strong reference
    /// keeping the session alive while the flow is open; dropping
    /// it via `removeUdpFlow` deallocates the session and the
    /// `ctx`/writer/closure graph it owns.
    func registerUdpFlow(_ flowId: ObjectIdentifier, anchor: UdpFlowSessionAnchor) {
        stateQueue.sync { self.udpSessions[flowId] = anchor }
    }

    func removeTcpFlow(_ flowId: ObjectIdentifier) {
        stateQueue.sync {
            self.tcpContexts.removeValue(forKey: flowId)
            // Belt-and-suspenders against `ObjectIdentifier` reuse:
            // if a torn-down flow's pointer is recycled for a new ctx
            // within one maintenance tick, the new ctx would inherit
            // the old's "stuck" status and be kicked on its very
            // first observation. Removing here keeps the watchdog's
            // tracking set in lockstep with the registry.
            self.stuckPreReadyFlowIds.remove(flowId)
        }
    }

    func removeUdpFlow(_ flowId: ObjectIdentifier) {
        stateQueue.sync { self.udpSessions.removeValue(forKey: flowId) }
    }

    /// Count of currently-registered TCP flows. Test-only signal for
    /// leak / churn assertions.
    var tcpFlowCount: Int {
        stateQueue.sync { self.tcpContexts.count }
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
            stateQueue.sync { self.tcpContexts[ObjectIdentifier(flow)] }
        }

        /// Insert a TCP context into the registry directly, without
        /// going through `registerTcpFlow` (which requires a real
        /// `RamaTcpSessionHandle`). Lets tests drive engine-less
        /// scenarios like `handleSystemSleep` walks.
        func testInsertTcpContext(_ flowId: ObjectIdentifier, _ ctx: TcpFlowContext) {
            stateQueue.sync { self.tcpContexts[flowId] = ctx }
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

    /// Emit a lifecycle / critical event.
    ///
    /// Routed through `LifecycleLog` (Apple `os.Logger`, direct) AND
    /// through the Rust tracing path. The direct route guarantees the
    /// message is in `log show` regardless of the Rust subscriber's
    /// current INFO-level mapping; the Rust route keeps the message in
    /// the unified stderr / dial9 trace for the demo binary. See
    /// `LifecycleLog` for the gap that motivates the dual path.
    func logLifecycle(_ message: String) {
        LifecycleLog.notice(message)
        logInfo(message)
    }

    /// Lifecycle-error counterpart of [`logLifecycle`].
    func logLifecycleError(_ message: String) {
        LifecycleLog.error(message)
        logError(message)
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
        UdpFlowSession(core: self, flow: flow, meta: bootMeta).start()
    }

}

#if DEBUG
    /// Stub anchor used by `testInsertUdpContext` — wraps a bare
    /// `UdpFlowContext` so the production registry's
    /// `UdpFlowSessionAnchor` invariant holds in tests that drive
    /// registry-walk code paths (`handleSystemSleep`,
    /// `detachEngine`) without spinning up a full session.
    final class _TestUdpFlowSessionAnchor: UdpFlowSessionAnchor {
        let ctx: UdpFlowContext
        init(ctx: UdpFlowContext) { self.ctx = ctx }
    }
#endif
