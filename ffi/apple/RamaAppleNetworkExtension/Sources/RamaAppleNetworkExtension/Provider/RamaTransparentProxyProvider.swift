import Darwin
import Foundation
import NetworkExtension
import RamaAppleNEFFI

// MARK: - Closure-capture rules (DO NOT REMOVE THIS COMMENT BLOCK)
//
// Every closure that is *stored* by a long-lived owner — meaning the
// closure outlives the call site that constructed it — MUST capture
// the receiver weakly. The owners that store closures in this file:
//
//   * `TcpFlowLike` / `UdpFlowLike` implementations (real or mock)
//     hold `readData`, `writeData`, `readDatagrams`, `writeDatagrams`,
//     and `open` completion handlers in their internal callback
//     queues until either the kernel fires them or the flow itself
//     is destroyed.
//   * `NwConnectionLike` implementations hold `receive`, `send`,
//     and `stateUpdateHandler` closures the same way.
//   * The Rust engine's `TcpSessionCallbackBox` /
//     `UdpSessionCallbackBox` hold `onServerBytes`,
//     `onServerClosed`, `onClientReadDemand`, `onServerDatagram`,
//     `onCloseEgress` closures for the lifetime of the session
//     handle.
//   * `DispatchSource.makeTimerSource` and `DispatchWorkItem` hold
//     their handler closure until cancel or fire.
//   * `TcpWritePumpCore.doWrite`, `.onDrained`, `.onDrainedClose`,
//     and `.logHwm` are stored on the core for its entire lifetime.
//
// For every such closure, the pattern is:
//
//   x.someAsyncCall { [weak self] args in
//       guard let self else { return }
//       self.queue.async { [weak self] in
//           guard let self else { return }
//           …
//       }
//   }
//
// Both the outer closure AND any nested `queue.async` block inside
// it need `[weak self]`. Once you have `guard let self`, the captured
// `self` inside that scope is strong; an inner async block re-captures
// it strongly unless you write `[weak self]` again.
//
// Cautionary example: a single missing `[weak self]` on
// `TcpClientReadPump.requestReadLocked`'s `flow.readData` callback
// produced the cycle `pump → flow (let) → kernel callback queue →
// closure → pump`. ARC can't see it; code review missed it for
// months in production. The retain cycle leaked every intercepted
// flow's per-flow context graph until the kernel-side flow state
// machine wrapped up, which under stuck-peer conditions never
// happened promptly. Please keep the closure-capture rule above
// in mind when adding any new async surface.

enum FlowLogLevel: Equatable {
    case trace
    case debug
    case info
    case error
}

struct FlowLogMessage {
    let level: FlowLogLevel
    let text: String
    /// Optional privacy-safe marker for automated diagnostics. `text` always
    /// remains private because it can contain OS error descriptions.
    let publicText: String?

    init(level: FlowLogLevel, text: String, publicText: String? = nil) {
        self.level = level
        self.text = text
        self.publicText = publicText
    }
}

/// Network Extension entry point that delivered a UDP flow.
enum UdpFlowCallbackSource: String, Sendable {
    case modern
    case legacy
    case genericFallback = "generic-fallback"
}

/// Rama's policy result before it is mapped onto Network Extension's
/// callback Boolean.
enum UdpFlowHandlingDecision: String, Sendable {
    case passthrough
    case intercept
    case blocked

    /// `false` declines the flow so the transparent provider passes it through.
    var callbackReturnValue: Bool {
        self != .passthrough
    }
}

/// Framework-independent endpoint snapshot passed into Rama flow metadata.
struct EndpointHostPort: Equatable, Sendable, CustomStringConvertible {
    let host: String
    let port: UInt16

    var description: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }
}

/// Mirror of Apple's `NEAppProxyFlowError` values used to classify callback errors.
///
/// Source of truth for the numeric enum values:
/// - Xcode SDK header:
///   `NetworkExtension.framework/Headers/NEAppProxyFlow.h`
/// - Apple enum docs:
///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code
private enum AppProxyFlowErrorCode: Int {
    /// The flow is not connected.
    ///
    /// We treat this as a normal teardown/disconnect signal in read/write callbacks.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorNotConnected = 1`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/notconnected
    case notConnected = 1

    /// The remote peer reset the flow.
    ///
    /// We treat this as an expected remote-close outcome, not a provider bug.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorPeerReset = 2`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/peerreset
    case peerReset = 2

    /// The remote peer is unreachable.
    ///
    /// This is a network-path/connectivity issue and remains worth surfacing at debug level.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorHostUnreachable = 3`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/hostunreachable
    case hostUnreachable = 3

    /// An invalid argument was passed to an `NEAppProxyFlow` method.
    ///
    /// This suggests a provider bug or incorrect API usage and should be treated as actionable.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorInvalidArgument = 4`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/invalidargument
    case invalidArgument = 4

    /// The flow was aborted.
    ///
    /// This can happen during shutdown, but when not already closing it may still indicate
    /// a noteworthy runtime interruption.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorAborted = 5`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/aborted
    case aborted = 5

    /// The flow was refused/disallowed.
    ///
    /// This is treated as an environment or policy failure rather than an expected disconnect.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorRefused = 6`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/refused
    case refused = 6

    /// The flow timed out.
    ///
    /// This is a network/runtime condition and remains visible at debug level.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorTimedOut = 7`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/timedout
    case timedOut = 7

    /// An internal NetworkExtension error occurred.
    ///
    /// This is not expected during normal flow teardown and should be treated as actionable.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorInternal = 8`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/internal
    case `internal` = 8

    /// A UDP datagram exceeded the socket receive window.
    ///
    /// This is an operational misuse/limit condition and is treated as actionable.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorDatagramTooLarge = 9`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/datagramtoolarge
    case datagramTooLarge = 9

    /// A second read was started while another read was still pending.
    ///
    /// This should not occur in our serialized read loops and therefore indicates a logic bug.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorReadAlreadyPending = 10`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/readalreadypending
    case readAlreadyPending = 10
}

private let appProxyFlowErrorDomains: Set<String> = [
    "NEAppProxyFlowErrorDomain",
    "NEAppProxyErrorDomain",
]

private let expectedDisconnectPosixCodes: Set<Int32> = [
    ECONNABORTED,
    ECONNRESET,
    ENOTCONN,
    EPIPE,
]

/// POSIX errors we treat as **transient backpressure** when a write into
/// `NEAppProxyFlow.writeData` (or the egress `NWConnection.send`) fails.
///
/// Hitting these does NOT mean the flow is dead — Apple's per-flow NE kernel
/// buffer is temporarily full because the destination app drains slower than
/// upstream produces. The correct response is to back off briefly and retry
/// the same chunk, not to tear the flow down. Tearing down on the first
/// `ENOBUFS` is what surfaces large-h2-response downloads (`go mod download`,
/// large github / golang artifacts) as "random unrelated errors" mid-transfer.
private let transientWriteBackpressurePosixCodes: Set<Int32> = [
    ENOBUFS,
    EAGAIN,
    // EWOULDBLOCK aliases EAGAIN on macOS.
]

/// Returns true when `error` should make a writer pump retry the same chunk
/// after a short backoff instead of tearing the flow down.
func isTransientWriteBackpressure(_ error: Error) -> Bool {
    let nsError = error as NSError
    if nsError.domain == NSPOSIXErrorDomain,
        transientWriteBackpressurePosixCodes.contains(Int32(nsError.code))
    {
        return true
    }
    // `NWError` from `NWConnection.send` bridges to `NSError` with a `.posix`
    // domain only when the underlying cause is a POSIX errno; the bridged
    // domain in that case is also `NSPOSIXErrorDomain`, so the check above
    // covers both `NEAppProxyFlow` and `NWConnection` write paths.
    return false
}

/// Initial / capped backoff delays (ms) for transient-error retry. Capped so
/// we keep retrying but at a bounded rate; the caller's natural drain cycle
/// is sub-second on a working flow, so 200 ms is plenty.
let writeRetryInitialDelayMs: Int = 5
let writeRetryMaxDelayMs: Int = 200

/// Wall-clock cap on the transient-error retry loop. The retry `asyncAfter`
/// is `[weak self]`, so a deallocated pump stops itself — but a flow still
/// held by its registered ctx would re-arm forever, waiting on a
/// non-transient error a dead app may never send. This bounds that; 5 s
/// rides out a real h2 stall.
///
/// `var` for tests that need a short deadline to keep runtime bounded
/// — same pattern as `defaultLingerCloseMs` / `defaultEgressWaitingToleranceMs`.
nonisolated(unsafe) var writeRetryHardDeadlineMs: Int = 5_000

/// Memory budget (in bytes) each writer pump (TCP response and TCP egress)
/// keeps queued before it tells the Rust bridge to pause.
///
/// The byte budget is paired with `tcpWritePumpMaxPendingItems`. Bytes bound
/// payload storage while the item cap bounds `Data`, queue-entry, and dispatch
/// metadata when a producer emits pathologically small writes. Neither bound
/// replaces the other: a byte-only budget could retain one item per byte, and
/// a count-only budget would retain `N * max_chunk_size` payload bytes.
///
/// Default 256 KiB, two pumps per flow = 512 KiB worst-case per flow on
/// the write side. Smaller than it sounds: any actively backpressured flow
/// uses far less because Swift hands us chunks of 4–16 KiB on a typical
/// kernel read, so the pump pauses well before the byte cap. Handlers
/// that proxy bulk transfers with rare backpressure can raise this via
/// `RamaTransparentProxyConfig.tcp_write_pump_max_pending_bytes` for the
/// flows that benefit; the global default is sized for the common case
/// (many concurrent flows, modest per-flow throughput).
nonisolated(unsafe) var writePumpMaxPendingBytes: Int = 256 * 1024

/// Total non-empty chunks accepted by one TCP write pump, including queued,
/// dispatch-pending, in-flight, and transient-retry work. The normal 4–16 KiB
/// transport chunks reach the default byte cap after only 16–64 entries, so
/// this second bound is inactive on the ordinary path while preventing tiny
/// writes from manufacturing hundreds of thousands of retained objects.
let tcpWritePumpMaxPendingItems: Int = 256

/// Drop-on-full bound for `UdpClientWritePump.pending`. UDP is lossy by
/// definition, so the pump prefers dropping the newest datagram on
/// overflow over indefinite buffering. Picked to absorb a brief stall
/// (e.g. waiting for the first client read so `sentByEndpoint` is
/// known) without blowing up under a misbehaving producer.
let udpWritePumpMaxPending: Int = 256
/// Total payload bytes retained by one UDP kernel-write pump, including the
/// in-flight datagram. Count and byte bounds are both enforced.
let udpWritePumpMaxRetainedBytes: Int = 256 * 1024

// ── High-water telemetry thresholds ──────────────────────────────────────────

/// `pendingBytes` level at which a TCP write pump emits its first
/// high-water trace log. Set at 50 % of the cap so a memory spike is
/// visible in logs before backpressure kicks in, making it possible to
/// tie a spike to an exact flow from the log timestamp rather than
/// inferring it from a vmmap snapshot after the fact.
nonisolated(unsafe) var writePumpHwmLogThresholdBytes: Int = writePumpMaxPendingBytes / 2

/// Queue-depth at which the UDP write pump emits a high-water trace
/// log — same 50 % heuristic as the TCP byte threshold.
let udpWritePumpHwmLogThreshold: Int = udpWritePumpMaxPending / 2

/// Default wall-clock grace after a promoted flow reaches terminal before
/// Swift force-cancels its egress NWConnection. Applied when
/// `RamaTcpEgressConnectOptions.has_linger_close_ms`
/// is `false`; an explicit Rust-side `NwTcpConnectOptions.linger_close_timeout`
/// overrides. A successful local FIN does not start this grace because the
/// opposite response half may remain quiet and legally resume later.
///
/// `var` for tests that need a short linger to keep ARC-leak-check
/// runtime bounded — same pattern as `defaultEgressWaitingToleranceMs`.
/// The terminal linger watchdog holds `connection` strongly until it fires;
/// tests that assert `weakConn == nil` after teardown need to clamp
/// this so the watchdog releases before the polling deadline.
nonisolated(unsafe) var defaultLingerCloseMs: UInt32 = 5_000

/// Default grace window after an abnormal egress-read stop. Applied when
/// `RamaTcpEgressConnectOptions.has_egress_eof_grace_ms` is `false`.
/// It bounds cleanup after a read error, a vanished Swift session, or Rust
/// dropping its egress consumer. Clean server→client EOF deliberately does
/// not arm it because a still-active upload may remain quiet and resume.
let defaultEgressEofGraceMs: UInt32 = 2_000

/// Default tolerance window for a post-ready `NWConnection` sitting
/// in `.waiting(_)`. `.waiting` after `.ready` means Network.framework
/// has lost the underlying path (network change, peer unreachable,
/// NECP path update) and is holding the connection in a recoverable
/// state. Briefly is fine — Wi-Fi roams routinely cause sub-second
/// `.waiting` blips. Sitting in `.waiting` for many seconds means the
/// path will not come back on its own and the connection is
/// effectively dead. After this window the state handler treats it
/// as failed and tears the flow down.
///
/// `var` for tests that need a short tolerance to keep runtime
/// bounded — same pattern as `writePumpMaxPendingBytes`. Production
/// code paths read; tests override before invoking the lifecycle.
nonisolated(unsafe) var defaultEgressWaitingToleranceMs: UInt32 = 5_000

/// Settle delay after `wake()` before the post-wake reconcile re-checks
/// an established egress flow's cached viability (`lastPathViable`).
/// Network.framework needs a brief moment after resume to re-evaluate
/// paths and fire `viabilityUpdateHandler(false)` for a torn-down one;
/// checking at the wake instant would race that and risk reaping a flow
/// whose path is about to come back. Long enough for that re-evaluation,
/// far shorter than the 60s maintenance watchdog that would otherwise be
/// the only backstop for a flow wedged `.ready` over a dead path (the
/// silent-death case `.waiting`/`.failed` never catches). A no-op
/// (Power-Nap) sleep keeps viability `true` throughout, so those flows
/// are never touched.
///
/// `var` for tests that need a short settle to keep runtime bounded —
/// same pattern as `defaultEgressWaitingToleranceMs`.
nonisolated(unsafe) var defaultPostWakePathRecheckMs: UInt32 = 1_500

/// Mid-session sibling of `defaultPostWakePathRecheckMs`: settle delay
/// before re-judging an established egress flow whose
/// `viabilityUpdateHandler` reported `false` WITHOUT a system sleep —
/// Wi-Fi roam, Wi-Fi↔Ethernet, VPN up/down. Long enough to ride out a
/// roam blip (a path that recovers in the window is spared by the
/// re-check), far shorter than the minutes-scale idle reapers that are
/// otherwise the only backstop for a flow stranded `.ready` over a dead
/// path mid-session (`.waiting`/`.failed` never fire for that strand).
///
/// Set to == `defaultEgressWaitingToleranceMs` ON PURPOSE: the two are
/// the same dead-path budget seen through two signals. A path loss that
/// ALSO drives the connection to `.waiting` arms the precise per-flow
/// `.waiting` tolerance timer; the viability re-check must NOT preempt
/// that timer (an earlier settle would silently shorten the carefully
/// chosen recovery budget and reset a flow that was still inside it —
/// e.g. an interface-pinned egress whose roam routinely exceeds a few
/// seconds). Keeping them equal means the `.waiting` timer owns flows
/// that report both signals, and the re-check is left to cover ONLY the
/// silent-strand case where `.waiting` never fires. `handleEgressViabilityLoss`
/// additionally defers to an armed `.waiting` timer (`postReadyWaitingArmed`)
/// so a value below the tolerance still cannot preempt it. Do not set this
/// below `defaultEgressWaitingToleranceMs` (see the guard test).
///
/// Ships ENABLED at `5_000`. Set to `0` to disable mid-session
/// re-checks entirely — the kill switch, mirroring
/// `defaultFlowPressureSoftCap`.
nonisolated(unsafe) var defaultViabilityLossRecheckMs: UInt32 = 5_000

/// Budget for an egress `NWConnection` in `.waiting(_)` *before* it
/// ever reaches `.ready` (path down at connect — boot, wake, VPN
/// transition). Fail fast instead of hanging the full connect timeout;
/// a few seconds, not instant, rides out a sub-second connect blip that
/// recovers to `.ready`. `var` for tests.
nonisolated(unsafe) var defaultEgressPreReadyWaitingBudgetMs: UInt32 = 3_000

/// Default per-UDP-flow idle watchdog. Apple's `NEAppProxyUDPFlow`
/// gives the extension no terminal signal for an idle peer (UDP has
/// no FIN, and the kernel's `flow.readDatagrams` callback only
/// observes errors / EOF on explicit close). Without a watchdog, a
/// flow that completes a few request/response datagrams and then
/// goes quiet (DNS, mDNS probes, NAT-binding pings, …) stays
/// registered in `TransparentProxyCore.udpSessions` indefinitely. Rust's
/// independent `udp_max_flow_lifetime` defaults to `None` so active QUIC/H3
/// flows are not cut off; deployments may opt into an absolute cap.
///
/// 60 s is the smallest window that comfortably exceeds typical
/// real-world UDP-flow idle gaps (DNS retry cadence, NAT-keepalive
/// intervals, mDNS jitter); active flows — QUIC long-poll, WebRTC
/// media — push the deadline forward on every datagram so they're
/// unaffected.
///
/// `var` for tests that need a short timeout to keep ARC-leak-check
/// runtime bounded — same pattern as `defaultLingerCloseMs`.
nonisolated(unsafe) var defaultUdpIdleTimeoutMs: UInt64 = 60_000

/// Idle (no-progress) reaper deadline for promoted-path TCP flows
/// (`TcpDirectForwarder`), in milliseconds. `0` disables the reaper.
///
/// The promoted path has NO in-Rust idle backstop: once a flow promotes, its
/// Rust service task drains to EOF and exits, so the engine's
/// `DEFAULT_TCP_IDLE_TIMEOUT` (15 min, byte-progress based) no longer applies.
/// Without this, an established promoted flow whose peer goes silent — yet
/// stays TCP-alive, so egress keepalive never fails it — pins its egress
/// `NWConnection`'s kernel nexus-flow slot indefinitely; enough of them
/// exhaust the extension's per-process NECP allocation and freeze ALL proxied
/// networking (`NECP_CLIENT_ACTION_ADD_FLOW … ENOMEM`).
///
/// Default 15 min mirrors the engine's `viaRust` idle timeout EXACTLY, so a
/// promoted flow is reaped on the same schedule it would have been before
/// promotion: this RESTORES PARITY, it does not add a more aggressive kill.
/// Like that timeout it keys on APP-byte progress, not TCP liveness — it
/// cannot distinguish a silently-dead peer from a genuinely idle-but-alive
/// one. Egress TCP keepalive (`applyTcpKeepalive`) is the precise dead-peer
/// detector; this is the coarse last-resort backstop for the alive-but-idle
/// remainder.
///
/// `var` so tests can shorten it to keep runtime bounded — same pattern as
/// `defaultLingerCloseMs` / `defaultUdpIdleTimeoutMs`.
nonisolated(unsafe) var defaultPromotedIdleTimeoutMs: UInt32 = 900_000

// ── Flow-pressure backstop (nexus-slot exhaustion) ───────────────────────────
//
// A macOS NE app-proxy provider has a per-process kernel nexus-flow allocation;
// each intercepted flow consumes a slot (the app's ingress NEAppProxyFlow plus
// our egress NWConnection). When `NECP_CLIENT_ACTION_ADD_FLOW` starts returning
// ENOMEM, ALL proxied networking stalls — a machine-wide freeze. Keepalive
// (dead peers, ~30s) and the idle reapers (wedged/idle flows, minutes) keep the
// steady-state population bounded, but a fast BURST of connections can approach
// the ceiling faster than those act. This is the burst backstop.
//
// Established-flow pressure policy (deliberately conservative — see the
// constraints it honours below):
//   * Triggered when the COMBINED live flow count (TCP + UDP — the nexus ceiling
//     is global across the flowswitch) crosses `…SoftCap` at admission time, on
//     BOTH TCP and UDP admission (a UDP burst can approach the ceiling too).
//   * This reaper never refuses or delays a new flow: the new flow is admitted;
//     the reap (async, off the delivery thread) frees room for SUBSEQUENT flows.
//     A burst of triggers is coalesced (`pressureReapSlot`) into one scan,
//     victims still tearing down stay excluded and count as gone (so triggers
//     in that window select nothing twice), and after a scan finds nothing
//     idle past the floor, rescans are skipped until the closest flow could
//     possibly cross it (bounded to 250ms–5s) — under a churn burst the
//     registry is not re-sorted per admission.
//     Separate TCP start admission caps below may still reject pre-ready egress
//     starts before another expensive `NWConnection.start` is added.
//   * NEVER touches an active or recently-active flow: only flows idle past
//     `…IdleFloorMs` are eligible, evicted oldest-idle first (LRU) down to
//     `…LowWater` for hysteresis. There is intentionally NO activity-blind
//     eviction: under genuine all-active saturation we admit and log (once per
//     episode) rather than reset a live connection — the SoftCap margin below
//     the ceiling is the cushion for that (rare) case.
//   * Mode-agnostic eviction: BOTH `viaRust` and `.promoted` flows are evictable
//     (both bump `lastActivityAt` from their read and write pumps, so the
//     idle-floor check excludes an actively-transferring flow of either mode).
//     Eviction is TCP-only: UDP flows self-bound via `defaultUdpIdleTimeoutMs`
//     (60s, far tighter than TCP), so a UDP-driven burst TRIGGERS the reap
//     (relieving the global ceiling by reaping idle TCP slots) but UDP flows are
//     not themselves evicted here. (The Rust engine's `DEFAULT_TCP_IDLE_TIMEOUT`
//     and the promoted maintenance reaper remain the slower per-mode hygiene
//     backstops; this is the fast, global one.)
//
// The kernel ceiling is undocumented (~600 live flows observed). Calibrate
// these margins with on-device burst and soak workloads. A zero soft cap
// disables the soft backstop. Startup publishes the controls under one lock;
// the byte and datagram paths do not read them.
private struct FlowPressureDefaults {
    var softCap: UInt32 = 450
    var lowWater: UInt32 = 350
    var idleFloorMs: UInt32 = 120_000
    var hardCap: UInt32 = 500
}

private let flowPressureDefaults = Locked(FlowPressureDefaults())

var defaultFlowPressureSoftCap: UInt32 {
    get { flowPressureDefaults.withLock { $0.softCap } }
    set { flowPressureDefaults.withLock { $0.softCap = newValue } }
}

var defaultFlowPressureLowWater: UInt32 {
    get { flowPressureDefaults.withLock { $0.lowWater } }
    set { flowPressureDefaults.withLock { $0.lowWater = newValue } }
}

var defaultFlowPressureIdleFloorMs: UInt32 {
    get { flowPressureDefaults.withLock { $0.idleFloorMs } }
    set { flowPressureDefaults.withLock { $0.idleFloorMs = newValue } }
}

var defaultLiveFlowHardCap: UInt32 {
    get { flowPressureDefaults.withLock { $0.hardCap } }
    set { flowPressureDefaults.withLock { $0.hardCap = newValue } }
}

private func setFlowPressureDefaults(
    softCap: UInt32, lowWater: UInt32, idleFloorMs: UInt32,
    hardCap: UInt32
) {
    flowPressureDefaults.withLock { defaults in
        defaults.softCap = softCap
        defaults.lowWater = lowWater
        defaults.idleFloorMs = idleFloorMs
        defaults.hardCap = hardCap
    }
}

/// Keep an enabled pressure-reaper trigger at or below an enabled admission
/// ceiling. Otherwise a hard-cap refusal can wake the reaper while registered
/// occupancy is still below its trigger, making the wake an unconditional
/// no-op. Zero retains its documented meaning on either side: a zero soft cap
/// disables reaping, while a zero hard cap leaves admission unbounded.
func normalizedFlowPressureSoftCap(softCap: UInt32, hardCap: UInt32) -> UInt32 {
    guard softCap > 0, hardCap > 0 else { return softCap }
    return min(softCap, hardCap)
}

/// Keep the latency/timeout pressure threshold reachable below an enabled
/// in-flight admission ceiling. Zero preserves its documented disable meaning
/// for either threshold.
func normalizedTcpStartSoftCap(softCap: UInt32, hardCap: UInt32) -> UInt32 {
    guard softCap > 0, hardCap > 0 else { return softCap }
    return min(softCap, hardCap)
}

/// Keep an enabled reaper's target strictly below its trigger. This guarantees
/// at least one slot of hysteresis; deployments that want a larger batch gap
/// configure a lower target. A cap of one has the sole meaningful target zero.
/// A zero soft cap disables pressure reaping, so its unused target is preserved.
func normalizedFlowPressureLowWater(softCap: UInt32, lowWater: UInt32) -> UInt32 {
    guard softCap > 0 else { return lowWater }
    return min(lowWater, softCap - 1)
}

/// Hard cap on egress `NWConnection.start` calls that have not reached
/// `.ready` yet. This is the admission-side circuit breaker: every pre-ready
/// egress connection is exactly the expensive NECP handler population that
/// makes the next `nw_connection_start` slower, so once this cap is full we
/// refuse newly-claimed intercepted flows — declined to the direct route, or
/// blocked, per `defaultFlowRefusalPassthrough` — instead of adding another
/// stalled start. `0` disables hard admission refusal.
nonisolated(unsafe) var defaultTcpStartInFlightHardCap: UInt32 = 128

/// When the provider declines a flow for its OWN reasons — the start hard cap /
/// latency breaker tripping, or the engine handing back an intercept decision
/// without a session — hand the flow to the kernel untouched (fail open) instead
/// of blocking it (fail closed). `true` (Passthrough) is the default, mirroring
/// the Rust `FlowRefusalAction` default: these are capacity refusals, and the
/// direct route the flow declines onto is the same one every policy-passthrough
/// flow already takes. Blocking turns transient overload into hard connect
/// errors machine-wide, whose retry storms feed the overload. A strict-posture
/// deployment opts into that via
/// `TransparentProxyConfig::with_flow_refusal_action(Block)`. The chosen action
/// is logged at each decision site regardless.
nonisolated(unsafe) var defaultFlowRefusalPassthrough: Bool = true

/// Softer pre-ready pressure level used by the latency breaker. A slow
/// start-to-ready window opens the breaker, but admission refusal only begins
/// once there is also real pre-ready pressure at/above this cap. That avoids
/// treating one slow cellular/VPN connect as global overload. `0` disables
/// latency-breaker admission refusal (the hard cap above still applies).
nonisolated(unsafe) var defaultTcpStartInFlightSoftCap: UInt32 = 64

/// Start-to-ready latency threshold for the breaker, in milliseconds. The core
/// tracks a rolling window of recent egress starts; if p95 crosses this
/// threshold while pre-ready pressure is present, it opens the breaker and
/// begins shedding new intercepted starts at the soft cap. Evaluated on
/// completion, on admission at/over the soft cap (ahead of the hard-cap
/// check), and on the maintenance tick, so the admission that brings pressure
/// onto an already-slow window opens it rather than the next completion. The
/// window is completed starts only; see `TcpOverloadState.percentile`.
nonisolated(unsafe) var defaultTcpStartLatencyBreakerP95Ms: UInt32 = 1_500

/// Close threshold for the start-latency breaker. Once p95 drops below this
/// and in-flight starts are below the soft cap, admission returns to normal.
nonisolated(unsafe) var defaultTcpStartLatencyBreakerCloseP95Ms: UInt32 = 500

/// Connect-timeout clamp once pre-ready pressure reaches the soft cap. The
/// normal Rust-provided/default timeout is useful at low load, but under an
/// overload spiral long pre-ready waits keep expensive NECP handlers alive and
/// make every subsequent start slower. This clamp bounds that residency while
/// still allowing a few seconds for transient path recovery.
nonisolated(unsafe) var defaultTcpPressureConnectTimeoutMs: UInt32 = 5_000

/// Stricter connect-timeout clamp while the latency breaker is open.
nonisolated(unsafe) var defaultTcpBreakerConnectTimeoutMs: UInt32 = 3_000

// ── Per-pump lifecycle / state enums ─────────────────────────────────────────

/// Queue-confined phase for read pumps.  Three `Bool` fields
/// (`readPending`/`receiving`, `paused`, `closed`) encoded the same
/// information; the compiler now enforces that only one branch is live
/// at a time.
enum ReadPumpPhase {
    /// Idle — ready to schedule the next read when asked.
    case open
    /// A `readData` or `connection.receive` call is in flight.
    case reading
    /// Rust signalled backpressure; waiting for `resume()`.
    case paused
    /// Terminal — no further transitions.
    case closed
}

/// Queue-confined lifecycle for TCP write pumps.  Replaces the pair of
/// `opened: Bool` + `closeRequested: Bool` flags so the compiler can
/// reason about valid transitions instead of scattered boolean checks.
enum WritePumpLifecycle {
    /// `markOpened()` has not yet been called; chunks are queued but
    /// `flushLocked` will not start a write until we transition.
    case pending
    /// Opened and accepting new chunks.
    case open
    /// `closeWhenDrained()` called; pump drains the queue then signals
    /// the FIN / `onDrainedClose` completion.
    case draining
}

/// Exponential-backoff retry state for write pumps.  `nil` means no
/// retry sequence is active; the two scalar fields `retryDelayMs` /
/// `retryDeadlineAt` live here so "am I retrying?" is a single
/// nil-check rather than a dual-field read.
struct WriteRetry {
    /// Delay to use for the *next* scheduled retry (ms); doubles each
    /// round up to `writeRetryMaxDelayMs`.
    var delayMs: Int
    /// Hard wall-clock deadline for the whole retry sequence.
    var deadline: DispatchTime
}

func blockedFlowError() -> NSError {
    NSError(
        domain: "NEAppProxyFlowErrorDomain",
        code: AppProxyFlowErrorCode.refused.rawValue,
        userInfo: [
            NSLocalizedDescriptionKey: "Flow blocked by transparent proxy policy",
            NSLocalizedFailureReasonErrorKey:
                "The transparent proxy policy rejected this flow.",
        ]
    )
}

func tcpUpstreamUnavailableError() -> NSError {
    NSError(
        domain: "NEAppProxyFlowErrorDomain",
        code: AppProxyFlowErrorCode.refused.rawValue,
        userInfo: [
            NSLocalizedDescriptionKey: "TCP upstream connection failed",
            NSLocalizedFailureReasonErrorKey:
                "The transparent proxy could not establish the outbound TCP connection.",
        ]
    )
}

/// Minimal read surface the client read pump needs. Abstracts
/// `NEAppProxyTCPFlow` so the pump can be driven by a mock flow in
/// unit tests — without it, the pump is only reachable through a
/// real Apple-internal flow object that can't be subclassed.
/// `@Sendable` on the completion handler matches Apple's declared
/// signature so Swift 6 strict-concurrency mode accepts the
/// conformance.
protocol TcpFlowReadable: AnyObject, Sendable {
    func readData(completionHandler: @escaping @Sendable (Data?, Error?) -> Void)
}
extension NEAppProxyTCPFlow: TcpFlowReadable {}

/// Routing decision when the client read pump terminates. Splitting
/// the natural-EOF path from the hard-error path is the dispatcher's
/// load-bearing distinction: natural EOF must defer write-side
/// teardown to the writer pump's drain so queued response bytes
/// reach the originating app, while a hard error tears the whole
/// flow down immediately.
///
/// Pulled out of the dispatcher's closure graph so the routing
/// decision is a single, testable surface — the alternative is an
/// inline `if let` deep inside `handleTcpFlow`, where a future edit
/// can silently swap branches and only surface in production
/// stress as the close-reason histogram regressing.
struct TcpReadTerminal: Sendable {
    let onNaturalEof: @Sendable () -> Void
    let onHardError: @Sendable (Error) -> Void

    func dispatch(_ readError: Error?) {
        if let err = readError {
            onHardError(err)
        } else {
            onNaturalEof()
        }
    }
}

/// Classify a `NEAppProxyFlow` callback error into an expected
/// disconnect vs. an actionable failure. Codes come from
/// `NEAppProxyFlow.h`; disconnect-like outcomes log at `trace` so
/// they don't drown out genuine provider faults.
func classifyFlowCallbackError(
    _ error: Error,
    operation: String,
    isClosing: Bool = false
) -> FlowLogMessage {
    let nsError = error as NSError
    let detail =
        "domain=\(nsError.domain) code=\(nsError.code) description=\(nsError.localizedDescription)"
    let operationToken = operation.replacingOccurrences(of: " ", with: "_")

    if appProxyFlowErrorDomains.contains(nsError.domain),
        let code = AppProxyFlowErrorCode(rawValue: nsError.code)
    {
        switch code {
        case .notConnected:
            let reason =
                isClosing ? "normal flow shutdown already in progress" : "flow already disconnected"
            return FlowLogMessage(
                level: .trace,
                text: "\(operation) ended during \(reason): \(detail)"
            )
        case .peerReset:
            return FlowLogMessage(
                level: .trace,
                text: "\(operation) ended after peer reset the flow: \(detail)"
            )
        case .aborted:
            let level: FlowLogLevel = isClosing ? .trace : .debug
            let reason =
                isClosing ? "flow shutdown already in progress" : "flow was aborted by the system"
            return FlowLogMessage(
                level: level,
                text: "\(operation) ended because \(reason): \(detail)"
            )
        case .hostUnreachable, .refused, .timedOut:
            return FlowLogMessage(
                level: .debug,
                text: "\(operation) failed because the network path was unavailable: \(detail)"
            )
        case .invalidArgument, .internal, .datagramTooLarge, .readAlreadyPending:
            return FlowLogMessage(
                level: .error,
                text: "\(operation) failed with an unexpected provider/runtime error: \(detail)",
                publicText:
                    "flow_callback_error operation=\(operationToken) classification=unexpected_provider_runtime"
            )
        }
    }

    if nsError.domain == NSPOSIXErrorDomain,
        expectedDisconnectPosixCodes.contains(Int32(nsError.code))
    {
        let reason = isClosing ? "normal flow shutdown already in progress" : "peer disconnected"
        return FlowLogMessage(
            level: .trace,
            text: "\(operation) ended during \(reason): \(detail)"
        )
    }

    return FlowLogMessage(
        level: .debug,
        text: "\(operation) failed with an unclassified callback error: \(detail)"
    )
}

/// Async-write surface the writer pump needs. `NEAppProxyTCPFlow`
/// already conforms structurally; abstracting via a protocol lets
/// unit tests drive the pump with a stub that simulates kernel-buffer
/// stalls without an actual NE flow. The completion handler is
/// `@Sendable` to match Apple's declared signature so Swift 6
/// strict-concurrency mode accepts the conformance.
protocol TcpFlowWritable: AnyObject, Sendable {
    func write(_ data: Data, withCompletionHandler: @escaping @Sendable (Error?) -> Void)
}
extension NEAppProxyTCPFlow: TcpFlowWritable {}

/// Full surface the per-flow TCP state machine needs from a flow:
/// the read + write halves (`TcpFlowReadable` + `TcpFlowWritable`),
/// plus the lifecycle methods `open` / `closeReadWithError` /
/// `closeWriteWithError`, plus a hook for applying NEFlowMetaData
/// onto egress NWParameters. Apple's `NEAppProxyTCPFlow` conforms
/// trivially; tests pass a `MockTcpFlow` that captures every call
/// for assertion. Existence of this protocol is what lets
/// `TransparentProxyCore.handleTcpFlow` be generic over flow type
/// — and therefore unit-testable end-to-end without a live system
/// extension.
protocol TcpFlowLike: TcpFlowReadable, TcpFlowWritable, AnyObject {
    func open(
        withLocalEndpoint localEndpoint: NWHostEndpoint?,
        completionHandler: @escaping @Sendable (Error?) -> Void
    )
    func closeReadWithError(_ error: Error?)
    func closeWriteWithError(_ error: Error?)
    /// Stamp the intercepted flow's NEFlowMetaData (source app identifier,
    /// audit token, …) onto the supplied egress `NWParameters`. Real
    /// `NEAppProxyTCPFlow` calls into `applyFlowMetadata` here; tests
    /// supply a no-op.
    func applyMetadata(to params: NWParameters)
}

extension NEAppProxyTCPFlow: @unchecked @retroactive Sendable {}
extension NEAppProxyTCPFlow: TcpFlowLike {
    func applyMetadata(to params: NWParameters) {
        applyFlowMetadata(self, params)
    }
}

/// Async-read surface the UDP read pump needs. Mirror of
/// `TcpFlowReadable` for the datagram path. `[NWEndpoint]?` tracks
/// the per-datagram source so `sentBy:` on a corresponding write
/// echoes back to the same peer.
protocol UdpFlowReadable: AnyObject, Sendable {
    func readDatagrams(
        completionHandler: @escaping @Sendable ([Data]?, [NWEndpoint]?, Error?) -> Void
    )
}
extension NEAppProxyUDPFlow: UdpFlowReadable {}

/// Async-write surface the UDP writer pump needs.
protocol UdpFlowWritable: AnyObject, Sendable {
    func writeDatagrams(
        _ datagrams: [Data],
        sentBy remoteEndpoints: [NWEndpoint],
        completionHandler: @escaping @Sendable (Error?) -> Void
    )
}
extension NEAppProxyUDPFlow: UdpFlowWritable {}

/// Full surface the per-flow UDP state machine needs from a flow.
/// Symmetric to `TcpFlowLike`: read + write halves plus the
/// open/close lifecycle and the metadata stamping hook.
protocol UdpFlowLike: UdpFlowReadable, UdpFlowWritable, AnyObject {
    func open(
        withLocalEndpoint localEndpoint: NWHostEndpoint?,
        completionHandler: @escaping @Sendable (Error?) -> Void
    )
    func closeReadWithError(_ error: Error?)
    func closeWriteWithError(_ error: Error?)
    func applyMetadata(to params: NWParameters)
}

extension NEAppProxyUDPFlow: @unchecked @retroactive Sendable {}
extension NEAppProxyUDPFlow: UdpFlowLike {
    func applyMetadata(to params: NWParameters) {
        applyFlowMetadata(self, params)
    }
}

/// Cross-thread state of `TcpClientWritePump`. Reachable only via
/// `Locked.withLock` so the closed-flag / byte-budget / drain-signal
/// triple is always read and updated as one consistent snapshot.
struct TcpWriterState {
    var closed: Bool = false
    /// Sum of bytes currently queued OR in-flight on the writer.
    /// Source of truth for backpressure decisions.
    var pendingBytes: Int = 0
    /// Number of accepted non-empty chunks currently dispatch-pending, queued,
    /// in-flight, or retained for transient retry. Charged over the same
    /// lifetime as `pendingBytes` so the asynchronous handoff itself is bounded.
    var pendingItems: Int = 0
    /// Exact byte count whose TCP retry is parked behind the process-wide
    /// writer envelope. A precharged grant must only satisfy this same retry.
    var aggregateWaitExpectedBytes: Int?
    var aggregateWaiter: WriterMemoryWaiter?
    var aggregateGrant: WriterMemoryGrant?
    /// Set when an `enqueue` returned `.paused`. We fire `onDrained`
    /// on the first removal that leaves headroom under both caps, then clear —
    /// edge-triggered so we never spam Rust with redundant drain signals while
    /// the queue churns at either cap.
    var pausedSignaled: Bool = false
    /// All-time peak of `pendingBytes` for this pump instance. Updated
    /// atomically under the lock; telemetry logs only its first threshold
    /// crossing so a byte-at-a-time producer cannot amplify logging.
    var pendingBytesHwm: Int = 0
}

/// Sendable wrapper for Apple's provider-start completion while it is
/// captured by the settings callback.
///
/// Invocation is deliberately unsynchronised: the caller must leave all
/// lifecycle locks and group leases before entering this external callback,
/// which is allowed to synchronously re-enter provider teardown.
private final class ProviderStartCompletion: @unchecked Sendable {
    private let body: (Error?) -> Void

    init(_ body: @escaping (Error?) -> Void) {
        self.body = body
    }

    func callAsFunction(_ error: Error?) {
        body(error)
    }
}

public final class RamaTransparentProxyProvider: NETransparentProxyProvider {
    /// The Apple-framework-free state machine, engine handle, and
    /// per-flow registration maps live here. This subclass exists
    /// only because the system extension runtime requires a
    /// `NETransparentProxyProvider` to instantiate; every override
    /// below is a thin delegation onto the core (plus the
    /// Apple-framework calls that can't move out of the subclass,
    /// like `setTunnelNetworkSettings` and the metadata extraction
    /// from `NEFlowMetaData`).
    let core = TransparentProxyCore()

    public override func startProxy(
        options: [String: Any]?, completionHandler: @escaping (Error?) -> Void
    ) {
        let storageDir = Self.defaultRustStorageDirectory()?.path
        RamaLog.info("startProxy called pid=\(ProcessInfo.processInfo.processIdentifier)")
        guard RamaTransparentProxyEngineHandle.initialize(storageDir: storageDir, appGroupDir: nil)
        else {
            RamaLog.error(
                "initialize() returned false — rust tracing or allocator init failed; "
                + "pid=\(ProcessInfo.processInfo.processIdentifier) "
                + "storageDir=\(storageDir ?? "<nil>")"
            )
            let error = NSError(
                domain: "RamaTransparentProxy.Startup",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "rust initialization failed before provider startup completed",
                    NSLocalizedFailureReasonErrorKey:
                        "rama_transparent_proxy_initialize returned false",
                    NSLocalizedRecoverySuggestionErrorKey:
                        "Inspect extension bootstrap logs for entitlement, protected-storage, or Rust startup failures.",
                    "storageDir": storageDir ?? NSNull(),
                    "startupStage": "initialize",
                ]
            )
            completionHandler(error)
            return
        }
        core.logLifecycle("extension startProxy")

        let engineConfigJson = Self.engineConfigJson(
            protocolConfiguration: self.protocolConfiguration as? NETunnelProviderProtocol,
            startOptions: options
        )
        if let engineConfigJson {
            core.logLifecycle("engine config json bytes=\(engineConfigJson.count)")
        }
        guard let engine = RamaTransparentProxyEngineHandle(engineConfigJson: engineConfigJson)
        else {
            core.logLifecycleError("engine creation error")
            completionHandler(
                NSError(
                    domain: "org.ramaproxy.example.tproxy.engine",
                    code: 1,
                    userInfo: [
                        NSLocalizedDescriptionKey: "Failed to create transparent proxy engine"
                    ]
                )
            )
            return
        }
        guard let startup = engine.config() else {
            core.logLifecycleError("failed to get transparent proxy config from rust")
            // The core is deliberately not attached until configuration is
            // installed. Stop this locally-owned engine because Apple does
            // not compensate a failed `startProxy` with `stopProxy`.
            engine.stop(reason: 0)
            let error = NSError(
                domain: "RamaTransparentProxy.Startup",
                code: 2,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "rust startup configuration could not be loaded",
                    NSLocalizedFailureReasonErrorKey:
                        "rama_transparent_proxy_get_config returned nil",
                    NSLocalizedRecoverySuggestionErrorKey:
                        "Inspect extension bootstrap logs for Rust-side configuration or secret-loading failures.",
                    "storageDir": storageDir ?? NSNull(),
                    "startupStage": "config",
                ]
            )
            completionHandler(error)
            return
        }

        let runtimePolicy = Self.makeRuntimePolicy(from: startup) { [core] msg in
            core.logLifecycle(msg)
        }
        // Publish the engine and its fully-built policy in one core transaction.
        // No maintenance task or flow callback can observe a partial config.
        let engineGeneration = core.attachEngine(engine, runtimePolicy: runtimePolicy)
        core.logLifecycle("engine created")

        let settings = Self.buildNetworkSettings(
            from: startup,
            logInfo: { [core] msg in core.logInfo(msg) },
            logError: { [core] msg in core.logError(msg) }
        )

        let completion = ProviderStartCompletion(completionHandler)
        setTunnelNetworkSettings(settings) { [core, completion] error in
            if let error {
                if core.detachEngine(ifGeneration: engineGeneration, reason: 0) {
                    core.logLifecycleError("setTunnelNetworkSettings error: \(error)")
                    // Apple won't compensate via `stopProxy`, so the current
                    // failed start must tear down its own engine locally.
                    completion(error)
                } else {
                    completion(Self.supersededStartError())
                }
                return
            }
            Self.completeStartAfterSettingsSuccess(
                core: core,
                engineGeneration: engineGeneration
            ) { error in
                completion(error)
            }
        }
    }

    /// Linearise a successful settings callback against engine replacement,
    /// then notify Apple only after the lifecycle-group lease has been left.
    /// The external completion may synchronously call back into `stopProxy`.
    internal static func completeStartAfterSettingsSuccess(
        core: TransparentProxyCore,
        engineGeneration: UInt64,
        completion: (Error?) -> Void
    ) {
        let completed = core.withActiveEngineGeneration(engineGeneration) {
            core.logLifecycle("setTunnelNetworkSettings ok")
        }
        completion(completed ? nil : supersededStartError())
    }

    private static func supersededStartError() -> NSError {
        NSError(
            domain: "RamaTransparentProxy.Startup",
            code: 3,
            userInfo: [
                NSLocalizedDescriptionKey:
                    "transparent proxy start was stopped or superseded before settings completed"
            ])
    }

    public override func stopProxy(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        core.logLifecycle("extension stopProxy reason=\(reason.rawValue)")
        core.detachEngine(reason: Int32(reason.rawValue))
        completionHandler()
    }

    public override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        completionHandler?(core.handleAppMessage(messageData))
    }

    public override func sleep(completionHandler: @escaping () -> Void) {
        core.handleSystemSleep(completion: completionHandler)
    }

    public override func wake() {
        core.handleSystemWake()
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // The adapter has one Apple-specific job here: extract the
        // NEFlowMetaData snapshot (and, for UDP, the callback-provided
        // initial remote endpoint) before handing the flow to the
        // core. Once the metadata is a plain struct the core's
        // per-flow handler is generic over `TcpFlowLike` /
        // `UdpFlowLike`, so the same code path is reused verbatim by
        // unit tests that pass in a mock flow.
        if let tcp = flow as? NEAppProxyTCPFlow {
            let meta = Self.tcpMeta(flow: tcp)
            return core.handleTcpFlow(tcp, meta: meta)
        }
        if let udp = flow as? NEAppProxyUDPFlow {
            // The designated UDP callbacks below supply the intended remote
            // endpoint. This generic fallback deliberately does not inspect
            // NEAppProxyUDPFlow via KVC: that object has no public remote
            // endpoint property on the modern API.
            return handleNewUdpFlow(
                udp,
                callback: .genericFallback,
                remoteEndpoint: nil,
                localEndpoint: Self.udpLocalEndpoint(flow: udp)
            )
        }
        core.logDebug("handleNewFlow unsupported type=\(String(describing: type(of: flow)))")
        return false
    }

    /// Deprecated NetworkExtension UDP entry point retained for supported
    /// macOS releases before 15.
    @available(macOS, deprecated: 15.0, message: "Use NEAppProxyUDPFlowHandling")
    public override func handleNewUDPFlow(
        _ flow: NEAppProxyUDPFlow,
        initialRemoteEndpoint remoteEndpoint: NWEndpoint
    ) -> Bool {
        handleNewUdpFlow(
            flow,
            callback: .legacy,
            remoteEndpoint: Self.endpointHostPort(remoteEndpoint),
            localEndpoint: Self.udpLocalEndpoint(flow: flow)
        )
    }

    /// Shared policy path for the modern and legacy UDP callbacks. Endpoint
    /// conversion happens at the typed framework boundary; metadata creation,
    /// Rama policy invocation, decision logging, and Bool mapping happen here
    /// exactly once so the callbacks cannot drift apart.
    internal func handleNewUdpFlow(
        _ flow: NEAppProxyUDPFlow,
        callback: UdpFlowCallbackSource,
        remoteEndpoint: EndpointHostPort?,
        localEndpoint: EndpointHostPort?
    ) -> Bool {
        let meta = Self.udpMeta(
            flow: flow,
            remoteEndpoint: remoteEndpoint,
            localEndpoint: localEndpoint
        )
        let decision = core.handleUdpFlowDecision(flow, meta: meta)
        return Self.finishUdpCallback(
            callback: callback,
            remoteEndpoint: remoteEndpoint,
            sourceAppSigningIdentifier: meta.sourceAppSigningIdentifier,
            decision: decision,
            logDebug: { publicMessage, privateMetadata in
                RamaLog.debug(publicMessage, privateMetadata: privateMetadata)
            }
        )
    }

    /// One decision-to-Bool mapping and one structured log shape for every
    /// UDP callback generation. Kept pure/injectable for unit tests.
    internal static func finishUdpCallback(
        callback: UdpFlowCallbackSource,
        remoteEndpoint: EndpointHostPort?,
        sourceAppSigningIdentifier: String?,
        decision: UdpFlowHandlingDecision,
        logDebug: (_ publicMessage: String, _ privateMetadata: String) -> Void
    ) -> Bool {
        let callbackReturn = decision.callbackReturnValue
        // Callback/decision/callback-return are stable public counters and
        // routing evidence. Source-app identity and destination are flow
        // metadata and must remain private.
        logDebug(
            "udp_callback=\(callback.rawValue) rama_decision=\(decision.rawValue) callback_return=\(callbackReturn)",
            "source_app=\(sourceAppSigningIdentifier ?? "<missing>") "
                + "initial_remote=\(remoteEndpoint?.description ?? "<unsupported-or-missing>")"
        )
        return callbackReturn
    }

    /// Translate a transparent-proxy config (tunnel address +
    /// list of rules) into the `NETransparentProxyNetworkSettings`
    /// that `startProxy` hands to `setTunnelNetworkSettings`.
    ///
    /// Pure with respect to its inputs except for the two log
    /// callbacks — extracted out of `startProxy` so the
    /// rule-iteration loop (which is where most validation
    /// edge cases live) can be exercised under unit tests
    /// without standing up an Apple-runtime `NETransparentProxyProvider`.
    /// Rules that `makeNetworkRules` rejects are logged via
    /// `logError` and skipped; every other rule contributes one
    /// or more entries to `includedNetworkRules` / `excludedNetworkRules`.
    /// `excludedNetworkRules` is left `nil` (not `[]`) when no
    /// exclude rules survive, matching Apple's documented
    /// "absent" sentinel.
    internal static func buildNetworkSettings(
        from config: RamaTransparentProxyConfigBridge,
        logInfo: (String) -> Void = { _ in },
        logError: (String) -> Void = { _ in }
    ) -> NETransparentProxyNetworkSettings {
        let settings = NETransparentProxyNetworkSettings(
            tunnelRemoteAddress: config.tunnelRemoteAddress
        )
        var includedRules: [NENetworkRule] = []
        var excludedRules: [NENetworkRule] = []
        for (idx, rule) in config.rules.enumerated() {
            let kind = rule.exclude ? "exclude" : "include"
            let built = makeNetworkRules(rule)
            if built.isEmpty {
                logError(
                    "invalid \(kind) rule[\(idx)] remote=\(rule.remoteNetwork ?? "<any>") remotePrefix=\(rule.remotePrefix.map(String.init) ?? "<none>") remotePort=\(rule.remotePort.map(String.init) ?? "<none>") local=\(rule.localNetwork ?? "<any>") localPrefix=\(rule.localPrefix.map(String.init) ?? "<none>") proto=\(rule.protocolRaw)"
                )
                continue
            }
            for one in built {
                if rule.exclude {
                    excludedRules.append(one)
                } else {
                    includedRules.append(one)
                }
            }
            logInfo(
                "\(kind) rule[\(idx)] remote=\(rule.remoteNetwork ?? "<any>") remotePrefix=\(rule.remotePrefix.map(String.init) ?? "<none>") remotePort=\(rule.remotePort.map(String.init) ?? "<none>") local=\(rule.localNetwork ?? "<any>") localPrefix=\(rule.localPrefix.map(String.init) ?? "<none>") proto=\(rule.protocolRaw) emitted=\(built.count)"
            )
        }
        settings.includedNetworkRules = includedRules
        settings.excludedNetworkRules = excludedRules.isEmpty ? nil : excludedRules
        logInfo(
            "network rules: included=\(includedRules.count) excluded=\(excludedRules.count)"
        )
        return settings
    }

    /// Build the immutable engine-generation policy for runtime knobs that live
    /// outside Apple's `NETransparentProxyNetworkSettings`.
    ///
    /// Rust's `TransparentProxyConfig` is authoritative. This function is pure
    /// apart from logging: a replacement start must not mutate policy observed
    /// by the still-active or retiring generation before atomic attachment.
    internal static func makeRuntimePolicy(
        from startup: RamaTransparentProxyConfigBridge,
        logLifecycle: (String) -> Void = { _ in }
    ) -> TransparentProxyRuntimePolicy {
        let policy = TransparentProxyRuntimePolicy(startup: startup)
        let flowPressure = policy.flowPressure
        let tcpStart = policy.tcpStartAdmission

        if flowPressure.softCap != startup.flowPressureSoftCap {
            logLifecycle(
                "flow pressure softCap=\(startup.flowPressureSoftCap) exceeds enabled "
                    + "liveHardCap=\(startup.liveFlowHardCap); using \(flowPressure.softCap)"
            )
        }
        if flowPressure.lowWater != startup.flowPressureLowWater {
            logLifecycle(
                "flow pressure lowWater=\(startup.flowPressureLowWater) outside 0..<"
                    + "\(flowPressure.softCap); using \(flowPressure.lowWater)"
            )
        }
        if tcpStart.softCap != startup.tcpStartInFlightSoftCap {
            logLifecycle(
                "tcp start softCap=\(startup.tcpStartInFlightSoftCap) exceeds enabled "
                    + "hardCap=\(startup.tcpStartInFlightHardCap); using \(tcpStart.softCap)"
            )
        }
        logLifecycle(
            "tcp write pump cap set to \(policy.tcpWritePump.maxPendingBytes) bytes from engine config")
        logLifecycle(
            "flow refusal action=\(policy.flowRefusal == .passthrough ? "passthrough (fail open)" : "block (fail closed)")"
        )
        logLifecycle(
            "tcp overload config hardCap=\(tcpStart.hardCap) softCap=\(tcpStart.softCap) openP95Ms=\(tcpStart.breakerOpenP95Ms) closeP95Ms=\(tcpStart.breakerCloseP95Ms) pressureTimeoutMs=\(tcpStart.pressureConnectTimeoutMs) breakerTimeoutMs=\(tcpStart.breakerConnectTimeoutMs)"
        )
        logLifecycle(
            "flow pressure config softCap=\(flowPressure.softCap) lowWater=\(flowPressure.lowWater) idleFloorMs=\(flowPressure.idleFloorMs) liveHardCap=\(flowPressure.liveHardCap)"
        )
        return policy
    }

    #if DEBUG || RAMA_TESTING
    /// Compatibility shim for tests that intentionally exercise the legacy
    /// engine-less defaults. Production startup never calls this mutating
    /// helper; it builds `makeRuntimePolicy` and publishes the value with the
    /// engine instead.
    @discardableResult
    internal static func applyRuntimeConfig(
        from startup: RamaTransparentProxyConfigBridge,
        logLifecycle: (String) -> Void = { _ in }
    ) -> TransparentProxyRuntimePolicy {
        let policy = makeRuntimePolicy(from: startup, logLifecycle: logLifecycle)
        writePumpMaxPendingBytes = policy.tcpWritePump.maxPendingBytes
        writePumpHwmLogThresholdBytes = policy.tcpWritePump.hwmLogThresholdBytes
        setFlowPressureDefaults(
            softCap: policy.flowPressure.softCap,
            lowWater: policy.flowPressure.lowWater,
            idleFloorMs: policy.flowPressure.idleFloorMs,
            hardCap: policy.flowPressure.liveHardCap)
        defaultUdpIdleTimeoutMs = policy.udpIdleTimeoutMs
        defaultTcpStartInFlightHardCap = policy.tcpStartAdmission.hardCap
        defaultTcpStartInFlightSoftCap = policy.tcpStartAdmission.softCap
        defaultTcpStartLatencyBreakerP95Ms = policy.tcpStartAdmission.breakerOpenP95Ms
        defaultTcpStartLatencyBreakerCloseP95Ms =
            policy.tcpStartAdmission.breakerCloseP95Ms
        defaultTcpPressureConnectTimeoutMs =
            policy.tcpStartAdmission.pressureConnectTimeoutMs
        defaultTcpBreakerConnectTimeoutMs =
            policy.tcpStartAdmission.breakerConnectTimeoutMs
        defaultFlowRefusalPassthrough = policy.flowRefusal.isPassthrough
        return policy
    }
    #endif

    /// Translate one Rust-side rule into one or more
    /// `NENetworkRule`s. Returns an empty array on invalid
    /// input. A port-only rule (no `remoteNetwork`) expands to
    /// two rules — one for IPv4, one for IPv6 wildcards — so
    /// the port constraint is preserved at the framework level.
    internal static func makeNetworkRules(_ rule: RamaTransparentProxyRuleBridge)
        -> [NENetworkRule]
    {
        let proto = networkRuleProtocol(rule.protocolRaw)
        let local = networkEndpoint(from: rule.localNetwork, port: nil)

        // Port-only: synthesise wildcard endpoints so the port
        // constraint actually reaches Apple's framework. Two
        // rules — v4 + v6 — because a wildcard endpoint can
        // only carry one address family.
        if rule.remoteNetwork == nil, let port = rule.remotePort {
            let portStr = String(port)
            let v4 = NWHostEndpoint(hostname: "0.0.0.0", port: portStr)
            let v6 = NWHostEndpoint(hostname: "::", port: portStr)
            let localPrefix =
                resolvedPrefix(
                    endpoint: local,
                    networkText: rule.localNetwork,
                    explicitPrefix: rule.localPrefix
                ) ?? 0
            return [v4, v6].map {
                NENetworkRule(
                    remoteNetwork: $0,
                    remotePrefix: 0,
                    localNetwork: local,
                    localPrefix: localPrefix,
                    protocol: proto,
                    direction: .outbound
                )
            }
        }

        let remote = networkEndpoint(from: rule.remoteNetwork, port: rule.remotePort)

        // Host/domain-only rule (no local matcher): use destination-host initializer.
        // This avoids forcing CIDR for non-IP hosts (e.g. example.com).
        if let remote, local == nil, rule.remotePrefix == nil {
            return [NENetworkRule(destinationHost: remote, protocol: proto)]
        }

        guard
            let remotePrefix = resolvedPrefix(
                endpoint: remote,
                networkText: rule.remoteNetwork,
                explicitPrefix: rule.remotePrefix
            ),
            let localPrefix = resolvedPrefix(
                endpoint: local,
                networkText: rule.localNetwork,
                explicitPrefix: rule.localPrefix
            )
        else {
            return []
        }

        return [
            NENetworkRule(
                remoteNetwork: remote,
                remotePrefix: remotePrefix,
                localNetwork: local,
                localPrefix: localPrefix,
                protocol: proto,
                direction: .outbound
            )
        ]
    }

    internal static func resolvedPrefix(
        endpoint: NWHostEndpoint?,
        networkText: String?,
        explicitPrefix: UInt8?
    ) -> Int? {
        guard endpoint != nil else { return 0 }
        if let explicitPrefix {
            guard
                let maxPrefix = maxPrefixLength(endpoint: endpoint, networkText: networkText),
                Int(explicitPrefix) <= maxPrefix
            else {
                return nil
            }
            return Int(explicitPrefix)
        }
        guard let networkText else { return nil }
        return inferredHostPrefix(networkText)
    }

    private static func maxPrefixLength(
        endpoint: NWHostEndpoint?,
        networkText: String?
    ) -> Int? {
        if let networkText, let prefix = inferredHostPrefix(networkText) {
            return prefix
        }
        guard let endpoint else { return nil }
        return inferredHostPrefix(endpoint.hostname)
    }

    internal static func networkEndpoint(from network: String?, port: UInt16?) -> NWHostEndpoint? {
        guard let network, !network.isEmpty else { return nil }
        let portStr = port.map(String.init) ?? "0"
        return NWHostEndpoint(hostname: network, port: portStr)
    }

    /// Pull `engineConfigJson` from `startOptions` (preferred — the
    /// container app passes it in the start API call) or from
    /// `providerConfiguration` (fallback, for cases where the
    /// container app stored it on the protocol configuration).
    ///
    /// # Security note
    ///
    /// `providerConfiguration` is **logged automatically** by the
    /// system: it shows up in Apple diagnostic output (`log show`
    /// streams, sysdiagnose archives, crash reports) with no way for
    /// the extension to suppress this. **Never put secrets, private
    /// keys, or credentials in `engineConfigJson`** — only
    /// non-sensitive runtime settings (timeouts, domain exclusions,
    /// feature flags, telemetry knobs, public-info config). For
    /// sensitive material, use the system keychain (see
    /// `system_keychain` in the rama Rust crate) or transport it
    /// over a secure XPC connection from the container app at
    /// runtime.
    ///
    /// The `startOptions` path is less leaky than
    /// `providerConfiguration` (it's not part of the persisted
    /// configuration), but Apple makes no guarantees that start
    /// options aren't logged either — the rule of thumb is the same:
    /// no secrets here.
    internal static func engineConfigJson(
        protocolConfiguration: NETunnelProviderProtocol?,
        startOptions: [String: Any]?
    ) -> Data? {
        if let json = startOptions?["engineConfigJson"] as? Data, !json.isEmpty {
            return json
        }
        if let json = startOptions?["engineConfigJson"] as? String, !json.isEmpty {
            return Data(json.utf8)
        }

        let providerConfiguration = protocolConfiguration?.providerConfiguration
        if let json = providerConfiguration?["engineConfigJson"] as? Data, !json.isEmpty {
            return json
        }
        if let json = providerConfiguration?["engineConfigJson"] as? String, !json.isEmpty {
            return Data(json.utf8)
        }

        return nil
    }

    internal static func networkRuleProtocol(_ raw: UInt32) -> NENetworkRule.`Protocol` {
        switch raw {
        case UInt32(RAMA_RULE_PROTOCOL_TCP.rawValue): return .TCP
        case UInt32(RAMA_RULE_PROTOCOL_UDP.rawValue): return .UDP
        default: return .any
        }
    }

    internal static func tcpMeta(flow: NEAppProxyTCPFlow) -> RamaTransparentProxyFlowMetaBridge {
        let remote: Any?
        if #available(macOS 15.0, *) {
            remote = flow.remoteFlowEndpoint
        } else {
            remote = flow.remoteEndpoint
        }
        let remoteEndpoint = endpointHostPort(remote)
        // NEAppProxyTCPFlow exposes the remote endpoint but no public local
        // endpoint on either callback generation. Keep the field absent rather
        // than probing undeclared selectors on the flow object.
        let localEndpoint: EndpointHostPort? = nil
        let appMeta = sourceAppMeta(flow)
        let ifaceMeta = flowInterfaceMeta(flow)
        return RamaTransparentProxyFlowMetaBridge(
            protocolRaw: UInt32(RAMA_FLOW_PROTOCOL_TCP.rawValue),
            remoteHost: remoteEndpoint?.host,
            remotePort: remoteEndpoint?.port ?? 0,
            localHost: localEndpoint?.host,
            localPort: localEndpoint?.port ?? 0,
            sourceAppSigningIdentifier: appMeta.signingIdentifier,
            sourceAppBundleIdentifier: appMeta.bundleIdentifier,
            sourceAppAuditToken: appMeta.auditToken,
            sourceAppPid: appMeta.pid,
            remoteHostname: ifaceMeta.remoteHostname,
            localInterfaceName: ifaceMeta.interfaceName,
            localInterfaceType: ifaceMeta.interfaceType,
            localInterfaceIndex: ifaceMeta.interfaceIndex,
            isBound: ifaceMeta.isBound
        )
    }

    internal static func udpMeta(
        flow: NEAppProxyUDPFlow?,
        remoteEndpoint: EndpointHostPort?,
        localEndpoint: EndpointHostPort?
    ) -> RamaTransparentProxyFlowMetaBridge {
        let appMeta = sourceAppMeta(flow)
        let ifaceMeta = flowInterfaceMeta(flow)
        return RamaTransparentProxyFlowMetaBridge(
            protocolRaw: UInt32(RAMA_FLOW_PROTOCOL_UDP.rawValue),
            remoteHost: remoteEndpoint?.host,
            remotePort: remoteEndpoint?.port ?? 0,
            localHost: localEndpoint?.host,
            localPort: localEndpoint?.port ?? 0,
            sourceAppSigningIdentifier: appMeta.signingIdentifier,
            sourceAppBundleIdentifier: appMeta.bundleIdentifier,
            sourceAppAuditToken: appMeta.auditToken,
            sourceAppPid: appMeta.pid,
            remoteHostname: ifaceMeta.remoteHostname,
            localInterfaceName: ifaceMeta.interfaceName,
            localInterfaceType: ifaceMeta.interfaceType,
            localInterfaceIndex: ifaceMeta.interfaceIndex,
            isBound: ifaceMeta.isBound
        )
    }

    internal static func sourceAppMeta(_ flow: NEAppProxyFlow?) -> (
        signingIdentifier: String?, bundleIdentifier: String?, auditToken: Data?, pid: Int32?
    ) {
        guard let flow else { return (nil, nil, nil, nil) }
        let raw = flow.metaData.sourceAppSigningIdentifier.trimmingCharacters(
            in: .whitespacesAndNewlines)
        let signingIdentifier = raw.isEmpty ? nil : raw
        let auditToken = flow.metaData.sourceAppAuditToken
        let pid: Int32? =
            auditToken.flatMap { token in
                guard !token.isEmpty else { return nil }
                let resolved = token.withUnsafeBytes { raw in
                    rama_apple_audit_token_to_pid(
                        raw.bindMemory(to: UInt8.self).baseAddress,
                        raw.count
                    )
                }
                return resolved >= 0 ? resolved : nil
            }
        return (
            signingIdentifier, deriveBundleId(fromSigningId: signingIdentifier), auditToken, pid
        )
    }

    /// Best-effort derivation of the bundle identifier from
    /// `NEFlowMetaData.sourceAppSigningIdentifier`. Apple does not
    /// expose a separate `sourceAppBundleIdentifier` on
    /// `NEFlowMetaData`; the signing identifier is either the bundle
    /// id directly (system / unsigned processes such as
    /// `org.mozilla.firefox`) or the bundle id prefixed with the
    /// 10-character Apple Developer team ID and a dot
    /// (e.g. `7VPF8GD6J4.com.example.app`).
    ///
    /// Returns the substring after the team-id prefix when one is
    /// detected, otherwise the signing identifier as-is. Per-app
    /// policy code that expects raw bundle ids (e.g.
    /// `com.fortinet.forticlient.ztagent`) needs this stripping;
    /// without it, team-signed apps silently fail to match because
    /// their signing id carries the prefix.
    ///
    /// **Heuristic, not exact.** A signing identifier whose first
    /// component happens to be exactly 10 uppercase alphanumeric
    /// characters followed by a dot (e.g.
    /// `ABCDEFGHIJ.example.weird-app`) is indistinguishable from a
    /// team-prefixed identifier. Real-world reverse-DNS bundle ids
    /// almost never collide with the team-id shape (they start with
    /// short lowercase TLD-style components), but rare exceptions
    /// will be misclassified. If exact attribution matters, key on
    /// the raw signing identifier instead.
    public static func deriveBundleId(fromSigningId signingId: String?) -> String? {
        guard let signingId, !signingId.isEmpty else { return nil }
        let teamIdLength = 10
        let scalars = signingId.unicodeScalars
        guard scalars.count > teamIdLength + 1 else { return signingId }
        let prefixEnd = scalars.index(scalars.startIndex, offsetBy: teamIdLength)
        // Team ID is exactly 10 ASCII alphanumeric chars, uppercase
        // letters or digits. Anything else means the signing id is
        // already a bare bundle id (e.g. `org.mozilla.firefox`).
        let isTeamPrefix = scalars[..<prefixEnd].allSatisfy { scalar in
            (scalar.value >= 0x41 && scalar.value <= 0x5A)  // A-Z
                || (scalar.value >= 0x30 && scalar.value <= 0x39)  // 0-9
        }
        guard isTeamPrefix, scalars[prefixEnd] == "." else { return signingId }
        let bundleStart = scalars.index(after: prefixEnd)
        return String(String.UnicodeScalarView(scalars[bundleStart...]))
    }

    internal static func udpLocalEndpoint(flow: NEAppProxyUDPFlow) -> EndpointHostPort? {
        if #available(macOS 15.0, *) {
            return flow.localFlowEndpoint.flatMap { networkEndpointHostPort($0) }
        }
        return legacyUdpLocalEndpoint(flow: flow)
    }

    /// `localEndpoint` is the public pre-15 UDP API. Isolating the deprecated
    /// reference in an obsoleted helper keeps the modern path warning-free.
    @available(macOS, introduced: 10.11, obsoleted: 15.0)
    internal static func legacyUdpLocalEndpoint(
        flow: NEAppProxyUDPFlow
    ) -> EndpointHostPort? {
        endpointHostPort(flow.localEndpoint)
    }

    internal static func endpointHostPort(_ endpoint: Any?) -> EndpointHostPort? {
        guard let endpoint else { return nil }

        // A typed Network endpoint (including TCP's macOS 15+
        // `remoteFlowEndpoint`) always uses the public enum conversion above.
        if let converted = networkEndpointHostPortFromAny(endpoint) {
            return converted
        }

        // Fast path: NWHostEndpoint (NetworkExtension class, works on macOS ≤ 15).
        if let hostEndpoint = endpoint as? NWHostEndpoint {
            let host = hostEndpoint.hostname.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty, let port = UInt16(hostEndpoint.port) else {
                return nil
            }
            return EndpointHostPort(host: host, port: port)
        }

        // macOS 15 can deliver the retained legacy callback's argument as the
        // private NWConcreteHostEndpoint class. It is not an NWHostEndpoint
        // subclass, but it exposes the same hostname/port Objective-C shape.
        // Keep this compatibility fallback after both public typed paths.
        if let object = endpoint as? NSObject {
            let hostnameSelector = NSSelectorFromString("hostname")
            let portSelector = NSSelectorFromString("port")
            if object.responds(to: hostnameSelector), object.responds(to: portSelector),
                let rawHostname = object.value(forKey: "hostname") as? String
            {
                let host = rawHostname.trimmingCharacters(in: .whitespacesAndNewlines)
                let rawPort = object.value(forKey: "port")
                let portText: String?
                if let string = rawPort as? String {
                    portText = string
                } else if let number = rawPort as? NSNumber {
                    portText = number.stringValue
                } else {
                    portText = nil
                }
                if !host.isEmpty, let portText, let port = UInt16(portText) {
                    return EndpointHostPort(host: host, port: port)
                }
            }
        }

        // Last resort: parse the endpoint's string description. That format is unstable
        // across macOS releases; log at DEBUG so a future breakage shows up as debug
        // chatter rather than silently degrading every flow to "no remote endpoint".
        let raw = String(describing: endpoint)
        guard !raw.isEmpty else { return nil }
        let parsed = parseEndpointString(raw)
        let typeName = String(reflecting: type(of: endpoint))
        if parsed != nil {
            RamaLog.debug(
                "endpointHostPort: description fallback succeeded for \(typeName): raw=\(raw)"
            )
        } else {
            RamaLog.debug(
                "endpointHostPort: all fallbacks failed for \(typeName): raw=\(raw)"
            )
        }
        return parsed.map { EndpointHostPort(host: $0.host, port: $0.port) }
    }

}

extension RamaTransparentProxyProvider {
    fileprivate static func defaultRustStorageDirectory() -> URL? {
        guard
            let base = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first
        else {
            return nil
        }
        return
            base
            .appendingPathComponent("rama", isDirectory: true)
            .appendingPathComponent("tproxy", isDirectory: true)
    }
}
// ── NWConnection helpers ──────────────────────────────────────────────────────

/// Creates TCP `NWParameters` from optional Rust-supplied egress options.
///
/// The `connect_timeout_ms` field intentionally does not propagate to
/// `NWProtocolTCP.Options.connectionTimeout`. Apple's API takes seconds
/// (Int), our FFI carries milliseconds, and the resulting ms→s round
/// would silently change a 999ms cap into 1s. The dispatcher already
/// enforces the timeout via a millisecond-precision DispatchWorkItem
/// (see `handleTcpFlow`), so we have a single canonical timeout
/// instead of two with mismatched precision.
///
/// Sets `preferNoProxies = true` unless the engine opts in via
/// `allow_system_proxy` — breaks the stacked-proxy loop documented in
/// the `tproxy` module preamble (Apple TN3134). Only scopes the
/// SystemConfiguration proxy table; other NE providers / VPNs are
/// unaffected.
///
/// Enables TCP keepalive on the egress connection by default (opt-out
/// via `tcp_keepalive_enabled`) — see `applyTcpKeepalive`. Further TCP
/// tuning (noDelay, MSS, …) is opt-in per field — see `applyTcpTuning`.
func makeTcpNwParameters(_ opts: RamaTcpEgressConnectOptions?) -> NWParameters {
    // Configure keepalive on the options before wrapping them, rather than
    // extracting them back out of the constructed NWParameters.
    let tcpOptions = NWProtocolTCP.Options()
    applyTcpKeepalive(opts, to: tcpOptions)
    applyTcpTuning(opts, to: tcpOptions)
    let params = NWParameters(tls: nil, tcp: tcpOptions)
    if let opts {
        applyNwEgressParameters(opts.parameters, to: params)
    }
    // `opts == nil` matches Rust-side default (`allow_system_proxy: false`).
    params.preferNoProxies = !(opts?.parameters.allow_system_proxy ?? false)
    return params
}

// Keepalive defaults: detection ≈ idle + interval*count = 30 s — under the
// 60 s watchdog, above a sub-second Wi-Fi blip. Overridable per flow.
let defaultTcpKeepaliveIdleSec: Int = 15
let defaultTcpKeepaliveIntervalSec: Int = 5
let defaultTcpKeepaliveCount: Int = 3

/// Apply TCP keepalive to the egress connection's `NWProtocolTCP.Options`.
/// On by default (nil opts, or `tcp_keepalive_enabled`). Self-heals a
/// silently-dead egress: after sleep / VPN reset / NAT rebind a connection
/// can sit `.ready` over a black-holed path (NW fires neither `.waiting` nor
/// `.failed`, viability stays true) and wedge until the 60 s watchdog;
/// keepalive probes fail it → `.failed` → existing reaper → app reconnects.
/// Opt out with `tcp_keepalive_enabled = false`.
private func applyTcpKeepalive(_ opts: RamaTcpEgressConnectOptions?, to tcp: NWProtocolTCP.Options)
{
    guard opts?.tcpKeepaliveEnabled ?? true else {
        tcp.enableKeepalive = false
        return
    }
    tcp.enableKeepalive = true
    tcp.keepaliveIdle = opts?.tcpKeepaliveIdleSec ?? defaultTcpKeepaliveIdleSec
    tcp.keepaliveInterval = opts?.tcpKeepaliveIntervalSec ?? defaultTcpKeepaliveIntervalSec
    tcp.keepaliveCount = opts?.tcpKeepaliveCount ?? defaultTcpKeepaliveCount
}

/// Apply the handler's per-field TCP tuning to the egress connection's
/// `NWProtocolTCP.Options`. `noDelay` is always applied and defaults ON
/// (nil opts, or `tcp_no_delay`) — on a claimed flow the app has no real
/// socket, so the egress connection is the only Nagle decision in the
/// path, and leaving Nagle on adds delayed-ACK TTFB stalls the app never
/// opted into. Every other field is opt-in (`has_*` false ⇒ the
/// Network.framework default is left untouched).
private func applyTcpTuning(_ opts: RamaTcpEgressConnectOptions?, to tcp: NWProtocolTCP.Options) {
    tcp.noDelay = opts?.tcpNoDelay ?? true
    guard let opts else { return }
    if let noPush = opts.tcpNoPush {
        tcp.noPush = noPush
    }
    if let noOptions = opts.tcpNoOptions {
        tcp.noOptions = noOptions
    }
    if let retransmitFinDrop = opts.tcpRetransmitFinDrop {
        tcp.retransmitFinDrop = retransmitFinDrop
    }
    if let disableAckStretching = opts.tcpDisableAckStretching {
        tcp.disableAckStretching = disableAckStretching
    }
    if let enableFastOpen = opts.tcpEnableFastOpen {
        tcp.enableFastOpen = enableFastOpen
    }
    if let disableEcn = opts.tcpDisableEcn {
        tcp.disableECN = disableEcn
    }
    if let maximumSegmentSize = opts.tcpMaximumSegmentSize {
        tcp.maximumSegmentSize = maximumSegmentSize
    }
    if let connectionDropTime = opts.tcpConnectionDropTimeSec {
        tcp.connectionDropTime = connectionDropTime
    }
    if let persistTimeout = opts.tcpPersistTimeoutSec {
        tcp.persistTimeout = persistTimeout
    }
}

/// Capability `applyFlowMetadata` needs from a flow: stamp the source-app
/// `NEFlowMetaData` onto egress `NWParameters` so a downstream proxy
/// attributes the connection to the original app, not to this extension.
///
/// Behind a protocol so the macOS-version routing in `applyFlowMetadata`
/// is unit-testable without a live `NEAppProxyFlow`. There is deliberately
/// no pre-macOS-15 member: before macOS 15 the stamp cannot be applied
/// safely (see `applyFlowMetadata`), so the seam must not offer a way to try.
protocol EgressMetadataFlow: AnyObject {
    /// Caller guarantees macOS 15+.
    func stampSourceAppMetadata(onto params: NWParameters)
}

extension NEAppProxyFlow: EgressMetadataFlow {
    func stampSourceAppMetadata(onto params: NWParameters) {
        // The typed overlay performs the `NWParameters -> nw_parameters_t`
        // bridge; it — and this method — only run on macOS 15+.
        if #available(macOS 15.0, *) {
            setMetadata(on: params)
        }
    }
}

func isMacOS15OrLater() -> Bool {
    if #available(macOS 15.0, *) { return true }
    return false
}

/// Stamp the intercepted flow's `NEFlowMetaData` onto the egress
/// `NWParameters` via the typed `NEAppProxyFlow.setMetadata(on:)` overlay.
///
/// macOS 15+ only. The Obj-C method `-[NEAppProxyFlow setMetadata:]` takes an
/// `nw_parameters_t`; the typed Swift overlay performs the `NWParameters ->
/// nw_parameters_t` bridge for us. Before macOS 15 there is no public way to
/// stamp: the overlay is 15.0-gated and there is no public `NWParameters ->
/// nw_parameters_t` accessor. A prior version invoked the raw `setMetadata:`
/// selector via `perform(_:with:)` with the Swift `NWParameters` wrapper —
/// unbridged — so Apple's `nw_parameters_set_metadata` read a
/// `Network._NWParameters` as an `OS_nw_parameters` and corrupted the heap.
/// That was the macOS-14 new-flow crashloop (over-release / dealloc faults
/// inside `nw_parameters_set_metadata`). So before macOS 15 we omit the stamp
/// rather than corrupt memory; egress source-app attribution is unavailable
/// on hosts older than macOS 15 (the gate is the runtime OS, not the
/// deployment target — the extension ships a macOS 12 target).
func applyFlowMetadata(
    _ flow: EgressMetadataFlow,
    _ params: NWParameters,
    macOS15OrLater: Bool = isMacOS15OrLater()
) {
    guard macOS15OrLater else {
        RamaLog.debug(
            "applyFlowMetadata: omitting egress source-app metadata on macOS < 15 (no safe public NWParameters -> nw_parameters_t bridge)"
        )
        return
    }
    flow.stampSourceAppMetadata(onto: params)
}

private func applyNwEgressParameters(_ p: RamaNwEgressParameters, to params: NWParameters) {
    if p.has_service_class, let sc = nwServiceClass(p.service_class) {
        params.serviceClass = sc
    }
    if p.has_multipath_service_type {
        params.multipathServiceType = nwMultipathServiceType(p.multipath_service_type)
    }
    if p.has_required_interface_type {
        params.requiredInterfaceType = nwInterfaceType(p.required_interface_type)
    }
    if #available(macOS 11.3, *), p.has_attribution {
        params.attribution = p.attribution == 1 ? .user : .developer
    }
    var prohibited: [NWInterface.InterfaceType] = []
    let mask = p.prohibited_interface_types_mask
    if mask & (1 << 0) != 0 { prohibited.append(.cellular) }
    if mask & (1 << 1) != 0 { prohibited.append(.loopback) }
    if mask & (1 << 2) != 0 { prohibited.append(.other) }
    if mask & (1 << 3) != 0 { prohibited.append(.wifi) }
    if mask & (1 << 4) != 0 { prohibited.append(.wiredEthernet) }
    if !prohibited.isEmpty {
        params.prohibitedInterfaceTypes = prohibited
    }
}

private func nwServiceClass(_ raw: UInt8) -> NWParameters.ServiceClass? {
    switch raw {
    case 0: return nil  // Default: don't override — omit the field entirely
    case 1: return .background
    case 2: return .interactiveVideo
    case 3: return .interactiveVoice
    case 4: return .responsiveData
    case 5: return .signaling
    default: return nil
    }
}

private func nwMultipathServiceType(_ raw: UInt8) -> NWParameters.MultipathServiceType {
    switch raw {
    case 1: return .handover
    case 2: return .interactive
    case 3: return .aggregate
    default: return .disabled
    }
}

private func nwInterfaceType(_ raw: UInt8) -> NWInterface.InterfaceType {
    switch raw {
    case 0: return .cellular
    case 1: return .loopback
    case 3: return .wifi
    case 4: return .wiredEthernet
    default: return .other
    }
}

/// Reads from a `NWConnection` in a loop and forwards data to a Rust TCP session.
///
/// Calls `session.onEgressBytes(_:)` for each received chunk and
/// `session.onEgressEof()` when the connection closes or fails.
///
/// Honors backpressure: when `onEgressBytes` returns `false` the Rust side's
/// per-flow egress channel is full, and we stop scheduling further
/// `connection.receive` calls until the matching `onEgressReadDemand`
/// callback flips `paused` back to `false` via `resume()`.
