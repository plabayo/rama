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

enum FlowLogLevel {
    case trace
    case debug
    case error
}

struct FlowLogMessage {
    let level: FlowLogLevel
    let text: String
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

/// Wall-clock cap on the transient-error retry loop. After this many
/// milliseconds without a successful write the pump tears down,
/// regardless of how short each individual retry was. Without a hard
/// deadline, sustained kernel-buffer pressure on a flow whose calling
/// app has effectively died keeps the retry loop spinning indefinitely
/// — the loop's `asyncAfter` strongly captures the pump, so it pins
/// itself alive until the kernel finally returns a non-transient
/// error. 5 s is enough to ride out a real h2 stall while bounding
/// the worst-case wedge.
///
/// `var` for tests that need a short deadline to keep runtime bounded
/// — same pattern as `defaultLingerCloseMs` / `defaultEgressWaitingToleranceMs`.
nonisolated(unsafe) var writeRetryHardDeadlineMs: Int = 5_000

/// Memory budget (in bytes) each writer pump (TCP response and TCP egress)
/// keeps queued before it tells the Rust bridge to pause.
///
/// Byte-based rather than chunk-count based: a chunk-count cap of N bounds
/// worst-case memory at `N * max_chunk_size`, which with our 16–64 KiB
/// chunks blows up fast under h2 multiplexing (many concurrent flows each
/// holding the full chunk-count budget). A byte budget is constant
/// regardless of chunk size.
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

/// Drop-on-full bound for `UdpClientWritePump.pending`. UDP is lossy by
/// definition, so the pump prefers dropping the newest datagram on
/// overflow over indefinite buffering. Picked to absorb a brief stall
/// (e.g. waiting for the first client read so `sentByEndpoint` is
/// known) without blowing up under a misbehaving producer.
let udpWritePumpMaxPending: Int = 256

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

/// Default wall-clock cap on how long the egress NWConnection lingers
/// after the local side has sent its FIN before Swift force-cancels
/// it. Applied when `RamaTcpEgressConnectOptions.has_linger_close_ms`
/// is `false`; an explicit Rust-side `NwTcpConnectOptions.linger_close_timeout`
/// overrides. 5 seconds is generous enough for any healthy peer to
/// FIN-ACK and short enough that 200 slow-closing flows cap at a few
/// hundred concurrent FIN_WAIT_1 sockets rather than accumulating.
///
/// `var` for tests that need a short linger to keep ARC-leak-check
/// runtime bounded — same pattern as `defaultEgressWaitingToleranceMs`.
/// The linger watchdog holds `connection` strongly until it fires;
/// tests that assert `weakConn == nil` after teardown need to clamp
/// this so the watchdog releases before the polling deadline.
nonisolated(unsafe) var defaultLingerCloseMs: UInt32 = 5_000

/// Default grace window between the egress read pump observing peer
/// EOF / read error and the backstop `connection.cancel()` firing.
/// Applied when `RamaTcpEgressConnectOptions.has_egress_eof_grace_ms`
/// is `false`. 2 seconds is enough headroom for the clean teardown
/// path (`on_server_closed` → `closeWhenDrained` → cancel) to
/// complete on the common case, while still bounding cleanup when
/// the originating app has stopped reading.
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

/// Budget for an egress `NWConnection` in `.waiting(_)` *before* it
/// ever reaches `.ready` (path down at connect — boot, wake, VPN
/// transition). Fail fast instead of hanging the 30 s connect timeout;
/// a few seconds, not instant, rides out a sub-second connect blip that
/// recovers to `.ready`. `var` for tests.
nonisolated(unsafe) var defaultEgressPreReadyWaitingBudgetMs: UInt32 = 3_000

/// Default per-UDP-flow idle watchdog. Apple's `NEAppProxyUDPFlow`
/// gives the extension no terminal signal for an idle peer (UDP has
/// no FIN, and the kernel's `flow.readDatagrams` callback only
/// observes errors / EOF on explicit close). Without a watchdog, a
/// flow that completes a few request/response datagrams and then
/// goes quiet (DNS, mDNS probes, NAT-binding pings, …) stays
/// registered in `TransparentProxyCore.udpSessions` until the
/// engine-side `udp_max_flow_lifetime` cap fires — 15 min by
/// default, which is long enough to accumulate thousands of
/// pinned sessions under normal device traffic.
///
/// 60 s is the smallest window that comfortably exceeds typical
/// real-world UDP-flow idle gaps (DNS retry cadence, NAT-keepalive
/// intervals, mDNS jitter); active flows — QUIC long-poll, WebRTC
/// media — push the deadline forward on every datagram so they're
/// unaffected.
///
/// `var` for tests that need a short timeout to keep ARC-leak-check
/// runtime bounded — same pattern as `defaultLingerCloseMs`.
nonisolated(unsafe) var defaultUdpIdleTimeoutMs: UInt32 = 60_000

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
protocol TcpFlowReadable: AnyObject {
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
struct TcpReadTerminal {
    let onNaturalEof: () -> Void
    let onHardError: (Error) -> Void

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
                text: "\(operation) failed with an unexpected provider/runtime error: \(detail)"
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
protocol TcpFlowWritable: AnyObject {
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

extension NEAppProxyTCPFlow: TcpFlowLike {
    func applyMetadata(to params: NWParameters) {
        applyFlowMetadata(self, params)
    }
}

/// Async-read surface the UDP read pump needs. Mirror of
/// `TcpFlowReadable` for the datagram path. `[NWEndpoint]?` tracks
/// the per-datagram source so `sentBy:` on a corresponding write
/// echoes back to the same peer.
protocol UdpFlowReadable: AnyObject {
    func readDatagrams(
        completionHandler: @escaping @Sendable ([Data]?, [NWEndpoint]?, Error?) -> Void
    )
}
extension NEAppProxyUDPFlow: UdpFlowReadable {}

/// Async-write surface the UDP writer pump needs.
protocol UdpFlowWritable: AnyObject {
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
    /// Set when an `enqueue` returned `.paused`. We fire `onDrained`
    /// on the first removal that drops `pendingBytes` below the cap,
    /// then clear — edge-triggered so we never spam Rust with
    /// redundant drain signals while the queue churns at-cap.
    var pausedSignaled: Bool = false
    /// All-time peak of `pendingBytes` for this pump instance.  Updated
    /// atomically under the lock so the high-water telemetry log fires
    /// exactly once per new peak above `writePumpHwmLogThresholdBytes`.
    var pendingBytesHwm: Int = 0
}

/// Delegates lifecycle callbacks from `TcpWritePumpCore` to its owner.
/// All calls are made on `core.queue`, never on a Tokio or FFI thread.
///
/// **Re-entrancy constraint:** implementations MUST NOT call back into
/// `core` or acquire `core.state` from within either method.
/// `Locked<T>` wraps a non-reentrant `NSLock`; a nested `withLock` on
/// the same instance deadlocks deterministically.  Both methods are
/// invoked after the lock has been released, so there is no active lock
/// to re-enter — but future implementors should not assume otherwise.


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
        guard RamaTransparentProxyEngineHandle.initialize(storageDir: storageDir, appGroupDir: nil)
        else {
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
        core.attachEngine(engine)
        core.logLifecycle("engine created")

        guard let startup = engine.config() else {
            core.logLifecycleError("failed to get transparent proxy config from rust")
            // Apple does NOT call `stopProxy` to clean up after a failed
            // `startProxy`, so any state we attached above must be torn
            // down locally before we surface the error — otherwise the
            // engine and the 60s flow-count telemetry timer leak until
            // the next provider lifecycle.
            core.detachEngine(reason: 0)
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

        // The engine's value is authoritative — the previous "0 means
        // unset" path was dead code (the default is non-zero), so the
        // Swift initial value of `writePumpMaxPendingBytes` was never
        // used in practice and the documented per-flow cap silently
        // drifted from what the comments described.
        writePumpMaxPendingBytes = startup.tcpWritePumpMaxPendingBytes
        writePumpHwmLogThresholdBytes = writePumpMaxPendingBytes / 2
        core.logLifecycle("tcp write pump cap set to \(writePumpMaxPendingBytes) bytes from engine config")

        let settings = Self.buildNetworkSettings(
            from: startup,
            logInfo: { [core] msg in core.logInfo(msg) },
            logError: { [core] msg in core.logError(msg) }
        )

        setTunnelNetworkSettings(settings) { [core] error in
            if let error {
                core.logLifecycleError("setTunnelNetworkSettings error: \(error)")
                // Same reason as the `engine.config()` failure path:
                // Apple won't compensate via `stopProxy`, so we must
                // tear down the engine + telemetry timer locally.
                core.detachEngine(reason: 0)
                completionHandler(error)
                return
            }
            core.logLifecycle("setTunnelNetworkSettings ok")
            completionHandler(nil)
        }
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
        // NEFlowMetaData snapshot (and, for UDP, the local / remote
        // NEAppProxyUDPFlow endpoints) before handing the flow to the
        // core. Once the metadata is a plain struct the core's
        // per-flow handler is generic over `TcpFlowLike` /
        // `UdpFlowLike`, so the same code path is reused verbatim by
        // unit tests that pass in a mock flow.
        if let tcp = flow as? NEAppProxyTCPFlow {
            let meta = Self.tcpMeta(flow: tcp)
            return core.handleTcpFlow(tcp, meta: meta)
        }
        if let udp = flow as? NEAppProxyUDPFlow {
            let meta = Self.udpMeta(
                flow: udp,
                remoteEndpoint: Self.udpRemoteEndpoint(flow: udp),
                localEndpoint: Self.udpLocalEndpoint(flow: udp)
            )
            return core.handleUdpFlow(udp, meta: meta)
        }
        core.logDebug("handleNewFlow unsupported type=\(String(describing: type(of: flow)))")
        return false
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
            let localPrefix = resolvedPrefix(
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

        return [NENetworkRule(
            remoteNetwork: remote,
            remotePrefix: remotePrefix,
            localNetwork: local,
            localPrefix: localPrefix,
            protocol: proto,
            direction: .outbound
        )]
    }

    internal static func resolvedPrefix(
        endpoint: NWHostEndpoint?,
        networkText: String?,
        explicitPrefix: UInt8?
    ) -> Int? {
        guard endpoint != nil else { return 0 }
        if let explicitPrefix { return Int(explicitPrefix) }
        guard let networkText else { return nil }
        return inferredHostPrefix(networkText)
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
        let localEndpoint = endpointHostPort(bestEffortLocalEndpoint(flow))
        let appMeta = sourceAppMeta(flow)
        return RamaTransparentProxyFlowMetaBridge(
            protocolRaw: UInt32(RAMA_FLOW_PROTOCOL_TCP.rawValue),
            remoteHost: remoteEndpoint?.host,
            remotePort: remoteEndpoint?.port ?? 0,
            localHost: localEndpoint?.host,
            localPort: localEndpoint?.port ?? 0,
            sourceAppSigningIdentifier: appMeta.signingIdentifier,
            sourceAppBundleIdentifier: appMeta.bundleIdentifier,
            sourceAppAuditToken: appMeta.auditToken,
            sourceAppPid: appMeta.pid
        )
    }

    internal static func udpMeta(
        flow: NEAppProxyUDPFlow?,
        remoteEndpoint: Any?,
        localEndpoint: Any?
    ) -> RamaTransparentProxyFlowMetaBridge {
        let remote = endpointHostPort(remoteEndpoint)
        let local = endpointHostPort(localEndpoint)
        let appMeta = sourceAppMeta(flow)
        return RamaTransparentProxyFlowMetaBridge(
            protocolRaw: UInt32(RAMA_FLOW_PROTOCOL_UDP.rawValue),
            remoteHost: remote?.host,
            remotePort: remote?.port ?? 0,
            localHost: local?.host,
            localPort: local?.port ?? 0,
            sourceAppSigningIdentifier: appMeta.signingIdentifier,
            sourceAppBundleIdentifier: appMeta.bundleIdentifier,
            sourceAppAuditToken: appMeta.auditToken,
            sourceAppPid: appMeta.pid
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
        return (signingIdentifier, deriveBundleId(fromSigningId: signingIdentifier), auditToken, pid)
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
    static func deriveBundleId(fromSigningId signingId: String?) -> String? {
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

    internal static func udpLocalEndpoint(flow: NEAppProxyUDPFlow) -> Any? {
        if #available(macOS 15.0, *) {
            return flow.localFlowEndpoint
        }
        return bestEffortLocalEndpoint(flow)
    }

    internal static func udpRemoteEndpoint(flow: NEAppProxyUDPFlow) -> Any? {
        let object = flow as NSObject
        if object.responds(to: NSSelectorFromString("remoteFlowEndpoint")) {
            return object.value(forKey: "remoteFlowEndpoint")
        }
        if object.responds(to: NSSelectorFromString("remoteEndpoint")) {
            return object.value(forKey: "remoteEndpoint")
        }
        return nil
    }

    internal static func bestEffortLocalEndpoint(_ flow: NEAppProxyFlow) -> Any? {
        let object = flow as NSObject
        if object.responds(to: NSSelectorFromString("localEndpoint")) {
            return object.value(forKey: "localEndpoint")
        }
        if object.responds(to: NSSelectorFromString("localFlowEndpoint")) {
            return object.value(forKey: "localFlowEndpoint")
        }
        return nil
    }

    internal static func endpointHostPort(_ endpoint: Any?) -> (host: String, port: UInt16)? {
        guard let endpoint else { return nil }

        // Fast path: NWHostEndpoint (NetworkExtension class, works on macOS ≤ 15).
        if let hostEndpoint = endpoint as? NWHostEndpoint {
            let host = hostEndpoint.hostname.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty, let port = UInt16(hostEndpoint.port) else {
                return nil
            }
            return (host, port)
        }

        // On macOS 15+ Apple ships a private concrete class (NWConcreteHostEndpoint) that
        // no longer inherits from the public NWHostEndpoint, but still exposes the same
        // `hostname: String` and `port: String` KVC keys. Reach for them directly so we
        // don't rely on the unstable string-description format.
        if let obj = endpoint as? NSObject,
            obj.responds(to: NSSelectorFromString("hostname")),
            obj.responds(to: NSSelectorFromString("port")),
            let hostname = obj.value(forKey: "hostname") as? String,
            let portStr = obj.value(forKey: "port") as? String
        {
            let host = hostname.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty, let port = UInt16(portStr) else { return nil }
            return (host, port)
        }

        // Last resort: parse the endpoint's string description. That format is unstable
        // across macOS releases; log at DEBUG so a future breakage shows up as debug
        // chatter rather than silently degrading every flow to "no remote endpoint".
        let raw = String(describing: endpoint)
        guard !raw.isEmpty else { return nil }
        let parsed = parseEndpointString(raw)
        let typeName = String(reflecting: type(of: endpoint))
        if parsed != nil {
            RamaTransparentProxyEngineHandle.log(
                level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
                message: "endpointHostPort: KVC fallback succeeded for \(typeName): raw=\(raw)"
            )
        } else {
            RamaTransparentProxyEngineHandle.log(
                level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
                message: "endpointHostPort: all fallbacks failed for \(typeName): raw=\(raw)"
            )
        }
        return parsed
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
func makeTcpNwParameters(_ opts: RamaTcpEgressConnectOptions?) -> NWParameters {
    let params = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
    if let opts {
        applyNwEgressParameters(opts.parameters, to: params)
    }
    return params
}

/// Stamp the intercepted flow's `NEFlowMetaData` onto the given egress
/// `NWParameters` via `NEAppProxyFlow.setMetadata(_:)`.
///
/// On macOS 15.0+ we call the typed Swift overlay (`setMetadata(on:)`).
/// On macOS 12.0–14.x we fall back to the Obj-C selector via
/// `perform(_:with:)`: the underlying selector `setMetadata:` is available
/// since macOS 10.15.4, but as of the macOS 26 SDK the Swift overlay only
/// exposes it under the renamed name gated on macOS 15.0+, even though the
/// runtime method exists earlier.
private func applyFlowMetadata(_ flow: NEAppProxyFlow, _ params: NWParameters) {
    if #available(macOS 15.0, *) {
        flow.setMetadata(on: params)
        return
    }
    // macOS 12.0–14.x fallback: invoke the selector dynamically. The
    // underlying `setMetadata:` is available since macOS 10.15.4, but
    // the typed Swift overlay only exposes it under #available(macOS
    // 15.0). If a future macOS removes the selector entirely, this
    // call silently no-ops and downstream NEAppProxyProviders that
    // intercept our egress will see this extension instead of the
    // original source app — observable as silently broken egress
    // attribution. Log when responds-to is false so a regression on
    // older OS surfaces in extension logs rather than failing
    // silently in production.
    let selector = NSSelectorFromString("setMetadata:")
    if !flow.responds(to: selector) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
            message: "applyFlowMetadata: NEAppProxyFlow does not respond to setMetadata: on this macOS version; egress NWParameters will not carry source-app metadata"
        )
        return
    }
    _ = flow.perform(selector, with: params)
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
