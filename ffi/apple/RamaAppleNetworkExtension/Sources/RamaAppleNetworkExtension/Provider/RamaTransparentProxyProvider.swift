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
private func isTransientWriteBackpressure(_ error: Error) -> Bool {
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
let writeRetryHardDeadlineMs: Int = 5_000

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
private let udpWritePumpMaxPending: Int = 256

// ── High-water telemetry thresholds ──────────────────────────────────────────

/// `pendingBytes` level at which a TCP write pump emits its first
/// high-water trace log. Set at 50 % of the cap so a memory spike is
/// visible in logs before backpressure kicks in, making it possible to
/// tie a spike to an exact flow from the log timestamp rather than
/// inferring it from a vmmap snapshot after the fact.
nonisolated(unsafe) var writePumpHwmLogThresholdBytes: Int = writePumpMaxPendingBytes / 2

/// Queue-depth at which the UDP write pump emits a high-water trace
/// log — same 50 % heuristic as the TCP byte threshold.
private let udpWritePumpHwmLogThreshold: Int = udpWritePumpMaxPending / 2

/// Default wall-clock cap on how long the egress NWConnection lingers
/// after the local side has sent its FIN before Swift force-cancels
/// it. Applied when `RamaTcpEgressConnectOptions.has_linger_close_ms`
/// is `false`; an explicit Rust-side `NwTcpConnectOptions.linger_close_timeout`
/// overrides. 5 seconds is generous enough for any healthy peer to
/// FIN-ACK and short enough that 200 slow-closing flows cap at a few
/// hundred concurrent FIN_WAIT_1 sockets rather than accumulating.
let defaultLingerCloseMs: UInt32 = 5_000

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
let defaultEgressWaitingToleranceMs: UInt32 = 5_000

// ── Per-pump lifecycle / state enums ─────────────────────────────────────────

/// Queue-confined phase for read pumps.  Three `Bool` fields
/// (`readPending`/`receiving`, `paused`, `closed`) encoded the same
/// information; the compiler now enforces that only one branch is live
/// at a time.
private enum ReadPumpPhase {
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
private enum WritePumpLifecycle {
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
private struct WriteRetry {
    /// Delay to use for the *next* scheduled retry (ms); doubles each
    /// round up to `writeRetryMaxDelayMs`.
    var delayMs: Int
    /// Hard wall-clock deadline for the whole retry sequence.
    var deadline: DispatchTime
}

/// Queue-confined state for a UDP flow's read side.  Replaces
/// `closed: Bool`, `readPending: Bool`, and `demandPending: Bool`.
enum UdpFlowReadState {
    /// No read in flight, no pending demand.
    case idle
    /// A `readDatagrams` call is in flight.
    case reading
    /// A `readDatagrams` call is in flight AND a second demand arrived
    /// while it was pending — re-trigger `requestRead` on completion.
    case readingWithDemand
    /// Terminal — no further reads will be issued.
    case closed
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

/// Cross-thread access pattern: `state`-protected fields are
/// accessed under the lock from any thread; everything else is
/// confined to `queue`. Apple's `flow.readData` completion handler
/// is `@Sendable`, which requires the captured `self` to be
/// `Sendable` too — `@unchecked` because Swift can't see the
/// runtime confinement (lock + serial queue) statically.
final class TcpClientReadPump: @unchecked Sendable {
    private let flow: any TcpFlowReadable
    /// `weak` so the pump doesn't pin the session alive (the session map is
    /// the single strong owner). Equally important: stops the strong-ref
    /// cycle ctx → pump → session → callback closures → ctx.
    private weak var session: RamaTcpSessionHandle?
    private let logger: (FlowLogMessage) -> Void
    private let onTerminal: (Error?) -> Void
    private let queue: DispatchQueue
    /// Lifecycle phase — replaces the former `readPending`, `paused`, and
    /// `closed` boolean triple.  The compiler now enforces that only one
    /// branch is active at a time instead of relying on scattered guards.
    private var phase: ReadPumpPhase = .open
    /// Bytes Rust rejected with `.paused` on a previous `onClientBytes`. We
    /// MUST replay them before issuing the next `flow.readData` — Rust does
    /// not take ownership on a `.paused` return, so dropping `data` here
    /// would punch a hole in the byte stream and the downstream TLS layer
    /// would surface "bad record MAC" once the gap reaches the decryptor.
    private var pendingData: Data?

    init(
        flow: any TcpFlowReadable,
        session: RamaTcpSessionHandle,
        queue: DispatchQueue,
        logger: @escaping (FlowLogMessage) -> Void,
        onTerminal: @escaping (Error?) -> Void
    ) {
        self.flow = flow
        self.session = session
        self.queue = queue
        self.logger = logger
        self.onTerminal = onTerminal
    }

    func requestRead() {
        queue.async { self.requestReadLocked() }
    }

    /// Resume reading after the Rust side has freed capacity in the per-flow
    /// ingress channel. No-op unless the pump is currently paused.
    func resume() {
        queue.async {
            guard self.phase == .paused else { return }
            self.phase = .open
            self.requestReadLocked()
        }
    }

    private func requestReadLocked() {
        guard phase == .open else { return }

        // Replay any chunk Rust rejected with `.paused` last time before we
        // ask the kernel for new bytes. If this still gets `.paused` we hold
        // the chunk and wait for the next `resume()`.
        if let pending = self.pendingData {
            guard let session = self.session else {
                self.pendingData = nil
                self.terminate(with: nil)
                return
            }
            switch session.onClientBytes(pending) {
            case .accepted:
                self.pendingData = nil
                // fall through to issue a fresh readData
            case .paused:
                self.phase = .paused
                return
            case .closed:
                self.pendingData = nil
                self.terminate(with: nil)
                return
            }
        }

        phase = .reading
        // `[weak self]` breaks the otherwise-fatal retain cycle:
        //   pump → flow (let) → kernel/mocked read-callback queue → this closure → pump.
        // `NEAppProxyTCPFlow` holds the completion handler in its
        // internal callback queue until the flow itself is destroyed,
        // so without the weak capture the pump (and through its
        // strongly-held `flow` field, the flow object too) lives
        // until the flow's kernel-side state machine wraps up — long
        // past the per-flow context's logical lifetime. The same
        // shape leaks `NEAppProxyUDPFlow` callbacks (see UDP read
        // path).
        self.flow.readData { [weak self] data, error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self, self.phase != .closed else { return }
                self.phase = .open

                if let error {
                    self.logger(
                        classifyFlowCallbackError(error, operation: "tcp flow.read")
                    )
                    self.terminate(with: error)
                    return
                }

                guard let data, !data.isEmpty else {
                    self.logger(
                        FlowLogMessage(
                            level: .trace,
                            text: "flow.readData eof"
                        )
                    )
                    self.terminate(with: nil)
                    return
                }

                guard let session = self.session else {
                    // Session was torn down while a read was in flight — drop
                    // the bytes and stop reading.
                    self.terminate(with: nil)
                    return
                }
                switch session.onClientBytes(data) {
                case .accepted:
                    self.requestReadLocked()
                case .paused:
                    // Rust did NOT take these bytes. Save them for replay on
                    // the next `resume()` and stop reading.
                    if self.pendingData == nil {
                        self.logger(FlowLogMessage(
                            level: .trace,
                            text: "tcp client read pump: replay buffer occupied (\(data.count) B); ingress channel full"
                        ))
                    }
                    self.pendingData = data
                    self.phase = .paused
                case .closed:
                    // Rust signaled the session is gone (teardown or
                    // bridge-side write failure). No demand callback will
                    // ever follow, so terminate the pump now instead of
                    // waiting for an outer cleanup path.
                    self.terminate(with: nil)
                }
            }
        }
    }

    private func terminate(with error: Error?) {
        guard phase != .closed else { return }
        phase = .closed
        onTerminal(error)
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
private protocol TcpWritePumpCoreDelegate: AnyObject {
    /// The core has encountered a terminal write error and has closed its
    /// internal state.  The delegate performs its own teardown here.
    func pumpCore(_ core: TcpWritePumpCore, didTerminateWith error: Error)
    /// The core has flushed all pending chunks with `lifecycle == .draining`
    /// and has atomically closed.  The delegate runs its drain-complete action
    /// (e.g. send a TCP FIN, fire a completion callback).
    func pumpCoreDidFinishDraining(_ core: TcpWritePumpCore)
}

/// Shared write-pump state machine used by both `TcpClientWritePump` and
/// `NwTcpConnectionWritePump`.  Owns the `Locked<TcpWriterState>` byte
/// budget, the in-flight queue, and the exponential-backoff retry loop.
///
/// The actual write primitive and HWM logging are injected at construction
/// time as closures so the core is agnostic of whether the underlying
/// transport is an `NEAppProxyTCPFlow` or an `NWConnection`.
private final class TcpWritePumpCore: @unchecked Sendable {
    let state = Locked(TcpWriterState())
    let queue: DispatchQueue
    private let onDrained: () -> Void
    private let doWrite: (Data, @escaping @Sendable (Error?) -> Void) -> Void
    private let logHwm: (Int) -> Void
    weak var delegate: TcpWritePumpCoreDelegate?

    // Queue-only mutable state — never read/written outside a block
    // executing on `queue`.
    private var pending: [Data] = []
    private var writing = false
    private var lifecycle: WritePumpLifecycle
    private var retrying: WriteRetry?

    init(
        queue: DispatchQueue,
        initialLifecycle: WritePumpLifecycle = .open,
        onDrained: @escaping () -> Void,
        doWrite: @escaping (Data, @escaping @Sendable (Error?) -> Void) -> Void,
        logHwm: @escaping (Int) -> Void
    ) {
        self.queue = queue
        self.lifecycle = initialLifecycle
        self.onDrained = onDrained
        self.doWrite = doWrite
        self.logHwm = logHwm
    }

    func isClosed() -> Bool { state.withLock { $0.closed } }

    /// Atomically marks the core closed and zeroes the byte budget.
    /// Returns a queue-side cleanup closure the caller must dispatch on
    /// `queue`.  Separating the atomic part from the queue work lets the
    /// outer class append its own cleanup (e.g. fire `onDrainedClose`)
    /// inside the same async block.
    func prepareCancel() -> () -> Void {
        state.withLock { s in
            s.closed = true
            s.pendingBytes = 0
        }
        return { [self] in
            self.pending.removeAll(keepingCapacity: false)
            self.retrying = nil
        }
    }

    /// Transitions lifecycle to `.open` and flushes any queued chunks.
    /// Must be called on `queue`.
    func markOpen() {
        if isClosed() { return }
        lifecycle = .open
        flush()
    }

    /// Transitions lifecycle to `.draining` and fires the drain-complete
    /// callback if the queue is already empty.  Must be called on `queue`.
    func beginDraining() {
        if isClosed() { return }
        lifecycle = .draining
        finishCloseIfDrained()
    }

    /// Same status contract as documented on `TcpClientWritePump.enqueue`.
    @discardableResult
    func enqueue(_ data: Data) -> RamaTcpDeliverStatusBridge {
        guard !data.isEmpty else { return .accepted }

        let (decision, hwm): (RamaTcpDeliverStatusBridge, Int?) = state.withLock { s in
            if s.closed { return (.closed, nil) }
            // First chunk always passes through — an oversized single
            // chunk must not deadlock the bridge.
            if s.pendingBytes > 0
                && s.pendingBytes + data.count > writePumpMaxPendingBytes
            {
                s.pausedSignaled = true
                return (.paused, nil)
            }
            s.pendingBytes += data.count
            var newHwm: Int? = nil
            if s.pendingBytes > s.pendingBytesHwm {
                s.pendingBytesHwm = s.pendingBytes
                if s.pendingBytes >= writePumpHwmLogThresholdBytes {
                    newHwm = s.pendingBytes
                }
            }
            return (.accepted, newHwm)
        }
        if let hwm { logHwm(hwm) }
        guard decision == .accepted else { return decision }

        queue.async { [weak self] in
            guard let self else { return }
            // Re-check under lock; cancel() can have flipped the flag
            // between the FFI fast-path return and this dispatch.
            // Do NOT subtract pendingBytes here: if cancel() ran first it
            // already zeroed the counter, and subtracting again would push
            // it negative.
            guard !self.state.withLock({ $0.closed }) else { return }
            self.pending.append(data)
            self.flush()
        }
        return .accepted
    }

    /// Queue-side terminal cleanup.  Publishes the closed flag under the
    /// lock so concurrent FFI `enqueue` calls return `.closed` immediately.
    func terminateLocked(with error: Error) {
        let alreadyClosed: Bool = state.withLock { s in
            let wasClosed = s.closed
            s.closed = true
            s.pendingBytes = 0
            return wasClosed
        }
        if alreadyClosed { return }
        lifecycle = .draining
        pending.removeAll(keepingCapacity: false)
        retrying = nil
        delegate?.pumpCore(self, didTerminateWith: error)
    }

    private func flush() {
        if isClosed() { return }
        if writing || pending.isEmpty || lifecycle == .pending {
            finishCloseIfDrained()
            return
        }

        writing = true
        let chunk = pending.removeFirst()

        let fireDrain: Bool = state.withLock { s in
            s.pendingBytes -= chunk.count
            if s.pausedSignaled && s.pendingBytes < writePumpMaxPendingBytes {
                s.pausedSignaled = false
                return true
            }
            return false
        }
        // Edge-triggered drain signal — wakes Rust before the current write
        // completes so it can start producing in parallel.
        if fireDrain { onDrained() }

        doWrite(chunk) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.writing = false
                if let error {
                    if isTransientWriteBackpressure(error) {
                        let now = DispatchTime.now()
                        let currentDelayMs: Int
                        let deadline: DispatchTime
                        if let existing = self.retrying {
                            if now >= existing.deadline {
                                self.terminateLocked(with: error)
                                return
                            }
                            currentDelayMs = existing.delayMs
                            deadline = existing.deadline
                        } else {
                            currentDelayMs = writeRetryInitialDelayMs
                            deadline = now + .milliseconds(writeRetryHardDeadlineMs)
                        }
                        self.pending.insert(chunk, at: 0)
                        self.state.withLock { $0.pendingBytes += chunk.count }
                        self.retrying = WriteRetry(
                            delayMs: min(currentDelayMs * 2, writeRetryMaxDelayMs),
                            deadline: deadline
                        )
                        self.queue.asyncAfter(
                            deadline: .now() + .milliseconds(currentDelayMs)
                        ) { [weak self] in
                            self?.flush()
                        }
                        return
                    }
                    self.terminateLocked(with: error)
                    return
                }
                self.retrying = nil
                self.flush()
            }
        }
    }

    private func finishCloseIfDrained() {
        guard lifecycle == .draining, !writing, pending.isEmpty else { return }
        let alreadyClosed: Bool = state.withLock { s in
            let wasClosed = s.closed
            if !wasClosed { s.closed = true }
            return wasClosed
        }
        if alreadyClosed { return }
        delegate?.pumpCoreDidFinishDraining(self)
    }
}

/// See `TcpClientReadPump` for the `@unchecked Sendable`
/// rationale — same lock + queue confinement applies here.
final class TcpClientWritePump: @unchecked Sendable {
    private let core: TcpWritePumpCore
    private let logger: (FlowLogMessage) -> Void
    private let onTerminalError: (Error) -> Void

    // Queue-only state.
    private var wasEverOpened = false
    private var onDrainedClose: ((Bool) -> Void)?

    init(
        flow: TcpFlowWritable,
        queue: DispatchQueue,
        logger: @escaping (FlowLogMessage) -> Void,
        onTerminalError: @escaping (Error) -> Void,
        onDrained: @escaping () -> Void
    ) {
        self.logger = logger
        self.onTerminalError = onTerminalError
        let core = TcpWritePumpCore(
            queue: queue,
            initialLifecycle: .pending,
            onDrained: onDrained,
            doWrite: { data, completion in flow.write(data, withCompletionHandler: completion) },
            logHwm: { hwm in
                logger(FlowLogMessage(
                    level: .trace,
                    text: "tcp client write pump pendingBytes hwm=\(hwm) cap=\(writePumpMaxPendingBytes)"
                ))
            }
        )
        self.core = core
        core.delegate = self
    }


    func markOpened() {
        core.queue.async { [weak self] in
            guard let self else { return }
            if self.core.isClosed() { return }
            self.wasEverOpened = true
            self.core.markOpen()
        }
    }

    func failOpen(_ error: Error) {
        core.queue.async { [weak self] in
            guard let self else { return }
            self.core.terminateLocked(with: error)
        }
    }

    /// Enqueue a chunk for delivery via the underlying flow's write.
    ///
    /// Returns synchronously with:
    ///   - `.accepted` — chunk queued; Rust may keep producing.
    ///   - `.paused` — byte budget reached; wait for `signalServerDrain`.
    ///   - `.closed` — pump is tearing down; no further drain will fire.
    @discardableResult
    func enqueue(_ data: Data) -> RamaTcpDeliverStatusBridge {
        core.enqueue(data)
    }

    func closeWhenDrained(_ onDrainedClose: @escaping (_ wasOpened: Bool) -> Void) {
        core.queue.async { [weak self] in
            guard let self else { return }
            if self.core.isClosed() {
                onDrainedClose(self.wasEverOpened)
                return
            }
            self.onDrainedClose = onDrainedClose
            self.core.beginDraining()
        }
    }

    /// External-cancel entry point. Sets the closed flag synchronously so
    /// any pending retry's flush short-circuits immediately, then schedules
    /// queue-side cleanup.  If a `closeWhenDrained` completion was
    /// registered it fires with `wasOpened = false` so the dispatcher's
    /// teardown chain always resolves.
    func cancel() {
        let coreCleanup = core.prepareCancel()
        core.queue.async { [weak self] in
            guard let self else { return }
            coreCleanup()
            let completion = self.onDrainedClose
            let wasOpened = self.wasEverOpened
            self.onDrainedClose = nil
            completion?(wasOpened)
        }
    }
}

extension TcpClientWritePump: TcpWritePumpCoreDelegate {
    fileprivate func pumpCore(_ core: TcpWritePumpCore, didTerminateWith error: Error) {
        logger(classifyFlowCallbackError(error, operation: "tcp flow.write", isClosing: true))
        onTerminalError(error)
        let completion = onDrainedClose
        onDrainedClose = nil
        completion?(wasEverOpened)
    }

    fileprivate func pumpCoreDidFinishDraining(_ core: TcpWritePumpCore) {
        let completion = onDrainedClose
        onDrainedClose = nil
        completion?(wasEverOpened)
    }
}

/// Queue-confined phase for `UdpClientWritePump`.  Replaces the former
/// `writing: Bool`, `closed: Bool`, and `opened: Bool` triple.
private enum UdpWritePumpPhase {
    /// `markOpened()` has not yet been called.
    case pending
    /// Opened and no write in flight.
    case idle
    /// A `writeDatagrams` call is in flight.
    case writing
    /// Terminal — pump has torn down.
    case closed
}

final class UdpClientWritePump {
    // Held behind the protocol so tests can drive the pump with a
    // capture-mock; production passes a concrete NEAppProxyUDPFlow.
    private let flow: any UdpFlowWritable
    private let logger: (FlowLogMessage) -> Void
    private let onTerminalError: (Error) -> Void
    private let queue: DispatchQueue
    /// Each pending entry pairs a reply datagram with the
    /// `sentBy` endpoint to use for `flow.writeDatagrams`. Capturing
    /// the endpoint AT ENQUEUE TIME (instead of reading the latest
    /// `sentByEndpoint` at flush time) means a queued reply still
    /// uses the peer that was current when the reply was produced
    /// even if a later `setSentByEndpoint` call has shifted the
    /// active peer in the meantime — fixes a queue-vs-peer-change
    /// race, but does NOT change the single-peer assumption (see
    /// `sentByEndpoint`): a multi-peer read batch is still collapsed
    /// to its first endpoint at the read site, so queued replies
    /// produced from that batch carry only that single endpoint.
    private var pending: [(Data, NWEndpoint?)] = []
    /// Lifecycle phase — replaces the former `writing`, `closed`, and
    /// `opened` boolean triple.
    private var phase: UdpWritePumpPhase = .pending
    /// All-time peak of `pending.count`; used to gate high-water logs
    /// so each new peak above `udpWritePumpHwmLogThreshold` is emitted
    /// exactly once per pump lifetime.
    private var pendingCountHwm: Int = 0
    /// Most-recently-seen source endpoint from `readDatagrams`.
    /// Used as the `sentBy` endpoint when writing datagrams back.
    ///
    /// **Single-peer assumption.** This implementation maintains one
    /// egress `NWConnection` per intercepted flow, established to the
    /// peer in `NEAppProxyUDPFlow.metaData.remoteEndpoint`. Apps that
    /// `sendto()` multiple peers from the same UDP socket are not
    /// faithfully proxied — outbound traffic is forwarded to the
    /// initial peer regardless of the destination the app intended,
    /// and replies are tagged with the most-recently-observed peer
    /// rather than per-peer correlated. We log a one-time warn when
    /// a multi-peer signal is detected (a `setSentByEndpoint` call
    /// with an endpoint different from the current one).
    private var sentByEndpoint: NWEndpoint?
    private var multiPeerLogged = false

    init(
        flow: any UdpFlowWritable,
        queue: DispatchQueue,
        logger: @escaping (FlowLogMessage) -> Void,
        onTerminalError: @escaping (Error) -> Void
    ) {
        self.flow = flow
        self.queue = queue
        self.logger = logger
        self.onTerminalError = onTerminalError
    }


    func markOpened() {
        queue.async {
            guard self.phase != .closed else { return }
            self.phase = .idle
            self.flushLocked()
        }
    }

    func failOpen(_ error: Error) {
        queue.async {
            guard self.phase != .closed else { return }
            self.phase = .closed
            self.pending.removeAll(keepingCapacity: false)
            self.onTerminalError(error)
        }
    }

    func setSentByEndpoint(_ endpoint: NWEndpoint?) {
        queue.async {
            guard let endpoint else {
                self.flushLocked()
                return
            }
            if let prev = self.sentByEndpoint, prev != endpoint, !self.multiPeerLogged {
                self.multiPeerLogged = true
                RamaTransparentProxyEngineHandle.log(
                    level: UInt32(RAMA_LOG_LEVEL_WARN.rawValue),
                    message:
                        "udp flow observed multiple peer endpoints (\(prev) → \(endpoint)); replies will be best-effort routed to the most-recent peer per datagram (single-peer assumption violated)"
                )
            }
            self.sentByEndpoint = endpoint
            self.flushLocked()
        }
    }

    func enqueue(_ data: Data) {
        guard !data.isEmpty else { return }
        queue.async {
            if self.phase == .closed { return }
            // Drop-on-full: UDP is lossy. Indefinite buffering would
            // deliver datagrams long after the kernel would have dropped
            // them on the wire. Bias toward dropping the newest entry so
            // an unstuck pump first drains older queued work.
            if self.pending.count >= udpWritePumpMaxPending {
                RamaTransparentProxyEngineHandle.log(
                    level: UInt32(RAMA_LOG_LEVEL_TRACE.rawValue),
                    message:
                        "udp client write pump full (>= \(udpWritePumpMaxPending) datagrams), dropping"
                )
                return
            }
            // Capture the endpoint at enqueue time so a queued reply
            // does not pick up a later peer change at flush time.
            // Pre-first-read replies have nil here and resolve at
            // flush time once `sentByEndpoint` is known.
            self.pending.append((data, self.sentByEndpoint))
            let depth = self.pending.count
            if depth > self.pendingCountHwm {
                self.pendingCountHwm = depth
                if depth > udpWritePumpHwmLogThreshold {
                    RamaTransparentProxyEngineHandle.log(
                        level: UInt32(RAMA_LOG_LEVEL_TRACE.rawValue),
                        message:
                            "udp client write pump queue depth hwm=\(depth) cap=\(udpWritePumpMaxPending)"
                    )
                }
            }
            self.flushLocked()
        }
    }

    func close() {
        queue.async {
            self.phase = .closed
            self.pending.removeAll(keepingCapacity: false)
        }
    }

    private func flushLocked() {
        guard phase == .idle, !pending.isEmpty else { return }

        // Resolve the endpoint: prefer the one captured at enqueue
        // time; fall back to the latest known peer for entries that
        // arrived before any `setSentByEndpoint` call.
        guard let endpoint = pending[0].1 ?? sentByEndpoint else {
            return
        }

        phase = .writing
        let chunk = pending.removeFirst().0
        // `[weak self]` for the same retain-cycle reason as
        // `TcpClientReadPump`'s `flow.readData` capture: the flow
        // (kernel or mock) stores the completion until it fires,
        // and the pump's `let flow` field strongly holds the flow.
        // Without the weak capture the pump is pinned until the
        // completion fires; under load + slow shutdown the chain
        // accumulates.
        self.flow.writeDatagrams([chunk], sentBy: [endpoint]) { [weak self] error in
            guard let self else { return }
            self.queue.async { [weak self] in
                guard let self else { return }
                if let error {
                    self.logger(
                        classifyFlowCallbackError(
                            error,
                            operation: "udp flow.write",
                            isClosing: self.phase == .closed
                        )
                    )
                    self.phase = .closed
                    self.pending.removeAll(keepingCapacity: false)
                    self.onTerminalError(error)
                    return
                }

                self.phase = .idle
                self.flushLocked()
            }
        }
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

/// Creates UDP `NWParameters` from optional Rust-supplied egress options.
func makeUdpNwParameters(_ opts: RamaUdpEgressConnectOptions?) -> NWParameters {
    let params = NWParameters.udp
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
final class NwTcpConnectionReadPump {
    private let connection: any NwConnectionLike
    /// `weak` for the same retain-cycle / ownership reasons as
    /// [`TcpClientReadPump.session`].
    private weak var session: RamaTcpSessionHandle?
    private let queue: DispatchQueue
    /// Grace window between observing peer EOF / error and force-
    /// cancelling the underlying connection. The clean teardown path
    /// (`on_server_closed` → cancel) depends on the originating app
    /// being able to drain; the grace gives the clean path a chance to
    /// run before the backstop fires.
    private let eofGraceDeadline: DispatchTimeInterval
    /// Scheduled EOF-cancel work, retained so we can invalidate it
    /// when the clean path beats us to the cancel.
    private var eofWork: DispatchWorkItem?
    /// Lifecycle phase — replaces the former `closed`, `paused`, and
    /// `receiving` boolean triple.  The `receiving` → `.reading` mapping
    /// also prevents `Network.framework`'s unsupported concurrent-receive
    /// invariant from being broken.
    private var phase: ReadPumpPhase = .open
    /// See [`TcpClientReadPump.pendingData`] — same contract for the egress
    /// (NWConnection-receive) direction. Dropping rejected bytes here is what
    /// the wails-zip / golang-module repro showed as TLS "bad record MAC".
    private var pendingData: Data?

    init(
        connection: any NwConnectionLike,
        session: RamaTcpSessionHandle,
        queue: DispatchQueue,
        eofGraceDeadline: DispatchTimeInterval
    ) {
        self.connection = connection
        self.session = session
        self.queue = queue
        self.eofGraceDeadline = eofGraceDeadline
    }


    func start() {
        queue.async { self.scheduleReadLocked() }
    }

    /// Resume scheduling receives after the Rust side has freed egress
    /// capacity. No-op unless the pump is currently paused.
    func resume() {
        queue.async {
            guard self.phase == .paused else { return }
            self.phase = .open
            self.scheduleReadLocked()
        }
    }

    private func scheduleReadLocked() {
        guard phase == .open else { return }

        // Replay any chunk Rust rejected with `.paused` last time before
        // issuing a new receive.
        if let pending = self.pendingData {
            guard let session = self.session else {
                self.pendingData = nil
                self.phase = .closed
                return
            }
            switch session.onEgressBytes(pending) {
            case .accepted:
                self.pendingData = nil
                // fall through to schedule the next receive
            case .paused:
                self.phase = .paused
                return
            case .closed:
                self.pendingData = nil
                self.phase = .closed
                return
            }
        }

        phase = .reading
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.queue.async {
                guard self.phase != .closed else { return }
                self.phase = .open

                if let data, !data.isEmpty {
                    guard let session = self.session else {
                        // Session was torn down while a receive was in
                        // flight — drop the bytes and stop. Re-issuing
                        // another `connection.receive` here would keep the
                        // NWConnection's read side draining bytes that have
                        // nowhere to go.
                        self.phase = .closed
                        return
                    }
                    switch session.onEgressBytes(data) {
                    case .accepted:
                        break
                    case .paused:
                        // Rust did NOT take these bytes. Save them for
                        // replay; do NOT issue another receive until
                        // `resume()`.
                        if self.pendingData == nil {
                            RamaTransparentProxyEngineHandle.log(
                                level: UInt32(RAMA_LOG_LEVEL_TRACE.rawValue),
                                message: "tcp egress read pump: replay buffer occupied (\(data.count) B); egress channel full"
                            )
                        }
                        self.pendingData = data
                        self.phase = .paused
                        return
                    case .closed:
                        // No demand will follow; tear the pump down now.
                        self.phase = .closed
                        return
                    }
                }
                if isComplete || error != nil {
                    self.phase = .closed
                    self.session?.onEgressEof()
                    // The clean teardown path runs `on_egress_eof` →
                    // bridge exits → `on_server_closed` → Swift
                    // cancels the connection. That path depends on
                    // the originating app's write pump being able to
                    // drain its queued response bytes. If the app
                    // stopped reading (process exit, browser tab
                    // closed) the drain never completes and the
                    // clean path stalls. Schedule a fallback cancel
                    // so the NWConnection registration is released
                    // within a bounded window regardless of app
                    // behavior. `cancel()` is idempotent — if the
                    // clean path reaches it first, the work item is
                    // invalidated by `cancel()` below or the call
                    // becomes a no-op.
                    let work = DispatchWorkItem { [weak self] in
                        guard let self else { return }
                        self.connection.cancel()
                        self.eofWork = nil
                    }
                    self.eofWork = work
                    self.queue.asyncAfter(deadline: .now() + self.eofGraceDeadline, execute: work)
                    return
                }
                self.scheduleReadLocked()
            }
        }
    }

    func cancel() {
        queue.async { [weak self] in
            guard let self else { return }
            self.phase = .closed
            // External cancel pre-empts the EOF backstop: the work
            // item's only job is to ensure cancel reaches the
            // connection if no other path does, and that no-longer-
            // applies once an outer teardown has fired.
            self.eofWork?.cancel()
            self.eofWork = nil
        }
    }
}

/// Queues outbound bytes and sends them to a `NWConnection` one at a time.
///
/// When `closeWhenDrained()` is called Rust signals it is done writing;
/// the pump drains its queue and then sends an empty final `send` to
/// signal half-close to the remote.
/// See `TcpClientReadPump` for the `@unchecked Sendable`
/// rationale — same lock + queue confinement applies here.
///
/// Internal (not private) so unit tests can construct one against a
/// `MockNwConnection` and exercise the linger-cancel watchdog and the
/// drain → FIN sequence directly. Tests are the only out-of-file
/// consumers; production code still constructs this only from
/// `handleTcpFlow`.
final class NwTcpConnectionWritePump: @unchecked Sendable {
    private let connection: any NwConnectionLike
    private let core: TcpWritePumpCore
    /// Wall-clock cap on how long the egress NWConnection lingers after
    /// the local side has sent its FIN (an empty `send` with
    /// `isComplete: true`) before this pump force-cancels the
    /// connection. A peer that fails to send its own FIN-ACK would
    /// otherwise keep the kernel socket in FIN_WAIT_1 and the macOS
    /// NECP flow registration alive — accumulating leaked
    /// registrations is what makes new `nw_connection_start` calls
    /// linearly slower on the workloop queue.
    private let lingerCloseDeadline: DispatchTimeInterval
    /// Scheduled linger-cancel work, retained so we can invalidate it
    /// when the connection closes naturally before the deadline (or
    /// when the pump is externally cancelled).
    private var lingerWork: DispatchWorkItem?

    init(
        connection: any NwConnectionLike,
        queue: DispatchQueue,
        lingerCloseDeadline: DispatchTimeInterval,
        onDrained: @escaping () -> Void
    ) {
        self.connection = connection
        self.lingerCloseDeadline = lingerCloseDeadline
        let core = TcpWritePumpCore(
            queue: queue,
            initialLifecycle: .open,
            onDrained: onDrained,
            doWrite: { data, completion in
                // `isComplete: true` matches `NWConnection.send`'s own
                // default for TCP; the value is a no-op for stream
                // transports but is set explicitly here because the
                // injectable protocol surface has no default arguments.
                connection.send(
                    content: data,
                    contentContext: .defaultMessage,
                    isComplete: true,
                    completion: .contentProcessed(completion)
                )
            },
            logHwm: { hwm in
                RamaTransparentProxyEngineHandle.log(
                    level: UInt32(RAMA_LOG_LEVEL_TRACE.rawValue),
                    message: "tcp egress write pump pendingBytes hwm=\(hwm) cap=\(writePumpMaxPendingBytes)"
                )
            }
        )
        self.core = core
        core.delegate = self
    }


    /// Same status contract as `TcpClientWritePump.enqueue`.
    @discardableResult
    func enqueue(_ data: Data) -> RamaTcpDeliverStatusBridge { core.enqueue(data) }

    func closeWhenDrained() {
        core.queue.async { [weak self] in
            guard let self else { return }
            self.core.beginDraining()
        }
    }

    func cancel() {
        let coreCleanup = core.prepareCancel()
        core.queue.async { [weak self] in
            coreCleanup()
            // External cancel makes any outstanding linger watchdog
            // moot — its only job is to force-cancel a connection
            // whose peer never closed, and that path has now been
            // pre-empted.
            self?.lingerWork?.cancel()
            self?.lingerWork = nil
        }
    }
}

extension NwTcpConnectionWritePump: TcpWritePumpCoreDelegate {
    fileprivate func pumpCore(_ core: TcpWritePumpCore, didTerminateWith error: Error) {
        // NWConnection write errors are surfaced via the connection state
        // handler; the write pump terminates silently.
    }

    fileprivate func pumpCoreDidFinishDraining(_ core: TcpWritePumpCore) {
        guard connection.state == .ready else { return }
        connection.send(
            content: nil,
            contentContext: .defaultMessage,
            isComplete: true,
            completion: .contentProcessed({ _ in })
        )
        // The FIN is queued. Schedule the linger watchdog so the
        // NWConnection registration is released even if the peer
        // never replies with its own FIN. `cancel()` is idempotent —
        // if a natural close path (state handler, read-pump EOF
        // backstop, external pump cancel) gets there first, this
        // work item is cancelled before firing or the cancel call
        // becomes a no-op.
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.connection.cancel()
            self.lingerWork = nil
        }
        lingerWork = work
        core.queue.asyncAfter(deadline: .now() + lingerCloseDeadline, execute: work)
    }
}

/// Minimal receive surface the UDP read pump needs. Abstracts
/// `NWConnection` so tests can drive the pump without a real
/// network socket.
protocol UdpConnectionReadable: AnyObject {
    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    )
}

extension NWConnection: UdpConnectionReadable {}

/// Reads datagrams from a `NWConnection` in a loop and delivers them to a Rust UDP session.
final class NwUdpConnectionReadPump: @unchecked Sendable {
    private let connection: any UdpConnectionReadable
    private let session: RamaUdpSessionHandle
    private let queue: DispatchQueue
    private var closed = false
    // Wires read-side EOF/error into the flow's `terminate` so a
    // half-open flow doesn't sit until `udp_max_flow_lifetime` reaps it.
    private let onTerminate: (Error?) -> Void

    init(
        connection: any UdpConnectionReadable,
        session: RamaUdpSessionHandle,
        queue: DispatchQueue,
        onTerminate: @escaping (Error?) -> Void
    ) {
        self.connection = connection
        self.session = session
        self.queue = queue
        self.onTerminate = onTerminate
    }


    func start() {
        scheduleRead()
    }

    private func scheduleRead() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_535) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.queue.async {
                guard !self.closed else { return }
                if let data, !data.isEmpty {
                    self.session.onEgressDatagram(data)
                }
                if isComplete || error != nil {
                    self.closed = true
                    self.onTerminate(error)
                    return
                }
                self.scheduleRead()
            }
        }
    }

    func cancel() {
        queue.async { [self] in closed = true }
    }
}

// ─────────────────────────────────────────────────────────────────────────────

/// Per-flow late-binding container for the Rust session handle.
///
/// `engine.newTcpSession(...)` and `engine.newUdpSession(...)` accept callbacks
/// that may need to refer back to the session, but the session is only
/// returned *after* those calls. The context lets early closures capture a
/// stable reference and read the session once it's set.
///
/// `weak` keeps the session map (`tcpSessions`/`udpSessions`) as the single
/// strong owner: once that map drops the session, late callbacks see `nil`
/// and become no-ops, avoiding a retain cycle through closures.
///
/// Swift weak references are thread-safe for both load and store on modern
/// runtimes, so no extra locking is required here.
/// Atomic live-instance counter; flipped on by tests via
/// `TcpFlowContext.diagnosticCountersEnabled = true` to surface ARC
/// leaks of the per-flow context graph. Off by default so production
/// callers don't take an atomic on every flow alloc.








final class TcpFlowContext {
    // Connection is held behind the injectable protocol so unit tests
    // can drive the per-flow state machine via a mock instead of
    // standing up a real NWConnection.
    weak var session: RamaTcpSessionHandle?
    /// Egress NWConnection, reachable from late callbacks that must
    /// still be able to `cancel()` the flow.
    var connection: (any NwConnectionLike)?
    /// Read pumps reachable from the Rust → Swift demand callbacks.
    var clientReadPump: TcpClientReadPump?
    var egressReadPump: NwTcpConnectionReadPump?
    /// Writer pumps retained until terminal teardown so we can
    /// cancel them from dispatcher-owned close paths.
    var clientWritePump: TcpClientWritePump?
    var egressWritePump: NwTcpConnectionWritePump?

    init() {
    }
}

final class UdpFlowContext {
    init() {
    }

    weak var session: RamaUdpSessionHandle?
    // See `TcpFlowContext.connection` for why this is the protocol type.
    var connection: (any NwConnectionLike)?
    /// Per-flow pumps + closures, owned by the provider's state map
    /// until the flow is removed.
    var egressReadPump: NwUdpConnectionReadPump?
    var writer: UdpClientWritePump?
    var requestRead: (() -> Void)?
    var terminate: ((Error?) -> Void)?
    /// Read-side lifecycle — replaces the former `closed: Bool`,
    /// `readPending: Bool`, and `demandPending: Bool` triple.
    var readState: UdpFlowReadState = .idle
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
        core.logInfo("extension startProxy")

        let engineConfigJson = Self.engineConfigJson(
            protocolConfiguration: self.protocolConfiguration as? NETunnelProviderProtocol,
            startOptions: options
        )
        if let engineConfigJson {
            core.logInfo("engine config json bytes=\(engineConfigJson.count)")
        }
        guard let engine = RamaTransparentProxyEngineHandle(engineConfigJson: engineConfigJson)
        else {
            core.logError("engine creation error")
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
        core.logInfo("engine created")

        guard let startup = engine.config() else {
            core.logError("failed to get transparent proxy config from rust")
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

        if startup.tcpWritePumpMaxPendingBytes > 0 {
            writePumpMaxPendingBytes = startup.tcpWritePumpMaxPendingBytes
            writePumpHwmLogThresholdBytes = writePumpMaxPendingBytes / 2
            core.logInfo("tcp write pump cap set to \(writePumpMaxPendingBytes) bytes from engine config")
        } else {
            core.logInfo("tcp write pump cap using built-in default \(writePumpMaxPendingBytes) bytes")
        }

        let settings = NETransparentProxyNetworkSettings(
            tunnelRemoteAddress: startup.tunnelRemoteAddress
        )
        var builtRules: [NENetworkRule] = []
        for (idx, rule) in startup.rules.enumerated() {
            if let built = Self.makeNetworkRule(rule) {
                builtRules.append(built)
                core.logInfo(
                    "include rule[\(idx)] remote=\(rule.remoteNetwork ?? "<any>") remotePrefix=\(rule.remotePrefix.map(String.init) ?? "<none>") local=\(rule.localNetwork ?? "<any>") localPrefix=\(rule.localPrefix.map(String.init) ?? "<none>") proto=\(rule.protocolRaw)"
                )
            } else {
                core.logError(
                    "invalid rule[\(idx)] remote=\(rule.remoteNetwork ?? "<any>") remotePrefix=\(rule.remotePrefix.map(String.init) ?? "<none>") local=\(rule.localNetwork ?? "<any>") localPrefix=\(rule.localPrefix.map(String.init) ?? "<none>") proto=\(rule.protocolRaw)"
                )
            }
        }
        settings.includedNetworkRules = builtRules
        core.logInfo("included network rules count=\(builtRules.count)")

        setTunnelNetworkSettings(settings) { [core] error in
            if let error {
                core.logError("setTunnelNetworkSettings error: \(error)")
                completionHandler(error)
                return
            }
            core.logInfo("setTunnelNetworkSettings ok")
            completionHandler(nil)
        }
    }

    public override func stopProxy(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        core.logInfo("extension stopProxy reason=\(reason.rawValue)")
        core.detachEngine(reason: Int32(reason.rawValue))
        completionHandler()
    }

    public override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        completionHandler?(core.handleAppMessage(messageData))
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

    private static func makeNetworkRule(_ rule: RamaTransparentProxyRuleBridge)
        -> NENetworkRule?
    {
        let remote = networkEndpoint(from: rule.remoteNetwork)
        let local = networkEndpoint(from: rule.localNetwork)
        let proto = networkRuleProtocol(rule.protocolRaw)

        // Host/domain-only rule (no local matcher): use destination-host initializer.
        // This avoids forcing CIDR for non-IP hosts (e.g. example.com).
        if let remote, local == nil, rule.remotePrefix == nil {
            return NENetworkRule(
                destinationHost: remote,
                protocol: proto
            )
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
            return nil
        }

        return NENetworkRule(
            remoteNetwork: remote,
            remotePrefix: remotePrefix,
            localNetwork: local,
            localPrefix: localPrefix,
            protocol: proto,
            direction: .outbound
        )
    }

    private static func resolvedPrefix(
        endpoint: NWHostEndpoint?,
        networkText: String?,
        explicitPrefix: UInt8?
    ) -> Int? {
        guard endpoint != nil else { return 0 }
        if let explicitPrefix { return Int(explicitPrefix) }
        guard let networkText else { return nil }
        return inferredHostPrefix(networkText)
    }

    private static func networkEndpoint(from network: String?) -> NWHostEndpoint? {
        guard let network, !network.isEmpty else { return nil }
        return NWHostEndpoint(hostname: network, port: "0")
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
    private static func engineConfigJson(
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

    private static func networkRuleProtocol(_ raw: UInt32) -> NENetworkRule.`Protocol` {
        switch raw {
        case UInt32(RAMA_RULE_PROTOCOL_TCP.rawValue): return .TCP
        case UInt32(RAMA_RULE_PROTOCOL_UDP.rawValue): return .UDP
        default: return .any
        }
    }

    private static func tcpMeta(flow: NEAppProxyTCPFlow) -> RamaTransparentProxyFlowMetaBridge {
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

    private static func udpMeta(
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

    private static func sourceAppMeta(_ flow: NEAppProxyFlow?) -> (
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

    private static func udpLocalEndpoint(flow: NEAppProxyUDPFlow) -> Any? {
        if #available(macOS 15.0, *) {
            return flow.localFlowEndpoint
        }
        return bestEffortLocalEndpoint(flow)
    }

    private static func udpRemoteEndpoint(flow: NEAppProxyUDPFlow) -> Any? {
        let object = flow as NSObject
        if object.responds(to: NSSelectorFromString("remoteFlowEndpoint")) {
            return object.value(forKey: "remoteFlowEndpoint")
        }
        if object.responds(to: NSSelectorFromString("remoteEndpoint")) {
            return object.value(forKey: "remoteEndpoint")
        }
        return nil
    }

    private static func bestEffortLocalEndpoint(_ flow: NEAppProxyFlow) -> Any? {
        let object = flow as NSObject
        if object.responds(to: NSSelectorFromString("localEndpoint")) {
            return object.value(forKey: "localEndpoint")
        }
        if object.responds(to: NSSelectorFromString("localFlowEndpoint")) {
            return object.value(forKey: "localFlowEndpoint")
        }
        return nil
    }

    private static func endpointHostPort(_ endpoint: Any?) -> (host: String, port: UInt16)? {
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
