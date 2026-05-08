import Darwin
import Foundation
import NetworkExtension
import RamaAppleNEFFI

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
/// 4 MiB sits comfortably above a typical h2 stream window (1–2 MiB) so
/// the writer can absorb a full window's worth of frames without pausing
/// per-stream-worth of bytes, while keeping per-flow memory bounded.
let writePumpMaxPendingBytes: Int = 4 * 1024 * 1024

/// Drop-on-full bound for `UdpClientWritePump.pending`. UDP is lossy by
/// definition, so the pump prefers dropping the newest datagram on
/// overflow over indefinite buffering. Picked to absorb a brief stall
/// (e.g. waiting for the first client read so `sentByEndpoint` is
/// known) without blowing up under a misbehaving producer.
private let udpWritePumpMaxPending: Int = 256

private func blockedFlowError() -> NSError {
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

private func tcpUpstreamUnavailableError() -> NSError {
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
    private var readPending = false
    private var closed = false
    /// Set when the Rust ingress channel signaled "full". While paused we
    /// stop calling `flow.readData` so kernel buffer pressure is propagated
    /// upstream to the originating app instead of accumulating on our side.
    /// Cleared by `resume()`, which is wired to the Rust → Swift
    /// `onClientReadDemand` callback.
    private var paused = false
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
    /// ingress channel. Idempotent — calling while not paused is a no-op.
    func resume() {
        queue.async {
            guard !self.closed else { return }
            self.paused = false
            self.requestReadLocked()
        }
    }

    private func requestReadLocked() {
        guard !self.closed, !self.readPending, !self.paused else { return }

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
                self.paused = true
                return
            case .closed:
                self.pendingData = nil
                self.terminate(with: nil)
                return
            }
        }

        self.readPending = true
        self.flow.readData { data, error in
            self.queue.async {
                guard !self.closed else { return }
                self.readPending = false

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
                    self.pendingData = data
                    self.paused = true
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
        guard !closed else { return }
        closed = true
        onTerminal(error)
    }
}

/// Classify a `NEAppProxyFlow` callback error into an expected
/// disconnect vs. an actionable failure. Codes come from
/// `NEAppProxyFlow.h`; disconnect-like outcomes log at `trace` so
/// they don't drown out genuine provider faults.
private func classifyFlowCallbackError(
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
}

/// See `TcpClientReadPump` for the `@unchecked Sendable`
/// rationale — same lock + queue confinement applies here.
final class TcpClientWritePump: @unchecked Sendable {
    private let flow: TcpFlowWritable
    private let logger: (FlowLogMessage) -> Void
    private let onTerminalError: (Error) -> Void
    /// Fired when `pending` drops back below `writePumpMaxPending` after a
    /// previous `enqueue` returned `.paused`. Wired to
    /// `RamaTcpSessionHandle.signalServerDrain` so the Rust bridge resumes
    /// pulling response bytes through the duplex.
    private let onDrained: () -> Void
    private let queue: DispatchQueue

    /// Cross-thread state. `enqueue` is called from a Tokio worker;
    /// the rest of the pump runs on `queue`. Wrapping in `Locked`
    /// keeps the "is the pump still alive + has it reached its byte
    /// budget" answer cheap and consistent for the FFI fast path so
    /// it can return synchronously without dispatching onto the
    /// serial queue (a sync hop from an async runtime worker is a
    /// foot-gun: any stall on the queue stalls a worker thread).
    private let state = Locked(TcpWriterState())

    // Queue-only state — only read/written on `queue`.
    private var pending: [Data] = []
    private var writing = false
    private var closeRequested = false
    private var opened = false
    private var onDrainedClose: ((Bool) -> Void)?
    /// Current exponential backoff for transient write errors (ms). Reset to
    /// `writeRetryInitialDelayMs` on every successful write.
    private var retryDelayMs: Int = writeRetryInitialDelayMs
    /// Wall-clock deadline for the in-progress retry sequence. Bounds the
    /// total time we spin on transient errors regardless of how many
    /// individual retries fit. Cleared on every successful write.
    private var retryDeadlineAt: DispatchTime?

    init(
        flow: TcpFlowWritable,
        queue: DispatchQueue,
        logger: @escaping (FlowLogMessage) -> Void,
        onTerminalError: @escaping (Error) -> Void,
        onDrained: @escaping () -> Void
    ) {
        self.flow = flow
        self.queue = queue
        self.logger = logger
        self.onTerminalError = onTerminalError
        self.onDrained = onDrained
    }

    func markOpened() {
        queue.async { [weak self] in
            guard let self else { return }
            if self.isClosed() { return }
            self.opened = true
            self.flushLocked()
        }
    }

    func failOpen(_ error: Error) {
        queue.async { [weak self] in
            guard let self else { return }
            self.terminateLocked(with: error)
        }
    }

    /// Enqueue a chunk for delivery via the underlying flow's write.
    ///
    /// Returns synchronously to the caller (the Rust bridge, via the FFI
    /// thunk) with one of:
    ///   - `.accepted` — chunk queued; Rust may keep producing.
    ///   - `.paused` — `pendingBytes` reached `writePumpMaxPendingBytes`.
    ///     Rust must wait for `signalServerDrain` (wired to `onDrained`)
    ///     before producing more.
    ///   - `.closed` — pump is being torn down; no further drain will fire.
    ///
    /// The cross-thread state check is lock-protected; the actual
    /// append + flush dispatches asynchronously onto the pump's queue
    /// so the FFI thread never blocks on the dispatch queue.
    @discardableResult
    func enqueue(_ data: Data) -> RamaTcpDeliverStatusBridge {
        guard !data.isEmpty else { return .accepted }

        let decision: RamaTcpDeliverStatusBridge = state.withLock { s in
            if s.closed { return .closed }
            // First chunk through unconditionally — an oversized
            // single chunk (larger than the cap) must not deadlock
            // the bridge.
            if s.pendingBytes > 0
                && s.pendingBytes + data.count > writePumpMaxPendingBytes
            {
                s.pausedSignaled = true
                return .paused
            }
            s.pendingBytes += data.count
            return .accepted
        }
        guard decision == .accepted else { return decision }

        queue.async { [weak self] in
            guard let self else { return }
            // Re-check under lock; cancel() can have flipped the flag
            // between the FFI fast-path return and this dispatch.
            let stillOpen: Bool = self.state.withLock { s in
                if s.closed {
                    s.pendingBytes -= data.count
                    return false
                }
                return true
            }
            guard stillOpen else { return }
            self.pending.append(data)
            self.flushLocked()
        }
        return .accepted
    }

    func closeWhenDrained(_ onDrainedClose: @escaping (_ wasOpened: Bool) -> Void) {
        queue.async { [weak self] in
            guard let self else { return }
            if self.isClosed() {
                onDrainedClose(self.opened)
                return
            }
            self.closeRequested = true
            self.onDrainedClose = onDrainedClose
            self.finishCloseIfDrainedLocked()
        }
    }

    /// External-cancel entry point. Sets the closed flag synchronously
    /// so any pending retry's `flushLocked` short-circuits immediately,
    /// then schedules queue-side cleanup. Required because the Rust
    /// bridge may have already torn down while the writer is still
    /// looping on transient errors against a dying flow.
    ///
    /// If a `closeWhenDrained` completion was registered, it fires
    /// with `wasOpened = false` so the dispatcher's teardown chain
    /// always resolves. Without this, a `cancel()` after
    /// `closeWhenDrained` would leave the completion pending forever.
    func cancel() {
        state.withLock { s in
            s.closed = true
            s.pendingBytes = 0
        }
        queue.async { [weak self] in
            guard let self else { return }
            self.pending.removeAll(keepingCapacity: false)
            self.retryDeadlineAt = nil
            let onDrainedClose = self.onDrainedClose
            let wasOpened = self.opened
            self.onDrainedClose = nil
            onDrainedClose?(wasOpened)
        }
    }

    private func isClosed() -> Bool {
        state.withLock { $0.closed }
    }

    private func flushLocked() {
        if isClosed() {
            return
        }
        if writing || pending.isEmpty || !opened {
            finishCloseIfDrainedLocked()
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
        if fireDrain {
            // Edge-triggered drain signal — wakes Rust before the
            // current write completes so it can start producing in
            // parallel with the in-flight write.
            onDrained()
        }

        self.flow.write(chunk) { [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.writing = false
                if let error {
                    if isTransientWriteBackpressure(error) {
                        // Apple's per-flow NE kernel buffer is full. Re-queue
                        // the chunk at the head of `pending` (preserves order)
                        // and back off briefly. Tearing the flow down here
                        // would surface as a "random" mid-stream connection
                        // drop to the originating app for the large-h2 case
                        // we deliberately ride out.
                        //
                        // Bound the loop with a wall-clock deadline so a
                        // dying flow's kernel buffer that keeps returning
                        // ENOBUFS can't pin the pump (and the queue's
                        // captured `self`) alive indefinitely.
                        let now = DispatchTime.now()
                        if self.retryDeadlineAt == nil {
                            self.retryDeadlineAt = now + .milliseconds(writeRetryHardDeadlineMs)
                        }
                        if let deadline = self.retryDeadlineAt, now >= deadline {
                            self.logger(
                                FlowLogMessage(
                                    level: .debug,
                                    text: "tcp flow.write transient-retry deadline (\(writeRetryHardDeadlineMs)ms) exceeded; tearing flow down",
                                )
                            )
                            self.terminateLocked(with: error)
                            return
                        }
                        self.pending.insert(chunk, at: 0)
                        self.state.withLock { $0.pendingBytes += chunk.count }
                        let delay = self.retryDelayMs
                        self.retryDelayMs = min(self.retryDelayMs * 2, writeRetryMaxDelayMs)
                        self.queue.asyncAfter(deadline: .now() + .milliseconds(delay)) { [weak self] in
                            self?.flushLocked()
                        }
                        return
                    }
                    self.logger(
                        classifyFlowCallbackError(
                            error,
                            operation: "tcp flow.write",
                            isClosing: self.isClosed()
                        )
                    )
                    self.terminateLocked(with: error)
                    return
                }
                self.retryDeadlineAt = nil
                self.retryDelayMs = writeRetryInitialDelayMs
                self.flushLocked()
            }
        }
    }

    /// Queue-side terminal cleanup. The closed flag is published under
    /// the lock so any concurrent FFI `enqueue` on another thread sees
    /// the shutdown and returns `.closed` without touching the queue.
    private func terminateLocked(with error: Error) {
        let alreadyClosed: Bool = state.withLock { s in
            let wasClosed = s.closed
            s.closed = true
            s.pendingBytes = 0
            return wasClosed
        }
        if alreadyClosed { return }
        closeRequested = true
        pending.removeAll(keepingCapacity: false)
        retryDeadlineAt = nil
        let onDrainedClose = self.onDrainedClose
        self.onDrainedClose = nil
        onTerminalError(error)
        // If the close-when-drained path was waiting for us, signal
        // it so the dispatcher's drain completion still runs.
        onDrainedClose?(opened)
    }

    private func finishCloseIfDrainedLocked() {
        guard closeRequested, !writing, pending.isEmpty else { return }
        let alreadyClosed: Bool = state.withLock { s in
            let wasClosed = s.closed
            if !wasClosed { s.closed = true }
            return wasClosed
        }
        if alreadyClosed { return }
        let onDrainedClose = self.onDrainedClose
        let wasOpened = self.opened
        self.onDrainedClose = nil
        onDrainedClose?(wasOpened)
    }
}

private final class UdpClientWritePump {
    private let flow: NEAppProxyUDPFlow
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
    private var writing = false
    private var closed = false
    private var opened = false
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
        flow: NEAppProxyUDPFlow,
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
            guard !self.closed else { return }
            self.opened = true
            self.flushLocked()
        }
    }

    func failOpen(_ error: Error) {
        queue.async {
            guard !self.closed else { return }
            self.closed = true
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
            if self.closed { return }
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
            self.flushLocked()
        }
    }

    func close() {
        queue.async {
            self.closed = true
            self.pending.removeAll(keepingCapacity: false)
        }
    }

    private func flushLocked() {
        if writing || pending.isEmpty || closed || !opened {
            return
        }

        // Resolve the endpoint: prefer the one captured at enqueue
        // time; fall back to the latest known peer for entries that
        // arrived before any `setSentByEndpoint` call.
        guard let endpoint = pending[0].1 ?? sentByEndpoint else {
            return
        }

        writing = true
        let chunk = pending.removeFirst().0
        self.flow.writeDatagrams([chunk], sentBy: [endpoint]) { error in
            self.queue.async {
                self.writing = false
                if let error {
                    self.logger(
                        classifyFlowCallbackError(
                            error,
                            operation: "udp flow.write",
                            isClosing: self.closed
                        )
                    )
                    self.closed = true
                    self.pending.removeAll(keepingCapacity: false)
                    self.onTerminalError(error)
                    return
                }

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
private func makeTcpNwParameters(_ opts: RamaTcpEgressConnectOptions?) -> NWParameters {
    let params = NWParameters(tls: nil, tcp: NWProtocolTCP.Options())
    if let opts {
        applyNwEgressParameters(opts.parameters, to: params)
    }
    return params
}

/// Creates UDP `NWParameters` from optional Rust-supplied egress options.
private func makeUdpNwParameters(_ opts: RamaUdpEgressConnectOptions?) -> NWParameters {
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
private final class NwTcpConnectionReadPump {
    private let connection: NWConnection
    /// `weak` for the same retain-cycle / ownership reasons as
    /// [`TcpClientReadPump.session`].
    private weak var session: RamaTcpSessionHandle?
    private let queue: DispatchQueue
    private var closed = false
    private var paused = false
    /// Tracks whether a `connection.receive(...)` call is in flight. Prevents
    /// `resume()` (or repeated `start()`s) from issuing a second concurrent
    /// receive, which `Network.framework` does not support.
    private var receiving = false
    /// See [`TcpClientReadPump.pendingData`] — same contract for the egress
    /// (NWConnection-receive) direction. Dropping rejected bytes here is what
    /// the wails-zip / golang-module repro showed as TLS "bad record MAC".
    private var pendingData: Data?

    init(connection: NWConnection, session: RamaTcpSessionHandle, queue: DispatchQueue) {
        self.connection = connection
        self.session = session
        self.queue = queue
    }

    func start() {
        queue.async { self.scheduleReadLocked() }
    }

    /// Resume scheduling receives after the Rust side has freed egress
    /// capacity. Idempotent.
    func resume() {
        queue.async {
            guard !self.closed else { return }
            self.paused = false
            self.scheduleReadLocked()
        }
    }

    private func scheduleReadLocked() {
        guard !self.closed, !self.paused, !self.receiving else { return }

        // Replay any chunk Rust rejected with `.paused` last time before
        // issuing a new receive.
        if let pending = self.pendingData {
            guard let session = self.session else {
                self.pendingData = nil
                self.closed = true
                return
            }
            switch session.onEgressBytes(pending) {
            case .accepted:
                self.pendingData = nil
                // fall through to schedule the next receive
            case .paused:
                self.paused = true
                return
            case .closed:
                self.pendingData = nil
                self.closed = true
                return
            }
        }

        self.receiving = true
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.queue.async {
                self.receiving = false
                guard !self.closed else { return }

                if let data, !data.isEmpty {
                    guard let session = self.session else {
                        // Session was torn down while a receive was in
                        // flight — drop the bytes and stop. Re-issuing
                        // another `connection.receive` here would keep the
                        // NWConnection's read side draining bytes that have
                        // nowhere to go.
                        self.closed = true
                        return
                    }
                    switch session.onEgressBytes(data) {
                    case .accepted:
                        break
                    case .paused:
                        // Rust did NOT take these bytes. Save them for
                        // replay; do NOT issue another receive until
                        // `resume()`.
                        self.pendingData = data
                        self.paused = true
                        return
                    case .closed:
                        // No demand will follow; tear the pump down now.
                        self.closed = true
                        return
                    }
                }
                if isComplete || error != nil {
                    self.closed = true
                    self.session?.onEgressEof()
                    return
                }
                self.scheduleReadLocked()
            }
        }
    }

    func cancel() {
        queue.async { self.closed = true }
    }
}

/// Queues outbound bytes and sends them to a `NWConnection` one at a time.
///
/// When `closeWhenDrained()` is called Rust signals it is done writing;
/// the pump drains its queue and then sends an empty final `send` to
/// signal half-close to the remote.
/// See `TcpClientReadPump` for the `@unchecked Sendable`
/// rationale — same lock + queue confinement applies here.
private final class NwTcpConnectionWritePump: @unchecked Sendable {
    private let connection: NWConnection
    /// See `TcpClientWritePump.onDrained`. Wired to
    /// `RamaTcpSessionHandle.signalEgressDrain`.
    private let onDrained: () -> Void
    private let queue: DispatchQueue

    /// See `TcpClientWritePump.state` for why this is a `Locked<…>`
    /// rather than a free-standing lock + ivars.
    private let state = Locked(TcpWriterState())

    private var pending: [Data] = []
    private var writing = false
    private var closeRequested = false
    private var retryDelayMs: Int = writeRetryInitialDelayMs
    /// See `TcpClientWritePump.retryDeadlineAt`. Same wall-clock cap
    /// on the transient-retry loop.
    private var retryDeadlineAt: DispatchTime?

    init(connection: NWConnection, queue: DispatchQueue, onDrained: @escaping () -> Void) {
        self.connection = connection
        self.queue = queue
        self.onDrained = onDrained
    }

    /// Same status contract as [`TcpClientWritePump.enqueue`].
    @discardableResult
    func enqueue(_ data: Data) -> RamaTcpDeliverStatusBridge {
        guard !data.isEmpty else { return .accepted }

        let decision: RamaTcpDeliverStatusBridge = state.withLock { s in
            if s.closed { return .closed }
            if s.pendingBytes > 0
                && s.pendingBytes + data.count > writePumpMaxPendingBytes
            {
                s.pausedSignaled = true
                return .paused
            }
            s.pendingBytes += data.count
            return .accepted
        }
        guard decision == .accepted else { return decision }

        queue.async { [weak self] in
            guard let self else { return }
            let stillOpen: Bool = self.state.withLock { s in
                if s.closed {
                    s.pendingBytes -= data.count
                    return false
                }
                return true
            }
            guard stillOpen else { return }
            self.pending.append(data)
            self.flush()
        }
        return .accepted
    }

    func closeWhenDrained() {
        queue.async { [weak self] in
            guard let self else { return }
            if self.isClosed() { return }
            self.closeRequested = true
            self.finishCloseIfDrained()
        }
    }

    func cancel() {
        state.withLock { s in
            s.closed = true
            s.pendingBytes = 0
        }
        queue.async { [weak self] in
            guard let self else { return }
            self.pending.removeAll(keepingCapacity: false)
            self.retryDeadlineAt = nil
        }
    }

    private func isClosed() -> Bool {
        state.withLock { $0.closed }
    }

    private func flush() {
        if isClosed() { return }
        guard !writing, !pending.isEmpty else { return }
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
        if fireDrain { onDrained() }

        connection.send(content: chunk, completion: .contentProcessed({ [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.writing = false
                if let error {
                    if isTransientWriteBackpressure(error) {
                        let now = DispatchTime.now()
                        if self.retryDeadlineAt == nil {
                            self.retryDeadlineAt = now + .milliseconds(writeRetryHardDeadlineMs)
                        }
                        if let deadline = self.retryDeadlineAt, now >= deadline {
                            self.terminateLocked()
                            return
                        }
                        self.pending.insert(chunk, at: 0)
                        self.state.withLock { $0.pendingBytes += chunk.count }
                        let delay = self.retryDelayMs
                        self.retryDelayMs = min(self.retryDelayMs * 2, writeRetryMaxDelayMs)
                        self.queue.asyncAfter(deadline: .now() + .milliseconds(delay)) { [weak self] in
                            self?.flush()
                        }
                        return
                    }
                    self.terminateLocked()
                    return
                }
                self.retryDeadlineAt = nil
                self.retryDelayMs = writeRetryInitialDelayMs
                self.flush()
                self.finishCloseIfDrained()
            }
        }))
    }

    private func terminateLocked() {
        let alreadyClosed: Bool = state.withLock { s in
            let wasClosed = s.closed
            s.closed = true
            s.pendingBytes = 0
            return wasClosed
        }
        if alreadyClosed { return }
        closeRequested = true
        pending.removeAll(keepingCapacity: false)
        retryDeadlineAt = nil
    }

    private func finishCloseIfDrained() {
        guard closeRequested, !writing, pending.isEmpty else { return }
        let alreadyClosed: Bool = state.withLock { s in
            let wasClosed = s.closed
            if !wasClosed { s.closed = true }
            return wasClosed
        }
        if alreadyClosed { return }
        connection.send(
            content: nil, isComplete: true,
            completion: .contentProcessed({ _ in }))
    }
}

/// Reads datagrams from a `NWConnection` in a loop and delivers them to a Rust UDP session.
private final class NwUdpConnectionReadPump {
    private let connection: NWConnection
    private let session: RamaUdpSessionHandle
    private let queue: DispatchQueue
    private var closed = false
    // Wires read-side EOF/error into the flow's `terminate` so a
    // half-open flow doesn't sit until `udp_max_flow_lifetime` reaps it.
    private let onTerminate: (Error?) -> Void

    init(
        connection: NWConnection,
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
        queue.async { self.closed = true }
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
private final class TcpFlowContext {
    weak var session: RamaTcpSessionHandle?
    /// Egress NWConnection, reachable from late callbacks that must
    /// still be able to `cancel()` the flow.
    var connection: NWConnection?
    /// Read pumps reachable from the Rust → Swift demand callbacks.
    var clientReadPump: TcpClientReadPump?
    var egressReadPump: NwTcpConnectionReadPump?
    /// Writer pumps retained until terminal teardown so we can
    /// cancel them from dispatcher-owned close paths.
    var clientWritePump: TcpClientWritePump?
    var egressWritePump: NwTcpConnectionWritePump?
}

private final class UdpFlowContext {
    weak var session: RamaUdpSessionHandle?
    var connection: NWConnection?
    /// Per-flow pumps + closures, owned by the provider's state map
    /// until the flow is removed.
    var writer: UdpClientWritePump?
    var requestRead: (() -> Void)?
    var terminate: ((Error?) -> Void)?
    var closed: Bool = false
    var readPending: Bool = false
    var demandPending: Bool = false
}

public final class RamaTransparentProxyProvider: NETransparentProxyProvider {
    private var engine: RamaTransparentProxyEngineHandle?
    private let stateQueue = DispatchQueue(label: "rama.tproxy.state")
    private var tcpSessions: [ObjectIdentifier: RamaTcpSessionHandle] = [:]
    private var tcpContexts: [ObjectIdentifier: TcpFlowContext] = [:]
    private var udpSessions: [ObjectIdentifier: RamaUdpSessionHandle] = [:]
    private var udpContexts: [ObjectIdentifier: UdpFlowContext] = [:]

    private func registerTcpFlow(
        _ flowId: ObjectIdentifier,
        session: RamaTcpSessionHandle,
        context: TcpFlowContext
    ) {
        stateQueue.sync {
            self.tcpSessions[flowId] = session
            self.tcpContexts[flowId] = context
        }
    }

    private func registerUdpFlow(
        _ flowId: ObjectIdentifier,
        session: RamaUdpSessionHandle,
        context: UdpFlowContext
    ) {
        stateQueue.sync {
            self.udpSessions[flowId] = session
            self.udpContexts[flowId] = context
        }
    }

    private func removeTcpFlow(_ flowId: ObjectIdentifier) {
        stateQueue.sync {
            self.tcpSessions.removeValue(forKey: flowId)
            self.tcpContexts.removeValue(forKey: flowId)
        }
    }

    private func removeUdpFlow(_ flowId: ObjectIdentifier) {
        stateQueue.sync {
            self.udpSessions.removeValue(forKey: flowId)
            self.udpContexts.removeValue(forKey: flowId)
        }
    }

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
        logInfo("extension startProxy")

        let engineConfigJson = Self.engineConfigJson(
            protocolConfiguration: self.protocolConfiguration as? NETunnelProviderProtocol,
            startOptions: options
        )
        if let engineConfigJson {
            self.logInfo("engine config json bytes=\(engineConfigJson.count)")
        }
        guard let engine = RamaTransparentProxyEngineHandle(engineConfigJson: engineConfigJson)
        else {
            self.logError("engine creation error")
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
        self.engine = engine
        self.logInfo("engine created")

        guard let startup = self.engine?.config() else {
            logError("failed to get transparent proxy config from rust")
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

        let settings = NETransparentProxyNetworkSettings(
            tunnelRemoteAddress: startup.tunnelRemoteAddress
        )
        var builtRules: [NENetworkRule] = []
        for (idx, rule) in startup.rules.enumerated() {
            if let built = Self.makeNetworkRule(rule) {
                builtRules.append(built)
                logInfo(
                    "include rule[\(idx)] remote=\(rule.remoteNetwork ?? "<any>") remotePrefix=\(rule.remotePrefix.map(String.init) ?? "<none>") local=\(rule.localNetwork ?? "<any>") localPrefix=\(rule.localPrefix.map(String.init) ?? "<none>") proto=\(rule.protocolRaw)"
                )
            } else {
                logError(
                    "invalid rule[\(idx)] remote=\(rule.remoteNetwork ?? "<any>") remotePrefix=\(rule.remotePrefix.map(String.init) ?? "<none>") local=\(rule.localNetwork ?? "<any>") localPrefix=\(rule.localPrefix.map(String.init) ?? "<none>") proto=\(rule.protocolRaw)"
                )
            }
        }
        settings.includedNetworkRules = builtRules
        logInfo("included network rules count=\(builtRules.count)")

        setTunnelNetworkSettings(settings) { error in
            if let error {
                self.logError("setTunnelNetworkSettings error: \(error)")
                completionHandler(error)
                return
            }

            self.logInfo("setTunnelNetworkSettings ok")
            completionHandler(nil)
        }
    }

    public override func stopProxy(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        logInfo("extension stopProxy reason=\(reason.rawValue)")
        self.engine?.stop(reason: Int32(reason.rawValue))
        self.engine = nil
        stateQueue.sync {
            self.tcpSessions.removeAll(keepingCapacity: false)
            self.tcpContexts.removeAll(keepingCapacity: false)
            self.udpSessions.removeAll(keepingCapacity: false)
            self.udpContexts.removeAll(keepingCapacity: false)
        }
        completionHandler()
    }

    public override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        logDebug("handleAppMessage bytes=\(messageData.count)")

        guard let engine else {
            logDebug("handleAppMessage ignored because engine is unavailable")
            completionHandler?(nil)
            return
        }

        completionHandler?(engine.handleAppMessage(messageData))
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if let tcp = flow as? NEAppProxyTCPFlow {
            let meta = Self.tcpMeta(flow: tcp)
            return handleTcpFlow(tcp, meta: meta)
        }

        if let udp = flow as? NEAppProxyUDPFlow {
            return handleUdpFlow(udp)
        }

        logDebug("handleNewFlow unsupported type=\(String(describing: type(of: flow)))")
        return false
    }

    private func handleTcpFlow(_ flow: NEAppProxyTCPFlow, meta: RamaTransparentProxyFlowMetaBridge)
        -> Bool
    {
        let flowId = ObjectIdentifier(flow)
        let flowQueue = DispatchQueue(label: "rama.tproxy.tcp.flow", qos: .utility)
        let ctx = TcpFlowContext()

        let writer = TcpClientWritePump(
            flow: flow,
            queue: flowQueue,
            logger: { [weak self] message in
                self?.logFlowMessage(message)
            },
            onTerminalError: { [weak self, weak ctx] error in
                // [weak ctx] keeps the writer's onTerminalError closure
                // from pinning the per-flow context graph alive after
                // the session is removed.
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                ctx?.connection?.cancel()
                ctx?.session?.cancel()
                self?.removeTcpFlow(flowId)
            },
            onDrained: { [weak ctx] in
                ctx?.session?.signalServerDrain()
            }
        )
        ctx.clientWritePump = writer

        let decision =
            engine?.newTcpSession(
                meta: meta,
                onServerBytes: { [weak ctx] data in
                    // Reach the writer through ctx so the Rust callback
                    // box can't keep the writer alive past dispatcher
                    // teardown. `.closed` tells the Rust bridge to stop
                    // producing.
                    ctx?.clientWritePump?.enqueue(data) ?? .closed
                },
                onClientReadDemand: { [weak ctx] in
                    // Rust → Swift: the per-flow ingress channel has space
                    // again, so we may resume `flow.readData`. Hop onto the
                    // flow's queue before touching `ctx`, since this fires
                    // from a Rust worker thread.
                    flowQueue.async { [weak ctx] in
                        ctx?.clientReadPump?.resume()
                    }
                },
                onServerClosed: { [weak self, weak ctx] in
                    ctx?.clientWritePump?.closeWhenDrained { wasOpened in
                        if wasOpened {
                            flow.closeReadWithError(nil)
                            flow.closeWriteWithError(nil)
                        } else {
                            let error = tcpUpstreamUnavailableError()
                            flow.closeReadWithError(error)
                            flow.closeWriteWithError(error)
                        }
                        ctx?.connection?.cancel()
                        self?.removeTcpFlow(flowId)
                    }
                }
            ) ?? .passthrough

        let session: RamaTcpSessionHandle
        switch decision {
        case .intercept(let createdSession):
            session = createdSession
        case .passthrough:
            logDebug("handleNewFlow tcp bypassed by rust flow policy")
            return false
        case .blocked:
            logInfo("handleNewFlow tcp blocked by rust flow policy")
            blockFlow(flow)
            return true
        }

        ctx.session = session
        // Publish the flow state before any callback that may observe it can fire.
        registerTcpFlow(flowId, session: session, context: ctx)

        // ── Phase 2: pre-connect egress NWConnection before opening the flow ──
        guard let remoteHost = meta.remoteHost, meta.remotePort > 0 else {
            logDebug("handleTcpFlow: missing remote endpoint; cancelling session")
            session.cancel()
            removeTcpFlow(flowId)
            return true
        }

        let egressOpts = session.getEgressConnectOptions()
        let connectTimeoutMs = egressOpts?.has_connect_timeout_ms == true
            ? egressOpts!.connect_timeout_ms : 30_000
        let nwParams = makeTcpNwParameters(egressOpts)

        // Stamp the intercepted flow's NEFlowMetaData (source app identifier,
        // audit token, …) onto the egress NWParameters when the handler asks
        // for it (default true). Downstream NEAppProxyProviders that
        // intercept our egress see the original app rather than this
        // extension. Must run before the NWConnection is constructed from
        // these params.
        if egressOpts?.parameters.preserve_original_meta_data ?? true {
            applyFlowMetadata(flow, nwParams)
        }

        guard let connection = makeNwConnection(
            host: remoteHost, port: meta.remotePort, using: nwParams)
        else {
            logDebug(
                "handleTcpFlow: invalid remote port \(meta.remotePort); cancelling session"
            )
            session.cancel()
            removeTcpFlow(flowId)
            return true
        }
        ctx.connection = connection

        // Track whether the egress connection succeeded before flow.open was called.
        var egressReady = false

        // Timeout: cancel if NWConnection doesn't reach .ready in time.
        let timeoutMs = Int(connectTimeoutMs)
        let timeoutWork = DispatchWorkItem { [weak self, weak ctx] in
            guard !egressReady else { return }
            self?.logDebug("egress NWConnection timed out for tcp flow remote=\(remoteHost):\(meta.remotePort)")
            ctx?.connection?.cancel()
            ctx?.session?.cancel()
            self?.removeTcpFlow(flowId)
        }
        flowQueue.asyncAfter(deadline: .now() + .milliseconds(timeoutMs), execute: timeoutWork)

        connection.stateUpdateHandler = { [weak self, weak ctx] (state: NWConnection.State) in
            flowQueue.async { [weak self, weak ctx] in
                guard let ctx, let connection = ctx.connection else { return }
                switch state {
                case .ready:
                    guard !egressReady else { return }
                    egressReady = true
                    timeoutWork.cancel()

                    let writePump = NwTcpConnectionWritePump(
                        connection: connection,
                        queue: flowQueue,
                        onDrained: { [weak ctx] in
                            ctx?.session?.signalEgressDrain()
                        }
                    )
                    ctx.egressWritePump = writePump
                    let readPump = NwTcpConnectionReadPump(
                        connection: connection, session: session, queue: flowQueue)
                    ctx.egressReadPump = readPump

                    session.activate(
                        onWriteToEgress: { [weak ctx] data in
                            ctx?.egressWritePump?.enqueue(data) ?? .closed
                        },
                        onEgressReadDemand: { [weak ctx] in
                            flowQueue.async { [weak ctx] in
                                ctx?.egressReadPump?.resume()
                            }
                        },
                        onCloseEgress: { [weak ctx] in
                            ctx?.egressWritePump?.closeWhenDrained()
                        }
                    )

                    flow.open(withLocalEndpoint: nil) { [weak self] error in
                        flowQueue.async {
                            if let error {
                                self?.logDebug("flow.open error after egress ready: \(error)")
                                connection.cancel()
                                session.cancel()
                                self?.removeTcpFlow(flowId)
                                return
                            }
                            self?.logTrace("flow.open ok (tcp, egress pre-connected)")
                            writer.markOpened()
                            readPump.start()

                            // Natural-EOF and hard-error paths
                            // intentionally diverge — see
                            // `TcpReadTerminal`. The natural-EOF
                            // path defers write-side teardown to
                            // the writer pump's drain so queued
                            // response bytes reach the originating
                            // app; closing the write side or
                            // calling `session.cancel()` here
                            // would truncate them. Weak captures
                            // keep this closure graph from pinning
                            // the per-flow context alive.
                            let terminal = TcpReadTerminal(
                                onNaturalEof: {
                                    [weak self, weak readPump, weak session] in
                                    self?.logTrace(
                                        "tcp natural EOF: deferring teardown to closeWhenDrained"
                                    )
                                    flow.closeReadWithError(nil)
                                    readPump?.cancel()
                                    session?.onClientEof()
                                },
                                onHardError: {
                                    [weak self, weak ctx, weak readPump, weak session] err in
                                    flow.closeReadWithError(err)
                                    flow.closeWriteWithError(err)
                                    ctx?.connection?.cancel()
                                    readPump?.cancel()
                                    ctx?.clientWritePump?.cancel()
                                    ctx?.egressWritePump?.cancel()
                                    session?.cancel()
                                    ctx?.clientReadPump = nil
                                    ctx?.egressReadPump = nil
                                    ctx?.clientWritePump = nil
                                    ctx?.egressWritePump = nil
                                    self?.removeTcpFlow(flowId)
                                }
                            )
                            let flowReadPump = TcpClientReadPump(
                                flow: flow,
                                session: session,
                                queue: flowQueue,
                                logger: { [weak self] message in self?.logFlowMessage(message) },
                                onTerminal: terminal.dispatch
                            )
                            ctx.clientReadPump = flowReadPump
                            flowReadPump.requestRead()
                        }
                    }

                case .failed(let error):
                    guard !egressReady else { return }
                    timeoutWork.cancel()
                    self?.logDebug(
                        "egress NWConnection failed before flow opened: \(String(describing: error))"
                    )
                    // Explicit cancel() releases the kernel NECP flow slot.
                    connection.cancel()
                    session.cancel()
                    self?.removeTcpFlow(flowId)

                default:
                    break
                }
            }
        }

        connection.start(queue: flowQueue)
        return true
    }

    private func handleUdpFlow(_ flow: NEAppProxyUDPFlow) -> Bool {
        let flowId = ObjectIdentifier(flow)
        let flowQueue = DispatchQueue(label: "rama.tproxy.udp.flow", qos: .utility)
        let ctx = UdpFlowContext()

        ctx.terminate = { [weak self, weak ctx] error in
            // Re-`[weak ctx]` at the nested closure boundary; see
            // `requestRead` for why.
            flowQueue.async { [weak self, weak ctx] in
                guard let ctx, !ctx.closed else { return }
                ctx.closed = true
                ctx.writer?.close()
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                ctx.connection?.cancel()
                ctx.session?.onClientClose()
                self?.removeUdpFlow(flowId)
            }
        }

        ctx.writer = UdpClientWritePump(
            flow: flow,
            queue: flowQueue,
            logger: { [weak self] message in
                self?.logFlowMessage(message)
            },
            onTerminalError: { [weak ctx] error in
                // Route through `[weak ctx]` so this closure (held
                // by the writer) does not strong-capture `terminate`
                // — terminate transitively reaches the writer via
                // `ctx.writer`, so a strong link in either direction
                // would close a writer ↔ terminate cycle.
                ctx?.terminate?(error)
            }
        )

        let bootMeta = Self.udpMeta(
            flow: flow,
            remoteEndpoint: Self.udpRemoteEndpoint(flow: flow),
            localEndpoint: Self.udpLocalEndpoint(flow: flow)
        )

        ctx.requestRead = { [weak self, weak ctx] in
            // Re-`[weak ctx]` at every nested-closure boundary.
            // A `guard let ctx` here would make `ctx` strong for
            // every closure further down, re-introducing a strong
            // capture path back through this chain.
            flowQueue.async { [weak ctx] in
                guard let ctx, !ctx.closed else { return }
                ctx.demandPending = true
                guard !ctx.readPending else { return }
                ctx.readPending = true
                ctx.demandPending = false
                flow.readDatagrams { [weak self, weak ctx] datagrams, endpoints, error in
                    flowQueue.async { [weak ctx] in
                        guard let ctx, !ctx.closed else { return }
                        ctx.readPending = false
                        if let error {
                            self?.logFlowMessage(
                                classifyFlowCallbackError(error, operation: "udp flow.read")
                            )
                            ctx.terminate?(error)
                            return
                        }

                        guard let datagrams, !datagrams.isEmpty else {
                            self?.logTrace("flow.readDatagrams eof")
                            ctx.terminate?(nil)
                            return
                        }

                        // Per-batch endpoint extraction. A multi-
                        // endpoint batch (rare; sendto() to multiple
                        // peers on an unconnected UDP socket) gets
                        // collapsed because the egress side has one
                        // NWConnection per flow; within-batch peer
                        // variation is logged so operators see the
                        // single-peer assumption being violated.
                        let endpoint = endpoints?.first
                        if let endpoints, endpoints.count > 1,
                            !endpoints.dropFirst().allSatisfy({ $0 == endpoints[0] })
                        {
                            self?.logDebug(
                                "udp flow.readDatagrams returned mixed peer endpoints in one batch (\(endpoints.count) entries); single-peer assumption violated"
                            )
                        }
                        ctx.writer?.setSentByEndpoint(endpoint)

                        guard let session = ctx.session else {
                            self?.logDebug(
                                "udp flow read received but session no longer active; closing flow"
                            )
                            ctx.terminate?(nil)
                            return
                        }

                        for datagram in datagrams where !datagram.isEmpty {
                            session.onClientDatagram(datagram)
                        }

                        if ctx.demandPending {
                            ctx.requestRead?()
                        }
                    }
                }
            }
        }

        let decision = engine?.newUdpSession(
            meta: bootMeta,
            // Rust-held closures route through `[weak ctx]` so the
            // callback box (Rust) does not strong-pin the per-flow
            // pumps. The box is dropped on `_session_free`, so once
            // `removeUdpFlow` releases the session-handle these
            // closures stop firing — no late-arrival hazard.
            onServerDatagram: { [weak ctx] data in ctx?.writer?.enqueue(data) },
            onClientReadDemand: { [weak ctx] in ctx?.requestRead?() },
            onServerClosed: { [weak ctx] in ctx?.terminate?(nil) }
        ) ?? .passthrough

        let session: RamaUdpSessionHandle
        switch decision {
        case .intercept(let createdSession):
            session = createdSession
        case .passthrough:
            logDebug("handleNewFlow udp bypassed by rust flow policy")
            return false
        case .blocked:
            logInfo("handleNewFlow udp blocked by rust flow policy")
            blockFlow(flow)
            return true
        }

        ctx.session = session
        // Publish the flow state before any callback that may observe it can fire.
        registerUdpFlow(flowId, session: session, context: ctx)

        // ── Phase 2: pre-connect egress NWConnection before opening the flow ──
        guard let remoteHost = bootMeta.remoteHost, bootMeta.remotePort > 0 else {
            logDebug("handleUdpFlow: missing remote endpoint; cancelling session")
            session.onClientClose()
            removeUdpFlow(flowId)
            return true
        }

        let egressOpts = session.getEgressConnectOptions()
        let nwParams = makeUdpNwParameters(egressOpts)
        let connectTimeoutMs: UInt32 = egressOpts?.has_connect_timeout_ms == true
            ? egressOpts!.connect_timeout_ms : 30_000

        // See TCP path for rationale; same metadata-propagation behavior.
        if egressOpts?.parameters.preserve_original_meta_data ?? true {
            applyFlowMetadata(flow, nwParams)
        }

        guard let connection = makeNwConnection(
            host: remoteHost, port: bootMeta.remotePort, using: nwParams)
        else {
            logDebug(
                "handleUdpFlow: invalid remote port \(bootMeta.remotePort); cancelling session"
            )
            session.onClientClose()
            removeUdpFlow(flowId)
            return true
        }
        ctx.connection = connection

        var egressReady = false

        // Wall-clock cap on the NWConnection.stateUpdateHandler reaching
        // `.ready`. Configurable via `NwUdpConnectOptions.connect_timeout`;
        // default 30s when the handler does not override.
        let timeoutWork = DispatchWorkItem { [weak self, weak ctx] in
            guard !egressReady else { return }
            self?.logDebug(
                "egress NWConnection timed out for udp flow remote=\(remoteHost):\(bootMeta.remotePort)"
            )
            ctx?.connection?.cancel()
            ctx?.session?.onClientClose()
            self?.removeUdpFlow(flowId)
        }
        flowQueue.asyncAfter(
            deadline: .now() + .milliseconds(Int(connectTimeoutMs)), execute: timeoutWork)

        connection.stateUpdateHandler = { [weak self, weak ctx] (state: NWConnection.State) in
            flowQueue.async { [weak self, weak ctx] in
                guard let ctx, let connection = ctx.connection else { return }
                switch state {
                case .ready:
                    guard !egressReady else { return }
                    egressReady = true
                    timeoutWork.cancel()

                    let readPump = NwUdpConnectionReadPump(
                        connection: connection,
                        session: session,
                        queue: flowQueue,
                        // Same anti-cycle pattern as the writer's
                        // `onTerminalError`: weak forwarder so the
                        // read pump doesn't strong-pin `terminate`.
                        onTerminate: { [weak ctx] error in ctx?.terminate?(error) }
                    )

                    session.activate(onSendToEgress: { [weak ctx] data in
                        // Surface send failures: the completion
                        // closure runs on NWConnection's scheduler,
                        // hop back onto `flowQueue` so `terminate`
                        // sees flow-scoped state single-threaded.
                        connection.send(
                            content: data,
                            completion: .contentProcessed({ error in
                                if let error {
                                    flowQueue.async { ctx?.terminate?(error) }
                                }
                            })
                        )
                    })

                    flow.open(withLocalEndpoint: nil) { [weak self, weak ctx] error in
                        flowQueue.async {
                            if let error {
                                self?.logDebug("udp flow.open error after egress ready: \(error)")
                                connection.cancel()
                                readPump.cancel()
                                session.onClientClose()
                                self?.removeUdpFlow(flowId)
                                return
                            }
                            self?.logTrace("flow.open ok (udp, egress pre-connected)")
                            ctx?.writer?.markOpened()
                            readPump.start()
                            ctx?.requestRead?()
                        }
                    }

                case .failed(let error):
                    guard !egressReady else { return }
                    timeoutWork.cancel()
                    self?.logDebug(
                        "egress NWConnection failed before udp flow opened: \(String(describing: error))"
                    )
                    // See TCP path: explicit cancel() returns the kernel flow slot.
                    connection.cancel()
                    session.onClientClose()
                    self?.removeUdpFlow(flowId)

                default:
                    break
                }
            }
        }

        connection.start(queue: flowQueue)
        return true
    }

    private func blockFlow(_ flow: NEAppProxyFlow) {
        let error = blockedFlowError()
        flow.closeReadWithError(error)
        flow.closeWriteWithError(error)
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

    private static func inferredHostPrefix(_ text: String) -> Int? {
        var v4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            return 32
        }
        var v6 = in6_addr()
        if text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            return 128
        }
        return nil
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

        if let hostEndpoint = endpoint as? NWHostEndpoint {
            let host = hostEndpoint.hostname.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty, let port = UInt16(hostEndpoint.port) else {
                return nil
            }
            return (host, port)
        }

        // Typed cast failed — fall back to parsing the endpoint's
        // string description. That format is unstable across macOS
        // releases (Apple has changed it before); log here so a
        // future breakage shows up as a flood of "fallback used"
        // debug events rather than silently degrading every flow to
        // "no remote endpoint" → passthrough.
        let raw = String(describing: endpoint)
        guard !raw.isEmpty else { return nil }
        let parsed = parseEndpointString(raw)
        let typeName = String(reflecting: type(of: endpoint))
        if parsed != nil {
            RamaTransparentProxyEngineHandle.log(
                level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
                message: "endpointHostPort: typed NWHostEndpoint cast failed; string-fallback succeeded for \(typeName): raw=\(raw)"
            )
        } else {
            RamaTransparentProxyEngineHandle.log(
                level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
                message: "endpointHostPort: typed NWHostEndpoint cast AND string-fallback failed for \(typeName): raw=\(raw)"
            )
        }
        return parsed
    }

    private static func parseEndpointString(_ raw: String) -> (host: String, port: UInt16)? {
        // IPv6 endpoint descriptions may be formatted as:
        // - 2a02:...:1.53
        // - [2a02:...:1]:53
        // while IPv4/domain typically use host:port.

        if raw.hasPrefix("["), let closeIdx = raw.lastIndex(of: "]") {
            let host = String(raw[raw.index(after: raw.startIndex)..<closeIdx])
            let tail = raw[raw.index(after: closeIdx)...]
            if tail.first == ":" {
                let portText = String(tail.dropFirst())
                if let port = UInt16(portText), !host.isEmpty {
                    return (host, port)
                }
            }
        }

        if let idx = raw.lastIndex(of: ":") {
            let hostPart = String(raw[..<idx]).trimmingCharacters(
                in: CharacterSet(charactersIn: "[]"))
            let portPart = String(raw[raw.index(after: idx)...])
            if let port = UInt16(portPart), !hostPart.isEmpty {
                return (hostPart, port)
            }
        }

        if let idx = raw.lastIndex(of: ".") {
            let hostPart = String(raw[..<idx]).trimmingCharacters(
                in: CharacterSet(charactersIn: "[]"))
            let portPart = String(raw[raw.index(after: idx)...])
            if hostPart.contains(":"), let port = UInt16(portPart), !hostPart.isEmpty {
                return (hostPart, port)
            }
        }

        return nil
    }

    private func logTrace(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_TRACE.rawValue),
            message: message
        )
    }

    private func logDebug(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
            message: message
        )
    }

    private func logInfo(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_INFO.rawValue),
            message: message
        )
    }

    private func logError(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_ERROR.rawValue),
            message: message
        )
    }

    private func logFlowMessage(_ message: FlowLogMessage) {
        switch message.level {
        case .trace:
            logTrace(message.text)
        case .debug:
            logDebug(message.text)
        case .error:
            logError(message.text)
        }
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
