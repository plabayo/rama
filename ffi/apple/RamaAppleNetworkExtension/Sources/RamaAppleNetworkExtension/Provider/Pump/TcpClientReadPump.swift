import Foundation
import Network
import NetworkExtension

/// The client→Rust ingress sink the read pump delivers into. Abstracts
/// `RamaTcpSessionHandle.onClientBytes` so unit tests can drive the pump's
/// `.paused`/`.accepted`/`.closed` replay state machine with a scripted
/// sink instead of a live Rust session (which always `.accepted`s in the
/// demo handler). `@Sendable`-free: the pump confines calls to its queue.
protocol TcpClientBytesSink: AnyObject {
    func onClientBytes(_ data: Data) -> RamaTcpDeliverStatusBridge
    func onClientPayload(_ payload: TcpPayloadSlice) -> RamaTcpDeliverStatusBridge
}
#if DEBUG || RAMA_TESTING
    extension TcpClientBytesSink {
        func onClientPayload(_ payload: TcpPayloadSlice) -> RamaTcpDeliverStatusBridge {
            onClientBytes(payload.copiedData)
        }
    }
#endif
extension RamaTcpSessionHandle: TcpClientBytesSink {}

/// Cross-thread access pattern: `state`-protected fields are
/// accessed under the lock from any thread; everything else is
/// confined to `queue`. Apple's `flow.readData` completion handler
/// is `@Sendable`, which requires the captured `self` to be
/// `Sendable` too — `@unchecked` because Swift can't see the
/// runtime confinement (lock + serial queue) statically.
final class TcpClientReadPump: @unchecked Sendable {
    private let flow: any TcpFlowReadable
    /// `weak` so the pump doesn't pin the session alive (the registry is
    /// the single strong owner). Equally important: stops the strong-ref
    /// cycle ctx → pump → session → callback closures → ctx.
    private weak var session: (any TcpClientBytesSink)?
    private let logger: @Sendable (FlowLogMessage) -> Void
    private let onTerminal: @Sendable (Error?) -> Void
    private let onActivity: @Sendable () -> Void
    private let queue: DispatchQueue
    private let queueKey = DispatchSpecificKey<UInt8>()
    /// Lifecycle phase — replaces the former `readPending`, `paused`, and
    /// `closed` boolean triple.  The compiler now enforces that only one
    /// branch is active at a time instead of relying on scattered guards.
    private var phase: ReadPumpPhase = .open
    /// Bytes Rust rejected with `.paused` on a previous `onClientBytes`. We
    /// MUST replay them before issuing the next `flow.readData` — Rust does
    /// not take ownership on a `.paused` return, so dropping `data` here
    /// would punch a hole in the byte stream and the downstream TLS layer
    /// would surface "bad record MAC" once the gap reaches the decryptor.
    private var pendingPayload: TcpPayloadCursor?
    private let writerMemoryBudget: WriterMemoryBudget
    /// Set by `cancelForPromote(onCarryover:)` to route in-flight
    /// `readData` results to a `TcpDirectForwarder` instead of dropping them.
    /// The separate error channel keeps a hard kernel-read failure distinct
    /// from clean EOF across the cutover. Fires at most once, then clears.
    private var onPromoteCarryover: (@Sendable (
        _ payload: TcpPayloadCursor?, _ error: Error?
    ) -> Void)?
    /// A clean EOF already consumed by the ordinary Rust-bound path. Promotion
    /// may still be valid while the server half remains open, so retain this
    /// one-shot terminal edge for the direct forwarder instead of issuing a
    /// second `readData` after the source has declared that no more data exists.
    private var observedNaturalEof = false

    init(
        flow: any TcpFlowReadable,
        session: any TcpClientBytesSink,
        queue: DispatchQueue,
        logger: @escaping @Sendable (FlowLogMessage) -> Void,
        onTerminal: @escaping @Sendable (Error?) -> Void,
        onActivity: @escaping @Sendable () -> Void = {},
        writerMemoryBudget: WriterMemoryBudget = WriterMemoryBudget()
    ) {
        self.flow = flow
        self.session = session
        self.queue = queue
        self.logger = logger
        self.onTerminal = onTerminal
        self.onActivity = onActivity
        self.writerMemoryBudget = writerMemoryBudget
        queue.setSpecific(key: queueKey, value: 1)
    }

    /// Normalize callers onto the pump queue without paying another dispatch
    /// when the owning flow state machine is already executing there.
    private func runOnQueue(_ work: @escaping @Sendable () -> Void) {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            work()
        } else {
            queue.async(execute: work)
        }
    }

    func requestRead() {
        runOnQueue { self.requestReadLocked() }
    }

    /// Resume reading after the Rust side has freed capacity in the per-flow
    /// ingress channel. No-op unless the pump is currently paused.
    func resume() {
        runOnQueue {
            guard self.phase == .paused else { return }
            self.phase = .open
            self.requestReadLocked()
        }
    }

    /// Stop this pump as part of a promote cutover and route any
    /// in-flight bytes to the caller-supplied carryover handler
    /// instead of dropping them.
    ///
    /// Three callbacks (all invoked on `queue`):
    ///   * `onCarryover(.some(data))` — for the `.paused`-replay
    ///     buffer (if non-nil), and for the result of an
    ///     in-flight `readData` once its completion handler
    ///     fires.
    ///   * `onCarryover(.none)` — if the in-flight read returned EOF.
    ///   * `onError(error)` — if the in-flight read failed.
    ///   * `onComplete()` — fires exactly once, AFTER any
    ///     `onCarryover` invocations, when the pump guarantees
    ///     no more carryover will be delivered. The direct
    ///     forwarder uses this as a barrier: it must NOT issue
    ///     its own `flow.readData` until `onComplete` has
    ///     fired, because `NEAppProxyTCPFlow.readData` is
    ///     caller-enforced serial and the in-flight read must
    ///     finish before a new one is issued.
    ///
    /// `onComplete` fires immediately for an idle pump (no
    /// in-flight read); otherwise after the in-flight read's
    /// completion handler has been routed through `onCarryover`.
    ///
    /// Does NOT fire `onTerminal` — the per-flow context's
    /// teardown path is owned by the cutover orchestrator from
    /// this point on.
    #if DEBUG || RAMA_TESTING
        func cancelForPromote(
            onCarryover: @escaping @Sendable (Data?) -> Void,
            onError: @escaping @Sendable (Error) -> Void = { _ in },
            onComplete: @escaping @Sendable () -> Void
        ) {
            runOnQueue {
                self.cancelForPromoteLocked(
                    onCarryover: { payload, error in
                        if let error {
                            onError(error)
                        } else {
                            onCarryover(payload?.copiedRemainder)
                        }
                    },
                    onComplete: onComplete)
            }
        }
    #endif

    /// Production cutover variant which transfers an existing replay-buffer
    /// charge into the direct forwarder instead of release/re-reserve racing.
    func cancelForPromoteWithReservations(
        onCarryover: @escaping @Sendable (TcpPayloadCursor?) -> Void,
        onError: @escaping @Sendable (Error) -> Void = { _ in },
        onComplete: @escaping @Sendable () -> Void
    ) {
        runOnQueue {
            self.cancelForPromoteLocked(
                onCarryover: { payload, error in
                    if let error {
                        onError(error)
                    } else {
                        onCarryover(payload)
                    }
                },
                onComplete: onComplete)
        }
    }

    private func cancelForPromoteLocked(
        onCarryover: @escaping @Sendable (TcpPayloadCursor?, Error?) -> Void,
        onComplete: @escaping @Sendable () -> Void
    ) {
        guard phase != .closed else {
            if observedNaturalEof {
                observedNaturalEof = false
                onCarryover(.none, nil)
            }
            onComplete()
            return
        }
        // Hand over the replay buffer immediately.
        if let pending = pendingPayload {
            pendingPayload = nil
            onCarryover(.some(pending), nil)
        }
        let hadInFlightRead = (phase == .reading)
        phase = .closed
        // Install the carryover sink for the in-flight read (if any). When
        // its completion lands, it routes here instead of to Rust. This
        // transition runs inline when promotion already owns `queue`, so the
        // ACK cannot overtake sink installation and lose a concurrent read.
        if hadInFlightRead {
            onPromoteCarryover = { payload, error in
                onCarryover(payload, error)
                onComplete()
            }
        } else {
            onComplete()
        }
    }

    private func requestReadLocked() {
        guard phase == .open else { return }

        // Replay any chunk Rust rejected with `.paused` last time before we
        // ask the kernel for new bytes. If this still gets `.paused` we hold
        // the chunk and wait for the next `resume()`.
        if pendingPayload != nil, !deliverPendingPayloadLocked(isInitialDelivery: false) { return }

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
            // Publish activity at the transport boundary, before enqueueing
            // delivery work. A pressure eviction can be queued on the same
            // flow queue concurrently; delaying this edge until that queue runs
            // would let the eviction observe a stale idle timestamp and win.
            if let data, !data.isEmpty {
                self.onActivity()
            }
            let transitPayload: TcpPayloadCursor?
            if let data, !data.isEmpty {
                guard let payload = self.writerMemoryBudget.makeTcpTransitCursor(data)
                else {
                    // Do not capture the uncharged payload in queue work.
                    self.queue.async { [weak self] in
                        guard let self else { return }
                        let pressureError = Self.memoryPressureError()
                        if self.phase == .closed {
                            // Promotion may have installed its in-flight read
                            // barrier before this callback reached the queue.
                            // The payload is deliberately not captured, but the
                            // barrier still needs one terminal result.
                            let sink = self.onPromoteCarryover
                            self.onPromoteCarryover = nil
                            sink?(nil, pressureError)
                            return
                        }
                        self.phase = .open
                        self.terminate(with: pressureError)
                    }
                    return
                }
                transitPayload = payload
            } else {
                transitPayload = nil
            }
            self.queue.async { [weak self, transitPayload] in
                guard let self else { return }
                if self.phase == .closed {
                    // Pump cancelled while a `readData` was in
                    // flight. If a promote-cutover installed a
                    // carryover sink, route the result through
                    // it so the bytes (or EOF) land in the
                    // direct forwarder; otherwise drop, as
                    // before — there is no sink to hand them
                    // to.
                    let sink = self.onPromoteCarryover
                    self.onPromoteCarryover = nil
                    if let sink {
                        if let error {
                            sink(nil, error)
                        } else if let transitPayload {
                            sink(.some(transitPayload), nil)
                        } else {
                            sink(.none, nil)
                        }
                    }
                    return
                }
                self.phase = .open

                if let error {
                    self.logger(
                        classifyFlowCallbackError(error, operation: "tcp flow.read")
                    )
                    self.terminate(with: error)
                    return
                }

                guard let transitPayload else {
                    self.logger(
                        FlowLogMessage(
                            level: .trace,
                            text: "flow.readData eof"
                        )
                    )
                    self.observedNaturalEof = true
                    self.terminate(with: nil)
                    return
                }

                guard self.session != nil else {
                    // Session was torn down while a read was in flight — drop
                    // the bytes and stop reading.
                    self.terminate(with: nil)
                    return
                }
                self.pendingPayload = transitPayload
                if self.deliverPendingPayloadLocked(isInitialDelivery: true) {
                    self.requestReadLocked()
                }
            }
        }
    }

    /// Deliver bounded views from one physical callback root. Accepted views
    /// may remain owned by Rust while the cursor advances; a paused view leaves
    /// the cursor unchanged for exact replay.
    /// Only initial delivery logs a pause, so resumed attempts do not format
    /// another diagnostic for the same physical callback.
    private func deliverPendingPayloadLocked(isInitialDelivery: Bool) -> Bool {
        while var cursor = pendingPayload {
            guard let session else {
                pendingPayload = nil
                terminate(with: nil)
                return false
            }
            let slice = cursor.prefix(maxBytes: writerMemoryBudget.tcpPayloadViewMaxBytes)
            switch session.onClientPayload(slice) {
            case .accepted:
                cursor.advance(by: slice.count)
                pendingPayload = cursor.isEmpty ? nil : cursor
            case .paused:
                if isInitialDelivery {
                    logger(FlowLogMessage(
                        level: .trace,
                        text: "tcp client read pump: replay cursor occupied (\(cursor.remainingBytes) B); ingress channel full"
                    ))
                }
                phase = .paused
                return false
            case .closed:
                pendingPayload = nil
                terminate(with: nil)
                return false
            }
        }
        return true
    }

    private func terminate(with error: Error?) {
        guard phase != .closed else { return }
        phase = .closed
        pendingPayload = nil
        onTerminal(error)
    }

    private static func memoryPressureError() -> Error {
        NSError(
            domain: "rama.tproxy.writer-memory",
            code: 2,
            userInfo: [
                NSLocalizedDescriptionKey:
                    "process Swift payload envelope exhausted retaining TCP client replay"
            ])
    }
}
