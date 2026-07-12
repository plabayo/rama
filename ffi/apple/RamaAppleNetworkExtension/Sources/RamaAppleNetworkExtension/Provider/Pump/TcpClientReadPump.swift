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
}
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
    /// Set by `cancelForPromote(onCarryover:)` to route in-flight
    /// `readData` results to a `TcpDirectForwarder` instead of
    /// dropping them. `Data?` payload: `.some(data)` for bytes,
    /// `.none` for EOF (or error). Fires at most once, then
    /// clears.
    private var onPromoteCarryover: (@Sendable (Data?) -> Void)?

    init(
        flow: any TcpFlowReadable,
        session: any TcpClientBytesSink,
        queue: DispatchQueue,
        logger: @escaping @Sendable (FlowLogMessage) -> Void,
        onTerminal: @escaping @Sendable (Error?) -> Void
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

    /// Stop this pump as part of a promote cutover and route any
    /// in-flight bytes to the caller-supplied carryover handler
    /// instead of dropping them.
    ///
    /// Three callbacks (all invoked on `queue`):
    ///   * `onCarryover(.some(data))` — for the `.paused`-replay
    ///     buffer (if non-nil), and for the result of an
    ///     in-flight `readData` once its completion handler
    ///     fires.
    ///   * `onCarryover(.none)` — if the in-flight read returned
    ///     EOF or an error (the cutover treats these uniformly:
    ///     the direct forwarder propagates EOF to its egress
    ///     pump).
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
    func cancelForPromote(
        onCarryover: @escaping @Sendable (Data?) -> Void,
        onComplete: @escaping @Sendable () -> Void
    ) {
        queue.async {
            guard self.phase != .closed else {
                onComplete()
                return
            }
            // Hand over the replay buffer immediately.
            if let pending = self.pendingData {
                self.pendingData = nil
                onCarryover(.some(pending))
            }
            let hadInFlightRead = (self.phase == .reading)
            self.phase = .closed
            // Install the carryover sink for the in-flight read
            // (if any). When the readData completion lands, it
            // routes through `onPromoteCarryover` rather than
            // the normal sink, then fires `onComplete`. For an
            // idle pump (no in-flight read) we fire `onComplete`
            // immediately — no further carryover can land.
            if hadInFlightRead {
                self.onPromoteCarryover = { payload in
                    onCarryover(payload)
                    onComplete()
                }
            } else {
                onComplete()
            }
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
                        if let data, !data.isEmpty {
                            sink(.some(data))
                        } else {
                            sink(.none)
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
