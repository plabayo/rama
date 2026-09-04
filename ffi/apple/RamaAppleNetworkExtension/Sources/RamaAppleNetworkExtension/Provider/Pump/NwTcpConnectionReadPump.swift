import Foundation
import Network
import NetworkExtension
import RamaAppleNEFFI

/// The upstream→Rust egress sink the egress read pump delivers into.
/// Abstracts `RamaTcpSessionHandle.onEgressBytes`/`onEgressEof` so unit
/// tests can drive the pump's `.paused` replay state machine with a
/// scripted sink — the egress counterpart of [`TcpClientBytesSink`].
protocol NwEgressBytesSink: AnyObject {
    func onEgressBytes(_ data: Data) -> RamaTcpDeliverStatusBridge
    func onEgressEof()
    func onEgressError()
}
extension RamaTcpSessionHandle: NwEgressBytesSink {}

private enum EgressReadTerminal {
    case eof
    case failure(Error)
}

final class NwTcpConnectionReadPump: @unchecked Sendable {
    private let connection: any NwConnectionLike
    /// `weak` for the same retain-cycle / ownership reasons as
    /// [`TcpClientReadPump.session`].
    private weak var session: (any NwEgressBytesSink)?
    private let queue: DispatchQueue
    private let queueKey = DispatchSpecificKey<UInt8>()
    /// Grace window after an abnormal read-side stop. It bounds cleanup when
    /// Rust drops the egress consumer, the session vanishes, or a read fails.
    /// Clean EOF does not arm it; the opposite upload half may remain live.
    private let eofGraceDeadline: DispatchTimeInterval
    private let onTerminalObserved: @Sendable () -> Void
    private let onReadError: @Sendable (Error) -> Void
    /// Owner-level teardown after an abnormal stop's grace expires. When nil,
    /// retain the historical connection-only fallback for standalone users.
    private let onAbnormalStop: (@Sendable (Error) -> Void)?
    private let onActivity: @Sendable () -> Void
    /// Scheduled abnormal-stop work, retained so the clean teardown or
    /// promotion path can invalidate it before its deadline.
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
    private var pendingTerminal: EgressReadTerminal?
    private var observedTerminal: EgressReadTerminal?
    /// See [`TcpClientReadPump.onPromoteCarryover`] — same role for
    /// the egress (NWConnection-receive) direction.
    private var onPromoteCarryover: (@Sendable (Data?) -> Void)?
    private var onPromoteError: (@Sendable (Error) -> Void)?
    private var onPromoteComplete: (@Sendable () -> Void)?

    init(
        connection: any NwConnectionLike,
        session: any NwEgressBytesSink,
        queue: DispatchQueue,
        eofGraceDeadline: DispatchTimeInterval,
        onTerminalObserved: @escaping @Sendable () -> Void = {},
        onReadError: @escaping @Sendable (Error) -> Void = { _ in },
        onAbnormalStop: (@Sendable (Error) -> Void)? = nil,
        onActivity: @escaping @Sendable () -> Void = {}
    ) {
        self.connection = connection
        self.session = session
        self.queue = queue
        self.eofGraceDeadline = eofGraceDeadline
        self.onTerminalObserved = onTerminalObserved
        self.onReadError = onReadError
        self.onAbnormalStop = onAbnormalStop
        self.onActivity = onActivity
        queue.setSpecific(key: queueKey, value: 1)
    }
    func start() {
        queue.async { self.scheduleReadLocked() }
    }

    /// Run queue-confined work inline when Network.framework has already
    /// delivered on the connection's start queue; retain the async fallback
    /// for mocks and any defensive caller arriving from another executor.
    private func runOnQueue(_ work: @escaping @Sendable () -> Void) {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            work()
        } else {
            queue.async(execute: work)
        }
    }

    /// Whether the EOF-grace backstop is armed; read on `queue`. Test seam.
    var isEofBackstopArmed: Bool { eofWork != nil }

    /// Resume scheduling receives after the Rust side has freed egress
    /// capacity. No-op unless the pump is currently paused.
    func resume() {
        runOnQueue {
            guard self.phase == .paused else { return }
            self.phase = .open
            self.scheduleReadLocked()
        }
    }

    /// Symmetric to [`TcpClientReadPump.cancelForPromote`] for the
    /// egress (NWConnection-receive) direction. See its doc for
    /// the carryover semantics and the `onComplete` barrier.
    func cancelForPromote(
        onCarryover: @escaping @Sendable (Data?) -> Void,
        onError: @escaping @Sendable (Error) -> Void = { _ in },
        onComplete: @escaping @Sendable () -> Void
    ) {
        runOnQueue {
            self.cancelForPromoteLocked(
                onCarryover: onCarryover,
                onError: onError,
                onComplete: onComplete)
        }
    }

    private func cancelForPromoteLocked(
        onCarryover: @escaping @Sendable (Data?) -> Void,
        onError: @escaping @Sendable (Error) -> Void,
        onComplete: @escaping @Sendable () -> Void
    ) {
        // Disarm the EOF-grace backstop BEFORE the `.closed` early return: an
        // armed timer always implies `.closed`, and a stale timer would cancel
        // the connection under the forwarder. Run inline when already on the
        // flow queue so the promotion ACK cannot overtake this transition.
        eofWork?.cancel()
        eofWork = nil
        guard phase != .closed else {
            if let terminal = observedTerminal {
                observedTerminal = nil
                if case .failure(let error) = terminal {
                    onError(error)
                }
                onCarryover(.none)
            }
            onComplete()
            return
        }
        if let pending = pendingData {
            pendingData = nil
            onCarryover(.some(pending))
        }
        if let terminal = pendingTerminal {
            pendingTerminal = nil
            if case .failure(let error) = terminal {
                onError(error)
            }
            onCarryover(.none)
        }
        let hadInFlightRead = (phase == .reading)
        phase = .closed
        if hadInFlightRead {
            onPromoteCarryover = onCarryover
            onPromoteError = onError
            onPromoteComplete = onComplete
        } else {
            onComplete()
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
                self.scheduleEgressReleaseLocked(
                    Self.abnormalStopError(
                        terminal: self.pendingTerminal,
                        reason: "egress consumer session disappeared"))
                return
            }
            switch session.onEgressBytes(pending) {
            case .accepted:
                self.pendingData = nil
                if let terminal = self.pendingTerminal {
                    self.pendingTerminal = nil
                    self.finishTerminalLocked(terminal)
                    return
                }
            case .paused:
                self.phase = .paused
                return
            case .closed:
                // Rust dropped the egress consumer; no demand will follow.
                // Stop reading AND arm the bounded release so the
                // NWConnection can't linger if the clean path never cancels.
                self.pendingData = nil
                let terminal = self.pendingTerminal
                self.pendingTerminal = nil
                self.phase = .closed
                self.scheduleEgressReleaseLocked(
                    Self.abnormalStopError(
                        terminal: terminal,
                        reason: "Rust egress consumer closed"))
                return
            }
        }

        phase = .reading
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            // Publish before queue normalization so a concurrently queued
            // pressure eviction cannot commit using an idle timestamp from
            // before these bytes arrived. Replays never pass this boundary a
            // second time.
            if let data, !data.isEmpty {
                self.onActivity()
            }
            self.runOnQueue {
                if self.phase == .closed {
                    // Receive in flight while the pump was
                    // cancelled. If a promote-cutover installed
                    // a carryover sink, route the result; else
                    // drop as before.
                    let sink = self.onPromoteCarryover
                    let errorSink = self.onPromoteError
                    let complete = self.onPromoteComplete
                    self.onPromoteCarryover = nil
                    self.onPromoteError = nil
                    self.onPromoteComplete = nil
                    if let data, !data.isEmpty {
                        sink?(.some(data))
                    }
                    if let error {
                        errorSink?(error)
                        sink?(.none)
                    } else if isComplete {
                        sink?(.none)
                    }
                    complete?()
                    return
                }
                self.phase = .open

                let terminal: EgressReadTerminal?
                if let error {
                    terminal = .failure(error)
                } else if isComplete {
                    terminal = .eof
                } else {
                    terminal = nil
                }

                if let data, !data.isEmpty {
                    guard let session = self.session else {
                        // Session was torn down while a receive was in
                        // flight — drop the bytes and stop. Re-issuing
                        // another `connection.receive` here would keep the
                        // NWConnection's read side draining bytes that have
                        // nowhere to go. Arm the bounded release so the
                        // connection can't linger.
                        self.phase = .closed
                        self.scheduleEgressReleaseLocked(
                            Self.abnormalStopError(
                                terminal: terminal,
                                reason: "egress consumer session disappeared"))
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
                            RamaLog.trace(
                                "tcp egress read pump: replay buffer occupied (\(data.count) B); egress channel full"
                            )
                        }
                        self.pendingData = data
                        self.pendingTerminal = terminal
                        self.phase = .paused
                        if case .failure(let error) = terminal {
                            // Bound a terminal tail that Rust never resumes.
                            // Promotion may still disarm this work and carry
                            // the bytes plus original error across.
                            self.scheduleEgressReleaseLocked(error)
                        }
                        return
                    case .closed:
                        // Rust dropped the egress consumer; no demand will
                        // follow. Stop reading AND arm the bounded release so
                        // the NWConnection can't linger if the clean teardown
                        // path never reaches the cancel. Symmetric with the
                        // EOF/error path and with `TcpClientReadPump`'s
                        // `.closed` → `terminate(...)`.
                        self.phase = .closed
                        self.scheduleEgressReleaseLocked(
                            Self.abnormalStopError(
                                terminal: terminal,
                                reason: "Rust egress consumer closed"))
                        return
                    }
                }
                if let terminal {
                    self.finishTerminalLocked(terminal)
                    return
                }
                self.scheduleReadLocked()
            }
        }
    }

    private func finishTerminalLocked(_ terminal: EgressReadTerminal) {
        phase = .closed
        observedTerminal = terminal
        // Publish the transport terminal before entering Rust. A promote
        // request can race the one-shot Rust close callback; the shared
        // lifecycle bit makes Swift reject that cutover instead of losing
        // the callback edge under a newly created forwarder.
        onTerminalObserved()
        switch terminal {
        case .eof:
            session?.onEgressEof()
        case .failure(let error):
            onReadError(error)
            session?.onEgressError()
            scheduleEgressReleaseLocked(error)
        }
    }

    private static func abnormalStopError(
        terminal: EgressReadTerminal?,
        reason: String
    ) -> Error {
        if case .failure(let error) = terminal { return error }
        return NSError(
            domain: "rama.tproxy.egress-read",
            code: -1,
            userInfo: [NSLocalizedDescriptionKey: reason])
    }

    /// Bounded fallback that asks the owner to tear down the entire flow when
    /// an abnormal stop cannot rely on the clean Rust close path. Standalone
    /// users without an owner callback retain connection-only cancellation.
    ///
    /// Armed for a peer error, Rust returning `.closed` (the bridge dropped the
    /// egress consumer), or the session vanishing mid-flight. Without it, a
    /// `.closed`/session-gone path would silently stop reading while the
    /// NWConnection (and its NECP registration) stays live until the OS reaps
    /// it — the sibling asymmetry with `TcpClientReadPump`, which routes its
    /// `.closed` through `terminate(...)`.
    ///
    /// Clean EOF deliberately does not arm this short fallback: it closes only
    /// server→client, while a quiet client→server half may legally resume much
    /// later. Rust's `on_server_closed` callback owns its eventual drain path.
    /// Both the callback and `connection` are captured strongly so an outer
    /// drop after a hard stop cannot lose the scheduled release action.
    private func scheduleEgressReleaseLocked(_ error: Error) {
        guard eofWork == nil else { return }
        let conn = self.connection
        let teardown = self.onAbnormalStop
        let work = DispatchWorkItem { [weak self] in
            if let teardown {
                teardown(error)
            } else {
                conn.cancelAndDetach()
            }
            self?.eofWork = nil
        }
        eofWork = work
        queue.asyncAfter(deadline: .now() + eofGraceDeadline, execute: work)
    }

    func cancel() {
        queue.async { [weak self] in
            guard let self else { return }
            self.phase = .closed
            self.pendingData = nil
            self.pendingTerminal = nil
            // External cancel pre-empts the EOF backstop: the work
            // item's only job is to ensure cancel reaches the
            // connection if no other path does, and that no-longer-
            // applies once an outer teardown has fired.
            self.eofWork?.cancel()
            self.eofWork = nil
        }
    }
}
