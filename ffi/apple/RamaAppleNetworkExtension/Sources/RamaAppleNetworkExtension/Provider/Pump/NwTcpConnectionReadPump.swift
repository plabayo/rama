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
    /// Grace window between observing peer EOF / error and force-
    /// cancelling the underlying connection. The clean teardown path
    /// (`on_server_closed` → cancel) depends on the originating app
    /// being able to drain; the grace gives the clean path a chance to
    /// run before the backstop fires.
    private let eofGraceDeadline: DispatchTimeInterval
    private let onReadError: @Sendable (Error) -> Void
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
    private var pendingTerminal: EgressReadTerminal?
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
        onReadError: @escaping @Sendable (Error) -> Void = { _ in }
    ) {
        self.connection = connection
        self.session = session
        self.queue = queue
        self.eofGraceDeadline = eofGraceDeadline
        self.onReadError = onReadError
    }
    func start() {
        queue.async { self.scheduleReadLocked() }
    }

    /// Whether the EOF-grace backstop is armed; read on `queue`. Test seam.
    var isEofBackstopArmed: Bool { eofWork != nil }

    /// Resume scheduling receives after the Rust side has freed egress
    /// capacity. No-op unless the pump is currently paused.
    func resume() {
        queue.async {
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
        queue.async {
            // Disarm the EOF-grace backstop BEFORE the `.closed` early
            // return: an armed timer always implies `.closed` (every arm
            // site sets it in the same block), and a stale timer would
            // force-cancel the connection under the new forwarder's feet.
            // The forwarder rediscovers a pre-existing EOF with one benign
            // direct `receive`.
            self.eofWork?.cancel()
            self.eofWork = nil
            guard self.phase != .closed else {
                onComplete()
                return
            }
            if let pending = self.pendingData {
                self.pendingData = nil
                onCarryover(.some(pending))
            }
            if let terminal = self.pendingTerminal {
                self.pendingTerminal = nil
                if case .failure(let error) = terminal {
                    onError(error)
                }
                onCarryover(.none)
            }
            let hadInFlightRead = (self.phase == .reading)
            self.phase = .closed
            if hadInFlightRead {
                self.onPromoteCarryover = onCarryover
                self.onPromoteError = onError
                self.onPromoteComplete = onComplete
            } else {
                onComplete()
            }
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
                self.scheduleEgressReleaseLocked()
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
                self.pendingTerminal = nil
                self.phase = .closed
                self.scheduleEgressReleaseLocked()
                return
            }
        }

        phase = .reading
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            self.queue.async {
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
                        self.scheduleEgressReleaseLocked()
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
                        return
                    case .closed:
                        // Rust dropped the egress consumer; no demand will
                        // follow. Stop reading AND arm the bounded release so
                        // the NWConnection can't linger if the clean teardown
                        // path never reaches the cancel. Symmetric with the
                        // EOF/error path and with `TcpClientReadPump`'s
                        // `.closed` → `terminate(...)`.
                        self.phase = .closed
                        self.scheduleEgressReleaseLocked()
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
        switch terminal {
        case .eof:
            session?.onEgressEof()
        case .failure(let error):
            onReadError(error)
            session?.onEgressError()
        }
        scheduleEgressReleaseLocked()
    }

    /// Bounded fallback that force-cancels the egress NWConnection if the
    /// clean teardown path (`on_egress_eof`/`on_server_closed` → Swift cancel)
    /// doesn't reach it first.
    ///
    /// Armed whenever this pump stops reading for a terminal reason — peer
    /// EOF/error, Rust returning `.closed` (the bridge dropped the egress
    /// consumer), or the session vanishing mid-flight. Without it, a
    /// `.closed`/session-gone path would silently stop reading while the
    /// NWConnection (and its NECP registration) stays live until the OS reaps
    /// it — the sibling asymmetry with `TcpClientReadPump`, which routes its
    /// `.closed` through `terminate(...)`.
    ///
    /// The clean path is given `eofGraceDeadline` to win first; `cancel()` is
    /// idempotent so a late watchdog is a no-op. `connection` is captured
    /// strongly (not via `[weak self]`) so a promote teardown / outer drop
    /// between arming and the deadline still releases the registration —
    /// mirrors the write pump's linger watchdog.
    private func scheduleEgressReleaseLocked() {
        guard eofWork == nil else { return }
        let conn = self.connection
        let work = DispatchWorkItem { [weak self] in
            conn.cancelAndDetach()
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
