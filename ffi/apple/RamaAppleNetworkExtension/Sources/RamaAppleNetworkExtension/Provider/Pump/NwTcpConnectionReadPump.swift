import Foundation
import Network
import NetworkExtension
import RamaAppleNEFFI

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
    /// See [`TcpClientReadPump.onPromoteCarryover`] — same role for
    /// the egress (NWConnection-receive) direction.
    private var onPromoteCarryover: ((Data?) -> Void)?

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

    /// Symmetric to [`TcpClientReadPump.cancelForPromote`] for the
    /// egress (NWConnection-receive) direction. See its doc for
    /// the carryover semantics and the `onComplete` barrier.
    func cancelForPromote(
        onCarryover: @escaping (Data?) -> Void,
        onComplete: @escaping () -> Void
    ) {
        queue.async {
            guard self.phase != .closed else {
                onComplete()
                return
            }
            if let pending = self.pendingData {
                self.pendingData = nil
                onCarryover(.some(pending))
            }
            let hadInFlightRead = (self.phase == .reading)
            self.phase = .closed
            // External cancel pre-empts the EOF backstop — same
            // rationale as the existing `cancel()` path.
            self.eofWork?.cancel()
            self.eofWork = nil
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
                if self.phase == .closed {
                    // Receive in flight while the pump was
                    // cancelled. If a promote-cutover installed
                    // a carryover sink, route the result; else
                    // drop as before.
                    let sink = self.onPromoteCarryover
                    self.onPromoteCarryover = nil
                    if let sink {
                        if let data, !data.isEmpty {
                            // Forward the bytes. A final receive that
                            // also carries `isComplete` loses its EOF
                            // bit here, but the forwarder rediscovers
                            // it with one benign direct `receive`.
                            sink(.some(data))
                        } else {
                            // No bytes: EOF / error / (defensively) an
                            // empty non-terminal receive. Always fire
                            // the sink so the carryover `onComplete`
                            // barrier (`markEgressReadDrained`) runs and
                            // the S→C direction can't wedge. Mirrors
                            // `TcpClientReadPump`.
                            sink(.none)
                        }
                    }
                    return
                }
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
                    //
                    // Capture `connection` strongly: a promote teardown
                    // (or any outer drop) can release the pump between
                    // EOF observation and the grace deadline. With
                    // `[weak self]` only, `self.connection.cancel()`
                    // never fires and the NWConnection registration
                    // leaks until the OS reaps it. Mirrors the write
                    // pump's linger watchdog.
                    let conn = self.connection
                    let work = DispatchWorkItem { [weak self] in
                        conn.cancelAndDetach()
                        self?.eofWork = nil
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
