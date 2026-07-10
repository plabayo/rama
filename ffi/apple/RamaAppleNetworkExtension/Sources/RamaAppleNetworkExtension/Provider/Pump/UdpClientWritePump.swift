import Foundation
import RamaAppleNEFFI
import NetworkExtension

enum UdpWritePumpPhase {
    /// `markOpened()` has not yet been called.
    case pending
    /// Opened and no write in flight.
    case idle
    /// A `writeDatagrams` call is in flight.
    case writing
    /// Terminal — pump has torn down.
    case closed
}

final class UdpClientWritePump: @unchecked Sendable {
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
    /// race. Combined with the engine's per-datagram peer
    /// threading (`Datagram::peer` carried through Rust both ways),
    /// the pump fully supports multi-peer UDP flows: each reply
    /// is written to its own peer, not collapsed to a flow-wide
    /// "current" peer.
    // `ChunkQueue` replaces `[(Data, NWEndpoint?)]` so dequeue is
    // amortised O(1) instead of O(n) on every drain step (UDP pumps
    // can queue up to `udpWritePumpMaxPending` entries under burst).
    private var pending: ChunkQueue<(Data, NWEndpoint?)> = ChunkQueue()
    /// Lifecycle phase — replaces the former `writing`, `closed`, and
    /// `opened` boolean triple.
    private var phase: UdpWritePumpPhase = .pending
    /// All-time peak of `pending.count`; used to gate high-water logs
    /// so each new peak above `udpWritePumpHwmLogThreshold` is emitted
    /// exactly once per pump lifetime.
    private var pendingCountHwm: Int = 0
    /// Most-recently-seen source endpoint from `readDatagrams`.
    /// Used only as a *fallback* `sentBy` endpoint for callers that
    /// `enqueue` without an explicit peer (e.g. early bootstrap
    /// before any client read has surfaced an endpoint, or tests).
    /// Healthy multi-peer flows carry per-datagram peers through
    /// the engine and each `enqueue` supplies its own `sentBy`, so
    /// this field is rarely consulted in production.
    private var sentByEndpoint: NWEndpoint?
    /// Sticky flag that fires a debug log exactly once when
    /// `flushLocked` cannot make progress because neither the
    /// per-datagram `sentBy` nor the cached `sentByEndpoint` is
    /// known. Without this the pump silently stalls until either
    /// a future datagram arrives with a peer or the engine's
    /// UDP max-lifetime backstop closes the flow — invisible in
    /// `log show`. The flag clears whenever a write finally
    /// progresses, so flapping is logged once per stall episode.
    private var unresolvedEndpointLogged = false
    #if DEBUG
        /// Test-only instrumentation. Counts every
        /// `setSentByEndpoint` invocation that supplies a non-nil
        /// endpoint; the read-loop in
        /// `TransparentProxyCore.handleUdpFlow` is its only caller
        /// in production. Used by `UdpReadEndpointMismatchTests` to
        /// assert "the read loop attributed exactly N datagrams" —
        /// a stale fabrication path would touch this counter once
        /// per datagram even on mismatched endpoint arrays, the
        /// strict-paired path touches it only for matched indices.
        ///
        /// Gated on `#if DEBUG` so production Release builds carry
        /// neither the field storage (24 bytes / flow) nor the
        /// per-datagram ARC retain on `NWEndpoint`. Tests run in
        /// Debug; the gating is invisible to them.
        internal private(set) var testSentByEndpointSetCount: Int = 0
        /// Companion: the last endpoint observed by
        /// `setSentByEndpoint`. Useful when a test needs to
        /// confirm WHICH endpoint, not just HOW MANY.
        internal private(set) var testLastSentByEndpoint: NWEndpoint?
    #endif

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

    func setSentByEndpoint(_ endpoint: NWEndpoint?) {
        queue.async {
            guard let endpoint else {
                self.flushLocked()
                return
            }
            #if DEBUG
                self.testSentByEndpointSetCount += 1
                self.testLastSentByEndpoint = endpoint
            #endif
            self.sentByEndpoint = endpoint
            self.flushLocked()
        }
    }

    /// Enqueue a reply datagram. `sentBy` is the peer the reply came
    /// from — surfaced from `Datagram.peer` on the Rust side and
    /// threaded through here so the kernel-bound write tags the
    /// correct source. `nil` falls back to the latest known peer
    /// captured via `setSentByEndpoint` (used by tests and very
    /// early bootstrap before the first per-peer read).
    func enqueue(_ data: Data, sentBy: NWEndpoint? = nil) {
        // RFC 768 admits zero-length UDP datagrams. Forward them
        // unchanged — filtering belongs in the service layer, not in
        // the transport plumbing.
        queue.async {
            if self.phase == .closed { return }
            // Drop-on-full: UDP is lossy. Indefinite buffering would
            // deliver datagrams long after the kernel would have dropped
            // them on the wire. Bias toward dropping the newest entry so
            // an unstuck pump first drains older queued work.
            if self.pending.count >= udpWritePumpMaxPending {
                RamaLog.trace(
                    "udp client write pump full (>= \(udpWritePumpMaxPending) datagrams), dropping"
                )
                return
            }
            // Capture the endpoint at enqueue time. Prefer the
            // per-datagram peer (multi-peer correctness); fall back
            // to the cached `sentByEndpoint` for callers that haven't
            // been peer-aware-ified yet (tests, early bootstrap).
            self.pending.pushBack((data, sentBy ?? self.sentByEndpoint))
            let depth = self.pending.count
            if depth > self.pendingCountHwm {
                self.pendingCountHwm = depth
                if depth > udpWritePumpHwmLogThreshold {
                    RamaLog.trace(
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
            self.pending.removeAll()
        }
    }

    private func flushLocked() {
        guard phase == .idle, !pending.isEmpty else { return }

        // Drain any leading orphan entries — a queued reply with
        // no captured `sentBy` and no usable `sentByEndpoint`
        // fallback has no kernel-acceptable peer. Holding it would
        // head-of-line block every later (attributed) reply in the
        // FIFO until either a future `setSentByEndpoint` populates
        // the cache or the engine's UDP max-flow-lifetime closes
        // the flow. UDP is lossy by design; dropping the orphan
        // is the correct trade-off.
        //
        // The cache-nil check is loop-invariant — `sentByEndpoint`
        // is mutated only by `setSentByEndpoint`, which runs on
        // the same serial queue and therefore cannot interleave.
        // Hoist it out so the inner loop is one branch instead of
        // two on the dominant (cache-present) path.
        var droppedOrphans = 0
        if sentByEndpoint == nil {
            while let head = pending.first(), head.1 == nil {
                _ = pending.popFront()
                droppedOrphans += 1
            }
        }
        if droppedOrphans > 0 && !unresolvedEndpointLogged {
            unresolvedEndpointLogged = true
            logger(
                FlowLogMessage(
                    level: .debug,
                    text:
                        "udp write pump dropped \(droppedOrphans) orphan datagram(s): no per-datagram peer and no cached endpoint. Subsequent drops in this episode will not be logged."
                )
            )
        }
        guard let head = pending.first() else { return }
        // `head.1 ?? sentByEndpoint` is now guaranteed non-nil for
        // the head because the orphan-drain above already removed
        // any leading entry where both were nil. If `head.1` is
        // nil here, `sentByEndpoint` must be non-nil.
        guard let endpoint = head.1 ?? sentByEndpoint else {
            // Defensive: should be unreachable after the orphan drain.
            // Keep as a safety net.
            return
        }
        unresolvedEndpointLogged = false

        phase = .writing
        // Safe: `first()` returned non-nil, no other thread mutates
        // `pending` (single-queue confinement).
        let chunk = pending.popFront()!.0
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
                guard self.phase == .writing else { return }
                if let error {
                    self.logger(
                        classifyFlowCallbackError(
                            error,
                            operation: "udp flow.write",
                            isClosing: self.phase == .closed
                        )
                    )
                    self.phase = .closed
                    self.pending.removeAll()
                    self.onTerminalError(error)
                    return
                }

                self.phase = .idle
                self.flushLocked()
            }
        }
    }
}
