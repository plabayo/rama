import Foundation
import RamaAppleNEFFI
@preconcurrency import NetworkExtension

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

private struct UdpWriterSharedState {
    var closed = false
    /// Accepted datagrams not yet handed to `writeDatagrams`. This covers
    /// both dispatch blocks waiting for the flow queue and `pending` entries.
    var waiting = 0
    /// Payload bytes retained by dispatch blocks, the queue, or the one
    /// in-flight kernel write.
    var retainedBytes = 0
    var fallbackEndpoint: NWEndpoint?
    var fullWasLogged = false
    #if DEBUG
        var acceptedDispatches: UInt64 = 0
        var droppedFull: UInt64 = 0
        var fullLogCount: UInt64 = 0
        var borrowedMaterializations: UInt64 = 0
    #endif
}

final class UdpClientWritePump: @unchecked Sendable {
    // Held behind the protocol so tests can drive the pump with a
    // capture-mock; production passes a concrete NEAppProxyUDPFlow.
    private let flow: any UdpFlowWritable
    private let logger: (FlowLogMessage) -> Void
    private let onTerminalError: (Error) -> Void
    private let onActivity: () -> Void
    private let queue: DispatchQueue
    private let queueKey = DispatchSpecificKey<UInt8>()
    /// Admission is synchronized before dispatch so the queue backlog itself
    /// cannot retain more datagrams than the documented lossy bound.
    private let shared = Locked(UdpWriterSharedState())
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
        /// Test-only rendezvous immediately before the write/close gate.
        /// Release builds carry no hook storage or branch.
        var testBeforeWriteGate: (() -> Void)?
    #endif

    init(
        flow: any UdpFlowWritable,
        queue: DispatchQueue,
        logger: @escaping (FlowLogMessage) -> Void,
        onTerminalError: @escaping (Error) -> Void,
        onActivity: @escaping () -> Void = {}
    ) {
        self.flow = flow
        self.queue = queue
        self.logger = logger
        self.onTerminalError = onTerminalError
        self.onActivity = onActivity
        queue.setSpecific(key: queueKey, value: 1)
    }


    func markOpened() {
        queue.async {
            guard self.phase != .closed,
                !self.shared.withLock({ $0.closed })
            else { return }
            self.phase = .idle
            self.flushLocked()
        }
    }

    func setSentByEndpoint(_ endpoint: NWEndpoint?) {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            setSentByEndpointLocked(endpoint)
        } else {
            queue.async { self.setSentByEndpointLocked(endpoint) }
        }
    }

    private func setSentByEndpointLocked(_ endpoint: NWEndpoint?) {
        guard phase != .closed,
            !shared.withLock({ $0.closed })
        else { return }
        guard let endpoint else {
            flushLocked()
            return
        }
        let accepted = shared.withLock { state in
            guard !state.closed else { return false }
            state.fallbackEndpoint = endpoint
            return true
        }
        guard accepted else { return }
        #if DEBUG
            testSentByEndpointSetCount += 1
            testLastSentByEndpoint = endpoint
        #endif
        sentByEndpoint = endpoint
        flushLocked()
    }

    /// Enqueue a reply datagram. `sentBy` is the peer the reply came
    /// from — surfaced from `Datagram.peer` on the Rust side and
    /// threaded through here so the kernel-bound write tags the
    /// correct source. `nil` falls back to the latest known peer
    /// captured via `setSentByEndpoint` (used by tests and very
    /// early bootstrap before the first per-peer read).
    func enqueue(_ data: Data, sentBy: NWEndpoint? = nil) {
        enqueue(byteCount: data.count) { (data, sentBy) }
    }

    /// Rust-backed counterpart. The borrowed FFI views are materialized only
    /// after a count+byte reservation succeeds, and always before returning to
    /// Rust. Raw pointers never escape onto `queue`.
    func enqueueBorrowed(_ view: RamaBytesView, peerView: RamaUdpPeerView) {
        let byteCount = Int(view.len)
        enqueue(byteCount: byteCount, borrowed: true) {
            (
                dataFromView(view),
                peerFromView(peerView)?.toNetworkExtensionEndpoint()
            )
        }
    }

    private func enqueue(
        byteCount: Int,
        borrowed: Bool = false,
        materialize: () -> (Data, NWEndpoint?)
    ) {
        // RFC 768 admits zero-length UDP datagrams. Forward them
        // unchanged — filtering belongs in the service layer, not in
        // the transport plumbing.
        enum Admission {
            case accepted
            case full(log: Bool)
            case closed
        }
        let admission = shared.withLock { state -> Admission in
            guard !state.closed else { return .closed }
            guard state.waiting < udpWritePumpMaxPending,
                byteCount >= 0,
                byteCount <= udpWritePumpMaxRetainedBytes,
                state.retainedBytes <= udpWritePumpMaxRetainedBytes - byteCount
            else {
                let shouldLog = !state.fullWasLogged
                state.fullWasLogged = true
                #if DEBUG
                    state.droppedFull &+= 1
                    if shouldLog { state.fullLogCount &+= 1 }
                #endif
                return .full(log: shouldLog)
            }

            let (data, explicitEndpoint) = materialize()
            let endpoint = explicitEndpoint ?? state.fallbackEndpoint
            state.waiting += 1
            state.retainedBytes += byteCount
            #if DEBUG
                state.acceptedDispatches &+= 1
                if borrowed { state.borrowedMaterializations &+= 1 }
            #endif
            // Submit while holding the admission lock. Two concurrent callers
            // therefore reach the serial queue in the same order in which
            // their capacity slots were reserved.
            queue.async { self.acceptLocked(data, sentBy: endpoint) }
            return .accepted
        }

        switch admission {
        case .accepted:
            onActivity()
        case .full(let shouldLog):
            // Receiving a datagram remains activity even when the bounded,
            // lossy writer must drop it. The activity clock is thread-safe.
            onActivity()
            if shouldLog {
                RamaLog.trace(
                    "udp client write pump full (count cap \(udpWritePumpMaxPending), byte cap \(udpWritePumpMaxRetainedBytes)), dropping subsequent arrivals"
                )
            }
        case .closed:
            break
        }
    }

    private func acceptLocked(_ data: Data, sentBy: NWEndpoint?) {
        guard phase != .closed,
            !shared.withLock({ $0.closed })
        else {
            releaseReservation(count: 1, bytes: data.count)
            return
        }
        pending.pushBack((data, sentBy))
        let depth = pending.count
        if depth > pendingCountHwm {
            pendingCountHwm = depth
            if depth > udpWritePumpHwmLogThreshold {
                RamaLog.trace(
                    "udp client write pump queue depth hwm=\(depth) cap=\(udpWritePumpMaxPending)"
                )
            }
        }
        flushLocked()
    }

    func close() {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            shared.withLock { state in
                state.closed = true
                state.fallbackEndpoint = nil
            }
            closeLocked()
            return
        }
        shared.withLock { state in
            guard !state.closed else { return }
            state.closed = true
            state.fallbackEndpoint = nil
            queue.async { self.closeLocked() }
        }
    }

    private func closeLocked() {
        phase = .closed
        pending.removeAll()
        sentByEndpoint = nil
        shared.withLock { state in
            state.closed = true
            state.waiting = 0
            state.retainedBytes = 0
            state.fallbackEndpoint = nil
        }
    }

    private func releaseReservation(count: Int = 0, bytes: Int = 0) {
        guard count > 0 || bytes > 0 else { return }
        shared.withLock { state in
            state.waiting = max(0, state.waiting - count)
            state.retainedBytes = max(0, state.retainedBytes - bytes)
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
        var droppedOrphanBytes = 0
        if sentByEndpoint == nil {
            while let head = pending.first(), head.1 == nil {
                droppedOrphanBytes += pending.popFront()!.0.count
                droppedOrphans += 1
            }
        }
        releaseReservation(count: droppedOrphans, bytes: droppedOrphanBytes)
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

        #if DEBUG
            testBeforeWriteGate?()
        #endif
        // Linearize the nonblocking kernel write invocation with off-queue
        // `close()`. If close wins this lock, no write can begin after close
        // returns. If this block wins, the write began before close returned.
        let started = shared.withLock { state -> Bool in
            guard !state.closed else { return false }
            phase = .writing
            // Safe: `first()` returned non-nil, no other thread mutates
            // `pending` (single-queue confinement).
            let chunk = pending.popFront()!.0
            state.waiting = max(0, state.waiting - 1)
            let chunkBytes = chunk.count
            // `[weak self]` breaks the flow→completion→pump cycle.
            flow.writeDatagrams([chunk], sentBy: [endpoint]) { [weak self] error in
                guard let self else { return }
                self.queue.async { [weak self] in
                    guard let self else { return }
                    guard self.phase == .writing else { return }
                    if let error {
                        self.shared.withLock { state in
                            state.closed = true
                            state.waiting = 0
                            state.retainedBytes = 0
                            state.fallbackEndpoint = nil
                        }
                        self.logger(
                            classifyFlowCallbackError(
                                error,
                                operation: "udp flow.write",
                                isClosing: self.phase == .closed
                            )
                        )
                        self.phase = .closed
                        self.pending.removeAll()
                        self.sentByEndpoint = nil
                        self.onTerminalError(error)
                        return
                    }

                    self.releaseReservation(bytes: chunkBytes)
                    self.phase = .idle
                    self.flushLocked()
                }
            }
            return true
        }
        if !started { closeLocked() }
    }

    #if DEBUG
        var testAdmissionSnapshot: (
            closed: Bool,
            waiting: Int,
            retainedBytes: Int,
            acceptedDispatches: UInt64,
            droppedFull: UInt64,
            fullLogCount: UInt64,
            borrowedMaterializations: UInt64
        ) {
            shared.withLock { state in
                (
                    state.closed,
                    state.waiting,
                    state.retainedBytes,
                    state.acceptedDispatches,
                    state.droppedFull,
                    state.fullLogCount,
                    state.borrowedMaterializations
                )
            }
        }
    #endif
}
