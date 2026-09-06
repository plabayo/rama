import Foundation
import RamaAppleNEFFI
@preconcurrency import NetworkExtension

/// Bound each NetworkExtension write call so a backlogged UDP flow amortizes
/// callback overhead without creating a large transient array or monopolizing
/// the flow queue. A valid non-jumbogram UDP payload fits within 64 KiB.
let udpWritePumpMaxBatchItems = 32
let udpWritePumpMaxBatchBytes = 64 * 1024
/// Keep Swift admission aligned with Rust's `u16::MAX` single-datagram bound.
let udpWritePumpMaxDatagramBytes = Int(UInt16.max)

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

private struct UdpWriterDropSample {
    let aggregate: Bool
    let droppedItems: UInt64
    let droppedBytes: UInt64
    let aggregateDroppedItems: UInt64
}

private struct UdpWriterSharedState {
    var closed = false
    /// False once natural server completion has stopped admission. Existing
    /// accepted work may still drain until `closed` becomes true.
    var accepting = true
    /// Accepted datagrams not yet handed to `writeDatagrams`. This covers
    /// both dispatch blocks waiting for the flow queue and `pending` entries.
    var waiting = 0
    /// Payload bytes retained by dispatch blocks, the queue, or the one
    /// in-flight kernel write.
    var retainedBytes = 0
    var retainedItems = 0
    /// Subset admitted from UDP's bounded service reserve while TCP waiters
    /// held the aggregate gate. These counts must be refunded to both atomics.
    var pressureRetainedBytes = 0
    var pressureRetainedItems = 0
    var fallbackEndpoint: NWEndpoint?
    var droppedFull: UInt64 = 0
    var droppedAggregate: UInt64 = 0
    var droppedBytes: UInt64 = 0
    #if DEBUG || RAMA_TESTING
        var acceptedDispatches: UInt64 = 0
        var fullLogCount: UInt64 = 0
        var borrowedMaterializations: UInt64 = 0
    #endif

    mutating func recordDrop(bytes: Int, aggregate: Bool) -> UdpWriterDropSample? {
        droppedFull = droppedFull == .max ? .max : droppedFull + 1
        if aggregate {
            droppedAggregate = droppedAggregate == .max ? .max : droppedAggregate + 1
        }
        let (totalBytes, overflow) = droppedBytes.addingReportingOverflow(UInt64(max(0, bytes)))
        droppedBytes = overflow ? .max : totalBytes
        guard droppedFull.nonzeroBitCount == 1 else { return nil }
        #if DEBUG || RAMA_TESTING
            fullLogCount += 1
        #endif
        return UdpWriterDropSample(
            aggregate: aggregate, droppedItems: droppedFull, droppedBytes: droppedBytes,
            aggregateDroppedItems: droppedAggregate)
    }
}

final class UdpClientWritePump: @unchecked Sendable {
    private final class PendingDatagram: @unchecked Sendable {
        private var dataStorage: Data?
        let sentBy: NWEndpoint?
        /// Native Swift enqueue calls may use an explicitly populated
        /// fallback. A borrowed Rust callback with an absent/invalid peer must
        /// not: nil is explicit absence in that ABI.
        let allowsFallback: Bool
        private let onPayloadDestroyed: @Sendable () -> Void

        init(
            data: Data,
            sentBy: NWEndpoint?,
            allowsFallback: Bool,
            onPayloadDestroyed: @escaping @Sendable () -> Void
        ) {
            self.dataStorage = data
            self.sentBy = sentBy
            self.allowsFallback = allowsFallback
            self.onPayloadDestroyed = onPayloadDestroyed
        }

        /// The refund callback runs only after this owner's payload reference
        /// is cleared. Queue and write-completion closures retain this object,
        /// so the accounting lifetime follows the last pump-managed owner.
        deinit {
            UdpPayloadLifetimeLease.destroy(&dataStorage, then: onPayloadDestroyed)
        }

        var data: Data {
            guard let dataStorage else {
                preconditionFailure("UDP pending payload accessed after lifetime ended")
            }
            return dataStorage
        }
    }

    /// The callback is queue-confined after construction. The box carries it
    /// across GCD's `@Sendable` boundary without imposing an unnecessary
    /// Sendable requirement on callers.
    private final class DrainCompletionBox: @unchecked Sendable {
        let body: (Bool) -> Void

        init(_ body: @escaping (Bool) -> Void) {
            self.body = body
        }
    }

    // Held behind the protocol so tests can drive the pump with a
    // capture-mock; production passes a concrete NEAppProxyUDPFlow.
    private let flow: any UdpFlowWritable
    private let logger: (FlowLogMessage) -> Void
    private let onTerminalError: (Error) -> Void
    private let onActivity: () -> Void
    private let queue: DispatchQueue
    private let writerMemoryBudget: WriterMemoryBudget
    var aggregateBudget: WriterMemoryBudget { writerMemoryBudget }
    private let queueKey = DispatchSpecificKey<UInt8>()
    /// Admission is synchronized before dispatch so the queue backlog itself
    /// cannot retain more datagrams than the documented lossy bound.
    private let shared = Locked(UdpWriterSharedState())
    /// Serializes close with kernel submission without blocking Rust admission.
    private let writeSubmissionGate = Locked(())
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
    private var pending: ChunkQueue<PendingDatagram> = ChunkQueue()
    /// Lifecycle phase — replaces the former `writing`, `closed`, and
    /// `opened` boolean triple.
    private var phase: UdpWritePumpPhase = .pending
    /// All-time peak of `pending.count`. Log emission is separately bucketed
    /// so a ramp to the cap emits at most three messages, not one per depth.
    private var pendingCountHwm: Int = 0
    private var pendingHwmLogBucket: Int = 0
    private var drainCompletion: DrainCompletionBox?
    private var drainBackstop: DispatchWorkItem?
    /// Explicitly populated fallback for native Swift/test `enqueue` calls
    /// without a peer. Rust-backed replies always carry a per-datagram peer
    /// and never consult this cache; Release client ingress does not update it.
    private var sentByEndpoint: NWEndpoint?
    /// Lifetime-sticky flag that emits one diagnostic when `flushLocked`
    /// drops work without a usable endpoint. It never resets: alternating
    /// peerless and attributed datagrams must not turn a diagnostic into a
    /// packet-rate log source.
    private var orphanDropLogged = false
    #if DEBUG || RAMA_TESTING
        /// Counts real delayed drain backstops. An empty drain completes before
        /// allocating or scheduling one, so close churn cannot leave canceled
        /// no-op work items retained by the dispatch queue until their deadline.
        private(set) var testDrainBackstopScheduleCount = 0
        /// Test-only instrumentation. Counts every
        /// `setSentByEndpoint` invocation that supplies a non-nil endpoint.
        /// `UdpFlowSession` invokes it solely as an explicit test observation
        /// seam for strict read-array pairing; production Release omits it.
        ///
        /// Enabled by DEBUG or RAMA_TESTING so production Release builds carry
        /// neither the field storage (24 bytes / flow) nor the
        /// per-datagram ARC retain on `NWEndpoint`. Debug and explicitly
        /// instrumented optimized tests can both observe it.
        internal private(set) var testSentByEndpointSetCount: Int = 0
        /// Companion: the last endpoint observed by
        /// `setSentByEndpoint`. Useful when a test needs to
        /// confirm WHICH endpoint, not just HOW MANY.
        internal private(set) var testLastSentByEndpoint: NWEndpoint?
        /// Test-only rendezvous immediately before the write/close gate.
        /// Release builds carry no hook storage or branch.
        var testBeforeWriteGate: (() -> Void)?
        /// Test-only ordering hook after callback-entry activity is recorded
        /// but before borrowed FFI views are materialized.
        var testBeforeBorrowedMaterialize: (() -> Void)?
        internal private(set) var testPendingHwmLogCount: Int = 0
    #endif

    init(
        flow: any UdpFlowWritable,
        queue: DispatchQueue,
        logger: @escaping (FlowLogMessage) -> Void,
        onTerminalError: @escaping (Error) -> Void,
        onActivity: @escaping () -> Void = {},
        writerMemoryBudget: WriterMemoryBudget = WriterMemoryBudget()
    ) {
        self.flow = flow
        self.queue = queue
        self.logger = logger
        self.onTerminalError = onTerminalError
        self.onActivity = onActivity
        self.writerMemoryBudget = writerMemoryBudget
        queue.setSpecific(key: queueKey, value: 1)
    }

    deinit {
        while pending.popFront() != nil {}
        shared.withLock { state in
            state.closed = true
            state.accepting = false
        }
    }


    func markOpened() {
        queue.async {
            guard self.phase != .closed,
                !self.shared.withLock({ $0.closed })
            else { return }
            self.phase = .idle
            self.flushLocked()
            self.finishDrainIfReadyLocked()
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
        #if DEBUG || RAMA_TESTING
            testSentByEndpointSetCount += 1
            testLastSentByEndpoint = endpoint
        #endif
        sentByEndpoint = endpoint
        flushLocked()
    }

    /// Enqueue a reply datagram. `sentBy` is the peer the reply came
    /// from — surfaced from `Datagram.peer` on the Rust side and
    /// threaded through here so the kernel-bound write tags the
    /// correct source. `nil` may use the explicitly populated native/test
    /// fallback captured via `setSentByEndpoint`. Rust callbacks use
    /// `enqueueBorrowed` and never opt into that cache.
    func enqueue(_ data: Data, sentBy: NWEndpoint? = nil) {
        enqueue(byteCount: data.count, allowsFallback: true) { (data, sentBy) }
    }

    /// Rust-backed counterpart. The borrowed FFI views are materialized only
    /// after a count+byte reservation succeeds, and always before returning to
    /// Rust. Raw pointers never escape onto `queue`.
    func enqueueBorrowed(_ view: RamaBytesView, peerView: RamaUdpPeerView) {
        // Stamp server activity at callback entry, before admission-lock
        // contention or borrowed-view copying can lose a deadline tie.
        onActivity()
        #if DEBUG || RAMA_TESTING
            testBeforeBorrowedMaterialize?()
        #endif
        let byteCount = Int(view.len)
        enqueue(
            byteCount: byteCount,
            borrowed: true,
            allowsFallback: false,
            activityRecordedAtEntry: true
        ) {
            (
                dataFromView(view),
                peerFromView(peerView)?.toNetworkExtensionEndpoint()
            )
        }
    }

    private func enqueue(
        byteCount: Int,
        borrowed: Bool = false,
        allowsFallback: Bool,
        activityRecordedAtEntry: Bool = false,
        materialize: () -> (Data, NWEndpoint?)
    ) {
        // RFC 768 admits zero-length UDP datagrams. Forward them
        // unchanged — filtering belongs in the service layer, not in
        // the transport plumbing.
        enum Admission {
            case accepted
            case full(UdpWriterDropSample?)
            case closed
        }
        let admission = shared.withLock { state -> Admission in
            guard !state.closed, state.accepting else { return .closed }
            guard state.waiting < udpWritePumpMaxPending,
                byteCount >= 0,
                byteCount <= udpWritePumpMaxDatagramBytes,
                byteCount <= udpWritePumpMaxRetainedBytes,
                state.retainedBytes <= udpWritePumpMaxRetainedBytes - byteCount
            else {
                return .full(state.recordDrop(bytes: byteCount, aggregate: false))
            }

            guard let budgetAdmission = writerMemoryBudget.tryReserveUdp(bytes: byteCount) else {
                return .full(state.recordDrop(bytes: byteCount, aggregate: true))
            }

            let (data, explicitEndpoint) = materialize()
            let endpoint = explicitEndpoint ?? (allowsFallback ? state.fallbackEndpoint : nil)
            state.waiting += 1
            state.retainedBytes += byteCount
            state.retainedItems += 1
            let pressureAdmission: Bool
            switch budgetAdmission {
            case .regular:
                pressureAdmission = false
            case .pressureUdp:
                pressureAdmission = true
                state.pressureRetainedBytes += byteCount
                state.pressureRetainedItems += 1
            }
            #if DEBUG || RAMA_TESTING
                state.acceptedDispatches &+= 1
                if borrowed { state.borrowedMaterializations &+= 1 }
            #endif
            let datagram = PendingDatagram(
                data: data,
                sentBy: endpoint,
                allowsFallback: allowsFallback,
                onPayloadDestroyed: { [shared = self.shared,
                                        budget = self.writerMemoryBudget] in
                    shared.withLock { state in
                        precondition(state.retainedItems >= 1)
                        precondition(state.retainedBytes >= byteCount)
                        state.retainedItems -= 1
                        state.retainedBytes -= byteCount
                        if pressureAdmission {
                            precondition(state.pressureRetainedItems >= 1)
                            precondition(state.pressureRetainedBytes >= byteCount)
                            state.pressureRetainedItems -= 1
                            state.pressureRetainedBytes -= byteCount
                        }
                    }
                    budget.releaseUdp(
                        bytes: byteCount,
                        items: 1,
                        pressureBytes: pressureAdmission ? byteCount : 0,
                        pressureItems: pressureAdmission ? 1 : 0)
                })
            // Submit while holding the admission lock. Two concurrent callers
            // therefore reach the serial queue in the same order in which
            // their capacity slots were reserved. Constructing the lifetime
            // owner first means this block captures no raw `Data` alias.
            queue.async {
                self.acceptLocked(datagram)
            }
            return .accepted
        }

        switch admission {
        case .accepted:
            if !activityRecordedAtEntry { onActivity() }
        case .full(let sample):
            // Receiving a datagram remains activity even when the bounded,
            // lossy writer must drop it. The activity clock is thread-safe.
            if !activityRecordedAtEntry { onActivity() }
            if let sample {
                let text = "UDP client writer dropped datagrams "
                    + "reason=\(sample.aggregate ? "aggregate_capacity" : "flow_capacity") "
                    + "cumulative_dropped_items=\(sample.droppedItems) "
                    + "cumulative_dropped_bytes=\(sample.droppedBytes) "
                    + "aggregate_dropped_items=\(sample.aggregateDroppedItems)"
                logger(FlowLogMessage(level: .info, text: text, publicText: text))
            }
        case .closed:
            break
        }
    }

    private func acceptLocked(_ datagram: PendingDatagram) {
        guard phase != .closed,
            !shared.withLock({ $0.closed })
        else {
            releaseWaiting(1)
            return
        }
        pending.pushBack(datagram)
        let depth = pending.count
        if depth > pendingCountHwm {
            pendingCountHwm = depth
            let bucket: Int
            if depth >= udpWritePumpMaxPending {
                bucket = 3
            } else if depth >= (udpWritePumpMaxPending * 3) / 4 {
                bucket = 2
            } else if depth > udpWritePumpHwmLogThreshold {
                bucket = 1
            } else {
                bucket = 0
            }
            if bucket > pendingHwmLogBucket {
                pendingHwmLogBucket = bucket
                #if DEBUG || RAMA_TESTING
                    testPendingHwmLogCount += 1
                #endif
                RamaLog.trace(
                    "udp client write pump queue depth hwm=\(depth) cap=\(udpWritePumpMaxPending) bucket=\(bucket)/3"
                )
            }
        }
        flushLocked()
    }

    /// Stops new admission synchronously. Accepted dispatch blocks and queued
    /// or in-flight datagrams remain owned by the pump and may still drain.
    func stopAcceptingForDrain() {
        shared.withLock { state in
            guard !state.closed else { return }
            state.accepting = false
        }
    }

    /// Gracefully drains work accepted before admission was stopped. The
    /// completion runs on the pump queue with `true` for a natural drain and
    /// `false` when the bounded backstop forced the pump closed.
    func closeWhenDrained(timeoutMs: UInt32, completion: @escaping (Bool) -> Void) {
        stopAcceptingForDrain()
        let completionBox = DrainCompletionBox(completion)
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            beginDrainLocked(timeoutMs: timeoutMs, completion: completionBox)
        } else {
            queue.async {
                self.beginDrainLocked(timeoutMs: timeoutMs, completion: completionBox)
            }
        }
    }

    private func beginDrainLocked(timeoutMs: UInt32, completion: DrainCompletionBox) {
        guard phase != .closed, !shared.withLock({ $0.closed }) else {
            completion.body(false)
            return
        }
        guard drainCompletion == nil else { return }
        drainCompletion = completion

        // The common empty/pre-activation close is already drained. Complete
        // it before allocating a delayed work item: canceling a scheduled GCD
        // item does not remove the queue's retention through its deadline.
        finishDrainIfReadyLocked()
        guard drainCompletion != nil else { return }

        let backstop = DispatchWorkItem { [weak self] in
            guard let self, self.drainCompletion != nil else { return }
            self.completeDrainLocked(drained: false)
        }
        drainBackstop = backstop
        #if DEBUG || RAMA_TESTING
            testDrainBackstopScheduleCount += 1
        #endif
        queue.asyncAfter(
            deadline: .now() + .milliseconds(Int(timeoutMs)),
            execute: backstop
        )
    }

    private func finishDrainIfReadyLocked() {
        guard drainCompletion != nil, pending.isEmpty,
            phase == .idle || phase == .pending,
            shared.withLock({ $0.waiting == 0 })
        else { return }
        completeDrainLocked(drained: true)
    }

    private func completeDrainLocked(drained: Bool) {
        guard let completion = drainCompletion else { return }
        drainCompletion = nil
        drainBackstop?.cancel()
        drainBackstop = nil
        closeLocked()
        completion.body(drained)
    }

    func close() {
        if DispatchQueue.getSpecific(key: queueKey) != nil {
            shared.withLock { state in
                state.closed = true
                state.accepting = false
                state.fallbackEndpoint = nil
            }
            closeLocked()
            return
        }
        writeSubmissionGate.withLock { _ in
            shared.withLock { state in
                guard !state.closed else { return }
                state.closed = true
                state.accepting = false
                state.fallbackEndpoint = nil
                queue.async { self.closeLocked() }
            }
        }
    }

    private func closeLocked() {
        drainBackstop?.cancel()
        drainBackstop = nil
        drainCompletion = nil
        phase = .closed
        var queuedItems = 0
        while pending.popFront() != nil {
            queuedItems += 1
        }
        sentByEndpoint = nil
        shared.withLock { state in
            state.closed = true
            state.accepting = false
            state.fallbackEndpoint = nil
        }
        releaseWaiting(queuedItems)
    }

    private func releaseWaiting(_ count: Int) {
        guard count > 0 else { return }
        shared.withLock { state in
            precondition(state.waiting >= count)
            state.waiting -= count
        }
    }

    private func flushLocked() {
        guard phase == .idle, !pending.isEmpty else { return }

        // Drain leading orphan entries immediately. A queued reply with no
        // eligible `sentBy` has no kernel-acceptable peer, and retaining it
        // would head-of-line block every later attributed reply. UDP is lossy
        // by design; future fallback updates apply only to native work that is
        // still queued before activation, not to an orphan already flushed.
        //
        // `sentByEndpoint` is queue-confined, so endpoint resolution remains
        // stable throughout this loop. Borrowed explicit absence bypasses the
        // cache; native fallback-eligible entries can still use it.
        var droppedOrphans = 0
        while let head = pending.first(),
            head.sentBy == nil,
            !head.allowsFallback || sentByEndpoint == nil
        {
            let orphan = pending.popFront()!
            _ = orphan
            droppedOrphans += 1
        }
        releaseWaiting(droppedOrphans)
        if droppedOrphans > 0 && !orphanDropLogged {
            orphanDropLogged = true
            logger(
                FlowLogMessage(
                    level: .debug,
                    text:
                        "udp write pump dropped \(droppedOrphans) orphan datagram(s): no usable sentBy endpoint (borrowed peer absent or invalid, or native fallback unavailable). Further orphan-drop diagnostics are suppressed for this pump."
                )
            )
        }
        guard let head = pending.first() else {
            finishDrainIfReadyLocked()
            return
        }
        // The head is now guaranteed to have a usable endpoint. Later orphan
        // entries stop this batch; they are dropped by the next flush before
        // any newer attributed datagram can pass them.
        guard (head.sentBy ?? (head.allowsFallback ? sentByEndpoint : nil)) != nil else {
            // Defensive: should be unreachable after the orphan drain.
            // Keep as a safety net.
            return
        }
        #if DEBUG || RAMA_TESTING
            testBeforeWriteGate?()
        #endif
        let started = writeSubmissionGate.withLock { _ -> Bool in
            guard !shared.withLock({ $0.closed }) else { return false }
            phase = .writing

            var datagrams: [Data] = []
            var endpoints: [NWEndpoint] = []
            var retainedBatch: [PendingDatagram] = []
            datagrams.reserveCapacity(min(udpWritePumpMaxBatchItems, pending.count))
            endpoints.reserveCapacity(min(udpWritePumpMaxBatchItems, pending.count))
            retainedBatch.reserveCapacity(min(udpWritePumpMaxBatchItems, pending.count))
            var batchBytes = 0

            while datagrams.count < udpWritePumpMaxBatchItems,
                let next = pending.first(),
                let endpoint = next.sentBy
                    ?? (next.allowsFallback ? sentByEndpoint : nil),
                next.data.count <= udpWritePumpMaxBatchBytes - batchBytes
            {
                // Safe: `pending` is confined to this serial queue. Payload
                // and peer are popped and appended in the same iteration so
                // the parallel NetworkExtension arrays remain exactly paired.
                let item = pending.popFront()!
                datagrams.append(item.data)
                endpoints.append(endpoint)
                retainedBatch.append(item)
                batchBytes += item.data.count
            }

            // The orphan drain and per-datagram admission ceiling guarantee
            // that the first entry fits and resolves. Keep a defensive guard
            // so an internal invariant violation cannot issue an empty write.
            guard !datagrams.isEmpty else {
                phase = .idle
                return false
            }
            releaseWaiting(datagrams.count)
            // `[weak self]` breaks the flow→completion→pump cycle.
            flow.writeDatagrams(datagrams, sentBy: endpoints) {
                [weak self, retainedBatch] error in
                _ = retainedBatch
                guard let self else { return }
                self.queue.async { [weak self, retainedBatch] in
                    _ = retainedBatch
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
                        self.closeLocked()
                        self.onTerminalError(error)
                        return
                    }
                    self.phase = .idle
                    self.flushLocked()
                    self.finishDrainIfReadyLocked()
                }
            }
            return true
        }
        if !started { closeLocked() }
    }

    #if DEBUG || RAMA_TESTING
        var testAdmissionSnapshot: (
            closed: Bool,
            waiting: Int,
            retainedBytes: Int,
            retainedItems: Int,
            acceptedDispatches: UInt64,
            droppedFull: UInt64,
            droppedAggregate: UInt64,
            fullLogCount: UInt64,
            borrowedMaterializations: UInt64
        ) {
            shared.withLock { state in
                (
                    state.closed,
                    state.waiting,
                    state.retainedBytes,
                    state.retainedItems,
                    state.acceptedDispatches,
                    state.droppedFull,
                    state.droppedAggregate,
                    state.fullLogCount,
                    state.borrowedMaterializations
                )
            }
        }
    #endif
}
