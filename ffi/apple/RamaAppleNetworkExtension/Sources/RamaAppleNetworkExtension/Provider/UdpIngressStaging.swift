import Foundation
import RamaAppleNEFFI
@preconcurrency import NetworkExtension

/// Rust-derived limits for payloads retained after Apple's UDP read callback
/// returns. NetworkExtension has already allocated the callback's `[Data]` and
/// endpoint arrays before application code runs; that framework-transient
/// allocation is outside this bound. Rama reserves first and asynchronously
/// captures only the admissible prefix, so its own retained staging is exact:
/// the process is bounded by the historically named
/// `maxItemsPerGeneration`/`maxBytesPerGeneration` fields, and each flow by
/// both `maxItemsPerFlow` and `maxBytesPerFlow`.
struct UdpIngressStagingPolicy: Sendable, Equatable {
    let maxItemsPerFlow: Int
    let maxItemsPerGeneration: Int
    let maxBytesPerFlow: Int
    let maxBytesPerGeneration: Int

    init(
        maxItemsPerFlow: Int,
        maxItemsPerGeneration: Int = 32 * 8_192,
        maxBytesPerFlow: Int,
        maxBytesPerGeneration: Int
    ) {
        self.maxItemsPerFlow = max(1, maxItemsPerFlow)
        self.maxItemsPerGeneration = max(1, maxItemsPerGeneration)
        self.maxBytesPerFlow = max(1, maxBytesPerFlow)
        self.maxBytesPerGeneration = max(1, maxBytesPerGeneration)
    }

    static let testDefaults = Self(
        maxItemsPerFlow: 32,
        maxItemsPerGeneration: 32 * 8_192,
        maxBytesPerFlow: 256 * 1024,
        maxBytesPerGeneration: 16 * 1024 * 1024)
}

let udpIngressStagingMaxGrants = 4
let udpIngressStagingMaxInspectionsPerTurn = 32
private let udpIngressStagingGrantLeaseNanoseconds: UInt64 = 10_000_000

/// Back-deployable atomic integer for the macOS 12 package floor. Swift's
/// `Synchronization.Atomic` starts at macOS 15, so this reuses the package's
/// C11 `_Atomic uint64_t` shim. Atomic loads are real loads rather than the
/// no-op read-modify-writes required by the old OSAtomic implementation.
private final class UdpIngressAtomicCounter: @unchecked Sendable {
    private let atomic: OpaquePointer

    init(_ value: Int = 0) {
        precondition(value >= 0)
        guard let atomic = rama_writer_budget_atomic_new(UInt64(value)) else {
            preconditionFailure("failed to allocate UDP ingress staging atomic")
        }
        self.atomic = atomic
    }

    deinit { rama_writer_budget_atomic_free(atomic) }

    func load() -> Int {
        let value = rama_writer_budget_atomic_load(atomic)
        precondition(value <= UInt64(Int.max), "UDP staging atomic counter overflow")
        return Int(value)
    }

    func loadSeqCst() -> Int {
        let value = rama_writer_budget_atomic_load_seq_cst(atomic)
        precondition(value <= UInt64(Int.max), "UDP staging atomic counter overflow")
        return Int(value)
    }

    var isLockFree: Bool { rama_writer_budget_atomic_is_lock_free(atomic) }

    func store(_ value: Int) {
        precondition(value >= 0)
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            var expected = current
            if rama_writer_budget_atomic_compare_exchange(
                atomic, &expected, UInt64(value))
            {
                return
            }
            current = expected
        }
    }

    func storeSeqCst(_ value: Int) {
        precondition(value >= 0)
        var current = rama_writer_budget_atomic_load_seq_cst(atomic)
        while true {
            var expected = current
            if rama_writer_budget_atomic_compare_exchange_seq_cst(
                atomic, &expected, UInt64(value))
            {
                return
            }
            current = expected
        }
    }

    func compareExchange(expected: Int, desired: Int) -> Bool {
        precondition(expected >= 0 && desired >= 0)
        let target = UInt64(expected)
        var current = target
        while current == target {
            var observed = current
            if rama_writer_budget_atomic_compare_exchange(
                atomic, &observed, UInt64(desired))
            {
                return true
            }
            current = observed
        }
        return false
    }

    func compareExchangeSeqCst(expected: Int, desired: Int) -> Bool {
        precondition(expected >= 0 && desired >= 0)
        let target = UInt64(expected)
        var current = target
        while current == target {
            var observed = current
            if rama_writer_budget_atomic_compare_exchange_seq_cst(
                atomic, &observed, UInt64(desired))
            {
                return true
            }
            current = observed
        }
        return false
    }

    @discardableResult
    func add(_ amount: Int) -> Int {
        precondition(amount >= 0)
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            precondition(current <= UInt64(Int.max - amount),
                "UDP staging atomic counter overflow")
            let desired = current + UInt64(amount)
            var expected = current
            if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired) {
                return Int(desired)
            }
            current = expected
        }
    }

    @discardableResult
    func subtract(_ amount: Int) -> Int {
        precondition(amount >= 0)
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            precondition(current >= UInt64(amount),
                "UDP staging atomic counter underflow")
            let desired = current - UInt64(amount)
            var expected = current
            if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired) {
                return Int(desired)
            }
            current = expected
        }
    }

    /// Atomically add `amount` only while the resulting value stays within
    /// `limit`. A failed CAS retries from the newly observed value.
    func tryReserve(_ amount: Int, limit: Int) -> Bool {
        precondition(amount >= 0 && limit >= 0)
        guard amount > 0 else { return true }
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            guard current <= UInt64(limit), UInt64(amount) <= UInt64(limit) - current
            else { return false }
            let desired = current + UInt64(amount)
            var expected = current
            if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired)
            {
                return true
            }
            current = expected
        }
    }
}

/// Shared destruction primitive for UDP payload owners. Clearing the optional
/// executes its payload's ARC releases before `refund` can advertise capacity.
/// The owner keeps the payload private, so callers cannot separate a raw
/// payload alias from the lifetime that carries its charge.
enum UdpPayloadLifetimeLease {
    static func destroy<Payload>(
        _ payload: inout Payload?, then refund: () -> Void
    ) {
        payload = nil
        refund()
    }
}

private final class UdpIngressStagingWaiter: @unchecked Sendable {
    weak var owner: UdpIngressFlowStaging?
    /// A leaf with no reference back to the flow. The coordinator must never
    /// upgrade `owner` while locked: releasing that temporary can run the
    /// flow's synchronous deinit cancellation under the coordinator lock.
    let pressureIdentity: Locked<Int?>
    let neededItems: Int
    let neededBytes: Int
    let onGrant: @Sendable (UInt64) -> Void
    weak var previous: UdpIngressStagingWaiter?
    var next: UdpIngressStagingWaiter?
    var queued = false
    var fittingIndexed = false
    var fittingSequence: UInt64 = 0
    var fittingLeft: UdpIngressStagingWaiter?
    var fittingRight: UdpIngressStagingWaiter?
    var fittingHeight = 1
    var fittingMinimumBytes = Int.max

    init(
        owner: UdpIngressFlowStaging,
        neededItems: Int,
        neededBytes: Int,
        onGrant: @escaping @Sendable (UInt64) -> Void
    ) {
        self.owner = owner
        self.pressureIdentity = owner.pressureIdentity
        self.neededItems = neededItems
        self.neededBytes = neededBytes
        self.onGrant = onGrant
    }

    var ownerIsOpen: Bool { pressureIdentity.withLock { $0 != nil } }

    func canDiscover(in epoch: Int) -> Bool {
        pressureIdentity.withLock { $0.map { $0 != epoch } ?? false }
    }

    func claimDiscovery(in epoch: Int) -> Bool {
        pressureIdentity.withLock { lastEpoch in
            guard let previous = lastEpoch, previous != epoch else { return false }
            lastEpoch = epoch
            return true
        }
    }
}

private struct UdpIngressStagingGrant {
    let waiter: UdpIngressStagingWaiter
    let ticket: UInt64
    let expiresAt: UInt64
    /// A discovery read reserves available headroom, not the size of the
    /// datagram which was already discarded. Payload admission remains exact.
    let bytes: Int
}

private struct UdpIngressStagingReservation {
    let count: Int
    let bytes: Int
    let generationItemHeadroom: Int
    let generationByteHeadroom: Int
    let globalMaxItems: Int
    let globalMaxBytes: Int
    let generationGateClosed: Bool
    let deliveries: [(UdpIngressStagingWaiter, UInt64)]
}

private struct UdpIngressAtomicReservation {
    let count: Int
    let bytes: Int
    let generationItemHeadroom: Int
    let generationByteHeadroom: Int
    let globalMaxItems: Int
    let globalMaxBytes: Int
    /// A published generation waiter prevents a ticket-zero producer from
    /// consuming capacity until the bounded coordinator has served the queue.
    let generationGateClosed: Bool
    /// The two-counter reservation may briefly reserve items before learning
    /// that bytes lost the race. Publishing the rollback as an opportunity
    /// closes the waiter-registration handshake for zero-byte datagrams.
    let releasedTransientCapacity: Bool
}

/// Process/core-lifetime aggregate for Swift UDP ingress staging. The historic
/// `Generation` type name is retained for source compatibility, but one object
/// and one FIFO deliberately span engine generations.
final class UdpIngressGenerationStagingBudget: @unchecked Sendable {
    private static let waiterGateMask = 1
    private static let reconfigurationMask = 2
    private static let controlVersionIncrement = 4

    private struct State {
        var firstWaiter: UdpIngressStagingWaiter?
        var lastWaiter: UdpIngressStagingWaiter?
        var waiterCount = 0
        var scanRemaining = 0
        /// After the complete fitting pass, traverse the same finite FIFO
        /// population for discovery. Filling the four-node sample pauses this
        /// traversal until its callbacks run; it does not restart a whole
        /// population scan after each sample drains.
        var discovering = false
        /// One finite fitting pass followed by its discovery traversal.
        /// Releases and fitting grant completions must not restart this cycle:
        /// a busy fitting flow would otherwise hide every stale large hint.
        var scanActive = false
        /// Changes during a pass receive one later pass after its discovery.
        /// This covers newly appended tails and a release which makes an
        /// already-inspected waiter fit, without extending the current pass.
        var scanNeedsFollowup = false
        var scanScheduled = false
        /// Constant-size oldest sample across bounded no-fit turns. These
        /// nodes are unlinked from the sample on grant or cancellation.
        var discoveryCandidates: [UdpIngressStagingWaiter] = []
        /// A secondary index gives recurring single-datagram reads an exact
        /// fitting opportunity beside the finite discovery traversal. Its
        /// AVL tree orders live nodes by registration sequence and caches the
        /// minimum byte hint per subtree. Finding the oldest fitting waiter,
        /// insertion, and cancellation are O(log N), without tombstones or a
        /// population scan. Children own nodes; owners and FIFO back-links stay
        /// weak, and removal clears both children of the retired node.
        var fittingRoot: UdpIngressStagingWaiter?
        var nextFittingSequence: UInt64 = 0
        /// One fitting grant may follow each successful partial discovery.
        /// Fitting completions cannot restart or erase the owed cohort walk.
        var fittingServiceDue = false
        /// Capacity observed when the current FIFO completed its last no-fit
        /// pass. It lets a newly linked tail be inspected without rescanning
        /// older known-nonfitting waiters, while detecting a racing release.
        var quiescentCapacityItems: Int?
        var quiescentCapacityBytes: Int?
        /// Currently programmed one-shot lease deadline. `nil` means the
        /// shared timer is already disarmed at `.distantFuture`.
        var scheduledLeaseExpiry: UInt64?
        var nextTicket: UInt64 = 1
        var grants: [UInt64: UdpIngressStagingGrant] = [:]
        var dropEvents: UInt64 = 0
        var droppedItems: UInt64 = 0
        var droppedBytesLowerBound: UInt64 = 0
        #if DEBUG || RAMA_TESTING
            var coordinatorInspections: UInt64 = 0
            var maxCoordinatorInspectionsPerTurn = 0
            var peakGrantCount = 0
            var leaseTimerReprograms: UInt64 = 0
        #endif
    }

    /// Per-flow fields are copied from this snapshot when a flow is created;
    /// only the two global limits below affect already-existing flows.
    private let latestPolicy: Locked<UdpIngressStagingPolicy>
    private let state = Locked(State())
    /// Capacity includes retained batches plus leased provisional grants.
    /// Retained counters exclude grants and back drop-sample/test snapshots.
    private let capacityItems = UdpIngressAtomicCounter()
    private let capacityBytes = UdpIngressAtomicCounter()
    private let retainedItems = UdpIngressAtomicCounter()
    private let retainedBytes = UdpIngressAtomicCounter()
    /// Only physical retained-batch release advances discovery eligibility.
    /// Refunding a speculative grant cannot manufacture another read loop.
    private let retainedReleaseEpoch = UdpIngressAtomicCounter(1)
    private let globalMaxItems: UdpIngressAtomicCounter
    private let globalMaxBytes: UdpIngressAtomicCounter
    /// Bits 0/1 are the waiter and reconfiguration gates; upper bits are a
    /// monotonic configuration version. Sequentially-consistent checks before
    /// and after ticket-zero reservation formally order waiter publication and
    /// detect every cap change, while ordinary capacity atomics stay cheaper.
    private let admissionControl = UdpIngressAtomicCounter()
    private let capacityWakeScheduled = UdpIngressAtomicCounter()
    #if DEBUG || RAMA_TESTING
        private let lastInspectedItems = UdpIngressAtomicCounter()
        private let coordinatorLockAcquisitions = UdpIngressAtomicCounter()
        private let reservationRollbacks = UdpIngressAtomicCounter()
        private let capacityWakeTurns = UdpIngressAtomicCounter()
        private let afterCapacityWakeScanHook = Locked<(@Sendable () -> Void)?>(nil)
        var testAfterItemReservation: (@Sendable () -> Void)?
        var testAfterCoordinatorIdentityLookup: (@Sendable () -> Void)?
        var testAfterCapacityWakeScan: (@Sendable () -> Void)? {
            get { afterCapacityWakeScanHook.withLock { $0 } }
            set { afterCapacityWakeScanHook.withLock { $0 = newValue } }
        }
    #endif
    private let coordinatorQueue = DispatchQueue(
        label: "rama.tproxy.udp.ingress-staging.coordinator", qos: .utility)
    private let leaseTimer: DispatchSourceTimer
    private let automaticScheduling: Bool

    init(policy: UdpIngressStagingPolicy, automaticScheduling: Bool = true) {
        self.latestPolicy = Locked(policy)
        self.globalMaxItems = UdpIngressAtomicCounter(policy.maxItemsPerGeneration)
        self.globalMaxBytes = UdpIngressAtomicCounter(policy.maxBytesPerGeneration)
        self.automaticScheduling = automaticScheduling
        let timer = DispatchSource.makeTimerSource(queue: coordinatorQueue)
        self.leaseTimer = timer
        timer.setEventHandler { [weak self] in
            self?.runCoordinatorTurn()
        }
        timer.schedule(deadline: .distantFuture)
        timer.resume()
    }

    deinit { leaseTimer.cancel() }

    private func withCoordinatorState<R>(_ body: (inout State) -> R) -> R {
        #if DEBUG || RAMA_TESTING
            coordinatorLockAcquisitions.add(1)
        #endif
        return state.withLock(body)
    }

    fileprivate func policySnapshotForNewFlow() -> UdpIngressStagingPolicy {
        latestPolicy.withLock { $0 }
    }

    fileprivate func requestFitsCurrentGlobalLimits(items: Int, bytes: Int) -> Bool {
        let initialControl = admissionControl.loadSeqCst()
        guard initialControl & Self.reconfigurationMask == 0 else { return false }
        let fits = items <= globalMaxItems.load() && bytes <= globalMaxBytes.load()
        return admissionControl.loadSeqCst() == initialControl && fits
    }

    /// Cold attach-time update of the process-wide envelope. Existing flow
    /// objects retain their per-flow limits, while every generation shares the
    /// new global limits, retained counters, grants, and FIFO. Lowering below
    /// current usage is intentional: no new reservation succeeds until drain.
    func reconfigure(policy: UdpIngressStagingPolicy) {
        let deliveries = withCoordinatorState { state in
            beginReconfigurationLocked()
            latestPolicy.withLock { $0 = policy }
            globalMaxItems.store(policy.maxItemsPerGeneration)
            globalMaxBytes.store(policy.maxBytesPerGeneration)
            endReconfigurationLocked(hasWaiters: state.waiterCount > 0)
            // A changed envelope invalidates the old no-fit/discovery view.
            // This cold lifecycle edge starts one new bounded pass, even if
            // the former sample no longer fits the configured global caps.
            state.scanActive = false
            requestScanLocked(&state)
            let now = DispatchTime.now().uptimeNanoseconds
            let deliveries = driveCoordinatorLocked(&state, now: now)
            scheduleLeaseTimerLocked(&state)
            return deliveries
        }
        deliver(deliveries)
    }

    private func beginReconfigurationLocked() {
        let current = admissionControl.loadSeqCst()
        precondition(current & Self.reconfigurationMask == 0)
        precondition(current <= Int.max - Self.controlVersionIncrement,
            "UDP staging configuration version exhausted")
        let desired = (current + Self.controlVersionIncrement)
            | Self.waiterGateMask | Self.reconfigurationMask
        precondition(admissionControl.compareExchangeSeqCst(
            expected: current, desired: desired))
    }

    private func endReconfigurationLocked(hasWaiters: Bool) {
        let current = admissionControl.loadSeqCst()
        precondition(current & Self.reconfigurationMask != 0)
        var desired = current & ~Self.reconfigurationMask
        if hasWaiters {
            desired |= Self.waiterGateMask
        } else {
            desired &= ~Self.waiterGateMask
        }
        precondition(admissionControl.compareExchangeSeqCst(
            expected: current, desired: desired))
    }

    private func setWaiterGateLocked() {
        let current = admissionControl.loadSeqCst()
        guard current & Self.waiterGateMask == 0 else { return }
        precondition(admissionControl.compareExchangeSeqCst(
            expected: current, desired: current | Self.waiterGateMask))
    }

    private func clearWaiterGateLocked() {
        let current = admissionControl.loadSeqCst()
        guard current & Self.waiterGateMask != 0 else { return }
        precondition(current & Self.reconfigurationMask == 0)
        precondition(admissionControl.compareExchangeSeqCst(
            expected: current, desired: current & ~Self.waiterGateMask))
    }

    /// Caller holds its per-flow lock. A matching grant is consumed
    /// atomically with the exact retained reservation; a late/stale ticket is
    /// merely ignored and the same capacity admission is applied.
    fileprivate func reservePrefix(
        owner: UdpIngressFlowStaging,
        ticket: UInt64,
        datagrams: [Data],
        maxCount: Int,
        maxBytes: Int
    ) -> UdpIngressStagingReservation {
        guard ticket != 0 else {
            let reservation = reservePrefixAtomically(
                datagrams: datagrams,
                maxCount: maxCount,
                maxBytes: maxBytes,
                creditedItems: 0,
                creditedBytes: 0)
            let deliveries = reservation.releasedTransientCapacity
                ? wakeAfterCapacityReleaseIfWaiting() : []
            return UdpIngressStagingReservation(
                count: reservation.count,
                bytes: reservation.bytes,
                generationItemHeadroom: reservation.generationItemHeadroom,
                generationByteHeadroom: reservation.generationByteHeadroom,
                globalMaxItems: reservation.globalMaxItems,
                globalMaxBytes: reservation.globalMaxBytes,
                generationGateClosed: reservation.generationGateClosed,
                deliveries: deliveries)
        }

        return withCoordinatorState { state -> UdpIngressStagingReservation in
            let now = DispatchTime.now().uptimeNanoseconds
            let expired = expireGrantsLocked(&state, now: now)
            var opportunityChanged = expired
            var creditedItems = 0
            var creditedBytes = 0
            if ticket != 0,
                let grant = state.grants[ticket],
                grant.waiter.pressureIdentity === owner.pressureIdentity
            {
                state.grants.removeValue(forKey: ticket)
                creditedItems = grant.waiter.neededItems
                creditedBytes = grant.bytes
                opportunityChanged = true
            }

            let reservation = reservePrefixAtomically(
                datagrams: datagrams,
                maxCount: maxCount,
                maxBytes: maxBytes,
                creditedItems: creditedItems,
                creditedBytes: creditedBytes)
            if opportunityChanged {
                requestScanLocked(&state)
            }
            let deliveries = driveCoordinatorLocked(&state, now: now)
            scheduleLeaseTimerLocked(&state)
            return UdpIngressStagingReservation(
                count: reservation.count,
                bytes: reservation.bytes,
                generationItemHeadroom: reservation.generationItemHeadroom,
                generationByteHeadroom: reservation.generationByteHeadroom,
                globalMaxItems: reservation.globalMaxItems,
                globalMaxBytes: reservation.globalMaxBytes,
                generationGateClosed: reservation.generationGateClosed,
                deliveries: deliveries)
        }
    }

    /// Lock-free exact process-global admission. A valid grant arrives as already
    /// credited capacity and is transformed in place into the actual prefix;
    /// positive deltas are reserved before unused credit is released.
    private func reservePrefixAtomically(
        datagrams: [Data],
        maxCount: Int,
        maxBytes: Int,
        creditedItems: Int,
        creditedBytes: Int
    ) -> UdpIngressAtomicReservation {
        var releasedTransientCapacity = false
        // A valid grant owns at least one provisionally charged item and is
        // the coordinator's selected producer. Ticket-zero and stale-ticket
        // admissions must respect the published waiter gate.
        let respectsAdmissionControl = creditedItems == 0
        while true {
            let initialControl = admissionControl.loadSeqCst()
            if respectsAdmissionControl,
                initialControl & (Self.waiterGateMask | Self.reconfigurationMask) != 0
            {
                return gatedReservation(
                    releasedTransientCapacity: releasedTransientCapacity)
            }
            let maxGlobalItems = globalMaxItems.load()
            let maxGlobalBytes = globalMaxBytes.load()
            let usedItems = capacityItems.load()
            let usedBytes = capacityBytes.load()
            precondition(usedItems >= creditedItems && usedBytes >= creditedBytes)
            let generationItemHeadroom = max(
                maxGlobalItems - usedItems + creditedItems, 0)
            let generationByteHeadroom = max(
                maxGlobalBytes - usedBytes + creditedBytes, 0)
            let countLimit = min(maxCount, generationItemHeadroom)
            let byteLimit = min(maxBytes, generationByteHeadroom)
            var count = 0
            var bytes = 0
            for datagram in datagrams.prefix(countLimit) {
                let size = datagram.count
                if size > byteLimit - bytes { break }
                bytes += size
                count += 1
            }
            #if DEBUG || RAMA_TESTING
                lastInspectedItems.store(count)
            #endif

            let additionalItems = max(count - creditedItems, 0)
            guard capacityItems.tryReserve(
                additionalItems, limit: maxGlobalItems)
            else { continue }
            #if DEBUG || RAMA_TESTING
                if additionalItems > 0 { testAfterItemReservation?() }
            #endif
            let additionalBytes = max(bytes - creditedBytes, 0)
            guard capacityBytes.tryReserve(
                additionalBytes, limit: maxGlobalBytes)
            else {
                if additionalItems > 0 {
                    capacityItems.subtract(additionalItems)
                    releasedTransientCapacity = true
                    #if DEBUG || RAMA_TESTING
                        reservationRollbacks.add(1)
                    #endif
                }
                continue
            }

            // Formal publication handshake: admission-control operations are
            // sequentially consistent. The coordinator sets the gate before
            // linking its first waiter and cannot clear it until FIFO is empty.
            // Therefore a waiter which precedes this final SC load either makes
            // the value differ (and we roll back) or was already served/cancelled;
            // a waiter ordered after it legitimately follows this admission.
            // Reconfiguration permanently increments the upper version bits,
            // so its set/update/clear cycle cannot disappear as an ABA. Capacity
            // counters themselves remain acquire/acq_rel and exact per dimension.
            if respectsAdmissionControl,
                admissionControl.loadSeqCst() != initialControl
            {
                if additionalBytes > 0 { capacityBytes.subtract(additionalBytes) }
                if additionalItems > 0 { capacityItems.subtract(additionalItems) }
                let released = additionalItems > 0 || additionalBytes > 0
                releasedTransientCapacity = releasedTransientCapacity || released
                #if DEBUG || RAMA_TESTING
                    if released { reservationRollbacks.add(1) }
                #endif
                return gatedReservation(
                    releasedTransientCapacity: releasedTransientCapacity)
            }

            if creditedItems > count { capacityItems.subtract(creditedItems - count) }
            if creditedBytes > bytes { capacityBytes.subtract(creditedBytes - bytes) }
            if count > 0 {
                retainedItems.add(count)
                retainedBytes.add(bytes)
            }
            return UdpIngressAtomicReservation(
                count: count,
                bytes: bytes,
                generationItemHeadroom: generationItemHeadroom,
                generationByteHeadroom: generationByteHeadroom,
                globalMaxItems: maxGlobalItems,
                globalMaxBytes: maxGlobalBytes,
                generationGateClosed: false,
                releasedTransientCapacity: releasedTransientCapacity)
        }
    }

    private func gatedReservation(
        releasedTransientCapacity: Bool
    ) -> UdpIngressAtomicReservation {
        let usedItems = capacityItems.load()
        let usedBytes = capacityBytes.load()
        let maxGlobalItems = globalMaxItems.load()
        let maxGlobalBytes = globalMaxBytes.load()
        return UdpIngressAtomicReservation(
            count: 0,
            bytes: 0,
            generationItemHeadroom: max(maxGlobalItems - usedItems, 0),
            generationByteHeadroom: max(maxGlobalBytes - usedBytes, 0),
            globalMaxItems: maxGlobalItems,
            globalMaxBytes: maxGlobalBytes,
            generationGateClosed: true,
            releasedTransientCapacity: releasedTransientCapacity)
    }

    private func tryReserveCapacity(items: Int, bytes: Int) -> Bool {
        guard capacityItems.tryReserve(items, limit: globalMaxItems.load()) else {
            return false
        }
        guard capacityBytes.tryReserve(bytes, limit: globalMaxBytes.load()) else {
            capacityItems.subtract(items)
            return false
        }
        return true
    }

    private func releaseCapacity(items: Int, bytes: Int) {
        capacityItems.subtract(items)
        capacityBytes.subtract(bytes)
    }

    private func releaseRetainedCapacity(items: Int, bytes: Int) {
        retainedItems.subtract(items)
        retainedBytes.subtract(bytes)
        releaseCapacity(items: items, bytes: bytes)
        retainedReleaseEpoch.add(1)
    }

    /// A release that races waiter publication either sees the atomic gate and
    /// drives the queue, or publication takes the coordinator lock afterward
    /// and observes the released capacity itself.
    private func wakeAfterCapacityReleaseIfWaiting()
        -> [(UdpIngressStagingWaiter, UInt64)]
    {
        guard admissionControl.loadSeqCst() & Self.waiterGateMask != 0 else { return [] }
        if automaticScheduling {
            if capacityWakeScheduled.compareExchange(expected: 0, desired: 1) {
                coordinatorQueue.async { [weak self] in self?.runCapacityWakeTurn() }
            }
            return []
        }
        return withCoordinatorState { state in
            requestScanLocked(&state)
            let now = DispatchTime.now().uptimeNanoseconds
            let deliveries = driveCoordinatorLocked(&state, now: now)
            scheduleLeaseTimerLocked(&state)
            return deliveries
        }
    }

    private func runCapacityWakeTurn() {
        // Clear before taking the coordinator lock. A concurrent release then
        // either schedules the next turn or precedes this turn's capacity
        // snapshot; it cannot disappear between the gate read and the scan.
        capacityWakeScheduled.store(0)
        #if DEBUG || RAMA_TESTING
            capacityWakeTurns.add(1)
        #endif
        let deliveries = withCoordinatorState { state in
            requestScanLocked(&state)
            let now = DispatchTime.now().uptimeNanoseconds
            let deliveries = driveCoordinatorLocked(&state, now: now)
            scheduleLeaseTimerLocked(&state)
            return deliveries
        }
        #if DEBUG || RAMA_TESTING
            // Test seam after the capacity snapshot/scan but outside every
            // lock. A release here must publish exactly one follow-up wake.
            testAfterCapacityWakeScan?()
        #endif
        deliver(deliveries)
    }

    private func appendLocked(_ waiter: UdpIngressStagingWaiter, state: inout State) {
        precondition(!waiter.queued)
        if state.waiterCount == 0 {
            setWaiterGateLocked()
        } else {
            precondition(
                admissionControl.loadSeqCst() & Self.waiterGateMask != 0)
        }
        waiter.previous = state.lastWaiter
        waiter.next = nil
        state.lastWaiter?.next = waiter
        if state.firstWaiter == nil { state.firstWaiter = waiter }
        state.lastWaiter = waiter
        waiter.queued = true
        state.waiterCount += 1
        insertFittingIndexLocked(waiter, state: &state)
    }

    private func removeLocked(_ waiter: UdpIngressStagingWaiter, state: inout State) {
        guard waiter.queued else { return }
        state.discoveryCandidates.removeAll { $0 === waiter }
        removeFittingIndexLocked(waiter, state: &state)
        let previous = waiter.previous
        let next = waiter.next
        if let previous { previous.next = next } else { state.firstWaiter = next }
        if let next { next.previous = previous } else { state.lastWaiter = previous }
        waiter.previous = nil
        waiter.next = nil
        waiter.queued = false
        state.waiterCount -= 1
        // A cancelled or granted node cannot leave more scan work than live
        // nodes. Keeping this invariant lets later registrations extend the
        // finite pass without restarting it.
        state.scanRemaining = min(state.scanRemaining, state.waiterCount)
    }

    private func updateFittingNode(_ node: UdpIngressStagingWaiter) {
        node.fittingHeight = 1 + max(
            node.fittingLeft?.fittingHeight ?? 0, node.fittingRight?.fittingHeight ?? 0)
        node.fittingMinimumBytes = min(
            node.neededBytes,
            node.fittingLeft?.fittingMinimumBytes ?? Int.max,
            node.fittingRight?.fittingMinimumBytes ?? Int.max)
    }

    private func rotateFittingLeft(_ root: UdpIngressStagingWaiter) -> UdpIngressStagingWaiter {
        let next = root.fittingRight!
        root.fittingRight = next.fittingLeft
        next.fittingLeft = root
        updateFittingNode(root)
        updateFittingNode(next)
        return next
    }

    private func rotateFittingRight(_ root: UdpIngressStagingWaiter) -> UdpIngressStagingWaiter {
        let next = root.fittingLeft!
        root.fittingLeft = next.fittingRight
        next.fittingRight = root
        updateFittingNode(root)
        updateFittingNode(next)
        return next
    }

    private func balanceFittingNode(_ root: UdpIngressStagingWaiter) -> UdpIngressStagingWaiter {
        updateFittingNode(root)
        let balance = (root.fittingLeft?.fittingHeight ?? 0) - (root.fittingRight?.fittingHeight ?? 0)
        if balance > 1 {
            let left = root.fittingLeft!
            if (left.fittingLeft?.fittingHeight ?? 0) < (left.fittingRight?.fittingHeight ?? 0) {
                root.fittingLeft = rotateFittingLeft(left)
            }
            return rotateFittingRight(root)
        }
        if balance < -1 {
            let right = root.fittingRight!
            if (right.fittingRight?.fittingHeight ?? 0) < (right.fittingLeft?.fittingHeight ?? 0) {
                root.fittingRight = rotateFittingRight(right)
            }
            return rotateFittingLeft(root)
        }
        return root
    }

    private func insertFittingNode(
        _ waiter: UdpIngressStagingWaiter, into root: UdpIngressStagingWaiter?
    ) -> UdpIngressStagingWaiter {
        guard let root else { return waiter }
        if waiter.fittingSequence < root.fittingSequence {
            root.fittingLeft = insertFittingNode(waiter, into: root.fittingLeft)
        } else {
            root.fittingRight = insertFittingNode(waiter, into: root.fittingRight)
        }
        return balanceFittingNode(root)
    }

    private func insertFittingIndexLocked(_ waiter: UdpIngressStagingWaiter, state: inout State) {
        // Production stage() always requests one next datagram. Multi-item
        // helper reservations retain the ordinary FIFO path; indexing only
        // single items makes the byte minimum an exact two-dimensional fit.
        guard waiter.neededItems == 1 else { return }
        precondition(!waiter.fittingIndexed && waiter.fittingLeft == nil && waiter.fittingRight == nil)
        precondition(state.nextFittingSequence < UInt64.max, "UDP fitting sequence exhausted")
        state.nextFittingSequence += 1
        waiter.fittingSequence = state.nextFittingSequence
        waiter.fittingIndexed = true
        updateFittingNode(waiter)
        state.fittingRoot = insertFittingNode(waiter, into: state.fittingRoot)
    }

    private func extractFirstFittingNode(
        _ root: UdpIngressStagingWaiter
    ) -> (root: UdpIngressStagingWaiter?, first: UdpIngressStagingWaiter) {
        guard let left = root.fittingLeft else {
            let next = root.fittingRight
            root.fittingRight = nil
            return (next, root)
        }
        let extracted = extractFirstFittingNode(left)
        root.fittingLeft = extracted.root
        return (balanceFittingNode(root), extracted.first)
    }

    private func removeFittingNode(
        sequence: UInt64, from root: UdpIngressStagingWaiter?
    ) -> UdpIngressStagingWaiter? {
        guard let root else { preconditionFailure("missing UDP fitting node") }
        if sequence < root.fittingSequence {
            root.fittingLeft = removeFittingNode(sequence: sequence, from: root.fittingLeft)
        } else if sequence > root.fittingSequence {
            root.fittingRight = removeFittingNode(sequence: sequence, from: root.fittingRight)
        } else {
            let left = root.fittingLeft
            let right = root.fittingRight
            root.fittingLeft = nil
            root.fittingRight = nil
            guard let left else { return right }
            guard let right else { return left }
            let extracted = extractFirstFittingNode(right)
            extracted.first.fittingLeft = left
            extracted.first.fittingRight = extracted.root
            return balanceFittingNode(extracted.first)
        }
        return balanceFittingNode(root)
    }

    private func removeFittingIndexLocked(_ waiter: UdpIngressStagingWaiter, state: inout State) {
        guard waiter.fittingIndexed else { return }
        state.fittingRoot = removeFittingNode(sequence: waiter.fittingSequence, from: state.fittingRoot)
        waiter.fittingIndexed = false
    }

    private func oldestFittingNode(
        _ root: UdpIngressStagingWaiter?, availableBytes: Int
    ) -> UdpIngressStagingWaiter? {
        guard let root, root.fittingMinimumBytes <= availableBytes else { return nil }
        var node = root
        while true {
            if let left = node.fittingLeft, left.fittingMinimumBytes <= availableBytes {
                node = left
            } else if node.neededBytes <= availableBytes {
                return node
            } else if let right = node.fittingRight {
                node = right
            } else {
                preconditionFailure("UDP fitting subtree minimum mismatch")
            }
        }
    }

    private func hasFittingServiceOpportunityLocked(_ state: State) -> Bool {
        guard state.discovering, state.fittingServiceDue,
            let root = state.fittingRoot,
            capacityItems.load() < globalMaxItems.load()
        else { return false }
        return root.fittingMinimumBytes <= max(globalMaxBytes.load() - capacityBytes.load(), 0)
    }

    private func grantFittingServiceLocked(
        _ state: inout State, now: UInt64, inspected: inout Int
    ) -> (UdpIngressStagingWaiter, UInt64)? {
        guard hasFittingServiceOpportunityLocked(state),
            state.grants.count < udpIngressStagingMaxGrants,
            let waiter = oldestFittingNode(
                state.fittingRoot,
                availableBytes: max(globalMaxBytes.load() - capacityBytes.load(), 0))
        else { return nil }
        // The tree metadata lookup is O(log N). Its resulting waiter shares
        // the same 32-inspection budget as the FIFO traversal below.
        inspected += 1
        #if DEBUG || RAMA_TESTING
            state.coordinatorInspections &+= 1
        #endif
        guard tryReserveCapacity(items: waiter.neededItems, bytes: waiter.neededBytes) else { return nil }
        guard let ticket = nextTicketLocked(&state) else {
            releaseCapacity(items: waiter.neededItems, bytes: waiter.neededBytes)
            return nil
        }
        removeLocked(waiter, state: &state)
        let expiry = now > UInt64.max - udpIngressStagingGrantLeaseNanoseconds
            ? UInt64.max : now + udpIngressStagingGrantLeaseNanoseconds
        state.grants[ticket] = UdpIngressStagingGrant(
            waiter: waiter, ticket: ticket, expiresAt: expiry, bytes: waiter.neededBytes)
        state.fittingServiceDue = false
        #if DEBUG || RAMA_TESTING
            state.peakGrantCount = max(state.peakGrantCount, state.grants.count)
        #endif
        return (waiter, ticket)
    }

    private func rotateToTailLocked(_ waiter: UdpIngressStagingWaiter, state: inout State) {
        guard waiter !== state.lastWaiter else { return }
        // Relink directly so the waiter gate remains continuously published.
        let previous = waiter.previous
        let next = waiter.next
        if let previous { previous.next = next } else { state.firstWaiter = next }
        next?.previous = previous
        waiter.previous = state.lastWaiter
        waiter.next = nil
        state.lastWaiter?.next = waiter
        state.lastWaiter = waiter
    }

    private func nextTicketLocked(_ state: inout State) -> UInt64? {
        guard state.nextTicket != 0 else { return nil }
        let ticket = state.nextTicket
        state.nextTicket = ticket == UInt64.max ? 0 : ticket + 1
        return ticket
    }

    /// Existing waiters have already completed a no-fit pass at the current
    /// capacity. Inspecting only a newly appended tail preserves their FIFO
    /// order and avoids restarting/rescanning the entire queue for an 8k-flow
    /// registration burst.
    private func inspectNewQuiescentTailLocked(
        _ waiter: UdpIngressStagingWaiter,
        state: inout State,
        now: UInt64,
        baselineItems: Int,
        baselineBytes: Int
    ) -> (deliveries: [(UdpIngressStagingWaiter, UInt64)], capacityChanged: Bool) {
        guard state.grants.count < udpIngressStagingMaxGrants else {
            return ([], capacityItems.load() != baselineItems
                || capacityBytes.load() != baselineBytes)
        }
        #if DEBUG || RAMA_TESTING
            state.coordinatorInspections &+= 1
            state.maxCoordinatorInspectionsPerTurn = max(
                state.maxCoordinatorInspectionsPerTurn, 1)
        #endif
        guard waiter.ownerIsOpen else {
            removeLocked(waiter, state: &state)
            if state.waiterCount == 0 { clearWaiterGateLocked() }
            return ([], false)
        }
        guard tryReserveCapacity(
            items: waiter.neededItems, bytes: waiter.neededBytes)
        else {
            rememberDiscoveryCandidateLocked(waiter, state: &state)
            return ([], capacityItems.load() != baselineItems
                || capacityBytes.load() != baselineBytes)
        }
        // The waiter gate excludes other ticket-zero reservations. Therefore
        // only a release can make these exact post-reservation values differ.
        // Roll back and give the older FIFO one full opportunity if that race
        // occurred; otherwise this new fitting tail cannot barge.
        let postItems = capacityItems.load()
        let postBytes = capacityBytes.load()
        guard postItems >= waiter.neededItems,
            postItems - waiter.neededItems == baselineItems,
            postBytes >= waiter.neededBytes,
            postBytes - waiter.neededBytes == baselineBytes
        else {
            releaseCapacity(items: waiter.neededItems, bytes: waiter.neededBytes)
            return ([], true)
        }
        guard let ticket = nextTicketLocked(&state) else {
            releaseCapacity(items: waiter.neededItems, bytes: waiter.neededBytes)
            return ([], false)
        }
        removeLocked(waiter, state: &state)
        let expiry = now > UInt64.max - udpIngressStagingGrantLeaseNanoseconds
            ? UInt64.max : now + udpIngressStagingGrantLeaseNanoseconds
        state.grants[ticket] = UdpIngressStagingGrant(
            waiter: waiter, ticket: ticket, expiresAt: expiry, bytes: waiter.neededBytes)
        #if DEBUG || RAMA_TESTING
            state.peakGrantCount = max(state.peakGrantCount, state.grants.count)
        #endif
        if state.waiterCount == 0 { clearWaiterGateLocked() }
        return ([(waiter, ticket)], false)
    }

    private func driveCoordinatorLocked(
        _ state: inout State, now: UInt64, allowDiscovery: Bool = false
    ) -> [(UdpIngressStagingWaiter, UInt64)] {
        if expireGrantsLocked(&state, now: now) {
            requestScanLocked(&state)
        }
        var deliveries: [(UdpIngressStagingWaiter, UInt64)] = []
        var inspected = 0
        if let fitting = grantFittingServiceLocked(&state, now: now, inspected: &inspected) {
            deliveries.append(fitting)
        }
        while state.grants.count < udpIngressStagingMaxGrants,
            state.scanRemaining > 0,
            !state.discovering
                || state.discoveryCandidates.count < udpIngressStagingMaxGrants,
            inspected < udpIngressStagingMaxInspectionsPerTurn,
            let waiter = state.firstWaiter
        {
            state.scanRemaining -= 1
            inspected += 1
            #if DEBUG || RAMA_TESTING
                state.coordinatorInspections &+= 1
            #endif
            guard waiter.ownerIsOpen else {
                removeLocked(waiter, state: &state)
                continue
            }
            guard tryReserveCapacity(
                items: waiter.neededItems, bytes: waiter.neededBytes)
            else {
                rememberDiscoveryCandidateLocked(waiter, state: &state)
                rotateToTailLocked(waiter, state: &state)
                continue
            }
            guard let ticket = nextTicketLocked(&state) else {
                releaseCapacity(items: waiter.neededItems, bytes: waiter.neededBytes)
                state.scanRemaining = 0
                break
            }
            removeLocked(waiter, state: &state)
            let expiry = now > UInt64.max - udpIngressStagingGrantLeaseNanoseconds
                ? UInt64.max : now + udpIngressStagingGrantLeaseNanoseconds
            state.grants[ticket] = UdpIngressStagingGrant(
                waiter: waiter, ticket: ticket, expiresAt: expiry, bytes: waiter.neededBytes)
            #if DEBUG || RAMA_TESTING
                state.peakGrantCount = max(state.peakGrantCount, state.grants.count)
            #endif
            deliveries.append((waiter, ticket))
        }
        if state.scanActive, !state.discovering, state.scanRemaining == 0,
            hasPendingDiscoveryLocked(state)
        {
            // Every initially fitting waiter has now had its FIFO opportunity.
            // Keep a finite discovery traversal across callback completions,
            // re-parks, and physical releases; those changes request one later
            // fitting pass instead of restarting this population walk.
            state.discovering = true
            state.scanRemaining = state.waiterCount
        }
        if deliveries.isEmpty {
            // Capacity may have grown since the finite pass inspected these
            // candidates. Exact fits retain the ordinary synchronous grant
            // path; only a speculative smaller-packet read needs the runner.
            while deliveries.count < udpIngressStagingMaxGrants,
                let exact = grantDiscoveryCandidateLocked(&state, now: now, allowPartial: false)
            {
                deliveries.append(exact)
            }
            if allowDiscovery, deliveries.isEmpty,
                let discovery = grantDiscoveryCandidateLocked(&state, now: now, allowPartial: true)
            {
                deliveries.append(discovery)
                state.fittingServiceDue = true
            }
        }
        #if DEBUG || RAMA_TESTING
            state.maxCoordinatorInspectionsPerTurn = max(
                state.maxCoordinatorInspectionsPerTurn, inspected)
        #endif
        if state.waiterCount == 0 {
            clearWaiterGateLocked()
        } else {
            precondition(
                admissionControl.loadSeqCst() & Self.waiterGateMask != 0)
        }
        if state.scanRemaining == 0 {
            // A completed pass owes its sampled flows discovery even if an
            // exact fitting grant temporarily consumed the last free byte.
            // Capacity controls scheduling, not that owed FIFO opportunity.
            state.scanActive = hasPendingDiscoveryLocked(state)
                && (state.scanActive || hasDiscoveryOpportunityLocked(state))
            if !state.scanActive, state.scanNeedsFollowup {
                requestScanLocked(&state)
            }
            if state.scanRemaining == 0 {
                state.quiescentCapacityItems = capacityItems.load()
                state.quiescentCapacityBytes = capacityBytes.load()
            }
        }
        scheduleScanLocked(&state)
        return deliveries
    }

    /// Begin a fresh capacity opportunity only after the previous bounded
    /// pass and its owed discovery have finished. The initial release
    /// still starts with the complete registered population; arrivals during
    /// an active pass wait for its completion instead of extending its budget.
    private func requestScanLocked(_ state: inout State) {
        guard !state.scanActive else {
            state.scanNeedsFollowup = true
            return
        }
        state.scanRemaining = state.waiterCount
        state.discovering = false
        state.scanActive = state.waiterCount > 0
        state.scanNeedsFollowup = false
        state.fittingServiceDue = false
        state.discoveryCandidates.removeAll(keepingCapacity: true)
    }

    private func rememberDiscoveryCandidateLocked(
        _ waiter: UdpIngressStagingWaiter, state: inout State
    ) {
        guard state.discoveryCandidates.count < udpIngressStagingMaxGrants,
            waiter.neededBytes > 0,
            waiter.neededBytes <= globalMaxBytes.load(),
            waiter.neededItems <= globalMaxItems.load(),
            waiter.canDiscover(in: retainedReleaseEpoch.load()),
            !state.discoveryCandidates.contains(where: { $0 === waiter })
        else { return }
        #if DEBUG || RAMA_TESTING
            testAfterCoordinatorIdentityLookup?()
        #endif
        state.discoveryCandidates.append(waiter)
    }

    /// Once all exact fits had a FIFO opportunity, one oldest sampled flow
    /// may discover a smaller next datagram. There is no timer for discovery:
    /// each flow gets at most one attempt per physical release epoch, even
    /// when its callback immediately discards another nonfitting datagram.
    /// Only the serial coordinator runner issues these speculative callbacks,
    /// so synchronous completion cannot recurse through the next discovery.
    private func grantDiscoveryCandidateLocked(
        _ state: inout State, now: UInt64, allowPartial: Bool
    ) -> (UdpIngressStagingWaiter, UInt64)? {
        guard state.discovering || state.scanRemaining == 0,
            state.grants.count < udpIngressStagingMaxGrants
        else { return nil }
        let epoch = retainedReleaseEpoch.load()
        for waiter in state.discoveryCandidates {
            guard waiter.queued, waiter.canDiscover(in: epoch),
                waiter.neededBytes <= globalMaxBytes.load()
            else { continue }
            let availableBytes = max(globalMaxBytes.load() - capacityBytes.load(), 0)
            let bytes = min(waiter.neededBytes, availableBytes)
            guard bytes > 0 else { continue }
            guard allowPartial || bytes == waiter.neededBytes else { continue }
            guard tryReserveCapacity(items: waiter.neededItems, bytes: bytes) else { continue }
            guard let ticket = nextTicketLocked(&state) else {
                releaseCapacity(items: waiter.neededItems, bytes: bytes)
                return nil
            }
            // Close can invalidate the leaf while capacity is reserved. Never
            // overwrite that terminal state with a later discovery epoch.
            guard waiter.claimDiscovery(in: epoch) else {
                releaseCapacity(items: waiter.neededItems, bytes: bytes)
                continue
            }
            removeLocked(waiter, state: &state)
            let expiry = now > UInt64.max - udpIngressStagingGrantLeaseNanoseconds
                ? UInt64.max : now + udpIngressStagingGrantLeaseNanoseconds
            state.grants[ticket] = UdpIngressStagingGrant(
                waiter: waiter, ticket: ticket, expiresAt: expiry, bytes: bytes)
            #if DEBUG || RAMA_TESTING
                state.peakGrantCount = max(state.peakGrantCount, state.grants.count)
            #endif
            return (waiter, ticket)
        }
        return nil
    }

    private func expireGrantsLocked(_ state: inout State, now: UInt64) -> Bool {
        let expired = state.grants.compactMap { ticket, grant in
            grant.expiresAt <= now ? ticket : nil
        }
        for ticket in expired {
            guard let grant = state.grants.removeValue(forKey: ticket) else { continue }
            releaseCapacity(
                items: grant.waiter.neededItems,
                bytes: grant.bytes)
        }
        return !expired.isEmpty
    }

    private func scheduleScanLocked(_ state: inout State) {
        guard automaticScheduling,
            (state.scanRemaining > 0
                && (!state.discovering
                    || state.discoveryCandidates.count < udpIngressStagingMaxGrants))
                || hasDiscoveryOpportunityLocked(state)
                || hasFittingServiceOpportunityLocked(state),
            state.waiterCount > 0,
            state.grants.count < udpIngressStagingMaxGrants,
            !state.scanScheduled
        else { return }
        state.scanScheduled = true
        coordinatorQueue.async { [weak self] in self?.runCoordinatorTurn() }
    }

    private func hasDiscoveryOpportunityLocked(_ state: State) -> Bool {
        guard globalMaxBytes.load() > capacityBytes.load() else { return false }
        let epoch = retainedReleaseEpoch.load()
        return state.discoveryCandidates.contains { waiter in
            waiter.queued && waiter.neededBytes > 0 && waiter.neededBytes <= globalMaxBytes.load()
                && waiter.neededItems <= max(globalMaxItems.load() - capacityItems.load(), 0)
                && waiter.canDiscover(in: epoch)
        }
    }

    /// An owed discovery survives a temporarily full byte/item envelope.
    /// Only grant/cancel/owner loss or spending this physical-release epoch
    /// retires it; the stricter runnable predicate above keeps idle queues
    /// disarmed until capacity actually returns.
    private func hasPendingDiscoveryLocked(_ state: State) -> Bool {
        let epoch = retainedReleaseEpoch.load()
        return state.discoveryCandidates.contains { waiter in
            waiter.queued && waiter.neededBytes > 0 && waiter.neededBytes <= globalMaxBytes.load()
                && waiter.neededItems <= globalMaxItems.load()
                && waiter.canDiscover(in: epoch)
        }
    }

    private func scheduleLeaseTimerLocked(_ state: inout State) {
        guard automaticScheduling else { return }
        let expiry = state.grants.values.lazy.map(\.expiresAt).min()
        guard expiry != state.scheduledLeaseExpiry else { return }
        state.scheduledLeaseExpiry = expiry
        #if DEBUG || RAMA_TESTING
            state.leaseTimerReprograms &+= 1
        #endif
        guard let expiry else {
            leaseTimer.schedule(deadline: .distantFuture)
            return
        }
        leaseTimer.schedule(deadline: DispatchTime(uptimeNanoseconds: expiry), leeway: .milliseconds(1))
    }

    private func runCoordinatorTurn() {
        let deliveries = withCoordinatorState { state in
            state.scanScheduled = false
            let now = DispatchTime.now().uptimeNanoseconds
            let deliveries = driveCoordinatorLocked(&state, now: now, allowDiscovery: true)
            scheduleLeaseTimerLocked(&state)
            return deliveries
        }
        deliver(deliveries)
    }

    fileprivate func deliver(_ deliveries: [(UdpIngressStagingWaiter, UInt64)]) {
        for (waiter, ticket) in deliveries {
            waiter.owner?.receiveGenerationGrant(waiter: waiter, ticket: ticket)
        }
    }

    fileprivate func register(
        _ waiter: UdpIngressStagingWaiter
    ) -> [(UdpIngressStagingWaiter, UInt64)] {
        withCoordinatorState { state in
            let now = DispatchTime.now().uptimeNanoseconds
            let capacityChanged = expireGrantsLocked(&state, now: now)
            let existingPassWasQuiescent = state.scanRemaining == 0
            let existingWaiterCount = state.waiterCount
            appendLocked(waiter, state: &state)
            if state.scanActive { state.scanNeedsFollowup = true }
            let deliveries: [(UdpIngressStagingWaiter, UInt64)]
            if capacityChanged {
                // Expired provisional capacity is a new opportunity for the
                // entire FIFO.
                requestScanLocked(&state)
                deliveries = driveCoordinatorLocked(&state, now: now)
            } else if existingPassWasQuiescent, !state.scanActive {
                let baselineItems = capacityItems.load()
                let baselineBytes = capacityBytes.load()
                if existingWaiterCount > 0,
                    (state.quiescentCapacityItems != baselineItems
                        || state.quiescentCapacityBytes != baselineBytes)
                {
                    requestScanLocked(&state)
                    deliveries = driveCoordinatorLocked(&state, now: now)
                } else {
                    let tailResult = inspectNewQuiescentTailLocked(
                        waiter, state: &state, now: now,
                        baselineItems: baselineItems,
                        baselineBytes: baselineBytes)
                    if tailResult.capacityChanged {
                        requestScanLocked(&state)
                        deliveries = driveCoordinatorLocked(&state, now: now)
                    } else {
                        deliveries = tailResult.deliveries
                        state.quiescentCapacityItems = capacityItems.load()
                        state.quiescentCapacityBytes = capacityBytes.load()
                    }
                }
            } else {
                // Keep the original inspection budget finite even if fitting
                // flows continuously re-park while their grants are consumed.
                deliveries = driveCoordinatorLocked(&state, now: now)
            }
            if state.scanRemaining == 0 {
                // The quiescent-tail fast path also completes an exact-fit
                // opportunity. Preserve its queued discovery against later
                // fitting arrivals until the serial runner can issue it.
                // A tail observed while the envelope was already full does
                // not itself establish a new pass: the next release must
                // still visit the complete registered population first.
                state.scanActive = hasPendingDiscoveryLocked(state)
                    && (state.scanActive || hasDiscoveryOpportunityLocked(state))
            }
            if state.waiterCount == 0 { clearWaiterGateLocked() }
            scheduleScanLocked(&state)
            scheduleLeaseTimerLocked(&state)
            return deliveries
        }
    }

    fileprivate func cancel(
        waiter: UdpIngressStagingWaiter?, owner: UdpIngressFlowStaging, ticket: UInt64
    ) {
        let deliveries = withCoordinatorState { state in
            var changed = false
            if let waiter, waiter.queued {
                removeLocked(waiter, state: &state)
            }
            if ticket != 0,
                let grant = state.grants[ticket],
                // The leaf keeps identity stable even after Swift has cleared
                // the weak flow reference at the beginning of deinit.
                grant.waiter.pressureIdentity === owner.pressureIdentity
            {
                state.grants.removeValue(forKey: ticket)
                releaseCapacity(
                    items: grant.waiter.neededItems,
                    bytes: grant.bytes)
                changed = true
            }
            if changed { requestScanLocked(&state) }
            let deliveries = driveCoordinatorLocked(
                &state, now: DispatchTime.now().uptimeNanoseconds)
            scheduleLeaseTimerLocked(&state)
            return deliveries
        }
        deliver(deliveries)
    }

    func recordDrop(
        reason: UdpIngressStagingDropReason,
        items: Int,
        bytesLowerBound: Int
    ) -> UdpIngressStagingDropSample? {
        withCoordinatorState { state in
            state.dropEvents = state.dropEvents == UInt64.max ? UInt64.max : state.dropEvents + 1
            let (droppedItems, itemsOverflow) = state.droppedItems
                .addingReportingOverflow(UInt64(items))
            state.droppedItems = itemsOverflow ? UInt64.max : droppedItems
            let (droppedBytes, bytesOverflow) = state.droppedBytesLowerBound
                .addingReportingOverflow(UInt64(bytesLowerBound))
            state.droppedBytesLowerBound = bytesOverflow ? UInt64.max : droppedBytes
            guard state.dropEvents.nonzeroBitCount == 1 else { return nil }
            let maxGlobalItems = globalMaxItems.load()
            let maxGlobalBytes = globalMaxBytes.load()
            return UdpIngressStagingDropSample(
                reason: reason,
                cumulativeDropEvents: state.dropEvents,
                cumulativeDroppedItems: state.droppedItems,
                cumulativeDroppedBytesLowerBound: state.droppedBytesLowerBound,
                generationRetainedItems: retainedItems.load(),
                generationMaxRetainedItems: maxGlobalItems,
                generationRetainedBytes: retainedBytes.load(),
                generationMaxRetainedBytes: maxGlobalBytes)
        }
    }

    fileprivate func release(
        items: Int, bytes: Int
    ) -> [(UdpIngressStagingWaiter, UInt64)] {
        releaseRetainedCapacity(items: items, bytes: bytes)
        return wakeAfterCapacityReleaseIfWaiting()
    }

    #if DEBUG || RAMA_TESTING
        var testRetainedBytes: Int { retainedBytes.load() }
        var testRetainedItems: Int { retainedItems.load() }
        var testReservedBytes: Int { capacityBytes.load() }
        var testReservedItems: Int { capacityItems.load() }
        var testLastInspectedItems: Int { lastInspectedItems.load() }
        var testCoordinatorLockAcquisitions: Int { coordinatorLockAcquisitions.load() }
        var testWaiterGate: Int {
            admissionControl.loadSeqCst() & Self.waiterGateMask == 0 ? 0 : 1
        }
        var testGlobalMaxItems: Int { globalMaxItems.load() }
        var testGlobalMaxBytes: Int { globalMaxBytes.load() }
        var testCapacityAtomicsAreLockFree: Bool {
            capacityItems.isLockFree && capacityBytes.isLockFree
                && retainedItems.isLockFree && retainedBytes.isLockFree
                && globalMaxItems.isLockFree && globalMaxBytes.isLockFree
                && admissionControl.isLockFree && capacityWakeScheduled.isLockFree
        }
        var testReservationRollbacks: Int { reservationRollbacks.load() }
        var testCapacityWakeTurns: Int { capacityWakeTurns.load() }
        var testGrantCount: Int { state.withLock { $0.grants.count } }
        var testWaiterCount: Int { state.withLock { $0.waiterCount } }
        var testCoordinatorInspections: UInt64 { state.withLock { $0.coordinatorInspections } }
        var testMaxCoordinatorInspectionsPerTurn: Int {
            state.withLock { $0.maxCoordinatorInspectionsPerTurn }
        }
        var testPeakGrantCount: Int { state.withLock { $0.peakGrantCount } }
        var testScanRemaining: Int { state.withLock { $0.scanRemaining } }
        var testLeaseTimerReprograms: UInt64 { state.withLock { $0.leaseTimerReprograms } }
        func testRunCoordinator(now: UInt64) {
            let deliveries = withCoordinatorState { state in
                state.scanScheduled = false
                let deliveries = driveCoordinatorLocked(&state, now: now, allowDiscovery: true)
                scheduleLeaseTimerLocked(&state)
                return deliveries
            }
            deliver(deliveries)
        }
        func testBlockCoordinatorQueue(
            started: DispatchSemaphore, until allowed: DispatchSemaphore
        ) {
            coordinatorQueue.async {
                started.signal()
                allowed.wait()
            }
        }
    #endif
}

final class UdpIngressFlowStaging: @unchecked Sendable {
    private struct State {
        var closed = false
        var retainedItems = 0
        var retainedBytes = 0
        var waiter: UdpIngressStagingWaiter?
        var activeGrantTicket: UInt64 = 0
    }

    private let generation: UdpIngressGenerationStagingBudget
    /// Immutable lease snapshot: replacement generations may reconfigure the
    /// shared global envelope but never change an existing flow's local caps.
    private let policy: UdpIngressStagingPolicy
    private let state = Locked(State())
    /// Shared pressure-only identity and last discovery epoch. `nil` marks
    /// closure. Waiters retain this leaf without retaining the flow; healthy
    /// datagram admission/release never touches it. Its lock is released
    /// before close acquires either the flow or generation lock.
    fileprivate let pressureIdentity = Locked<Int?>(0)
    #if DEBUG || RAMA_TESTING
        var testBeforeCloseCancellation: (@Sendable () -> Void)?
    #endif

    init(
        generation: UdpIngressGenerationStagingBudget,
        policy: UdpIngressStagingPolicy? = nil
    ) {
        self.generation = generation
        self.policy = policy ?? generation.policySnapshotForNewFlow()
    }

    deinit { close() }

    /// Reserve and retain only the longest admissible FIFO prefix. Endpoint
    /// indices remain paired exactly; a short endpoint array stays short so
    /// the forwarding path continues to assign `nil` to surplus datagrams.
    func stage(
        datagrams: [Data], endpoints: [NWEndpoint]?, grantTicket: UInt64 = 0
    ) -> UdpIngressStageOutcome {
        guard !datagrams.isEmpty else {
            if grantTicket != 0 {
                let reservation = state.withLock { state in
                    if state.activeGrantTicket == grantTicket { state.activeGrantTicket = 0 }
                    return generation.reservePrefix(
                        owner: self, ticket: grantTicket, datagrams: [],
                        maxCount: 0, maxBytes: 0)
                }
                generation.deliver(reservation.deliveries)
            }
            return UdpIngressStageOutcome(
                batch: nil, dropSample: nil, blockedReason: nil,
                neededItems: 0, neededBytes: 0)
        }
        var reason: UdpIngressStagingDropReason?
        var generationDeliveries: [(UdpIngressStagingWaiter, UInt64)] = []
        let reservation = state.withLock { state -> (Int, Int)? in
            guard !state.closed else {
                reason = .closed
                if state.activeGrantTicket == grantTicket { state.activeGrantTicket = 0 }
                return nil
            }
            if state.activeGrantTicket == grantTicket { state.activeGrantTicket = 0 }
            let itemHeadroom = max(
                policy.maxItemsPerFlow - state.retainedItems, 0)
            let byteHeadroom = max(
                policy.maxBytesPerFlow - state.retainedBytes, 0)
            let reserved = generation.reservePrefix(
                owner: self,
                ticket: grantTicket,
                datagrams: datagrams,
                maxCount: itemHeadroom,
                maxBytes: byteHeadroom)
            generationDeliveries = reserved.deliveries
            guard reserved.count > 0 else {
                if datagrams[0].count > policy.maxBytesPerFlow
                    || datagrams[0].count > reserved.globalMaxBytes
                {
                    reason = .oversizedBytes
                } else if itemHeadroom == 0 {
                    reason = .flowItems
                } else if reserved.generationItemHeadroom == 0 {
                    reason = .generationItems
                } else if datagrams[0].count > byteHeadroom {
                    reason = .flowBytes
                } else if datagrams[0].count > reserved.generationByteHeadroom {
                    reason = .generationBytes
                } else if reserved.generationGateClosed {
                    // Capacity exists, but a previously published generation
                    // waiter owns the next admission opportunity.
                    reason = .generationItems
                } else {
                    reason = byteHeadroom <= reserved.generationByteHeadroom
                        ? .flowBytes : .generationBytes
                }
                return nil
            }
            state.retainedItems += reserved.count
            state.retainedBytes += reserved.bytes
            if reserved.count < datagrams.count {
                if reserved.count == reserved.generationItemHeadroom
                    && reserved.generationItemHeadroom < itemHeadroom
                {
                    reason = .generationItems
                } else if reserved.count == itemHeadroom {
                    reason = .flowItems
                } else {
                    reason = byteHeadroom <= reserved.generationByteHeadroom
                        ? .flowBytes : .generationBytes
                }
            }
            return (reserved.count, reserved.bytes)
        }
        generation.deliver(generationDeliveries)
        if reason == .closed, grantTicket != 0 {
            generation.cancel(waiter: nil, owner: self, ticket: grantTicket)
        }
        let count = reservation?.0 ?? 0
        let bytes = reservation?.1 ?? 0
        let droppedItems = datagrams.count - count
        // Inspect at most one rejected item. Exact suffix-byte totals would
        // turn an adversarial callback array into unbounded synchronous work;
        // the public field is deliberately named as a lower bound.
        let droppedBytesLowerBound = droppedItems > 0 ? datagrams[count].count : 0
        // A late callback after normal teardown is not pressure and must not
        // poison the signed soak gate. Terminal reasons likewise have their
        // own lifecycle path and must not enter the four-reason pressure schema.
        let dropSample: UdpIngressStagingDropSample? = reason.flatMap { reason in
            guard reason.isRetryableCapacityPressure else { return nil }
            return generation.recordDrop(
                reason: reason,
                items: droppedItems,
                bytesLowerBound: droppedBytesLowerBound)
        }
        guard count > 0 else {
            return UdpIngressStageOutcome(
                batch: nil,
                dropSample: dropSample,
                blockedReason: reason,
                neededItems: 1,
                neededBytes: datagrams[0].count)
        }

        // Reservation precedes these allocations and the later async capture.
        let stagedDatagrams = Array(datagrams.prefix(count))
        let stagedEndpoints = endpoints.map { Array($0.prefix(min(count, $0.count))) }
        let batch = UdpIngressStagedBatch(
            datagrams: stagedDatagrams,
            endpoints: stagedEndpoints,
            itemCount: count,
            byteCount: bytes,
            sourceDatagramCount: datagrams.count,
            sourceEndpointCount: endpoints?.count,
            owner: self)
        return UdpIngressStageOutcome(
            batch: batch,
            dropSample: dropSample,
            blockedReason: nil,
            neededItems: 0,
            neededBytes: 0)
    }

    func close() {
        pressureIdentity.withLock { $0 = nil }
        let pending = state.withLock { state -> (UdpIngressStagingWaiter?, UInt64) in
            state.closed = true
            let pending = (state.waiter, state.activeGrantTicket)
            state.waiter = nil
            state.activeGrantTicket = 0
            return pending
        }
        #if DEBUG || RAMA_TESTING
            testBeforeCloseCancellation?()
        #endif
        generation.cancel(waiter: pending.0, owner: self, ticket: pending.1)
    }

    /// Error/EOF can finish a granted Apple read without a payload admission.
    /// Release that exact grant immediately rather than waiting for its lease.
    func completeWithoutStaging(grantTicket: UInt64) {
        guard grantTicket != 0 else { return }
        let shouldCancel = state.withLock { state -> Bool in
            guard state.activeGrantTicket == grantTicket else { return false }
            state.activeGrantTicket = 0
            return true
        }
        if shouldCancel {
            generation.cancel(waiter: nil, owner: self, ticket: grantTicket)
        }
    }

    /// Each flow releases its staged completion before reading again, so only
    /// process capacity needs a waiter; per-flow caps bound one callback prefix.
    @discardableResult
    func waitForCapacity(
        reason: UdpIngressStagingDropReason,
        neededItems: Int,
        neededBytes: Int,
        onReady: @escaping @Sendable (UInt64) -> Void
    ) -> Bool {
        guard reason.isRetryableCapacityPressure,
            neededItems > 0,
            neededItems <= policy.maxItemsPerFlow,
            neededBytes >= 0,
            neededBytes <= policy.maxBytesPerFlow,
            generation.requestFitsCurrentGlobalLimits(
                items: neededItems, bytes: neededBytes)
        else { return false }
        let waiter = UdpIngressStagingWaiter(
            owner: self,
            neededItems: neededItems,
            neededBytes: neededBytes,
            onGrant: onReady)
        var deliveries: [(UdpIngressStagingWaiter, UInt64)] = []
        let armed = state.withLock { state -> Bool in
            guard !state.closed else { return false }
            guard state.waiter == nil, state.activeGrantTicket == 0 else { return true }
            state.waiter = waiter
            deliveries = generation.register(waiter)
            return true
        }
        guard armed else { return false }
        generation.deliver(deliveries)
        return true
    }

    fileprivate func receiveGenerationGrant(
        waiter: UdpIngressStagingWaiter, ticket: UInt64
    ) {
        let callback = state.withLock { state -> (@Sendable (UInt64) -> Void)? in
            guard !state.closed, state.waiter === waiter else { return nil }
            state.waiter = nil
            state.activeGrantTicket = ticket
            return waiter.onGrant
        }
        guard let callback else {
            generation.cancel(waiter: nil, owner: self, ticket: ticket)
            return
        }
        callback(ticket)
    }

    fileprivate func release(items: Int, bytes: Int) {
        var generationDeliveries: [(UdpIngressStagingWaiter, UInt64)] = []
        state.withLock { state in
            precondition(state.retainedItems >= items, "UDP flow staging item underflow")
            precondition(state.retainedBytes >= bytes, "UDP flow staging byte underflow")
            state.retainedItems -= items
            state.retainedBytes -= bytes
            generationDeliveries = generation.release(items: items, bytes: bytes)
        }
        generation.deliver(generationDeliveries)
    }

    #if DEBUG || RAMA_TESTING
        var testSnapshot: (closed: Bool, items: Int, bytes: Int) {
            state.withLock { ($0.closed, $0.retainedItems, $0.retainedBytes) }
        }
        var testWaitSnapshot: (waiting: Bool, activeTicket: UInt64) {
            state.withLock { ($0.waiter != nil, $0.activeGrantTicket) }
        }
    #endif
}

enum UdpIngressStagingDropReason: String, Sendable {
    case flowItems = "flow_items"
    case flowBytes = "flow_bytes"
    case generationItems = "generation_items"
    case generationBytes = "generation_bytes"
    case oversizedBytes = "oversized_bytes"
    case closed

    fileprivate var isRetryableCapacityPressure: Bool {
        switch self {
        case .flowItems, .flowBytes, .generationItems, .generationBytes:
            return true
        case .oversizedBytes, .closed:
            return false
        }
    }
}

struct UdpIngressStagingDropSample: Sendable {
    let reason: UdpIngressStagingDropReason
    let cumulativeDropEvents: UInt64
    let cumulativeDroppedItems: UInt64
    let cumulativeDroppedBytesLowerBound: UInt64
    let generationRetainedItems: Int
    let generationMaxRetainedItems: Int
    let generationRetainedBytes: Int
    let generationMaxRetainedBytes: Int
}

struct UdpIngressStageOutcome {
    let batch: UdpIngressStagedBatch?
    let dropSample: UdpIngressStagingDropSample?
    /// Non-nil only when no datagram could be staged. Capacity reasons require
    /// a replacement-read wait; `closed` and `oversizedBytes` are terminal.
    let blockedReason: UdpIngressStagingDropReason?
    let neededItems: Int
    let neededBytes: Int
}

final class UdpIngressStagedBatch: @unchecked Sendable {
    private struct Payload {
        let datagrams: [Data]
        let endpoints: [NWEndpoint]?
    }

    private var payload: Payload?
    let itemCount: Int
    let byteCount: Int
    let sourceDatagramCount: Int
    let sourceEndpointCount: Int?
    private let owner: UdpIngressFlowStaging

    fileprivate init(
        datagrams: [Data],
        endpoints: [NWEndpoint]?,
        itemCount: Int,
        byteCount: Int,
        sourceDatagramCount: Int,
        sourceEndpointCount: Int?,
        owner: UdpIngressFlowStaging
    ) {
        self.payload = Payload(datagrams: datagrams, endpoints: endpoints)
        self.itemCount = itemCount
        self.byteCount = byteCount
        self.sourceDatagramCount = sourceDatagramCount
        self.sourceEndpointCount = sourceEndpointCount
        self.owner = owner
    }

    deinit {
        UdpPayloadLifetimeLease.destroy(&payload) { [owner] in
            owner.release(items: itemCount, bytes: byteCount)
        }
    }

    /// Synchronously forwards the private payload while this batch is the
    /// receiver. No generic `[Data]` accessor is exposed, and the batch is
    /// explicitly kept alive until every temporary forwarding alias has left
    /// this nonescaping scope.
    func forward(
        to session: RamaUdpSessionHandle,
        onMatchedEndpoint: ((NWEndpoint) -> Void)? = nil
    ) -> (datagrams: Int, endpoints: Int)? {
        withExtendedLifetime(self) {
            guard let payload else {
                preconditionFailure("UDP staged payload accessed after lifetime ended")
            }
            let mismatch: (Int, Int)?
            if let endpointCount = sourceEndpointCount,
                endpointCount != sourceDatagramCount
            {
                mismatch = (sourceDatagramCount, endpointCount)
            } else {
                mismatch = nil
            }
            for (index, datagram) in payload.datagrams.enumerated() {
                let endpoint = payload.endpoints.flatMap { endpoints in
                    index < endpoints.count ? endpoints[index] : nil
                }
                let peer = endpoint.flatMap(ramaUdpPeer(from:))
                #if DEBUG || RAMA_TESTING
                    if peer != nil, let endpoint {
                        onMatchedEndpoint?(endpoint)
                    }
                #endif
                session.onClientDatagram(datagram, peer: peer)
            }
            return mismatch
        }
    }

    #if DEBUG || RAMA_TESTING
        func testPayloadEquals(_ datagrams: [Data], endpointCount: Int?) -> Bool {
            guard let payload else { return false }
            return payload.datagrams == datagrams
                && payload.endpoints?.count == endpointCount
        }
    #endif
}
