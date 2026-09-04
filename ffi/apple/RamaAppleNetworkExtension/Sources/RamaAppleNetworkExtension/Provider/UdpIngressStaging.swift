import Foundation
@preconcurrency import NetworkExtension

/// Rust-derived limits for payloads retained after Apple's UDP read callback
/// returns. NetworkExtension has already allocated the callback's `[Data]` and
/// endpoint arrays before application code runs; that framework-transient
/// allocation is outside this bound. Rama reserves first and asynchronously
/// captures only the admissible prefix, so its own retained staging is exact:
/// one generation is bounded by `maxItemsPerGeneration` and
/// `maxBytesPerGeneration`, and each flow by both `maxItemsPerFlow` and
/// `maxBytesPerFlow`.
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

private final class UdpIngressStagingWaiter: @unchecked Sendable {
    weak var owner: UdpIngressFlowStaging?
    let neededItems: Int
    let neededBytes: Int
    /// Mutated only while the owning flow lock is held. A waiter begins here
    /// for flow-local pressure and joins the generation coordinator exactly
    /// once when its local capacity becomes sufficient.
    var generationScoped: Bool
    let onGrant: @Sendable (UInt64) -> Void
    weak var previous: UdpIngressStagingWaiter?
    var next: UdpIngressStagingWaiter?
    var queued = false

    init(
        owner: UdpIngressFlowStaging,
        neededItems: Int,
        neededBytes: Int,
        generationScoped: Bool,
        onGrant: @escaping @Sendable (UInt64) -> Void
    ) {
        self.owner = owner
        self.neededItems = neededItems
        self.neededBytes = neededBytes
        self.generationScoped = generationScoped
        self.onGrant = onGrant
    }
}

private struct UdpIngressStagingGrant {
    let waiter: UdpIngressStagingWaiter
    let ticket: UInt64
    let expiresAt: UInt64
}

private struct UdpIngressStagingReservation {
    let count: Int
    let bytes: Int
    let generationItemHeadroom: Int
    let generationByteHeadroom: Int
    let deliveries: [(UdpIngressStagingWaiter, UInt64)]
}

final class UdpIngressGenerationStagingBudget: @unchecked Sendable {
    private struct State {
        var retainedBytes = 0
        var retainedItems = 0
        var provisionalBytes = 0
        var provisionalItems = 0
        var firstWaiter: UdpIngressStagingWaiter?
        var lastWaiter: UdpIngressStagingWaiter?
        var waiterCount = 0
        var scanRemaining = 0
        var scanScheduled = false
        /// Currently programmed one-shot lease deadline. `nil` means the
        /// shared timer is already disarmed at `.distantFuture`.
        var scheduledLeaseExpiry: UInt64?
        var nextTicket: UInt64 = 1
        var grants: [UInt64: UdpIngressStagingGrant] = [:]
        var dropEvents: UInt64 = 0
        var droppedItems: UInt64 = 0
        var droppedBytesLowerBound: UInt64 = 0
        #if DEBUG
            var lastInspectedItems = 0
            var coordinatorInspections: UInt64 = 0
            var peakGrantCount = 0
            var leaseTimerReprograms: UInt64 = 0
        #endif
    }

    let policy: UdpIngressStagingPolicy
    private let state = Locked(State())
    private let coordinatorQueue = DispatchQueue(
        label: "rama.tproxy.udp.ingress-staging.coordinator", qos: .utility)
    private let leaseTimer: DispatchSourceTimer
    private let automaticScheduling: Bool

    init(policy: UdpIngressStagingPolicy, automaticScheduling: Bool = true) {
        self.policy = policy
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
        var deliveries: [(UdpIngressStagingWaiter, UInt64)] = []
        let reservation = state.withLock { state -> UdpIngressStagingReservation in
            let now = DispatchTime.now().uptimeNanoseconds
            let expired = expireGrantsLocked(&state, now: now)
            var opportunityChanged = expired
            if ticket != 0,
                let grant = state.grants[ticket],
                grant.waiter.owner === owner
            {
                state.grants.removeValue(forKey: ticket)
                state.provisionalItems -= grant.waiter.neededItems
                state.provisionalBytes -= grant.waiter.neededBytes
                opportunityChanged = true
            }

            let generationItemHeadroom = max(
                policy.maxItemsPerGeneration - state.retainedItems - state.provisionalItems, 0)
            let generationByteHeadroom = max(
                policy.maxBytesPerGeneration - state.retainedBytes - state.provisionalBytes, 0)
            let byteLimit = min(maxBytes, generationByteHeadroom)
            let countLimit = min(maxCount, generationItemHeadroom)
            var count = 0
            var bytes = 0
            #if DEBUG
                state.lastInspectedItems = 0
            #endif
            for datagram in datagrams.prefix(countLimit) {
                #if DEBUG
                    state.lastInspectedItems += 1
                #endif
                let size = datagram.count
                if size > byteLimit - bytes { break }
                bytes += size
                count += 1
            }
            if count > 0 {
                state.retainedItems += count
                state.retainedBytes += bytes
            }
            if opportunityChanged {
                state.scanRemaining = state.waiterCount
            }
            deliveries = driveCoordinatorLocked(&state, now: now)
            scheduleLeaseTimerLocked(&state)
            return UdpIngressStagingReservation(
                count: count,
                bytes: bytes,
                generationItemHeadroom: generationItemHeadroom,
                generationByteHeadroom: generationByteHeadroom,
                deliveries: [])
        }
        return UdpIngressStagingReservation(
            count: reservation.count,
            bytes: reservation.bytes,
            generationItemHeadroom: reservation.generationItemHeadroom,
            generationByteHeadroom: reservation.generationByteHeadroom,
            deliveries: deliveries)
    }

    private func appendLocked(_ waiter: UdpIngressStagingWaiter, state: inout State) {
        precondition(!waiter.queued)
        waiter.previous = state.lastWaiter
        waiter.next = nil
        state.lastWaiter?.next = waiter
        if state.firstWaiter == nil { state.firstWaiter = waiter }
        state.lastWaiter = waiter
        waiter.queued = true
        state.waiterCount += 1
    }

    private func removeLocked(_ waiter: UdpIngressStagingWaiter, state: inout State) {
        guard waiter.queued else { return }
        let previous = waiter.previous
        let next = waiter.next
        if let previous { previous.next = next } else { state.firstWaiter = next }
        if let next { next.previous = previous } else { state.lastWaiter = previous }
        waiter.previous = nil
        waiter.next = nil
        waiter.queued = false
        state.waiterCount -= 1
    }

    private func rotateToTailLocked(_ waiter: UdpIngressStagingWaiter, state: inout State) {
        guard waiter !== state.lastWaiter else { return }
        removeLocked(waiter, state: &state)
        appendLocked(waiter, state: &state)
    }

    private func nextTicketLocked(_ state: inout State) -> UInt64? {
        guard state.nextTicket != 0 else { return nil }
        let ticket = state.nextTicket
        state.nextTicket = ticket == UInt64.max ? 0 : ticket + 1
        return ticket
    }

    private func driveCoordinatorLocked(
        _ state: inout State, now: UInt64
    ) -> [(UdpIngressStagingWaiter, UInt64)] {
        if expireGrantsLocked(&state, now: now) {
            state.scanRemaining = state.waiterCount
        }
        var deliveries: [(UdpIngressStagingWaiter, UInt64)] = []
        var inspected = 0
        var availableItems = max(
            policy.maxItemsPerGeneration - state.retainedItems - state.provisionalItems, 0)
        var availableBytes = max(
            policy.maxBytesPerGeneration - state.retainedBytes - state.provisionalBytes, 0)
        while state.grants.count < udpIngressStagingMaxGrants,
            state.scanRemaining > 0,
            inspected < udpIngressStagingMaxInspectionsPerTurn,
            let waiter = state.firstWaiter
        {
            state.scanRemaining -= 1
            inspected += 1
            #if DEBUG
                state.coordinatorInspections &+= 1
            #endif
            guard waiter.owner != nil else {
                removeLocked(waiter, state: &state)
                continue
            }
            guard waiter.neededItems <= availableItems,
                waiter.neededBytes <= availableBytes
            else {
                rotateToTailLocked(waiter, state: &state)
                continue
            }
            guard let ticket = nextTicketLocked(&state) else {
                state.scanRemaining = 0
                break
            }
            removeLocked(waiter, state: &state)
            availableItems -= waiter.neededItems
            availableBytes -= waiter.neededBytes
            state.provisionalItems += waiter.neededItems
            state.provisionalBytes += waiter.neededBytes
            let expiry = now > UInt64.max - udpIngressStagingGrantLeaseNanoseconds
                ? UInt64.max : now + udpIngressStagingGrantLeaseNanoseconds
            state.grants[ticket] = UdpIngressStagingGrant(
                waiter: waiter, ticket: ticket, expiresAt: expiry)
            #if DEBUG
                state.peakGrantCount = max(state.peakGrantCount, state.grants.count)
            #endif
            deliveries.append((waiter, ticket))
        }
        scheduleScanLocked(&state)
        return deliveries
    }

    private func expireGrantsLocked(_ state: inout State, now: UInt64) -> Bool {
        let expired = state.grants.compactMap { ticket, grant in
            grant.expiresAt <= now ? ticket : nil
        }
        for ticket in expired {
            guard let grant = state.grants.removeValue(forKey: ticket) else { continue }
            state.provisionalItems -= grant.waiter.neededItems
            state.provisionalBytes -= grant.waiter.neededBytes
        }
        return !expired.isEmpty
    }

    private func scheduleScanLocked(_ state: inout State) {
        guard automaticScheduling,
            state.scanRemaining > 0,
            state.waiterCount > 0,
            state.grants.count < udpIngressStagingMaxGrants,
            !state.scanScheduled
        else { return }
        state.scanScheduled = true
        coordinatorQueue.async { [weak self] in self?.runCoordinatorTurn() }
    }

    private func scheduleLeaseTimerLocked(_ state: inout State) {
        guard automaticScheduling else { return }
        let expiry = state.grants.values.lazy.map(\.expiresAt).min()
        guard expiry != state.scheduledLeaseExpiry else { return }
        state.scheduledLeaseExpiry = expiry
        #if DEBUG
            state.leaseTimerReprograms &+= 1
        #endif
        guard let expiry else {
            leaseTimer.schedule(deadline: .distantFuture)
            return
        }
        leaseTimer.schedule(deadline: DispatchTime(uptimeNanoseconds: expiry), leeway: .milliseconds(1))
    }

    private func runCoordinatorTurn() {
        let deliveries = state.withLock { state in
            state.scanScheduled = false
            let now = DispatchTime.now().uptimeNanoseconds
            let deliveries = driveCoordinatorLocked(&state, now: now)
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
        state.withLock { state in
            let now = DispatchTime.now().uptimeNanoseconds
            _ = expireGrantsLocked(&state, now: now)
            appendLocked(waiter, state: &state)
            state.scanRemaining = state.waiterCount
            let deliveries = driveCoordinatorLocked(&state, now: now)
            scheduleLeaseTimerLocked(&state)
            return deliveries
        }
    }

    fileprivate func cancel(
        waiter: UdpIngressStagingWaiter?, owner: UdpIngressFlowStaging, ticket: UInt64
    ) {
        let deliveries = state.withLock { state in
            var changed = false
            if let waiter, waiter.queued {
                removeLocked(waiter, state: &state)
            }
            if ticket != 0,
                let grant = state.grants[ticket],
                grant.waiter.owner === owner
            {
                state.grants.removeValue(forKey: ticket)
                state.provisionalItems -= grant.waiter.neededItems
                state.provisionalBytes -= grant.waiter.neededBytes
                changed = true
            }
            if changed { state.scanRemaining = state.waiterCount }
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
        state.withLock { state in
            state.dropEvents = state.dropEvents == UInt64.max ? UInt64.max : state.dropEvents + 1
            let (droppedItems, itemsOverflow) = state.droppedItems
                .addingReportingOverflow(UInt64(items))
            state.droppedItems = itemsOverflow ? UInt64.max : droppedItems
            let (droppedBytes, bytesOverflow) = state.droppedBytesLowerBound
                .addingReportingOverflow(UInt64(bytesLowerBound))
            state.droppedBytesLowerBound = bytesOverflow ? UInt64.max : droppedBytes
            guard state.dropEvents.nonzeroBitCount == 1 else { return nil }
            return UdpIngressStagingDropSample(
                reason: reason,
                cumulativeDropEvents: state.dropEvents,
                cumulativeDroppedItems: state.droppedItems,
                cumulativeDroppedBytesLowerBound: state.droppedBytesLowerBound,
                generationRetainedItems: state.retainedItems,
                generationMaxRetainedItems: policy.maxItemsPerGeneration,
                generationRetainedBytes: state.retainedBytes,
                generationMaxRetainedBytes: policy.maxBytesPerGeneration)
        }
    }

    fileprivate func release(
        items: Int, bytes: Int, registering waiter: UdpIngressStagingWaiter? = nil
    ) -> [(UdpIngressStagingWaiter, UInt64)] {
        state.withLock { state in
            precondition(state.retainedItems >= items, "UDP generation staging item underflow")
            precondition(state.retainedBytes >= bytes, "UDP generation staging underflow")
            state.retainedItems -= items
            state.retainedBytes -= bytes
            if let waiter { appendLocked(waiter, state: &state) }
            state.scanRemaining = state.waiterCount
            let deliveries = driveCoordinatorLocked(
                &state, now: DispatchTime.now().uptimeNanoseconds)
            scheduleLeaseTimerLocked(&state)
            return deliveries
        }
    }

    #if DEBUG
        var testRetainedBytes: Int { state.withLock { $0.retainedBytes } }
        var testRetainedItems: Int { state.withLock { $0.retainedItems } }
        var testLastInspectedItems: Int { state.withLock { $0.lastInspectedItems } }
        var testGrantCount: Int { state.withLock { $0.grants.count } }
        var testWaiterCount: Int { state.withLock { $0.waiterCount } }
        var testCoordinatorInspections: UInt64 { state.withLock { $0.coordinatorInspections } }
        var testPeakGrantCount: Int { state.withLock { $0.peakGrantCount } }
        var testScanRemaining: Int { state.withLock { $0.scanRemaining } }
        var testLeaseTimerReprograms: UInt64 { state.withLock { $0.leaseTimerReprograms } }
        func testRunCoordinator(now: UInt64) {
            let deliveries = state.withLock { state in
                state.scanScheduled = false
                let deliveries = driveCoordinatorLocked(&state, now: now)
                scheduleLeaseTimerLocked(&state)
                return deliveries
            }
            deliver(deliveries)
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
    private let state = Locked(State())

    init(generation: UdpIngressGenerationStagingBudget) {
        self.generation = generation
    }

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
                generation.policy.maxItemsPerFlow - state.retainedItems, 0)
            let byteHeadroom = max(
                generation.policy.maxBytesPerFlow - state.retainedBytes, 0)
            let reserved = generation.reservePrefix(
                owner: self,
                ticket: grantTicket,
                datagrams: datagrams,
                maxCount: itemHeadroom,
                maxBytes: byteHeadroom)
            generationDeliveries = reserved.deliveries
            guard reserved.count > 0 else {
                if datagrams[0].count > generation.policy.maxBytesPerFlow
                    || datagrams[0].count > generation.policy.maxBytesPerGeneration
                {
                    reason = .oversizedBytes
                } else if itemHeadroom == 0 {
                    reason = .flowItems
                } else if reserved.generationItemHeadroom == 0 {
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
        let pending = state.withLock { state -> (UdpIngressStagingWaiter?, UInt64) in
            state.closed = true
            let pending = (state.waiter, state.activeGrantTicket)
            state.waiter = nil
            state.activeGrantTicket = 0
            return pending
        }
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

    /// Arm one coalesced capacity-driven replacement read. Generation
    /// pressure enters the shared coordinator immediately. Per-flow pressure
    /// waits for this flow's own retained batch release, then enters that same
    /// coordinator before any callback can run. Every restart therefore owns
    /// a nonzero provisional grant and participates in the global wake bound.
    @discardableResult
    func waitForCapacity(
        reason: UdpIngressStagingDropReason,
        neededItems: Int,
        neededBytes: Int,
        onReady: @escaping @Sendable (UInt64) -> Void
    ) -> Bool {
        guard reason.isRetryableCapacityPressure,
            neededItems > 0,
            neededItems <= generation.policy.maxItemsPerFlow,
            neededItems <= generation.policy.maxItemsPerGeneration,
            neededBytes >= 0,
            neededBytes <= generation.policy.maxBytesPerFlow,
            neededBytes <= generation.policy.maxBytesPerGeneration
        else { return false }
        let generationScoped = reason == .generationItems || reason == .generationBytes
        let waiter = UdpIngressStagingWaiter(
            owner: self,
            neededItems: neededItems,
            neededBytes: neededBytes,
            generationScoped: generationScoped,
            onGrant: onReady)
        var deliveries: [(UdpIngressStagingWaiter, UInt64)] = []
        let armed = state.withLock { state -> Bool in
            guard !state.closed else { return false }
            guard state.waiter == nil, state.activeGrantTicket == 0 else { return true }
            state.waiter = waiter
            if generationScoped {
                deliveries = generation.register(waiter)
            } else {
                let itemHeadroom = max(
                    generation.policy.maxItemsPerFlow - state.retainedItems, 0)
                let byteHeadroom = max(
                    generation.policy.maxBytesPerFlow - state.retainedBytes, 0)
                if neededItems <= itemHeadroom, neededBytes <= byteHeadroom {
                    waiter.generationScoped = true
                    deliveries = generation.register(waiter)
                }
            }
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
            var promotedWaiter: UdpIngressStagingWaiter?
            if let waiter = state.waiter, !waiter.generationScoped {
                let itemHeadroom = max(
                    generation.policy.maxItemsPerFlow - state.retainedItems, 0)
                let byteHeadroom = max(
                    generation.policy.maxBytesPerFlow - state.retainedBytes, 0)
                if waiter.neededItems <= itemHeadroom, waiter.neededBytes <= byteHeadroom {
                    waiter.generationScoped = true
                    promotedWaiter = waiter
                }
            }
            // Flow -> generation is the sole nested lock order. Combining the
            // retained release and waiter publication under one generation
            // lock prevents a missed wake and costs at most one bounded scan.
            generationDeliveries = generation.release(
                items: items, bytes: bytes, registering: promotedWaiter)
        }
        generation.deliver(generationDeliveries)
    }

    #if DEBUG
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
    let datagrams: [Data]
    let endpoints: [NWEndpoint]?
    let itemCount: Int
    let byteCount: Int
    let sourceDatagramCount: Int
    let sourceEndpointCount: Int?
    private let owner: UdpIngressFlowStaging
    private let released = Locked(false)

    fileprivate init(
        datagrams: [Data],
        endpoints: [NWEndpoint]?,
        itemCount: Int,
        byteCount: Int,
        sourceDatagramCount: Int,
        sourceEndpointCount: Int?,
        owner: UdpIngressFlowStaging
    ) {
        self.datagrams = datagrams
        self.endpoints = endpoints
        self.itemCount = itemCount
        self.byteCount = byteCount
        self.sourceDatagramCount = sourceDatagramCount
        self.sourceEndpointCount = sourceEndpointCount
        self.owner = owner
    }

    func release() {
        let shouldRelease = released.withLock { released in
            guard !released else { return false }
            released = true
            return true
        }
        if shouldRelease { owner.release(items: itemCount, bytes: byteCount) }
    }

    deinit { release() }
}
