import Foundation
import RamaAppleNEFFI

/// One process/core-lifetime envelope for payloads retained by Swift writers.
///
/// The packed atomic layout keeps the healthy path independent across flows:
///
/// - high 40 bits: retained bytes;
/// - low 23 bits: retained items;
/// - bit 23: TCP waiter gate.
///
/// Bytes and items move in one CAS, so neither limit can be crossed between two
/// independent atomics. The waiter gate shares that same linearization point:
/// once pressure publishes a TCP waiter, newcomers cannot consume capacity in
/// front of it. Only the pressure path touches `coordinator`.
struct WriterMemoryPolicy: Sendable, Equatable {
    static let maxRepresentableBytes = Int((UInt64(1) << 40) - 1)
    static let maxRepresentableItems = Int((UInt64(1) << 23) - 1)
    static let minimumUdpPressureReserveBytes = 64 * 1024

    let maxBytes: Int
    let maxItems: Int
    /// Maximum size of one TCP retry. Pressure service reserve is clamped so
    /// the FIFO head can always fit in the TCP share.
    let tcpWaiterMaxBytes: Int
    /// Capacity kept available to lossy UDP while TCP waiters hold the gate.
    /// Production configuration leaves space for one TCP read view and one
    /// maximum-sized retry before allocating this reserve.
    let udpPressureReserveBytes: Int
    let udpPressureReserveItems: Int

    /// Maximum zero-copy TCP read/promotion view handed across the Rust FFI or
    /// into one direct-forwarded write. This is independent of the larger FIFO
    /// waiter cap used for Rust→Swift writer callbacks.
    var tcpPayloadViewMaxBytes: Int { min(64 * 1024, tcpWaiterMaxBytes) }

    /// Read-side roots may survive in Rust, a promotion cursor, and a writer
    /// simultaneously. Cap that physical transit population below the global
    /// envelope so it can never consume the UDP reserve or the capacity needed
    /// to grant one maximum-sized FIFO TCP waiter. The separate 64 KiB cap
    /// limits individual views only; a waiter can represent a larger callback.
    var tcpTransitMaxBytes: Int {
        max(0, maxBytes - udpPressureReserveBytes - tcpWaiterMaxBytes)
    }

    var tcpTransitMaxItems: Int {
        max(0, maxItems - udpPressureReserveItems - 1)
    }

    init(
        maxBytes: Int,
        maxItems: Int,
        tcpWaiterMaxBytes: Int? = nil,
        udpPressureReserveBytes: Int = 1024 * 1024,
        udpPressureReserveItems: Int = 256
    ) {
        precondition(maxBytes > 0 && maxBytes <= Self.maxRepresentableBytes)
        precondition(maxItems > 0 && maxItems <= Self.maxRepresentableItems)
        let tcpWaiterMaxBytes = tcpWaiterMaxBytes ?? maxBytes
        precondition(tcpWaiterMaxBytes > 0 && tcpWaiterMaxBytes <= maxBytes)
        precondition(udpPressureReserveBytes >= 0 && udpPressureReserveItems >= 0)
        self.maxBytes = maxBytes
        self.maxItems = maxItems
        self.tcpWaiterMaxBytes = tcpWaiterMaxBytes
        let transitViewBytes = min(64 * 1024, tcpWaiterMaxBytes)
        self.udpPressureReserveBytes = min(
            udpPressureReserveBytes,
            max(0, maxBytes - tcpWaiterMaxBytes - transitViewBytes))
        self.udpPressureReserveItems = min(
            udpPressureReserveItems,
            max(0, maxItems - 2))
    }

    static let `default` = Self(
        maxBytes: 64 * 1024 * 1024,
        maxItems: 65_536,
        tcpWaiterMaxBytes: 256 * 1024)
}

enum WriterMemoryAdmission: Sendable {
    case regular
    case pressureUdp
}

enum WriterMemoryPressureProtocol: String, Sendable {
    case tcp
    case udp
}

enum WriterMemoryPressureReason: String, Sendable {
    case aggregateBytes = "aggregate_bytes"
    case aggregateItems = "aggregate_items"
    case tcpWaiterGate = "tcp_waiter_gate"
    case udpServiceBytes = "udp_service_bytes"
    case udpServiceItems = "udp_service_items"
    case reconfiguring
}

enum WriterMemoryPressureTransition: String, Sendable {
    case entered
    case recovered
}

struct WriterMemoryPressureEvent: Sendable, Equatable {
    let transition: WriterMemoryPressureTransition
    let `protocol`: WriterMemoryPressureProtocol?
    let reason: WriterMemoryPressureReason?
    let retainedBytes: Int
    let maxBytes: Int
    let retainedItems: Int
    let maxItems: Int

    var logMessage: String {
        let protocolName = self.protocol?.rawValue ?? "aggregate"
        let reasonName = reason?.rawValue ?? "low_water"
        return "writer memory pressure \(transition.rawValue) protocol=\"\(protocolName)\" reason=\"\(reasonName)\" retainedBytes=\(retainedBytes) maxBytes=\(maxBytes) retainedItems=\(retainedItems) maxItems=\(maxItems)"
    }
}

struct WriterMemorySnapshot: Sendable, Equatable {
    let retainedBytes: Int
    let retainedItems: Int
    let tcpWaiterGate: Bool
}

/// A capacity grant is already charged to the aggregate counter before its
/// callback runs. Consuming transfers that charge to the pump's accepted item;
/// release/deinit refunds an unused or stale grant exactly once.
final class WriterMemoryGrant: @unchecked Sendable {
    let bytes: Int
    let items: Int
    private let budget: WriterMemoryBudget
    private let active = Locked(true)

    fileprivate init(budget: WriterMemoryBudget, bytes: Int, items: Int) {
        self.budget = budget
        self.bytes = bytes
        self.items = items
    }

    func belongs(to candidate: WriterMemoryBudget) -> Bool {
        budget === candidate
    }

    @discardableResult
    func consume() -> Bool {
        active.withLock { active in
            guard active else { return false }
            active = false
            return true
        }
    }

    func release() {
        let shouldRelease = active.withLock { active in
            guard active else { return false }
            active = false
            return true
        }
        if shouldRelease { budget.release(bytes: bytes, items: items) }
    }

    deinit { release() }
}

/// The aggregate charge for one physical TCP backing allocation.
///
/// This is deliberately ARC-owned: slices, replay cursors, Rust FFI owners,
/// and write completions retain the same root, and the budget is refunded only
/// when the last of those owners releases it. No logical prefix/slice is
/// allowed to refund part of a still-live backing allocation.
final class PhysicalPayloadCharge: @unchecked Sendable {
    let bytes: Int
    let items: Int
    private let budget: WriterMemoryBudget
    private let isTcpTransit: Bool

    fileprivate init(
        budget: WriterMemoryBudget,
        bytes: Int,
        items: Int,
        isTcpTransit: Bool
    ) {
        self.budget = budget
        self.bytes = bytes
        self.items = items
        self.isTcpTransit = isTcpTransit
    }

    deinit {
        if isTcpTransit {
            budget.releaseTcpTransit(bytes: bytes, items: items)
        } else {
            budget.release(bytes: bytes, items: items)
        }
    }
}

/// Stable immutable storage for one physically charged TCP callback payload.
/// `NSData.bytes` remains valid for this object's lifetime and is the pointer
/// shared with Rust and zero-copy `Data` views.
final class TcpRetainedBuffer: @unchecked Sendable {
    fileprivate let storage: NSData
    private let charge: PhysicalPayloadCharge

    var count: Int { storage.length }

    fileprivate init(data: Data, charge: PhysicalPayloadCharge) {
        storage = data as NSData
        self.charge = charge
    }

    fileprivate var bytes: UnsafePointer<UInt8> {
        storage.bytes.assumingMemoryBound(to: UInt8.self)
    }
}

/// A logical view which retains the complete physical backing charge. Read and
/// direct-forwarding cursors emit these at `tcpPayloadViewMaxBytes`; a regular
/// writer callback may use one larger view up to `tcpWaiterMaxBytes`.
struct TcpPayloadSlice: @unchecked Sendable {
    let root: TcpRetainedBuffer
    fileprivate let offset: Int
    let count: Int

    fileprivate init(root: TcpRetainedBuffer, offset: Int, count: Int) {
        precondition(offset >= 0 && count > 0 && offset <= root.count - count)
        self.root = root
        self.offset = offset
        self.count = count
    }

    var bytes: UnsafePointer<UInt8> { root.bytes.advanced(by: offset) }

    /// A no-copy transport view. The caller must retain this slice until the
    /// transport completion; `TcpWritePumpCore.ChargedChunk` does exactly that.
    var data: Data {
        Data(
            bytesNoCopy: UnsafeMutableRawPointer(mutating: bytes),
            count: count,
            deallocator: .none)
    }

    /// Compatibility copy for test/legacy sinks which only understand `Data`
    /// and may retain it after the synchronous sink call returns.
    #if DEBUG || RAMA_TESTING
        var copiedData: Data { Data(bytes: bytes, count: count) }
    #endif
}

/// Remaining logical range of one retained TCP root. Advancing the cursor does
/// not alter physical accounting; every emitted slice shares `root`.
struct TcpPayloadCursor: @unchecked Sendable {
    fileprivate let root: TcpRetainedBuffer
    fileprivate var offset: Int

    fileprivate init(root: TcpRetainedBuffer, offset: Int = 0) {
        precondition(offset >= 0 && offset <= root.count)
        self.root = root
        self.offset = offset
    }

    var isEmpty: Bool { offset == root.count }
    var remainingBytes: Int { root.count - offset }

    func prefix(maxBytes: Int) -> TcpPayloadSlice {
        precondition(maxBytes > 0 && !isEmpty)
        return TcpPayloadSlice(
            root: root,
            offset: offset,
            count: min(maxBytes, remainingBytes))
    }

    mutating func advance(by count: Int) {
        precondition(count > 0 && count <= remainingBytes)
        offset += count
    }

    /// Compatibility copy used only by the legacy promotion test surface.
    #if DEBUG || RAMA_TESTING
        var copiedRemainder: Data {
            guard !isEmpty else { return Data() }
            return Data(bytes: root.bytes.advanced(by: offset), count: remainingBytes)
        }
    #endif
}

/// Cancellation handle for one queued TCP reservation. Queue records do not
/// retain this token, so dropping it automatically removes an obsolete waiter.
final class WriterMemoryWaiter: @unchecked Sendable {
    private weak var budget: WriterMemoryBudget?
    private let id: UInt64
    private let active = Locked(true)

    fileprivate init(budget: WriterMemoryBudget, id: UInt64) {
        self.budget = budget
        self.id = id
    }

    func cancel() {
        let shouldCancel = active.withLock { active in
            guard active else { return false }
            active = false
            return true
        }
        if shouldCancel { budget?.cancelWaiter(id) }
    }

    deinit { cancel() }
}

final class WriterMemoryBudget: @unchecked Sendable {
    private static let itemBits: UInt64 = 23
    private static let lowBits: UInt64 = 24
    private static let itemMask: UInt64 = (1 << itemBits) - 1
    private static let waiterGateMask: UInt64 = 1 << itemBits
    private static let byteMask: UInt64 = (1 << 40) - 1
    private static let grantBatch = 4

    private struct WaiterRecord {
        let bytes: Int
        let items: Int
        let onGrant: @Sendable (WriterMemoryGrant) -> Void
        let onUnavailable: @Sendable () -> Void
        var previous: UInt64?
        var next: UInt64?
    }

    private struct CoordinatorState {
        var nextWaiterId: UInt64 = 1
        var firstWaiterId: UInt64?
        var lastWaiterId: UInt64?
        var waiters: [UInt64: WaiterRecord] = [:]
        var scheduled = false
    }

    private struct DriveResult {
        var deliveries: [(WaiterRecord, WriterMemoryGrant)] = []
        var unavailable: [WaiterRecord] = []
        var scheduleContinuation = false
    }

    private let atomic: OpaquePointer
    /// Only UDP admitted while the TCP waiter gate is set is charged here.
    /// This pressure-only sub-budget prevents either protocol from starving
    /// the other without putting a lock on healthy UDP admission.
    private let pressureUdpAtomic: OpaquePointer
    /// Physical read-side TCP roots which can be retained concurrently by
    /// Rust, promotion, and a transport writer.
    private let tcpTransitAtomic: OpaquePointer
    /// Packed byte/item caps. Its gate bit is a cold reconfiguration fence:
    /// publishing it before the aggregate gate prevents an admission from
    /// returning under stale, lowered limits.
    private let limitsAtomic: OpaquePointer
    /// Current UDP service reserve, packed as bytes/items without a gate.
    private let pressureUdpLimitsAtomic: OpaquePointer
    /// Current physical TCP transit and bounded-view limits. Items are packed
    /// with bytes in `tcpTransitLimitsAtomic`; the view byte cap is stored in a
    /// separate lock-free word because it is not an accounting dimension.
    private let tcpTransitLimitsAtomic: OpaquePointer
    private let tcpPayloadViewMaxBytesAtomic: OpaquePointer
    /// Monotonic seqlock epoch closes the extremely narrow ABA window where a
    /// stalled admission could miss both set/clear transitions of the gates.
    private let configurationEpochAtomic: OpaquePointer
    /// Telemetry state machine: 0 idle, 2 entering/enqueueing, 1 active,
    /// 3 recovering/enqueueing. Intermediate states prevent cross-thread
    /// dispatch inversion without making repeated overload take a lock.
    private let pressureEpisodeAtomic: OpaquePointer
    private let onPressureEvent: @Sendable (WriterMemoryPressureEvent) -> Void
    private let coordinator = Locked(CoordinatorState())
    private let coordinatorQueue = DispatchQueue(
        label: "rama.tproxy.writer-memory.coordinator", qos: .utility)

    init(
        policy: WriterMemoryPolicy = .default,
        onPressureEvent: @escaping @Sendable (WriterMemoryPressureEvent) -> Void = {
            RamaLog.info($0.logMessage)
        }
    ) {
        guard let atomic = rama_writer_budget_atomic_new(0) else {
            preconditionFailure("failed to allocate writer-memory atomic")
        }
        guard let pressureUdpAtomic = rama_writer_budget_atomic_new(0) else {
            rama_writer_budget_atomic_free(atomic)
            preconditionFailure("failed to allocate writer-memory UDP pressure atomic")
        }
        guard let tcpTransitAtomic = rama_writer_budget_atomic_new(0) else {
            rama_writer_budget_atomic_free(pressureUdpAtomic)
            rama_writer_budget_atomic_free(atomic)
            preconditionFailure("failed to allocate writer-memory TCP transit atomic")
        }
        guard let limitsAtomic = rama_writer_budget_atomic_new(
            Self.pack(bytes: policy.maxBytes, items: policy.maxItems, waiterGate: false)
        ) else {
            rama_writer_budget_atomic_free(tcpTransitAtomic)
            rama_writer_budget_atomic_free(pressureUdpAtomic)
            rama_writer_budget_atomic_free(atomic)
            preconditionFailure("failed to allocate writer-memory limits atomic")
        }
        guard let tcpTransitLimitsAtomic = rama_writer_budget_atomic_new(
            Self.pack(
                bytes: policy.tcpTransitMaxBytes,
                items: policy.tcpTransitMaxItems,
                waiterGate: false)
        ) else {
            rama_writer_budget_atomic_free(limitsAtomic)
            rama_writer_budget_atomic_free(tcpTransitAtomic)
            rama_writer_budget_atomic_free(pressureUdpAtomic)
            rama_writer_budget_atomic_free(atomic)
            preconditionFailure("failed to allocate writer-memory TCP transit limits atomic")
        }
        guard let tcpPayloadViewMaxBytesAtomic = rama_writer_budget_atomic_new(
            UInt64(policy.tcpPayloadViewMaxBytes)
        ) else {
            rama_writer_budget_atomic_free(tcpTransitLimitsAtomic)
            rama_writer_budget_atomic_free(limitsAtomic)
            rama_writer_budget_atomic_free(tcpTransitAtomic)
            rama_writer_budget_atomic_free(pressureUdpAtomic)
            rama_writer_budget_atomic_free(atomic)
            preconditionFailure("failed to allocate writer-memory TCP view limit atomic")
        }
        guard let pressureUdpLimitsAtomic = rama_writer_budget_atomic_new(
            Self.pack(
                bytes: policy.udpPressureReserveBytes,
                items: policy.udpPressureReserveItems,
                waiterGate: false)
        ) else {
            rama_writer_budget_atomic_free(tcpPayloadViewMaxBytesAtomic)
            rama_writer_budget_atomic_free(tcpTransitLimitsAtomic)
            rama_writer_budget_atomic_free(limitsAtomic)
            rama_writer_budget_atomic_free(tcpTransitAtomic)
            rama_writer_budget_atomic_free(pressureUdpAtomic)
            rama_writer_budget_atomic_free(atomic)
            preconditionFailure("failed to allocate writer-memory UDP limits atomic")
        }
        guard let configurationEpochAtomic = rama_writer_budget_atomic_new(0) else {
            rama_writer_budget_atomic_free(pressureUdpLimitsAtomic)
            rama_writer_budget_atomic_free(limitsAtomic)
            rama_writer_budget_atomic_free(tcpPayloadViewMaxBytesAtomic)
            rama_writer_budget_atomic_free(tcpTransitLimitsAtomic)
            rama_writer_budget_atomic_free(tcpTransitAtomic)
            rama_writer_budget_atomic_free(pressureUdpAtomic)
            rama_writer_budget_atomic_free(atomic)
            preconditionFailure("failed to allocate writer-memory epoch atomic")
        }
        guard let pressureEpisodeAtomic = rama_writer_budget_atomic_new(0) else {
            rama_writer_budget_atomic_free(configurationEpochAtomic)
            rama_writer_budget_atomic_free(pressureUdpLimitsAtomic)
            rama_writer_budget_atomic_free(limitsAtomic)
            rama_writer_budget_atomic_free(tcpPayloadViewMaxBytesAtomic)
            rama_writer_budget_atomic_free(tcpTransitLimitsAtomic)
            rama_writer_budget_atomic_free(tcpTransitAtomic)
            rama_writer_budget_atomic_free(pressureUdpAtomic)
            rama_writer_budget_atomic_free(atomic)
            preconditionFailure("failed to allocate writer-memory pressure atomic")
        }
        self.atomic = atomic
        self.pressureUdpAtomic = pressureUdpAtomic
        self.tcpTransitAtomic = tcpTransitAtomic
        self.limitsAtomic = limitsAtomic
        self.pressureUdpLimitsAtomic = pressureUdpLimitsAtomic
        self.tcpTransitLimitsAtomic = tcpTransitLimitsAtomic
        self.tcpPayloadViewMaxBytesAtomic = tcpPayloadViewMaxBytesAtomic
        self.configurationEpochAtomic = configurationEpochAtomic
        self.pressureEpisodeAtomic = pressureEpisodeAtomic
        self.onPressureEvent = onPressureEvent
    }

    deinit {
        rama_writer_budget_atomic_free(pressureEpisodeAtomic)
        rama_writer_budget_atomic_free(configurationEpochAtomic)
        rama_writer_budget_atomic_free(pressureUdpLimitsAtomic)
        rama_writer_budget_atomic_free(tcpPayloadViewMaxBytesAtomic)
        rama_writer_budget_atomic_free(tcpTransitLimitsAtomic)
        rama_writer_budget_atomic_free(limitsAtomic)
        rama_writer_budget_atomic_free(tcpTransitAtomic)
        rama_writer_budget_atomic_free(pressureUdpAtomic)
        rama_writer_budget_atomic_free(atomic)
    }

    /// Cold lifecycle update for a replacement engine generation. The limits
    /// and aggregate gate form a CAS fence, so an admission either linearizes
    /// before this update or observes the new caps. Lowering below current
    /// usage is safe: existing ownership drains, while every new reservation
    /// is rejected until both dimensions are within the new envelope.
    func reconfigure(policy: WriterMemoryPolicy) {
        coordinator.withLock { state in
            incrementConfigurationEpoch() // odd: update in progress
            setReconfigurationGate()
            setWaiterGate()

            let reserveBytes = min(
                policy.udpPressureReserveBytes,
                max(0, policy.maxBytes - policy.tcpWaiterMaxBytes))
            let reserveItems = min(
                policy.udpPressureReserveItems,
                max(0, policy.maxItems - 1))
            storeRaw(
                pressureUdpLimitsAtomic,
                value: Self.pack(
                    bytes: reserveBytes,
                    items: reserveItems,
                    waiterGate: false))
            storeRaw(
                tcpTransitLimitsAtomic,
                value: Self.pack(
                    bytes: policy.tcpTransitMaxBytes,
                    items: policy.tcpTransitMaxItems,
                    waiterGate: false))
            storeRaw(
                tcpPayloadViewMaxBytesAtomic,
                value: UInt64(policy.tcpPayloadViewMaxBytes))
            storeRaw(
                limitsAtomic,
                value: Self.pack(
                    bytes: policy.maxBytes,
                    items: policy.maxItems,
                    waiterGate: true))

            if state.waiters.isEmpty { clearWaiterGate() }
            clearReconfigurationGate()
            incrementConfigurationEpoch() // even: new limits published
        }
        kickCoordinator()
        maybeRecordPressureRecovery()
    }

    /// Healthy TCP/UDP admission: one lock-free CAS, with no allocation or
    /// callback. A published TCP waiter closes the gate so UDP remains lossy
    /// and later TCP producers cannot barge in front of FIFO grants.
    func tryReserve(bytes: Int, items: Int = 1) -> Bool {
        guard validRequest(bytes: bytes, items: items) else { return false }
        let epoch = rama_writer_budget_atomic_load_seq_cst(configurationEpochAtomic)
        guard epoch & 1 == 0 else {
            recordPressure(protocol: .tcp, reason: .reconfiguring)
            return false
        }
        let limits = Self.unpack(rama_writer_budget_atomic_load(limitsAtomic))
        guard !limits.tcpWaiterGate else {
            recordPressure(protocol: .tcp, reason: .reconfiguring)
            return false
        }
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            let snapshot = Self.unpack(current)
            guard !snapshot.tcpWaiterGate else {
                recordPressure(protocol: .tcp, reason: .tcpWaiterGate)
                return false
            }
            guard bytes <= limits.retainedBytes - snapshot.retainedBytes else {
                recordPressure(protocol: .tcp, reason: .aggregateBytes)
                return false
            }
            guard items <= limits.retainedItems - snapshot.retainedItems else {
                recordPressure(protocol: .tcp, reason: .aggregateItems)
                return false
            }
            var expected = current
            let desired = Self.pack(
                bytes: snapshot.retainedBytes + bytes,
                items: snapshot.retainedItems + items,
                waiterGate: false)
            if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired) {
                guard rama_writer_budget_atomic_load_seq_cst(configurationEpochAtomic) == epoch else {
                    release(bytes: bytes, items: items)
                    return false
                }
                return true
            }
            current = expected
        }
    }

    /// Pressure-path ownership token for payload retained outside a writer
    /// pump (for example a Rust-paused read replay). No allocation occurs
    /// unless the caller has already decided it must retain the payload.
    func tryReserveGrant(bytes: Int, items: Int = 1) -> WriterMemoryGrant? {
        guard tryReserve(bytes: bytes, items: items) else { return nil }
        return WriterMemoryGrant(budget: self, bytes: bytes, items: items)
    }

    var tcpPayloadViewMaxBytes: Int {
        Int(rama_writer_budget_atomic_load(tcpPayloadViewMaxBytesAtomic))
    }

    /// Bind an aggregate reservation already consumed from a FIFO grant to a
    /// writer root. This contains no fallible work after the charge transfer.
    func makePregrantedWriterPayload(_ data: Data) -> TcpPayloadSlice {
        precondition(!data.isEmpty)
        let charge = PhysicalPayloadCharge(
            budget: self, bytes: data.count, items: 1, isTcpTransit: false)
        let root = TcpRetainedBuffer(data: data, charge: charge)
        return TcpPayloadSlice(root: root, offset: 0, count: root.count)
    }

    /// Charge one complete callback backing allocation against both the global
    /// writer envelope and the TCP-transit subcap. Logical slices never alter
    /// this charge.
    func makeTcpTransitCursor(_ data: Data) -> TcpPayloadCursor? {
        guard !data.isEmpty else { return nil }
        let bytes = data.count
        let items = 1
        let epoch = rama_writer_budget_atomic_load_seq_cst(configurationEpochAtomic)
        guard epoch & 1 == 0, tryReserve(bytes: bytes, items: items) else { return nil }
        let limits = Self.unpack(rama_writer_budget_atomic_load(tcpTransitLimitsAtomic))
        guard tryReserveRaw(
            tcpTransitAtomic,
            bytes: bytes,
            items: items,
            maxBytes: limits.retainedBytes,
            maxItems: limits.retainedItems)
        else {
            release(bytes: bytes, items: items)
            return nil
        }
        guard rama_writer_budget_atomic_load_seq_cst(configurationEpochAtomic) == epoch else {
            releaseTcpTransit(bytes: bytes, items: items)
            return nil
        }
        let charge = PhysicalPayloadCharge(
            budget: self, bytes: bytes, items: items, isTcpTransit: true)
        return TcpPayloadCursor(root: TcpRetainedBuffer(data: data, charge: charge))
    }

    fileprivate func releaseTcpTransit(bytes: Int, items: Int) {
        releaseRaw(tcpTransitAtomic, bytes: bytes, items: items)
        release(bytes: bytes, items: items)
    }

    /// UDP admission remains one CAS while healthy. During TCP pressure it
    /// additionally charges a small protocol-service sub-budget; aggregate
    /// accounting is still authoritative and exact.
    func tryReserveUdp(bytes: Int, items: Int = 1) -> WriterMemoryAdmission? {
        guard validRequest(bytes: bytes, items: items) else { return nil }
        let epoch = rama_writer_budget_atomic_load_seq_cst(configurationEpochAtomic)
        guard epoch & 1 == 0 else {
            recordPressure(protocol: .udp, reason: .reconfiguring)
            return nil
        }
        let limits = Self.unpack(rama_writer_budget_atomic_load(limitsAtomic))
        guard !limits.tcpWaiterGate else {
            recordPressure(protocol: .udp, reason: .reconfiguring)
            return nil
        }
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            let snapshot = Self.unpack(current)
            if !snapshot.tcpWaiterGate {
                guard bytes <= limits.retainedBytes - snapshot.retainedBytes else {
                    recordPressure(protocol: .udp, reason: .aggregateBytes)
                    return nil
                }
                guard items <= limits.retainedItems - snapshot.retainedItems else {
                    recordPressure(protocol: .udp, reason: .aggregateItems)
                    return nil
                }
                var expected = current
                let desired = Self.pack(
                    bytes: snapshot.retainedBytes + bytes,
                    items: snapshot.retainedItems + items,
                    waiterGate: false)
                if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired) {
                    guard rama_writer_budget_atomic_load_seq_cst(configurationEpochAtomic) == epoch else {
                        release(bytes: bytes, items: items)
                        return nil
                    }
                    return .regular
                }
                current = expected
                continue
            }
            // The gate path is already pressure-only. Serialize its two CASes
            // with the same coordinator that grants TCP waiters and publishes
            // reconfiguration. TCP can therefore never consume capacity after
            // seeing a UDP subcharge that has not yet reached the aggregate.
            return coordinator.withLock { _ in
                tryReserveUdpWhileGated(bytes: bytes, items: items, epoch: epoch)
            }
        }
    }

    private func tryReserveUdpWhileGated(
        bytes: Int,
        items: Int,
        epoch: UInt64
    ) -> WriterMemoryAdmission? {
        guard rama_writer_budget_atomic_load_seq_cst(configurationEpochAtomic) == epoch else {
            recordPressure(protocol: .udp, reason: .reconfiguring)
            return nil
        }
        let aggregate = snapshot()
        let limits = Self.unpack(rama_writer_budget_atomic_load(limitsAtomic))
        guard aggregate.tcpWaiterGate, !limits.tcpWaiterGate else {
            // Gate cleared while acquiring the pressure lock. Retry one normal
            // aggregate CAS here; do not recurse through the lock.
            guard !aggregate.tcpWaiterGate,
                bytes <= limits.retainedBytes - aggregate.retainedBytes,
                items <= limits.retainedItems - aggregate.retainedItems
            else { return nil }
            var expected = Self.pack(
                bytes: aggregate.retainedBytes,
                items: aggregate.retainedItems,
                waiterGate: false)
            let desired = Self.pack(
                bytes: aggregate.retainedBytes + bytes,
                items: aggregate.retainedItems + items,
                waiterGate: false)
            return rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired)
                ? .regular : nil
        }

        let udpLimits = Self.unpack(
            rama_writer_budget_atomic_load(pressureUdpLimitsAtomic))
        guard tryReserveRaw(
            pressureUdpAtomic,
            bytes: bytes,
            items: items,
            maxBytes: udpLimits.retainedBytes,
            maxItems: udpLimits.retainedItems)
        else {
            let pressure = Self.unpack(rama_writer_budget_atomic_load(pressureUdpAtomic))
            recordPressure(
                protocol: .udp,
                reason: bytes > udpLimits.retainedBytes - pressure.retainedBytes
                    ? .udpServiceBytes : .udpServiceItems)
            return nil
        }
        #if DEBUG || RAMA_TESTING
            testAfterPressureUdpSubcharge?()
        #endif
        guard tryReserveAggregateIgnoringGate(bytes: bytes, items: items) else {
            releaseRaw(pressureUdpAtomic, bytes: bytes, items: items)
            let current = snapshot()
            recordPressure(
                protocol: .udp,
                reason: bytes > limits.retainedBytes - current.retainedBytes
                    ? .aggregateBytes : .aggregateItems)
            return nil
        }
        return .pressureUdp
    }

    /// Release an accepted item or unused grant. The CAS remains the entire
    /// healthy path. Only a set waiter gate schedules cold coordinator work.
    func release(bytes: Int, items: Int = 1) {
        guard bytes >= 0, items > 0 else { return }
        var current = rama_writer_budget_atomic_load(atomic)
        var wakeCoordinator = false
        while true {
            let snapshot = Self.unpack(current)
            precondition(
                snapshot.retainedBytes >= bytes && snapshot.retainedItems >= items,
                "writer-memory budget underflow")
            var expected = current
            let desired = Self.pack(
                bytes: snapshot.retainedBytes - bytes,
                items: snapshot.retainedItems - items,
                waiterGate: snapshot.tcpWaiterGate)
            if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired) {
                wakeCoordinator = snapshot.tcpWaiterGate
                break
            }
            current = expected
        }
        #if DEBUG || RAMA_TESTING
            testAfterReleaseBeforeCoordinatorKick?()
        #endif
        if wakeCoordinator { kickCoordinator() }
        maybeRecordPressureRecovery()
    }

    func releaseUdp(
        bytes: Int,
        items: Int,
        pressureBytes: Int,
        pressureItems: Int
    ) {
        precondition(pressureBytes >= 0 && pressureBytes <= bytes)
        precondition(pressureItems >= 0 && pressureItems <= items)
        if pressureBytes > 0 || pressureItems > 0 {
            releaseRaw(
                pressureUdpAtomic,
                bytes: pressureBytes,
                items: pressureItems)
        }
        release(bytes: bytes, items: items)
    }

    /// Queue one exact TCP retry. The callback receives capacity which has
    /// already been atomically charged, so a new producer cannot take it first.
    func waitForTcpCapacity(
        bytes: Int,
        items: Int = 1,
        onUnavailable: @escaping @Sendable () -> Void = {},
        onGrant: @escaping @Sendable (WriterMemoryGrant) -> Void
    ) -> WriterMemoryWaiter {
        precondition(validRequest(bytes: bytes, items: items))
        let (id, shouldSchedule) = coordinator.withLock {
            state -> (UInt64, Bool) in
            setWaiterGate()
            let id = state.nextWaiterId
            precondition(id != 0, "writer-memory waiter ID exhausted")
            state.nextWaiterId = id == UInt64.max ? 0 : id + 1
            state.waiters[id] = WaiterRecord(
                bytes: bytes,
                items: items,
                onGrant: onGrant,
                onUnavailable: onUnavailable,
                previous: state.lastWaiterId)
            if let previous = state.lastWaiterId {
                state.waiters[previous]?.next = id
            } else {
                state.firstWaiterId = id
            }
            state.lastWaiterId = id
            let schedule = !state.scheduled
            if schedule { state.scheduled = true }
            return (id, schedule)
        }
        if shouldSchedule { scheduleCoordinatorTurn() }
        return WriterMemoryWaiter(budget: self, id: id)
    }

    func snapshot() -> WriterMemorySnapshot {
        Self.unpack(rama_writer_budget_atomic_load(atomic))
    }

    #if DEBUG || RAMA_TESTING
        var testWaiterCount: Int { coordinator.withLock { $0.waiters.count } }
        var testCoordinatorNodeCount: Int { coordinator.withLock { $0.waiters.count } }
        var testCapacityAtomicIsLockFree: Bool {
            rama_writer_budget_atomic_is_lock_free(atomic)
        }
        var testAfterPressureUdpSubcharge: (() -> Void)?
        var testAfterReleaseBeforeCoordinatorKick: (() -> Void)?
        var testBeforePressureEventEnqueue: (() -> Void)?
        var testTcpTransitSnapshot: WriterMemorySnapshot {
            Self.unpack(rama_writer_budget_atomic_load(tcpTransitAtomic))
        }
    #endif

    fileprivate func cancelWaiter(_ id: UInt64) {
        let shouldSchedule = coordinator.withLock { state -> Bool in
            guard removeWaiterLocked(id, state: &state) != nil else { return false }
            if state.waiters.isEmpty {
                clearWaiterGate()
                maybeRecordPressureRecovery()
                return false
            }
            let schedule = !state.scheduled
            if schedule { state.scheduled = true }
            return schedule
        }
        if shouldSchedule { scheduleCoordinatorTurn() }
    }

    /// ID links keep cancellation O(1), including behind a blocked FIFO head.
    /// Every queue node is one live dictionary entry: retired flows leave no
    /// tombstones to retain memory or scan under the coordinator lock later.
    @discardableResult
    private func removeWaiterLocked(
        _ id: UInt64, state: inout CoordinatorState
    ) -> WaiterRecord? {
        guard let record = state.waiters.removeValue(forKey: id) else { return nil }
        if let previous = record.previous {
            state.waiters[previous]?.next = record.next
        } else {
            state.firstWaiterId = record.next
        }
        if let next = record.next {
            state.waiters[next]?.previous = record.previous
        } else {
            state.lastWaiterId = record.previous
        }
        return record
    }

    private func validRequest(bytes: Int, items: Int) -> Bool {
        bytes >= 0 &&
            bytes <= WriterMemoryPolicy.maxRepresentableBytes &&
            items > 0 &&
            items <= WriterMemoryPolicy.maxRepresentableItems
    }

    private func incrementConfigurationEpoch() {
        var current = rama_writer_budget_atomic_load_seq_cst(configurationEpochAtomic)
        while true {
            precondition(current != UInt64.max, "writer-memory configuration epoch exhausted")
            var expected = current
            if rama_writer_budget_atomic_compare_exchange_seq_cst(
                configurationEpochAtomic, &expected, current + 1)
            { return }
            current = expected
        }
    }

    private func kickCoordinator() {
        let shouldSchedule = coordinator.withLock { state -> Bool in
            guard !state.waiters.isEmpty, !state.scheduled else { return false }
            state.scheduled = true
            return true
        }
        if shouldSchedule { scheduleCoordinatorTurn() }
    }

    private func scheduleCoordinatorTurn() {
        coordinatorQueue.async { [weak self] in self?.runCoordinatorTurn() }
    }

    private func runCoordinatorTurn() {
        let result = coordinator.withLock { state -> DriveResult in
            state.scheduled = false
            return driveLocked(&state)
        }
        for (record, grant) in result.deliveries {
            record.onGrant(grant)
        }
        for record in result.unavailable { record.onUnavailable() }
        if result.scheduleContinuation { kickCoordinator() }
    }

    private func driveLocked(_ state: inout CoordinatorState) -> DriveResult {
        var result = DriveResult()
        while result.deliveries.count + result.unavailable.count < Self.grantBatch {
            guard let id = state.firstWaiterId else { break }
            guard let record = state.waiters[id] else {
                preconditionFailure("writer-memory FIFO head must be live")
            }
            let limits = Self.unpack(rama_writer_budget_atomic_load(limitsAtomic))
            let udpLimits = Self.unpack(
                rama_writer_budget_atomic_load(pressureUdpLimitsAtomic))
            if record.bytes > limits.retainedBytes - udpLimits.retainedBytes
                || record.items > limits.retainedItems - udpLimits.retainedItems
            {
                removeWaiterLocked(id, state: &state)
                result.unavailable.append(record)
                continue
            }
            guard tryReserveWhileGated(bytes: record.bytes, items: record.items) else { break }
            removeWaiterLocked(id, state: &state)
            result.deliveries.append((
                record,
                WriterMemoryGrant(budget: self, bytes: record.bytes, items: record.items)
            ))
        }

        if state.waiters.isEmpty {
            clearWaiterGate()
            maybeRecordPressureRecovery()
        } else if result.deliveries.count + result.unavailable.count == Self.grantBatch {
            result.scheduleContinuation = true
        }
        return result
    }

    private func tryReserveWhileGated(bytes: Int, items: Int) -> Bool {
        let limits = Self.unpack(rama_writer_budget_atomic_load(limitsAtomic))
        let udpLimits = Self.unpack(
            rama_writer_budget_atomic_load(pressureUdpLimitsAtomic))
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            let snapshot = Self.unpack(current)
            precondition(snapshot.tcpWaiterGate)
            // Aggregate usage already includes admitted pressure UDP. Preserve
            // only the UNUSED service reserve; subtracting the whole reserve
            // here would count used UDP twice and starve TCP while capacity is
            // actually available.
            let pressureUdp = Self.unpack(
                rama_writer_budget_atomic_load(pressureUdpAtomic))
            let unusedUdpBytes = max(
                udpLimits.retainedBytes - pressureUdp.retainedBytes, 0)
            let unusedUdpItems = max(
                udpLimits.retainedItems - pressureUdp.retainedItems, 0)
            let tcpMaxBytes = limits.retainedBytes - unusedUdpBytes
            let tcpMaxItems = limits.retainedItems - unusedUdpItems
            guard bytes <= tcpMaxBytes - snapshot.retainedBytes,
                items <= tcpMaxItems - snapshot.retainedItems
            else { return false }
            var expected = current
            let desired = Self.pack(
                bytes: snapshot.retainedBytes + bytes,
                items: snapshot.retainedItems + items,
                waiterGate: true)
            if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired) {
                return true
            }
            current = expected
        }
    }

    private func tryReserveAggregateIgnoringGate(bytes: Int, items: Int) -> Bool {
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            let limits = Self.unpack(rama_writer_budget_atomic_load(limitsAtomic))
            guard !limits.tcpWaiterGate else { return false }
            let snapshot = Self.unpack(current)
            guard bytes <= limits.retainedBytes - snapshot.retainedBytes,
                items <= limits.retainedItems - snapshot.retainedItems
            else { return false }
            var expected = current
            let desired = Self.pack(
                bytes: snapshot.retainedBytes + bytes,
                items: snapshot.retainedItems + items,
                waiterGate: snapshot.tcpWaiterGate)
            if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired) {
                return true
            }
            current = expected
        }
    }

    private func tryReserveRaw(
        _ counter: OpaquePointer,
        bytes: Int,
        items: Int,
        maxBytes: Int,
        maxItems: Int
    ) -> Bool {
        var current = rama_writer_budget_atomic_load(counter)
        while true {
            let snapshot = Self.unpack(current)
            guard bytes <= maxBytes - snapshot.retainedBytes,
                items <= maxItems - snapshot.retainedItems
            else { return false }
            var expected = current
            let desired = Self.pack(
                bytes: snapshot.retainedBytes + bytes,
                items: snapshot.retainedItems + items,
                waiterGate: false)
            if rama_writer_budget_atomic_compare_exchange(counter, &expected, desired) {
                return true
            }
            current = expected
        }
    }

    private func releaseRaw(
        _ counter: OpaquePointer,
        bytes: Int,
        items: Int
    ) {
        var current = rama_writer_budget_atomic_load(counter)
        while true {
            let snapshot = Self.unpack(current)
            precondition(snapshot.retainedBytes >= bytes && snapshot.retainedItems >= items)
            var expected = current
            let desired = Self.pack(
                bytes: snapshot.retainedBytes - bytes,
                items: snapshot.retainedItems - items,
                waiterGate: false)
            if rama_writer_budget_atomic_compare_exchange(counter, &expected, desired) { return }
            current = expected
        }
    }

    private func setWaiterGate() {
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            let snapshot = Self.unpack(current)
            if snapshot.tcpWaiterGate { return }
            var expected = current
            let desired = Self.pack(
                bytes: snapshot.retainedBytes,
                items: snapshot.retainedItems,
                waiterGate: true)
            if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired) { return }
            current = expected
        }
    }

    private func clearWaiterGate() {
        var current = rama_writer_budget_atomic_load(atomic)
        while true {
            let snapshot = Self.unpack(current)
            if !snapshot.tcpWaiterGate { return }
            var expected = current
            let desired = Self.pack(
                bytes: snapshot.retainedBytes,
                items: snapshot.retainedItems,
                waiterGate: false)
            if rama_writer_budget_atomic_compare_exchange(atomic, &expected, desired) { return }
            current = expected
        }
    }

    private func setReconfigurationGate() {
        var current = rama_writer_budget_atomic_load(limitsAtomic)
        while true {
            let limits = Self.unpack(current)
            if limits.tcpWaiterGate { return }
            var expected = current
            let desired = Self.pack(
                bytes: limits.retainedBytes,
                items: limits.retainedItems,
                waiterGate: true)
            if rama_writer_budget_atomic_compare_exchange(
                limitsAtomic, &expected, desired)
            { return }
            current = expected
        }
    }

    private func clearReconfigurationGate() {
        var current = rama_writer_budget_atomic_load(limitsAtomic)
        while true {
            let limits = Self.unpack(current)
            if !limits.tcpWaiterGate { return }
            var expected = current
            let desired = Self.pack(
                bytes: limits.retainedBytes,
                items: limits.retainedItems,
                waiterGate: false)
            if rama_writer_budget_atomic_compare_exchange(
                limitsAtomic, &expected, desired)
            { return }
            current = expected
        }
    }

    private func storeRaw(_ counter: OpaquePointer, value: UInt64) {
        var current = rama_writer_budget_atomic_load(counter)
        while true {
            var expected = current
            if rama_writer_budget_atomic_compare_exchange(counter, &expected, value) { return }
            current = expected
        }
    }

    private func recordPressure(
        protocol pressureProtocol: WriterMemoryPressureProtocol,
        reason: WriterMemoryPressureReason
    ) {
        // Overload is the common state after the first denial. Avoid a global
        // failed RMW per dropped datagram; only the first observer competes on
        // the transition CAS.
        guard rama_writer_budget_atomic_load(pressureEpisodeAtomic) == 0 else { return }
        var expected: UInt64 = 0
        guard rama_writer_budget_atomic_compare_exchange(
            pressureEpisodeAtomic, &expected, 2)
        else { return }
        let usage = snapshot()
        let limits = Self.unpack(rama_writer_budget_atomic_load(limitsAtomic))
        let event = WriterMemoryPressureEvent(
            transition: .entered,
            protocol: pressureProtocol,
            reason: reason,
            retainedBytes: usage.retainedBytes,
            maxBytes: limits.retainedBytes,
            retainedItems: usage.retainedItems,
            maxItems: limits.retainedItems)
        #if DEBUG || RAMA_TESTING
            testBeforePressureEventEnqueue?()
        #endif
        coordinatorQueue.async { [onPressureEvent] in onPressureEvent(event) }
        expected = 2
        precondition(rama_writer_budget_atomic_compare_exchange(
            pressureEpisodeAtomic, &expected, 1))
        // A release/reconfigure can cross the short state-2 interval. It could
        // not publish recovery before entry, so re-evaluate after entry has
        // been ordered onto the serial telemetry queue.
        maybeRecordPressureRecovery()
    }

    private func maybeRecordPressureRecovery() {
        guard rama_writer_budget_atomic_load(pressureEpisodeAtomic) == 1 else { return }
        let usage = snapshot()
        guard !usage.tcpWaiterGate else { return }
        let limits = Self.unpack(rama_writer_budget_atomic_load(limitsAtomic))
        guard usage.retainedBytes <= (limits.retainedBytes * 3) / 4,
            usage.retainedItems <= (limits.retainedItems * 3) / 4
        else { return }
        var expected: UInt64 = 1
        guard rama_writer_budget_atomic_compare_exchange(
            pressureEpisodeAtomic, &expected, 3)
        else { return }
        let event = WriterMemoryPressureEvent(
            transition: .recovered,
            protocol: nil,
            reason: nil,
            retainedBytes: usage.retainedBytes,
            maxBytes: limits.retainedBytes,
            retainedItems: usage.retainedItems,
            maxItems: limits.retainedItems)
        coordinatorQueue.async { [onPressureEvent] in onPressureEvent(event) }
        expected = 3
        precondition(rama_writer_budget_atomic_compare_exchange(
            pressureEpisodeAtomic, &expected, 0))
    }

    private static func pack(bytes: Int, items: Int, waiterGate: Bool) -> UInt64 {
        precondition(bytes >= 0 && UInt64(bytes) <= byteMask)
        precondition(items >= 0 && UInt64(items) <= itemMask)
        return (UInt64(bytes) << lowBits)
            | UInt64(items)
            | (waiterGate ? waiterGateMask : 0)
    }

    private static func unpack(_ packed: UInt64) -> WriterMemorySnapshot {
        WriterMemorySnapshot(
            retainedBytes: Int((packed >> lowBits) & byteMask),
            retainedItems: Int(packed & itemMask),
            tcpWaiterGate: packed & waiterGateMask != 0)
    }
}
