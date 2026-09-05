import Foundation

/// Provider-side action for a flow that Rama cannot safely intercept for a
/// local capacity or malformed-FFI reason.
enum FlowRefusalPolicy: Sendable, Equatable {
    case passthrough
    case block

    init(passthrough: Bool) {
        self = passthrough ? .passthrough : .block
    }

    var isPassthrough: Bool { self == .passthrough }

    var logDescription: String {
        switch self {
        case .passthrough: return "passing through (fail open)"
        case .block: return "blocking (fail closed)"
        }
    }
}

/// Immutable limits captured by each TCP write pump. A pump must use the same
/// byte cap for admission and later drain-headroom decisions even if the
/// provider replaces its engine while that pump is retiring.
struct TcpWritePumpPolicy: Sendable, Equatable {
    let maxPendingBytes: Int

    var hwmLogThresholdBytes: Int { maxPendingBytes / 2 }
}

struct FlowPressurePolicy: Sendable, Equatable {
    let softCap: UInt32
    let lowWater: UInt32
    let idleFloorMs: UInt32
    let liveHardCap: UInt32

    static var testDefaultsSnapshot: Self {
        let softCap = normalizedFlowPressureSoftCap(
            softCap: defaultFlowPressureSoftCap,
            hardCap: defaultLiveFlowHardCap)
        return Self(
            softCap: softCap,
            lowWater: normalizedFlowPressureLowWater(
                softCap: softCap,
                lowWater: defaultFlowPressureLowWater),
            idleFloorMs: defaultFlowPressureIdleFloorMs,
            liveHardCap: defaultLiveFlowHardCap)
    }
}

struct TcpStartAdmissionPolicy: Sendable, Equatable {
    let hardCap: UInt32
    let softCap: UInt32
    let breakerOpenP95Ms: UInt32
    let breakerCloseP95Ms: UInt32
    let pressureConnectTimeoutMs: UInt32
    let breakerConnectTimeoutMs: UInt32

    static var testDefaultsSnapshot: Self {
        Self(
            hardCap: defaultTcpStartInFlightHardCap,
            softCap: normalizedTcpStartSoftCap(
                softCap: defaultTcpStartInFlightSoftCap,
                hardCap: defaultTcpStartInFlightHardCap),
            breakerOpenP95Ms: defaultTcpStartLatencyBreakerP95Ms,
            breakerCloseP95Ms: defaultTcpStartLatencyBreakerCloseP95Ms,
            pressureConnectTimeoutMs: defaultTcpPressureConnectTimeoutMs,
            breakerConnectTimeoutMs: defaultTcpBreakerConnectTimeoutMs)
    }
}

/// One coherent provider policy published with one Rust engine generation.
///
/// Value semantics are intentional: engine leases, sessions, and pumps retain
/// their generation's snapshot while a replacement engine is configured and
/// attached. No callback consults a mutable process-global runtime policy.
struct TransparentProxyRuntimePolicy: Sendable, Equatable {
    let tcpWritePump: TcpWritePumpPolicy
    let flowPressure: FlowPressurePolicy
    let udpIdleTimeoutMs: UInt64
    let udpIngressStaging: UdpIngressStagingPolicy
    let writerMemory: WriterMemoryPolicy
    let tcpStartAdmission: TcpStartAdmissionPolicy
    let flowRefusal: FlowRefusalPolicy

    init(
        tcpWritePumpMaxPendingBytes: Int,
        flowPressureSoftCap: UInt32,
        flowPressureLowWater: UInt32,
        flowPressureIdleFloorMs: UInt32,
        liveFlowHardCap: UInt32,
        udpIdleTimeoutMs: UInt64,
        tcpStartInFlightHardCap: UInt32,
        tcpStartInFlightSoftCap: UInt32,
        tcpStartLatencyBreakerP95Ms: UInt32,
        tcpStartLatencyBreakerCloseP95Ms: UInt32,
        tcpPressureConnectTimeoutMs: UInt32,
        tcpBreakerConnectTimeoutMs: UInt32,
        flowRefusalPassthrough: Bool,
        udpChannelCapacity: Int = 32,
        udpIngressPerFlowMaxBytes: Int = 256 * 1024,
        udpIngressGlobalMaxBytes: Int = 16 * 1024 * 1024,
        writerMemoryMaxBytes: Int = WriterMemoryPolicy.default.maxBytes,
        writerMemoryMaxItems: Int = WriterMemoryPolicy.default.maxItems
    ) {
        let pressureSoftCap = normalizedFlowPressureSoftCap(
            softCap: flowPressureSoftCap,
            hardCap: liveFlowHardCap)
        let pressureLowWater = normalizedFlowPressureLowWater(
            softCap: pressureSoftCap,
            lowWater: flowPressureLowWater)
        let tcpStartSoftCap = normalizedTcpStartSoftCap(
            softCap: tcpStartInFlightSoftCap,
            hardCap: tcpStartInFlightHardCap)

        // Mirror Rust's order-independent effective getter. This also keeps an
        // older engine from letting one TCP retry consume every aggregate byte
        // and black-hole UDP/QUIC/H3 behind the TCP waiter gate.
        let effectiveTcpWritePumpMaxPendingBytes = min(
            tcpWritePumpMaxPendingBytes,
            max(
                writerMemoryMaxBytes - WriterMemoryPolicy.minimumUdpPressureReserveBytes,
                1))
        self.tcpWritePump = TcpWritePumpPolicy(
            maxPendingBytes: effectiveTcpWritePumpMaxPendingBytes)
        self.flowPressure = FlowPressurePolicy(
            softCap: pressureSoftCap,
            lowWater: pressureLowWater,
            idleFloorMs: flowPressureIdleFloorMs,
            liveHardCap: liveFlowHardCap)
        self.udpIdleTimeoutMs = udpIdleTimeoutMs
        // A zero hard cap intentionally disables live-flow admission limiting;
        // it must not collapse the independent process-wide staging budget
        // to one item. Keep that configuration bounded with the documented
        // conservative population used by the staging layer itself.
        let stagingFlowPopulation = liveFlowHardCap == 0
            ? udpIngressStagingUnboundedLiveFlowPopulation
            : Int(liveFlowHardCap)
        let (generationItems, generationItemsOverflow) = udpChannelCapacity
            .multipliedReportingOverflow(by: stagingFlowPopulation)
        self.udpIngressStaging = UdpIngressStagingPolicy(
            maxItemsPerFlow: udpChannelCapacity,
            maxItemsPerGeneration: generationItemsOverflow ? Int.max : generationItems,
            maxBytesPerFlow: udpIngressPerFlowMaxBytes,
            maxBytesPerGeneration: udpIngressGlobalMaxBytes)
        self.writerMemory = WriterMemoryPolicy(
            maxBytes: writerMemoryMaxBytes,
            maxItems: writerMemoryMaxItems,
            tcpWaiterMaxBytes: effectiveTcpWritePumpMaxPendingBytes)
        self.tcpStartAdmission = TcpStartAdmissionPolicy(
            hardCap: tcpStartInFlightHardCap,
            softCap: tcpStartSoftCap,
            breakerOpenP95Ms: tcpStartLatencyBreakerP95Ms,
            breakerCloseP95Ms: tcpStartLatencyBreakerCloseP95Ms,
            pressureConnectTimeoutMs: tcpPressureConnectTimeoutMs,
            breakerConnectTimeoutMs: tcpBreakerConnectTimeoutMs)
        self.flowRefusal = FlowRefusalPolicy(passthrough: flowRefusalPassthrough)
    }

    init(startup: RamaTransparentProxyConfigBridge) {
        self.init(
            tcpWritePumpMaxPendingBytes: startup.tcpWritePumpMaxPendingBytes,
            flowPressureSoftCap: startup.flowPressureSoftCap,
            flowPressureLowWater: startup.flowPressureLowWater,
            flowPressureIdleFloorMs: startup.flowPressureIdleFloorMs,
            liveFlowHardCap: startup.liveFlowHardCap,
            udpIdleTimeoutMs: startup.udpIdleTimeoutMs,
            tcpStartInFlightHardCap: startup.tcpStartInFlightHardCap,
            tcpStartInFlightSoftCap: startup.tcpStartInFlightSoftCap,
            tcpStartLatencyBreakerP95Ms: startup.tcpStartLatencyBreakerP95Ms,
            tcpStartLatencyBreakerCloseP95Ms: startup.tcpStartLatencyBreakerCloseP95Ms,
            tcpPressureConnectTimeoutMs: startup.tcpPressureConnectTimeoutMs,
            tcpBreakerConnectTimeoutMs: startup.tcpBreakerConnectTimeoutMs,
            flowRefusalPassthrough: startup.flowRefusalPassthrough,
            udpChannelCapacity: startup.udpChannelCapacity,
            udpIngressPerFlowMaxBytes: startup.udpIngressPerFlowMaxBytes,
            udpIngressGlobalMaxBytes: startup.udpIngressGlobalMaxBytes,
            writerMemoryMaxBytes: startup.writerMemoryMaxBytes,
            writerMemoryMaxItems: startup.writerMemoryMaxItems)
    }

    /// Compatibility snapshot for engine-less and narrowly-scoped unit tests.
    /// Production startup always supplies an explicit policy derived from Rust.
    static var testDefaultsSnapshot: Self {
        Self(
            tcpWritePumpMaxPendingBytes: writePumpMaxPendingBytes,
            flowPressureSoftCap: defaultFlowPressureSoftCap,
            flowPressureLowWater: defaultFlowPressureLowWater,
            flowPressureIdleFloorMs: defaultFlowPressureIdleFloorMs,
            liveFlowHardCap: defaultLiveFlowHardCap,
            udpIdleTimeoutMs: defaultUdpIdleTimeoutMs,
            tcpStartInFlightHardCap: defaultTcpStartInFlightHardCap,
            tcpStartInFlightSoftCap: defaultTcpStartInFlightSoftCap,
            tcpStartLatencyBreakerP95Ms: defaultTcpStartLatencyBreakerP95Ms,
            tcpStartLatencyBreakerCloseP95Ms: defaultTcpStartLatencyBreakerCloseP95Ms,
            tcpPressureConnectTimeoutMs: defaultTcpPressureConnectTimeoutMs,
            tcpBreakerConnectTimeoutMs: defaultTcpBreakerConnectTimeoutMs,
            flowRefusalPassthrough: defaultFlowRefusalPassthrough)
    }
}

/// Conservative item-budget population when the live-flow admission hard cap
/// is explicitly disabled. This remains an independent memory-safety bound:
/// at the default 32-item Rust channel capacity, one generation may stage at
/// most 262,144 datagrams, including zero-length datagrams.
let udpIngressStagingUnboundedLiveFlowPopulation = 8_192
