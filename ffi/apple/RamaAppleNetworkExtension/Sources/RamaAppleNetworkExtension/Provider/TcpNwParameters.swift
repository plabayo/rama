import Darwin
import Network
import RamaAppleNEFFI
import RamaAppleNetwork

/// The requested setting and the control actually applied are separate from
/// the observed establishment report. Private API availability is not a promise
/// of identical behavior on every OS release.
enum TcpProxyPolicy: UInt8, Sendable {
    case allowed = 0
    case noProxyApplied = 1
    case preferDirectOnly = 2
}

struct TcpProxyControl: @unchecked Sendable {
    typealias Setter = @convention(c) (nw_parameters_t, Bool) -> Void
    let setter: Setter?

    // Resolve once per process, only in explicitly opted-in builds.
    #if PrivateNetworkProxyControl
    static let system = TcpProxyControl(
        setter: dlsym(
            UnsafeMutableRawPointer(bitPattern: -2), "nw_parameters_set_no_proxy"
        ).map { unsafeBitCast($0, to: Setter.self) })
    #else
    static let system = TcpProxyControl(setter: nil)
    #endif

    func apply(to parameters: nw_parameters_t, allowProxy: Bool) -> TcpProxyPolicy {
        nw_parameters_set_prefer_no_proxy(parameters, !allowProxy)
        setter?(parameters, !allowProxy)
        return allowProxy ? .allowed : setter == nil ? .preferDirectOnly : .noProxyApplied
    }
}

struct TcpNwParameters: @unchecked Sendable {
    let native: nw_parameters_t
    let proxyPolicy: TcpProxyPolicy
}

// Keepalive defaults also bound silent-peer recovery after sleep/VPN changes.
let defaultTcpKeepaliveIdleSec = 15
let defaultTcpKeepaliveIntervalSec = 5
let defaultTcpKeepaliveCount = 3

/// Build native Network.framework parameters, retaining all existing TCP tuning.
/// Millisecond connect timeouts remain enforced by the flow's dispatch timer.
func makeTcpNwParameters(
    _ opts: RamaTcpEgressConnectOptions?, proxyControl: TcpProxyControl = .system,
    stampMetadata: ((nw_parameters_t) -> Void)? = nil
) -> TcpNwParameters {
    let parameters = rama_nw_tcp_parameters()
    let stack = nw_parameters_copy_default_protocol_stack(parameters)
    let tcp = nw_protocol_stack_copy_transport_protocol(stack)!
    let keepalive = opts?.tcpKeepaliveEnabled ?? true
    nw_tcp_options_set_enable_keepalive(tcp, keepalive)
    if keepalive {
        nw_tcp_options_set_keepalive_idle_time(
            tcp, UInt32(opts?.tcpKeepaliveIdleSec ?? defaultTcpKeepaliveIdleSec))
        nw_tcp_options_set_keepalive_interval(
            tcp, UInt32(opts?.tcpKeepaliveIntervalSec ?? defaultTcpKeepaliveIntervalSec))
        nw_tcp_options_set_keepalive_count(
            tcp, UInt32(opts?.tcpKeepaliveCount ?? defaultTcpKeepaliveCount))
    }
    nw_tcp_options_set_no_delay(tcp, opts?.tcpNoDelay ?? true)
    if let opts {
        if let value = opts.tcpNoPush { nw_tcp_options_set_no_push(tcp, value) }
        if let value = opts.tcpNoOptions { nw_tcp_options_set_no_options(tcp, value) }
        if let value = opts.tcpRetransmitFinDrop {
            nw_tcp_options_set_retransmit_fin_drop(tcp, value)
        }
        if let value = opts.tcpDisableAckStretching {
            nw_tcp_options_set_disable_ack_stretching(tcp, value)
        }
        if let value = opts.tcpEnableFastOpen { nw_tcp_options_set_enable_fast_open(tcp, value) }
        if let value = opts.tcpDisableEcn { nw_tcp_options_set_disable_ecn(tcp, value) }
        if let value = opts.tcpMaximumSegmentSize {
            nw_tcp_options_set_maximum_segment_size(tcp, UInt32(value))
        }
        if let value = opts.tcpConnectionDropTimeSec {
            nw_tcp_options_set_retransmit_connection_drop_time(tcp, UInt32(value))
        }
        if let value = opts.tcpPersistTimeoutSec {
            nw_tcp_options_set_persist_timeout(tcp, UInt32(value))
        }
        applyNativeNwEgressParameters(opts.parameters, to: parameters)
    }
    if opts?.parameters.preserve_original_meta_data ?? true { stampMetadata?(parameters) }
    let policy = proxyControl.apply(
        to: parameters, allowProxy: opts?.parameters.allow_proxy ?? false)
    return TcpNwParameters(native: parameters, proxyPolicy: policy)
}

private func applyNativeNwEgressParameters(
    _ options: RamaNwEgressParameters, to parameters: nw_parameters_t
) {
    if options.has_service_class {
        if options.service_class != 0,
            Int(options.service_class) < NativeParameterTables.classes.count
        {
            nw_parameters_set_service_class(
                parameters, NativeParameterTables.classes[Int(options.service_class)])
        }
    }
    if options.has_multipath_service_type {
        nw_parameters_set_multipath_service(
            parameters,
            Int(options.multipath_service_type) < NativeParameterTables.modes.count
                ? NativeParameterTables.modes[Int(options.multipath_service_type)]
                : nw_multipath_service_disabled)
    }
    if options.has_required_interface_type {
        let index = Int(options.required_interface_type)
        nw_parameters_set_required_interface_type(
            parameters,
            index < NativeParameterTables.types.count
                ? NativeParameterTables.types[index] : nw_interface_type_other)
    }
    for (index, type) in NativeParameterTables.types.enumerated()
    where options.prohibited_interface_types_mask & (1 << index) != 0 {
        nw_parameters_prohibit_interface_type(parameters, type)
    }
    if options.has_attribution {
        nw_parameters_set_attribution(parameters, options.attribution == 1 ? .user : .developer)
    }
}

private enum NativeParameterTables {
    static let classes: [nw_service_class_t] = [
        nw_service_class_best_effort, nw_service_class_background,
        nw_service_class_interactive_video,
        nw_service_class_interactive_voice, nw_service_class_responsive_data,
        nw_service_class_signaling,
    ]
    static let modes: [nw_multipath_service_t] = [
        nw_multipath_service_disabled, nw_multipath_service_handover,
        nw_multipath_service_interactive, nw_multipath_service_aggregate,
    ]
    static let types: [nw_interface_type_t] = [
        nw_interface_type_cellular, nw_interface_type_loopback, nw_interface_type_other,
        nw_interface_type_wifi, nw_interface_type_wired,
    ]
}
