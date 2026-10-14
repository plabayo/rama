import Foundation
import Network
import RamaAppleNetwork

/// Native Network.framework TCP connection. The flow pumps retain their existing
/// interface; parameters and metadata never cross an unsafe Swift-object bridge.
final class NativeTcpConnection: NwConnectionLike, @unchecked Sendable {
    let native: nw_connection_t
    private let lock = NSLock()
    private var currentState: NWConnection.State = .setup
    private var stateHandler: (@Sendable (NWConnection.State) -> Void)?
    private var viabilityHandler: (@Sendable (Bool) -> Void)?

    init?(host: String, port: UInt16, parameters: nw_parameters_t) {
        guard port != 0 else { return nil }
        native = nw_connection_create(nw_endpoint_create_host(host, String(port)), parameters)
    }

    var state: NWConnection.State { lock.withLock { currentState } }

    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)? {
        get { lock.withLock { stateHandler } }
        set {
            lock.withLock { stateHandler = newValue }
            if newValue == nil {
                nw_connection_set_state_changed_handler(native, nil)
            } else {
                nw_connection_set_state_changed_handler(native) { [weak self] state, error in
                    guard let self else { return }
                    let converted: NWConnection.State
                    switch state {
                    case nw_connection_state_invalid: converted = .setup
                    case nw_connection_state_waiting:
                        converted = .waiting(Self.error(error) ?? .posix(.EIO))
                    case nw_connection_state_preparing: converted = .preparing
                    case nw_connection_state_ready: converted = .ready
                    case nw_connection_state_failed:
                        converted = .failed(Self.error(error) ?? .posix(.EIO))
                    case nw_connection_state_cancelled: converted = .cancelled
                    default: converted = .failed(.posix(.EIO))
                    }
                    let handler = self.lock.withLock {
                        self.currentState = converted
                        return self.stateHandler
                    }
                    handler?(converted)
                }
            }
        }
    }

    var viabilityUpdateHandler: (@Sendable (Bool) -> Void)? {
        get { lock.withLock { viabilityHandler } }
        set {
            lock.withLock { viabilityHandler = newValue }
            if newValue == nil {
                nw_connection_set_viability_changed_handler(native, nil)
            } else {
                nw_connection_set_viability_changed_handler(native) { [weak self] viable in
                    guard let self else { return }
                    let handler = self.lock.withLock { self.viabilityHandler }
                    handler?(viable)
                }
            }
        }
    }

    func start(queue: DispatchQueue) {
        nw_connection_set_queue(native, queue)
        nw_connection_start(native)
    }

    func cancel() { nw_connection_cancel(native) }
    func forceCancel() { nw_connection_force_cancel(native) }

    func send(
        content: Data?, contentContext: NWConnection.ContentContext, isComplete: Bool,
        completion: NWConnection.SendCompletion
    ) {
        switch completion {
        case .contentProcessed(let handler):
            rama_nw_tcp_send(native, content, contentContext.isFinal, isComplete) { error in
                handler(Self.error(error))
            }
        case .idempotent:
            rama_nw_tcp_send(native, content, contentContext.isFinal, isComplete, nil)
        @unknown default:
            preconditionFailure("unsupported Network.framework send completion")
        }
    }

    func receive(
        minimumIncompleteLength: Int, maximumLength: Int,
        completion:
            @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    ) {
        rama_nw_tcp_receive(native, UInt32(minimumIncompleteLength), UInt32(maximumLength)) {
            data, complete, error in
            completion(
                data, complete ? .finalMessage : .defaultMessage, complete, Self.error(error))
        }
    }

    func requestTcpEstablishmentReport(
        queue: DispatchQueue,
        completion: @escaping @Sendable (TcpEstablishmentReport?) -> Void
    ) {
        // Read just the needed scalars, without constructing Swift's resolution
        // and handshake arrays. Called only when the Rust event is enabled.
        nw_connection_access_establishment_report(native, queue) { report in
            completion(
                report.map { report in
                    let endpoint = nw_establishment_report_copy_proxy_endpoint(report)
                    let description = endpoint.flatMap { endpoint -> String? in
                        let type = nw_endpoint_get_type(endpoint)
                        guard type == nw_endpoint_type_host || type == nw_endpoint_type_address
                        else {
                            return String(describing: endpoint)
                        }
                        let host = nw_endpoint_get_hostname(endpoint)
                        let hostname = String(cString: host)
                        let port = nw_endpoint_get_port(endpoint)
                        return hostname.contains(":")
                            ? "[\(hostname)]:\(port)" : "\(hostname):\(port)"
                    }
                    return TcpEstablishmentReport(
                        usedProxy: nw_establishment_report_get_used_proxy(report),
                        proxyConfigured: nw_establishment_report_get_proxy_configured(report),
                        proxyEndpoint: description,
                        duration: Double(nw_establishment_report_get_duration_milliseconds(report))
                            / 1_000)
                })
        }
    }

    private static func error(_ error: nw_error_t?) -> NWError? {
        guard let error else { return nil }
        let code = nw_error_get_error_code(error)
        switch nw_error_get_error_domain(error) {
        case nw_error_domain_posix: return .posix(POSIXErrorCode(rawValue: code) ?? .EIO)
        case nw_error_domain_dns: return .dns(code)
        case nw_error_domain_tls: return .tls(code)
        default: return .posix(.EIO)
        }
    }

    deinit {
        nw_connection_set_state_changed_handler(native, nil)
        nw_connection_set_viability_changed_handler(native, nil)
        nw_connection_cancel(native)
    }
}
