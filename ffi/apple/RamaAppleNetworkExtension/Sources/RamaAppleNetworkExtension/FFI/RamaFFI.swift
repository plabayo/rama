import Foundation
import RamaAppleNEFFI

struct RamaTransparentProxyFlowMetaBridge {
    var protocolRaw: UInt32
    var remoteHost: String?
    var remotePort: UInt16
    var localHost: String?
    var localPort: UInt16
    var sourceAppSigningIdentifier: String?
    var sourceAppBundleIdentifier: String?
    var sourceAppAuditToken: Data?
    var sourceAppPid: Int32?
}

struct RamaTransparentProxyRuleBridge {
    var remoteNetwork: String?
    var remotePrefix: UInt8?
    var localNetwork: String?
    var localPrefix: UInt8?
    var protocolRaw: UInt32
}

struct RamaTransparentProxyConfigBridge {
    var tunnelRemoteAddress: String
    var rules: [RamaTransparentProxyRuleBridge]
}

enum RamaTransparentProxyFlowActionBridge: UInt32 {
    case intercept = 1
    case passthrough = 2
    case blocked = 3
}

enum RamaTransparentProxyTcpSessionDecision {
    case intercept(RamaTcpSessionHandle)
    case passthrough
    case blocked
}

enum RamaTransparentProxyUdpSessionDecision {
    case intercept(RamaUdpSessionHandle)
    case passthrough
    case blocked
}

final class TcpSessionCallbackBox {
    let onServerBytes: (Data) -> Void
    let onClientReadDemand: () -> Void
    let onServerClosed: () -> Void

    init(
        onServerBytes: @escaping (Data) -> Void,
        onClientReadDemand: @escaping () -> Void,
        onServerClosed: @escaping () -> Void
    ) {
        self.onServerBytes = onServerBytes
        self.onClientReadDemand = onClientReadDemand
        self.onServerClosed = onServerClosed
    }
}

final class UdpSessionCallbackBox {
    let onServerDatagram: (Data) -> Void
    let onClientReadDemand: () -> Void
    let onServerClosed: () -> Void

    init(
        onServerDatagram: @escaping (Data) -> Void,
        onClientReadDemand: @escaping () -> Void,
        onServerClosed: @escaping () -> Void
    ) {
        self.onServerDatagram = onServerDatagram
        self.onClientReadDemand = onClientReadDemand
        self.onServerClosed = onServerClosed
    }
}

private func dataFromView(_ view: RamaBytesView) -> Data {
    guard let ptr = view.ptr, view.len > 0 else {
        return Data()
    }
    return Data(bytes: ptr, count: Int(view.len))
}

private func dataFromOwnedBytes(_ bytes: RamaBytesOwned) -> Data {
    defer { rama_owned_bytes_free(bytes) }
    guard let ptr = bytes.ptr, bytes.len > 0 else {
        return Data()
    }
    return Data(bytes: ptr, count: Int(bytes.len))
}

private func stringFromUtf8(_ ptr: UnsafePointer<CChar>?, _ len: Int) -> String? {
    guard let ptr, len > 0 else { return nil }
    let raw = UnsafeRawPointer(ptr).assumingMemoryBound(to: UInt8.self)
    let buffer = UnsafeBufferPointer(start: raw, count: len)
    return String(decoding: buffer, as: UTF8.self)
}

private func withUtf8OrNil<T>(
    _ value: String?,
    _ body: (UnsafePointer<CChar>?, Int) -> T
) -> T {
    guard let value else {
        return body(nil, 0)
    }

    var bytes = Array(value.utf8)
    return bytes.withUnsafeMutableBufferPointer { buffer in
        guard let base = buffer.baseAddress else {
            return body(nil, 0)
        }
        let ptr = UnsafeRawPointer(base).assumingMemoryBound(to: CChar.self)
        return body(ptr, buffer.count)
    }
}

private func withDataOrNil<T>(
    _ value: Data?,
    _ body: (UnsafePointer<UInt8>?, Int) -> T
) -> T {
    guard let value, !value.isEmpty else {
        return body(nil, 0)
    }

    return value.withUnsafeBytes { raw in
        body(raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
    }
}

private func withFlowMeta<T>(
    _ meta: RamaTransparentProxyFlowMetaBridge,
    _ body: (UnsafePointer<RamaTransparentProxyFlowMeta>) -> T
) -> T {
    withUtf8OrNil(meta.remoteHost) { remoteHostPtr, remoteHostLen in
        withUtf8OrNil(meta.localHost) { localHostPtr, localHostLen in
            withUtf8OrNil(meta.sourceAppSigningIdentifier) { signingIdPtr, signingIdLen in
                withUtf8OrNil(meta.sourceAppBundleIdentifier) { bundleIdPtr, bundleIdLen in
                    withDataOrNil(meta.sourceAppAuditToken) { auditTokenPtr, auditTokenLen in
                        var cMeta = RamaTransparentProxyFlowMeta(
                            protocol: meta.protocolRaw,
                            remote_endpoint: RamaTransparentProxyFlowEndpoint(
                                host_utf8: remoteHostPtr,
                                host_utf8_len: remoteHostLen,
                                port: meta.remotePort,
                            ),
                            local_endpoint: RamaTransparentProxyFlowEndpoint(
                                host_utf8: localHostPtr,
                                host_utf8_len: localHostLen,
                                port: meta.localPort,
                            ),
                            source_app_signing_identifier_utf8: signingIdPtr,
                            source_app_signing_identifier_utf8_len: signingIdLen,
                            source_app_bundle_identifier_utf8: bundleIdPtr,
                            source_app_bundle_identifier_utf8_len: bundleIdLen,
                            source_app_audit_token_bytes: auditTokenPtr,
                            source_app_audit_token_bytes_len: auditTokenLen,
                            source_app_pid: meta.sourceAppPid ?? 0,
                            source_app_pid_is_set: meta.sourceAppPid != nil
                        )
                        return withUnsafePointer(to: &cMeta) { metaPtr in
                            body(metaPtr)
                        }
                    }
                }
            }
        }
    }
}

private let ramaTcpOnServerBytesCallback:
    @convention(c) (UnsafeMutableRawPointer?, RamaBytesView)
        -> Void = { context, view in
            guard let context else { return }
            let box = Unmanaged<TcpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
            let data = dataFromView(view)
            if data.isEmpty { return }
            box.onServerBytes(data)
        }

private let ramaTcpOnServerClosedCallback: @convention(c) (UnsafeMutableRawPointer?) -> Void = {
    context in
    guard let context else { return }
    let box = Unmanaged<TcpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
    box.onServerClosed()
}

private let ramaTcpOnClientReadDemandCallback: @convention(c) (UnsafeMutableRawPointer?) -> Void =
    { context in
        guard let context else { return }
        let box = Unmanaged<TcpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
        box.onClientReadDemand()
    }

private let ramaUdpOnServerDatagramCallback:
    @convention(c) (
        UnsafeMutableRawPointer?, RamaBytesView
    ) -> Void = { context, view in
        guard let context else { return }
        let box = Unmanaged<UdpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
        let data = dataFromView(view)
        if data.isEmpty { return }
        box.onServerDatagram(data)
    }

private let ramaUdpOnServerClosedCallback: @convention(c) (UnsafeMutableRawPointer?) -> Void = {
    context in
    guard let context else { return }
    let box = Unmanaged<UdpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
    box.onServerClosed()
}

private let ramaUdpOnClientReadDemandCallback: @convention(c) (UnsafeMutableRawPointer?) -> Void =
    { context in
        guard let context else { return }
        let box = Unmanaged<UdpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
        box.onClientReadDemand()
    }

final class RamaTransparentProxyEngineHandle {
    private var enginePtr: OpaquePointer?

    init?(engineConfigJson: Data? = nil) {
        if let engineConfigJson, !engineConfigJson.isEmpty {
            self.enginePtr = engineConfigJson.withUnsafeBytes { raw in
                let ptr = raw.bindMemory(to: UInt8.self).baseAddress
                return rama_transparent_proxy_engine_new_with_config(
                    RamaBytesView(ptr: ptr, len: raw.count)
                )
            }
        } else {
            self.enginePtr = rama_transparent_proxy_engine_new()
        }

        if enginePtr == nil {
            return nil
        }
    }

    deinit {
        if let p = enginePtr {
            rama_transparent_proxy_engine_free(p)
        }
    }

    static func initialize(storageDir: String?, appGroupDir: String?) -> Bool {
        return withUtf8OrNil(storageDir) { storagePtr, storageLen in
            withUtf8OrNil(appGroupDir) { appGroupPtr, appGroupLen in
                var cConfig = RamaTransparentProxyInitConfig(
                    storage_dir_utf8: storagePtr,
                    storage_dir_utf8_len: storageLen,
                    app_group_dir_utf8: appGroupPtr,
                    app_group_dir_utf8_len: appGroupLen
                )
                return withUnsafePointer(to: &cConfig) { cfgPtr in
                    rama_transparent_proxy_initialize(cfgPtr)
                }
            }
        }
    }

    static func log(level: UInt32, message: String) {
        let data = Data(message.utf8)
        data.withUnsafeBytes { raw in
            let ptr = raw.bindMemory(to: UInt8.self).baseAddress
            let view = RamaBytesView(ptr: ptr, len: raw.count)
            rama_log(level, view)
        }
    }

    static func config() -> RamaTransparentProxyConfigBridge? {
        guard let outPtr = rama_transparent_proxy_get_config() else { return nil }
        defer { rama_transparent_proxy_config_free(outPtr) }
        let out = outPtr.pointee
        guard
            let tunnelRemoteAddress = stringFromUtf8(
                out.tunnel_remote_address_utf8,
                Int(out.tunnel_remote_address_utf8_len)
            )
        else {
            return nil
        }

        var rules: [RamaTransparentProxyRuleBridge] = []
        if let ptr = out.rules, out.rules_len > 0 {
            let buffer: UnsafeBufferPointer<RamaTransparentProxyNetworkRule> =
                UnsafeBufferPointer(start: ptr, count: Int(out.rules_len))
            for cRule in buffer {
                rules.append(
                    RamaTransparentProxyRuleBridge(
                        remoteNetwork: stringFromUtf8(
                            cRule.remote_network_utf8,
                            Int(cRule.remote_network_utf8_len)
                        ),
                        remotePrefix: cRule.remote_prefix_is_set ? cRule.remote_prefix : nil,
                        localNetwork: stringFromUtf8(
                            cRule.local_network_utf8,
                            Int(cRule.local_network_utf8_len)
                        ),
                        localPrefix: cRule.local_prefix_is_set ? cRule.local_prefix : nil,
                        protocolRaw: cRule.protocol
                    )
                )
            }
        }

        return RamaTransparentProxyConfigBridge(
            tunnelRemoteAddress: tunnelRemoteAddress,
            rules: rules
        )
    }

    func stop(reason: Int32) {
        guard let p = enginePtr else { return }
        rama_transparent_proxy_engine_stop(p, reason)
        enginePtr = nil
    }

    func newTcpSession(
        meta: RamaTransparentProxyFlowMetaBridge,
        onServerBytes: @escaping (Data) -> Void,
        onClientReadDemand: @escaping () -> Void,
        onServerClosed: @escaping () -> Void
    ) -> RamaTransparentProxyTcpSessionDecision {
        guard let p = enginePtr else { return .passthrough }

        let callbackBox = Unmanaged.passRetained(
            TcpSessionCallbackBox(
                onServerBytes: onServerBytes,
                onClientReadDemand: onClientReadDemand,
                onServerClosed: onServerClosed
            ))
        let callbacks = RamaTransparentProxyTcpSessionCallbacks(
            context: callbackBox.toOpaque(),
            on_server_bytes: ramaTcpOnServerBytesCallback,
            on_client_read_demand: ramaTcpOnClientReadDemandCallback,
            on_server_closed: ramaTcpOnServerClosedCallback
        )

        let result = withFlowMeta(meta) { metaPtr in
            rama_transparent_proxy_engine_new_tcp_session(p, metaPtr, callbacks)
        }
        let action = RamaTransparentProxyFlowActionBridge(rawValue: result.action.rawValue)
            ?? .passthrough
        guard action == .intercept, let sessionPtr = result.session else {
            callbackBox.release()
            switch action {
            case .intercept:
                return .passthrough
            case .passthrough:
                return .passthrough
            case .blocked:
                return .blocked
            }
        }

        return .intercept(RamaTcpSessionHandle(sessionPtr: sessionPtr, callbackBox: callbackBox))
    }

    func newUdpSession(
        meta: RamaTransparentProxyFlowMetaBridge,
        onServerDatagram: @escaping (Data) -> Void,
        onClientReadDemand: @escaping () -> Void,
        onServerClosed: @escaping () -> Void
    ) -> RamaTransparentProxyUdpSessionDecision {
        guard let p = enginePtr else { return .passthrough }

        let callbackBox = Unmanaged.passRetained(
            UdpSessionCallbackBox(
                onServerDatagram: onServerDatagram,
                onClientReadDemand: onClientReadDemand,
                onServerClosed: onServerClosed
            ))
        let callbacks = RamaTransparentProxyUdpSessionCallbacks(
            context: callbackBox.toOpaque(),
            on_server_datagram: ramaUdpOnServerDatagramCallback,
            on_client_read_demand: ramaUdpOnClientReadDemandCallback,
            on_server_closed: ramaUdpOnServerClosedCallback
        )

        let result = withFlowMeta(meta) { metaPtr in
            rama_transparent_proxy_engine_new_udp_session(p, metaPtr, callbacks)
        }
        let action = RamaTransparentProxyFlowActionBridge(rawValue: result.action.rawValue)
            ?? .passthrough
        guard action == .intercept, let sessionPtr = result.session else {
            callbackBox.release()
            switch action {
            case .intercept:
                return .passthrough
            case .passthrough:
                return .passthrough
            case .blocked:
                return .blocked
            }
        }

        return .intercept(RamaUdpSessionHandle(sessionPtr: sessionPtr, callbackBox: callbackBox))
    }
}

final class RamaTcpSessionHandle {
    private var sessionPtr: OpaquePointer?
    private let callbackBox: Unmanaged<TcpSessionCallbackBox>

    fileprivate init(sessionPtr: OpaquePointer, callbackBox: Unmanaged<TcpSessionCallbackBox>) {
        self.sessionPtr = sessionPtr
        self.callbackBox = callbackBox
    }

    deinit {
        if let p = sessionPtr {
            rama_transparent_proxy_tcp_session_free(p)
        }
        callbackBox.release()
    }

    func onClientBytes(_ data: Data) {
        guard let s = sessionPtr else { return }
        guard !data.isEmpty else { return }

        data.withUnsafeBytes { raw in
            let base = raw.bindMemory(to: UInt8.self).baseAddress
            guard let base else { return }
            let view = RamaBytesView(ptr: base, len: Int(data.count))
            rama_transparent_proxy_tcp_session_on_client_bytes(s, view)
        }
    }

    func onClientEof() {
        guard let s = sessionPtr else { return }
        rama_transparent_proxy_tcp_session_on_client_eof(s)
    }

    func cancel() {
        guard let s = sessionPtr else { return }
        rama_transparent_proxy_tcp_session_cancel(s)
    }
}

final class RamaUdpSessionHandle {
    private var sessionPtr: OpaquePointer?
    private let callbackBox: Unmanaged<UdpSessionCallbackBox>

    fileprivate init(sessionPtr: OpaquePointer, callbackBox: Unmanaged<UdpSessionCallbackBox>) {
        self.sessionPtr = sessionPtr
        self.callbackBox = callbackBox
    }

    deinit {
        if let p = sessionPtr {
            rama_transparent_proxy_udp_session_free(p)
        }
        callbackBox.release()
    }

    func onClientDatagram(_ data: Data) {
        guard let s = sessionPtr else { return }
        guard !data.isEmpty else { return }

        data.withUnsafeBytes { raw in
            let base = raw.bindMemory(to: UInt8.self).baseAddress
            guard let base else { return }
            let view = RamaBytesView(ptr: base, len: Int(data.count))
            rama_transparent_proxy_udp_session_on_client_datagram(s, view)
        }
    }

    func onClientClose() {
        guard let s = sessionPtr else { return }
        rama_transparent_proxy_udp_session_on_client_close(s)
    }
}
