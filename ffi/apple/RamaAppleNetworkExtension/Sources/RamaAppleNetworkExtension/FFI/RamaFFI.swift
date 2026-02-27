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

final class TcpSessionCallbackBox {
    let onServerBytes: (Data) -> Void
    let onServerClosed: () -> Void

    init(onServerBytes: @escaping (Data) -> Void, onServerClosed: @escaping () -> Void) {
        self.onServerBytes = onServerBytes
        self.onServerClosed = onServerClosed
    }
}

final class UdpSessionCallbackBox {
    let onServerDatagram: (Data) -> Void
    let onServerClosed: () -> Void

    init(onServerDatagram: @escaping (Data) -> Void, onServerClosed: @escaping () -> Void) {
        self.onServerDatagram = onServerDatagram
        self.onServerClosed = onServerClosed
    }
}

private func dataFromView(_ view: RamaBytesView) -> Data {
    guard let ptr = view.ptr, view.len > 0 else {
        return Data()
    }
    return Data(bytes: ptr, count: Int(view.len))
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

private func withFlowMeta<T>(
    _ meta: RamaTransparentProxyFlowMetaBridge,
    _ body: (UnsafePointer<RamaTransparentProxyFlowMeta>) -> T
) -> T {
    withUtf8OrNil(meta.remoteHost) { remoteHostPtr, remoteHostLen in
        withUtf8OrNil(meta.localHost) { localHostPtr, localHostLen in
            withUtf8OrNil(meta.sourceAppSigningIdentifier) { signingIdPtr, signingIdLen in
                withUtf8OrNil(meta.sourceAppBundleIdentifier) { bundleIdPtr, bundleIdLen in
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
                        source_app_bundle_identifier_utf8_len: bundleIdLen
                    )
                    return withUnsafePointer(to: &cMeta) { metaPtr in
                        body(metaPtr)
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

final class RamaTransparentProxyEngineHandle {
    private var enginePtr: OpaquePointer?

    init() {
        self.enginePtr = rama_transparent_proxy_engine_new()
    }

    deinit {
        if let p = enginePtr {
            rama_transparent_proxy_engine_free(p)
        }
    }

    static func initialize() -> Bool {
        return rama_transparent_proxy_initialize()
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

    static func shouldIntercept(meta: RamaTransparentProxyFlowMetaBridge) -> Bool {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
            message:
                "swift shouldIntercept call protocol=\(meta.protocolRaw) remote=\(meta.remoteHost ?? "<nil>"):\(meta.remotePort) local=\(meta.localHost ?? "<nil>"):\(meta.localPort)"
        )
        let result = withFlowMeta(meta) { metaPtr in
            rama_transparent_proxy_should_intercept_flow(metaPtr)
        }
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
            message: "swift shouldIntercept result=\(result)"
        )
        return result
    }

    func start() {
        guard let p = enginePtr else { return }
        rama_transparent_proxy_engine_start(p)
    }

    func stop(reason: Int32) {
        guard let p = enginePtr else { return }
        rama_transparent_proxy_engine_stop(p, reason)
    }

    func newTcpSession(
        meta: RamaTransparentProxyFlowMetaBridge,
        onServerBytes: @escaping (Data) -> Void,
        onServerClosed: @escaping () -> Void
    ) -> RamaTcpSessionHandle? {
        guard let p = enginePtr else { return nil }

        let callbackBox = Unmanaged.passRetained(
            TcpSessionCallbackBox(onServerBytes: onServerBytes, onServerClosed: onServerClosed))
        let callbacks = RamaTransparentProxyTcpSessionCallbacks(
            context: callbackBox.toOpaque(),
            on_server_bytes: ramaTcpOnServerBytesCallback,
            on_server_closed: ramaTcpOnServerClosedCallback
        )

        let sessionPtr: OpaquePointer? = withFlowMeta(meta) { metaPtr in
            rama_transparent_proxy_engine_new_tcp_session(p, metaPtr, callbacks)
        }
        guard let sessionPtr else {
            callbackBox.release()
            return nil
        }

        return RamaTcpSessionHandle(sessionPtr: sessionPtr, callbackBox: callbackBox)
    }

    func newUdpSession(
        meta: RamaTransparentProxyFlowMetaBridge,
        onServerDatagram: @escaping (Data) -> Void,
        onServerClosed: @escaping () -> Void
    ) -> RamaUdpSessionHandle? {
        guard let p = enginePtr else { return nil }

        let callbackBox = Unmanaged.passRetained(
            UdpSessionCallbackBox(
                onServerDatagram: onServerDatagram,
                onServerClosed: onServerClosed
            ))
        let callbacks = RamaTransparentProxyUdpSessionCallbacks(
            context: callbackBox.toOpaque(),
            on_server_datagram: ramaUdpOnServerDatagramCallback,
            on_server_closed: ramaUdpOnServerClosedCallback
        )

        let sessionPtr: OpaquePointer? = withFlowMeta(meta) { metaPtr in
            rama_transparent_proxy_engine_new_udp_session(p, metaPtr, callbacks)
        }
        guard let sessionPtr else {
            callbackBox.release()
            return nil
        }

        return RamaUdpSessionHandle(sessionPtr: sessionPtr, callbackBox: callbackBox)
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
