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

struct RamaTransparentProxyStartupRuleBridge {
    var remoteNetwork: String?
    var remotePrefix: UInt8
    var localNetwork: String?
    var localPrefix: UInt8
    var protocolRaw: UInt32
    var directionRaw: UInt32
}

struct RamaStartupConfigBridge {
    var tunnelRemoteAddress: String
    var rules: [RamaTransparentProxyStartupRuleBridge]
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

private func stringFromPtr(_ ptr: UnsafePointer<CChar>?) -> String? {
    guard let ptr else { return nil }
    return String(cString: ptr)
}

private func withCStringOrNil<T>(_ value: String?, _ body: (UnsafePointer<CChar>?) -> T) -> T {
    guard let value else {
        return body(nil)
    }
    return value.withCString { ptr in body(ptr) }
}

private func withFlowMeta<T>(
    _ meta: RamaTransparentProxyFlowMetaBridge,
    _ body: (UnsafePointer<RamaTransparentProxyFlowMeta>) -> T
) -> T {
    withCStringOrNil(meta.remoteHost) { remoteHostPtr in
        withCStringOrNil(meta.localHost) { localHostPtr in
            withCStringOrNil(meta.sourceAppSigningIdentifier) { signingIdPtr in
                withCStringOrNil(meta.sourceAppBundleIdentifier) { bundleIdPtr in
                    var cMeta = RamaTransparentProxyFlowMeta(
                        protocol: meta.protocolRaw,
                        remote_endpoint: RamaTransparentProxyFlowEndpoint(
                            host_utf8: remoteHostPtr,
                            port: meta.remotePort,
                        ),
                        local_endpoint: RamaTransparentProxyFlowEndpoint(
                            host_utf8: localHostPtr,
                            port: meta.localPort,
                        ),
                        source_app_signing_identifier_utf8: signingIdPtr,
                        source_app_bundle_identifier_utf8: bundleIdPtr
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
        rama_transparent_proxy_initialize()
    }

    static func log(level: UInt32, message: String) {
        let data = Data(message.utf8)
        data.withUnsafeBytes { raw in
            let ptr = raw.bindMemory(to: UInt8.self).baseAddress
            let view = RamaBytesView(ptr: ptr, len: raw.count)
            rama_log(level, view)
        }
    }

    static func startupConfig() -> RamaStartupConfigBridge? {
        var out = RamaTransparentProxyStartupConfig(
            tunnel_remote_address_utf8: nil,
            rules: nil,
            rules_len: 0
        )
        let ok = withUnsafeMutablePointer(to: &out) { outPtr in
            rama_transparent_proxy_get_startup_config(outPtr)
        }
        guard ok else { return nil }
        guard let tunnelRemoteAddress = stringFromPtr(out.tunnel_remote_address_utf8) else {
            return nil
        }

        var rules: [RamaTransparentProxyStartupRuleBridge] = []
        if let ptr = out.rules, out.rules_len > 0 {
            let buffer = UnsafeBufferPointer(start: ptr, count: Int(out.rules_len))
            for cRule in buffer {
                rules.append(
                    RamaTransparentProxyStartupRuleBridge(
                        remoteNetwork: stringFromPtr(cRule.remote_network_utf8),
                        remotePrefix: cRule.remote_prefix,
                        localNetwork: stringFromPtr(cRule.local_network_utf8),
                        localPrefix: cRule.local_prefix,
                        protocolRaw: cRule.protocol,
                        directionRaw: cRule.direction
                    )
                )
            }
        }

        return RamaStartupConfigBridge(
            tunnelRemoteAddress: tunnelRemoteAddress,
            rules: rules
        )
    }

    static func shouldIntercept(meta: RamaTransparentProxyFlowMetaBridge) -> Bool {
        withFlowMeta(meta) { metaPtr in
            rama_transparent_proxy_should_intercept_flow(metaPtr)
        }
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
