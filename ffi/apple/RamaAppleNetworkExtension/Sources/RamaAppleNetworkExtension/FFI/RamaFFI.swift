import Foundation
import RamaAppleNEFFI

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

private let ramaTcpOnServerBytesCallback: @convention(c) (UnsafeMutableRawPointer?, RamaBytesView)
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

private let ramaUdpOnServerDatagramCallback: @convention(c) (
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

    init(configJSON: String) {
        self.enginePtr = rama_transparent_proxy_engine_new(configJSON)
    }

    deinit {
        if let p = enginePtr {
            rama_transparent_proxy_engine_free(p)
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
        metaJSON: String,
        onServerBytes: @escaping (Data) -> Void,
        onServerClosed: @escaping () -> Void
    ) -> RamaTcpSessionHandle? {
        guard let p = enginePtr else { return nil }

        let callbackBox = Unmanaged.passRetained(
            TcpSessionCallbackBox(onServerBytes: onServerBytes, onServerClosed: onServerClosed))
        let callbacks = RamaTcpSessionCallbacks(
            context: callbackBox.toOpaque(),
            on_server_bytes: ramaTcpOnServerBytesCallback,
            on_server_closed: ramaTcpOnServerClosedCallback
        )

        let sessionPtr = rama_transparent_proxy_engine_new_tcp_session(p, metaJSON, callbacks)
        guard let sessionPtr else {
            callbackBox.release()
            return nil
        }

        return RamaTcpSessionHandle(sessionPtr: sessionPtr, callbackBox: callbackBox)
    }

    func newUdpSession(
        metaJSON: String,
        onServerDatagram: @escaping (Data) -> Void,
        onServerClosed: @escaping () -> Void
    ) -> RamaUdpSessionHandle? {
        guard let p = enginePtr else { return nil }

        let callbackBox = Unmanaged.passRetained(
            UdpSessionCallbackBox(
                onServerDatagram: onServerDatagram,
                onServerClosed: onServerClosed
            ))
        let callbacks = RamaUdpSessionCallbacks(
            context: callbackBox.toOpaque(),
            on_server_datagram: ramaUdpOnServerDatagramCallback,
            on_server_closed: ramaUdpOnServerClosedCallback
        )

        let sessionPtr = rama_transparent_proxy_engine_new_udp_session(p, metaJSON, callbacks)
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
            rama_tcp_session_free(p)
        }
        callbackBox.release()
    }

    func onClientBytes(_ data: Data) {
        guard let s = sessionPtr else { return }
        guard !data.isEmpty else { return }

        data.withUnsafeBytes { raw in
            let base = raw.bindMemory(to: UInt8.self).baseAddress
            guard let base else { return }
            let view = RamaBytesView(ptr: base, len: Int32(data.count))
            rama_tcp_session_on_client_bytes(s, view)
        }
    }

    func onClientEof() {
        guard let s = sessionPtr else { return }
        rama_tcp_session_on_client_eof(s)
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
            rama_udp_session_free(p)
        }
        callbackBox.release()
    }

    func onClientDatagram(_ data: Data) {
        guard let s = sessionPtr else { return }
        guard !data.isEmpty else { return }

        data.withUnsafeBytes { raw in
            let base = raw.bindMemory(to: UInt8.self).baseAddress
            guard let base else { return }
            let view = RamaBytesView(ptr: base, len: Int32(data.count))
            rama_udp_session_on_client_datagram(s, view)
        }
    }

    func onClientClose() {
        guard let s = sessionPtr else { return }
        rama_udp_session_on_client_close(s)
    }
}
