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
    /// Per-flow TCP write-pump back-pressure cap in bytes.
    /// `0` means the Rust side did not set a value; Swift falls back to its built-in default.
    var tcpWritePumpMaxPendingBytes: Int
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

/// Outcome of a Swift → Rust TCP byte-delivery call.
///
/// Mirrors the C-side `RamaTcpDeliverStatus` enum exactly. Swift code must
/// distinguish `.paused` from `.closed`: `.paused` means wait for the
/// matching `onClientReadDemand` / `onEgressReadDemand` callback before
/// resuming; `.closed` is terminal and the read pump must stop immediately.
enum RamaTcpDeliverStatusBridge: UInt8 {
    case accepted = 0
    case paused = 1
    case closed = 2
}

private func tcpDeliverStatus(_ raw: RamaTcpDeliverStatus) -> RamaTcpDeliverStatusBridge {
    // The C enum is `repr(u8)` with the same discriminants; treat any
    // unknown value as `.closed` rather than silently dropping the signal.
    RamaTcpDeliverStatusBridge(rawValue: UInt8(raw.rawValue)) ?? .closed
}

/// Inverse of [`tcpDeliverStatus`] — used when Swift returns a status to
/// Rust through the byte-delivery callbacks (`on_server_bytes`,
/// `on_write_to_egress`).
private func cTcpDeliverStatus(_ status: RamaTcpDeliverStatusBridge) -> RamaTcpDeliverStatus {
    switch status {
    case .accepted: return RAMA_TCP_DELIVER_ACCEPTED
    case .paused: return RAMA_TCP_DELIVER_PAUSED
    case .closed: return RAMA_TCP_DELIVER_CLOSED
    }
}

enum RamaTransparentProxyUdpSessionDecision {
    case intercept(RamaUdpSessionHandle)
    case passthrough
    case blocked
}

final class TcpSessionCallbackBox {
    /// Returns a [`RamaTcpDeliverStatusBridge`] so the Rust bridge can pause
    /// when the writer pump is full. `onServerBytes` MUST honor the
    /// contract: `.paused` requires Swift to call `signalServerDrain` once
    /// the writer drains; `.closed` is terminal.
    let onServerBytes: (Data) -> RamaTcpDeliverStatusBridge
    let onClientReadDemand: () -> Void
    let onServerClosed: () -> Void

    init(
        onServerBytes: @escaping (Data) -> RamaTcpDeliverStatusBridge,
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

/// Holds the Rust→Swift egress callbacks for a TCP session.
///
/// Retained for the lifetime of the session; Rust may call these at any time
/// while the egress `NWConnection` is active.
final class TcpEgressCallbackBox {
    /// See `TcpSessionCallbackBox.onServerBytes` — same status contract for
    /// the egress (NWConnection-write) direction. `.paused` requires Swift
    /// to call `signalEgressDrain` once the writer drains.
    let onWriteToEgress: (Data) -> RamaTcpDeliverStatusBridge
    let onEgressReadDemand: () -> Void
    let onCloseEgress: () -> Void

    init(
        onWriteToEgress: @escaping (Data) -> RamaTcpDeliverStatusBridge,
        onEgressReadDemand: @escaping () -> Void,
        onCloseEgress: @escaping () -> Void
    ) {
        self.onWriteToEgress = onWriteToEgress
        self.onEgressReadDemand = onEgressReadDemand
        self.onCloseEgress = onCloseEgress
    }
}

/// Holds the Rust→Swift egress callback for a UDP session.
final class UdpEgressCallbackBox {
    let onSendToEgress: (Data) -> Void

    init(onSendToEgress: @escaping (Data) -> Void) {
        self.onSendToEgress = onSendToEgress
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
    @convention(c) (UnsafeMutableRawPointer?, RamaBytesView) -> RamaTcpDeliverStatus = {
        context, view in
        guard let context else { return RAMA_TCP_DELIVER_CLOSED }
        let box = Unmanaged<TcpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
        let data = dataFromView(view)
        if data.isEmpty { return RAMA_TCP_DELIVER_ACCEPTED }
        return cTcpDeliverStatus(box.onServerBytes(data))
    }

private let ramaTcpOnClientReadDemandCallback: @convention(c) (UnsafeMutableRawPointer?) -> Void =
    { context in
        guard let context else { return }
        let box = Unmanaged<TcpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
        box.onClientReadDemand()
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
        // RFC 768: zero-length UDP datagrams are valid; forward
        // unchanged. The matching filter on TCP (`onServerBytes`)
        // is correct because an empty TCP read is a non-event.
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

// ── Egress C callbacks ────────────────────────────────────────────────────────

private let ramaTcpOnWriteToEgressCallback:
    @convention(c) (UnsafeMutableRawPointer?, RamaBytesView) -> RamaTcpDeliverStatus = {
        context, view in
        guard let context else { return RAMA_TCP_DELIVER_CLOSED }
        let box = Unmanaged<TcpEgressCallbackBox>.fromOpaque(context).takeUnretainedValue()
        let data = dataFromView(view)
        if data.isEmpty { return RAMA_TCP_DELIVER_ACCEPTED }
        return cTcpDeliverStatus(box.onWriteToEgress(data))
    }

private let ramaTcpOnCloseEgressCallback: @convention(c) (UnsafeMutableRawPointer?) -> Void = {
    context in
    guard let context else { return }
    let box = Unmanaged<TcpEgressCallbackBox>.fromOpaque(context).takeUnretainedValue()
    box.onCloseEgress()
}

private let ramaTcpOnEgressReadDemandCallback: @convention(c) (UnsafeMutableRawPointer?) -> Void =
    { context in
        guard let context else { return }
        let box = Unmanaged<TcpEgressCallbackBox>.fromOpaque(context).takeUnretainedValue()
        box.onEgressReadDemand()
    }

private let ramaUdpOnSendToEgressCallback:
    @convention(c) (UnsafeMutableRawPointer?, RamaBytesView) -> Void = { context, view in
        guard let context else { return }
        let box = Unmanaged<UdpEgressCallbackBox>.fromOpaque(context).takeUnretainedValue()
        let data = dataFromView(view)
        // See `ramaUdpOnServerDatagramCallback`: RFC 768 admits
        // zero-length UDP datagrams. Forward unchanged.
        box.onSendToEgress(data)
    }

final class RamaTransparentProxyEngineHandle {
    // Serialises `enginePtr` access so `stop()` can't free the engine
    // while another thread is mid-FFI call. The session handles already
    // use this exact pattern; mirror it here. Apple's
    // `handleAppMessage(_:completionHandler:)` runs on the provider's
    // dispatch queue, but a swift caller can still race a stop() against
    // an in-flight message — without the lock, `enginePtr` is a non-
    // atomic Swift property and the access is a data race.
    private let lock = NSLock()
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
        // No lock: Swift's deinit only fires when no strong references
        // exist, so there is no concurrent caller to race against.
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

    func config() -> RamaTransparentProxyConfigBridge? {
        lock.lock()
        defer { lock.unlock() }
        guard let p = enginePtr else { return nil }
        guard let outPtr = rama_transparent_proxy_get_config(p) else { return nil }
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
            rules: rules,
            tcpWritePumpMaxPendingBytes: Int(out.tcp_write_pump_max_pending_bytes)
        )
    }

    func stop(reason: Int32) {
        lock.lock()
        let p = enginePtr
        enginePtr = nil
        lock.unlock()
        if let p {
            rama_transparent_proxy_engine_stop(p, reason)
        }
    }

    /// Forward a provider message into Rust and return the reply (or `nil` for
    /// "no reply").
    ///
    /// The Rust shim already maps `None` and `Some(empty)` to the same empty
    /// payload, so an empty `Data` reaching this point is indistinguishable
    /// from "no reply" — we surface both as `nil`. Rust handlers that want a
    /// distinguishable ack must return a non-empty payload.
    func handleAppMessage(_ message: Data) -> Data? {
        // Hold the lock across the FFI call so a concurrent stop() can't
        // free the engine while we're using it. stop() takes the same
        // lock to swap enginePtr to nil before freeing.
        lock.lock()
        defer { lock.unlock() }
        guard let p = enginePtr else { return nil }

        let ownedReply = message.withUnsafeBytes { raw in
            let ptr = raw.bindMemory(to: UInt8.self).baseAddress
            return rama_transparent_proxy_engine_handle_app_message(
                p,
                RamaBytesView(ptr: ptr, len: raw.count)
            )
        }

        let reply = dataFromOwnedBytes(ownedReply)
        return reply.isEmpty ? nil : reply
    }

    func newTcpSession(
        meta: RamaTransparentProxyFlowMetaBridge,
        onServerBytes: @escaping (Data) -> RamaTcpDeliverStatusBridge,
        onClientReadDemand: @escaping () -> Void,
        onServerClosed: @escaping () -> Void
    ) -> RamaTransparentProxyTcpSessionDecision {
        lock.lock()
        defer { lock.unlock() }
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
            on_server_closed: ramaTcpOnServerClosedCallback,
            on_client_read_demand: ramaTcpOnClientReadDemandCallback
        )

        let result = withFlowMeta(meta) { metaPtr in
            rama_transparent_proxy_engine_new_tcp_session(p, metaPtr, callbacks)
        }
        let action =
            RamaTransparentProxyFlowActionBridge(rawValue: result.action.rawValue)
            ?? .passthrough
        if action == .intercept, result.session == nil {
            NSLog(
                "RamaFFI: ffi returned tcp intercept without a session pointer; coercing decision to passthrough"
            )
            callbackBox.release()
            return .passthrough
        }
        guard action == .intercept, let sessionPtr = result.session else {
            callbackBox.release()
            switch action {
            case .intercept, .passthrough:
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
        lock.lock()
        defer { lock.unlock() }
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
        let action =
            RamaTransparentProxyFlowActionBridge(rawValue: result.action.rawValue)
            ?? .passthrough
        if action == .intercept, result.session == nil {
            NSLog(
                "RamaFFI: ffi returned udp intercept without a session pointer; coercing decision to passthrough"
            )
            callbackBox.release()
            return .passthrough
        }
        guard action == .intercept, let sessionPtr = result.session else {
            callbackBox.release()
            switch action {
            case .intercept, .passthrough:
                return .passthrough
            case .blocked:
                return .blocked
            }
        }

        return .intercept(RamaUdpSessionHandle(sessionPtr: sessionPtr, callbackBox: callbackBox))
    }
}

final class RamaTcpSessionHandle {
    private let lock = NSLock()
    private var sessionPtr: OpaquePointer?
    private let callbackBox: Unmanaged<TcpSessionCallbackBox>
    /// Retained while the session is alive so Rust can call the egress write callbacks.
    private var egressCallbackBox: Unmanaged<TcpEgressCallbackBox>?
    private var cancelled = false

    fileprivate init(sessionPtr: OpaquePointer, callbackBox: Unmanaged<TcpSessionCallbackBox>) {
        self.sessionPtr = sessionPtr
        self.callbackBox = callbackBox
    }

    deinit {
        lock.lock()
        let p = sessionPtr
        sessionPtr = nil
        cancelled = true
        let egressBox = egressCallbackBox
        egressCallbackBox = nil
        lock.unlock()

        // Free the Rust session before releasing the boxes:
        // `_session_free` invokes `cancel()` which serialises against
        // any in-flight bridge dispatch via the engine's
        // `callback_active` mutex (see `engine/mod.rs::guarded_*_sink`).
        // The engine guard is the load-bearing piece; this ordering
        // alone is necessary but insufficient.
        if let p {
            rama_transparent_proxy_tcp_session_free(p)
        }
        callbackBox.release()
        egressBox?.release()
    }

    /// Deliver bytes from the intercepted flow to the Rust session.
    ///
    /// Returns the FFI delivery status. Callers MUST honor the status:
    ///   * `.accepted` — keep reading from the kernel.
    ///   * `.paused` — pause `flow.readData` until `onClientReadDemand` fires.
    ///   * `.closed` — terminate the read pump; no demand will follow.
    @discardableResult
    func onClientBytes(_ data: Data) -> RamaTcpDeliverStatusBridge {
        guard !data.isEmpty else { return .accepted }

        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return .closed }

        return data.withUnsafeBytes { raw -> RamaTcpDeliverStatusBridge in
            let base = raw.bindMemory(to: UInt8.self).baseAddress
            guard let base else { return .closed }
            let view = RamaBytesView(ptr: base, len: Int(data.count))
            return tcpDeliverStatus(
                rama_transparent_proxy_tcp_session_on_client_bytes(s, view)
            )
        }
    }

    func onClientEof() {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        rama_transparent_proxy_tcp_session_on_client_eof(s)
    }

    /// Query handler-supplied egress connect options.
    ///
    /// Returns the options struct when the handler provided custom settings, or
    /// `nil` when Swift should use `NWParameters` defaults.
    func getEgressConnectOptions() -> RamaTcpEgressConnectOptions? {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return nil }

        var opts = RamaTcpEgressConnectOptions(
            parameters: RamaNwEgressParameters(
                has_service_class: false, service_class: 0,
                has_multipath_service_type: false, multipath_service_type: 0,
                has_required_interface_type: false, required_interface_type: 0,
                has_attribution: false, attribution: 0,
                prohibited_interface_types_mask: 0,
                preserve_original_meta_data: true
            ),
            has_connect_timeout_ms: false,
            connect_timeout_ms: 0,
            has_linger_close_ms: false,
            linger_close_ms: 0,
            has_egress_eof_grace_ms: false,
            egress_eof_grace_ms: 0
        )
        let hasCustom = rama_transparent_proxy_tcp_session_get_egress_connect_options(s, &opts)
        return hasCustom ? opts : nil
    }

    /// Activate the session once the egress `NWConnection` is ready and the
    /// intercepted flow has been opened successfully.
    ///
    /// `activate` is one-shot: a second call would leak the previous
    /// callback box (Rust still holds its raw pointer because Rust's
    /// `_session_activate` rejects double-activation as a no-op + log)
    /// and the new callbacks would never fire. Logged + ignored on
    /// repeat.
    ///
    /// - Parameters:
    ///   - onWriteToEgress: Called by Rust when the service has bytes to send to the
    ///     egress NWConnection.
    ///   - onCloseEgress: Called by Rust when the egress write direction is done.
    func activate(
        onWriteToEgress: @escaping (Data) -> RamaTcpDeliverStatusBridge,
        onEgressReadDemand: @escaping () -> Void,
        onCloseEgress: @escaping () -> Void
    ) {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        if egressCallbackBox != nil {
            RamaTransparentProxyEngineHandle.log(
                level: UInt32(RAMA_LOG_LEVEL_WARN.rawValue),
                message:
                    "RamaTcpSessionHandle.activate called twice; ignoring second call to avoid leaking the egress callback box"
            )
            return
        }
        let box = Unmanaged.passRetained(
            TcpEgressCallbackBox(
                onWriteToEgress: onWriteToEgress,
                onEgressReadDemand: onEgressReadDemand,
                onCloseEgress: onCloseEgress
            ))
        egressCallbackBox = box

        let callbacks = RamaTransparentProxyTcpEgressCallbacks(
            context: box.toOpaque(),
            on_write_to_egress: ramaTcpOnWriteToEgressCallback,
            on_close_egress: ramaTcpOnCloseEgressCallback,
            on_egress_read_demand: ramaTcpOnEgressReadDemandCallback
        )
        rama_transparent_proxy_tcp_session_activate(s, callbacks)
    }

    /// Deliver bytes from the egress `NWConnection` to the Rust session.
    ///
    /// Same status contract as [`onClientBytes`] — see there.
    @discardableResult
    func onEgressBytes(_ data: Data) -> RamaTcpDeliverStatusBridge {
        guard !data.isEmpty else { return .accepted }

        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return .closed }

        return data.withUnsafeBytes { raw -> RamaTcpDeliverStatusBridge in
            let base = raw.bindMemory(to: UInt8.self).baseAddress
            guard let base else { return .closed }
            let view = RamaBytesView(ptr: base, len: data.count)
            return tcpDeliverStatus(
                rama_transparent_proxy_tcp_session_on_egress_bytes(s, view)
            )
        }
    }

    /// Signal that the egress `NWConnection` has closed or failed.
    func onEgressEof() {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        rama_transparent_proxy_tcp_session_on_egress_eof(s)
    }

    /// Wake the Rust bridge after our `TcpClientWritePump` drains capacity
    /// following a `.paused` return from `onServerBytes`. Idempotent —
    /// redundant calls collapse to a single permit on the Rust side.
    func signalServerDrain() {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        rama_transparent_proxy_tcp_session_signal_server_drain(s)
    }

    /// Same as [`signalServerDrain`] but for the egress (NWConnection-write)
    /// direction.
    func signalEgressDrain() {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        rama_transparent_proxy_tcp_session_signal_egress_drain(s)
    }

    func cancel() {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        cancelled = true
        rama_transparent_proxy_tcp_session_cancel(s)
    }
}

final class RamaUdpSessionHandle {
    private let lock = NSLock()
    private var sessionPtr: OpaquePointer?
    private let callbackBox: Unmanaged<UdpSessionCallbackBox>
    /// Retained while the session is alive so Rust can call the egress send callback.
    private var egressCallbackBox: Unmanaged<UdpEgressCallbackBox>?
    private var cancelled = false

    fileprivate init(sessionPtr: OpaquePointer, callbackBox: Unmanaged<UdpSessionCallbackBox>) {
        self.sessionPtr = sessionPtr
        self.callbackBox = callbackBox
    }

    deinit {
        lock.lock()
        let p = sessionPtr
        sessionPtr = nil
        cancelled = true
        let egressBox = egressCallbackBox
        egressCallbackBox = nil
        lock.unlock()

        if let p {
            rama_transparent_proxy_udp_session_free(p)
        }
        callbackBox.release()
        egressBox?.release()
    }

    func onClientDatagram(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }

        // Zero-length datagrams are valid per RFC 768 and must be
        // forwarded. `withUnsafeBytes` may hand us a nil baseAddress
        // for an empty `Data` — the Rust `BytesView::into_slice`
        // treats (null ptr, len 0) as an empty slice so passing nil
        // through is safe.
        data.withUnsafeBytes { raw in
            let base = raw.bindMemory(to: UInt8.self).baseAddress
            let view = RamaBytesView(ptr: base, len: Int(data.count))
            rama_transparent_proxy_udp_session_on_client_datagram(s, view)
        }
    }

    /// Query handler-supplied egress connect options.
    ///
    /// Returns the options struct when the handler provided custom settings, or
    /// `nil` when Swift should use `NWParameters` defaults.
    func getEgressConnectOptions() -> RamaUdpEgressConnectOptions? {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return nil }

        var opts = RamaUdpEgressConnectOptions(
            parameters: RamaNwEgressParameters(
                has_service_class: false, service_class: 0,
                has_multipath_service_type: false, multipath_service_type: 0,
                has_required_interface_type: false, required_interface_type: 0,
                has_attribution: false, attribution: 0,
                prohibited_interface_types_mask: 0,
                preserve_original_meta_data: true
            ),
            has_connect_timeout_ms: false,
            connect_timeout_ms: 0
        )
        let hasCustom = rama_transparent_proxy_udp_session_get_egress_connect_options(s, &opts)
        return hasCustom ? opts : nil
    }

    /// Activate the session once the egress `NWConnection` is ready.
    ///
    /// `activate` is one-shot: a second call would leak the previous
    /// callback box (Rust holds its raw pointer; Rust's
    /// `_session_activate` rejects double-activation) and the new
    /// callbacks would never fire. Logged + ignored on repeat.
    ///
    /// - Parameter onSendToEgress: Called by Rust when the service has a datagram
    ///   to deliver via the egress NWConnection.
    func activate(onSendToEgress: @escaping (Data) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        if egressCallbackBox != nil {
            RamaTransparentProxyEngineHandle.log(
                level: UInt32(RAMA_LOG_LEVEL_WARN.rawValue),
                message:
                    "RamaUdpSessionHandle.activate called twice; ignoring second call to avoid leaking the egress callback box"
            )
            return
        }
        let box = Unmanaged.passRetained(UdpEgressCallbackBox(onSendToEgress: onSendToEgress))
        egressCallbackBox = box

        let callbacks = RamaTransparentProxyUdpEgressCallbacks(
            context: box.toOpaque(),
            on_send_to_egress: ramaUdpOnSendToEgressCallback
        )
        rama_transparent_proxy_udp_session_activate(s, callbacks)
    }

    /// Deliver one datagram from the egress `NWConnection` to the Rust session.
    func onEgressDatagram(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }

        // Zero-length datagrams are valid per RFC 768 — see
        // `onClientDatagram` for the rationale and the BytesView
        // null-pointer guarantee.
        data.withUnsafeBytes { raw in
            let base = raw.bindMemory(to: UInt8.self).baseAddress
            let view = RamaBytesView(ptr: base, len: data.count)
            rama_transparent_proxy_udp_session_on_egress_datagram(s, view)
        }
    }

    func onClientClose() {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        cancelled = true
        rama_transparent_proxy_udp_session_on_client_close(s)
    }
}
