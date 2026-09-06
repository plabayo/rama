import Foundation
import RamaAppleNEFFI

func clampedFFISizeToInt<T: BinaryInteger>(_ value: T) -> Int {
    Int(clamping: value)
}

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
    /// Remote hostname (DNS name) the app connected to, when known.
    var remoteHostname: String?
    /// Egress interface name (e.g. `en0`, `utun4`), when known.
    var localInterfaceName: String?
    /// Egress interface type as a `NwInterfaceType` discriminant (the Rust wire
    /// value), already mapped from `nw_interface_type_t` by the caller.
    var localInterfaceType: UInt8?
    /// Egress interface index, when known.
    var localInterfaceIndex: UInt32?
    /// Whether the app bound this flow to a specific interface, when known.
    var isBound: Bool?
}

struct RamaTransparentProxyRuleBridge {
    var remoteNetwork: String?
    var remotePrefix: UInt8?
    var remotePort: UInt16?
    var localNetwork: String?
    var localPrefix: UInt8?
    var protocolRaw: UInt32
    var exclude: Bool = false
}

struct RamaTransparentProxyConfigBridge {
    var tunnelRemoteAddress: String
    var rules: [RamaTransparentProxyRuleBridge]
    /// Per-flow TCP write-pump back-pressure cap in bytes.
    /// Authoritative — `startProxy` captures this in the immutable policy
    /// attached with the engine. The Rust engine guarantees a non-zero
    /// default via its builder.
    var tcpWritePumpMaxPendingBytes: Int
    var flowPressureSoftCap: UInt32
    var flowPressureLowWater: UInt32
    var flowPressureIdleFloorMs: UInt32
    var liveFlowHardCap: UInt32
    /// Effective builder-owned UDP idle timeout. Zero disables both the Rust
    /// service timer and Swift's independent kernel-flow watchdog.
    var udpIdleTimeoutMs: UInt64 = 60_000
    /// Effective Rust UDP ingress limits. Swift mirrors these exactly for the
    /// pre-queue Apple callback staging bound of the same engine generation.
    var udpChannelCapacity: Int = 32
    var udpIngressPerFlowMaxBytes: Int = 256 * 1024
    var udpIngressGlobalMaxBytes: Int = 16 * 1024 * 1024
    /// Exact process/core-lifetime payload and item envelope shared by every Swift
    /// TCP and UDP writer. This remains enabled when live-flow hardCap is zero.
    var writerMemoryMaxBytes: Int = WriterMemoryPolicy.default.maxBytes
    var writerMemoryMaxItems: Int = WriterMemoryPolicy.default.maxItems
    var tcpStartInFlightHardCap: UInt32
    var tcpStartInFlightSoftCap: UInt32
    var tcpStartLatencyBreakerP95Ms: UInt32
    var tcpStartLatencyBreakerCloseP95Ms: UInt32
    var tcpPressureConnectTimeoutMs: UInt32
    var tcpBreakerConnectTimeoutMs: UInt32
    /// When the provider declines a flow for its own reasons (start cap /
    /// breaker, or a missing session), hand it to the kernel untouched instead
    /// of blocking it. `true` (Passthrough, fail open) is the default; see
    /// `FlowRefusalAction` on the Rust side.
    var flowRefusalPassthrough: Bool
}

/// Log and decide fail-open (passthrough) vs fail-closed (blocked) for a flow the
/// provider declines for its own reasons. Production callers pass the policy
/// captured by their engine lease; the default preserves direct FFI unit tests.
func failOpenOnFlowRefusal(
    _ reason: String,
    policy: FlowRefusalPolicy = FlowRefusalPolicy(
        passthrough: defaultFlowRefusalPassthrough)
) -> Bool {
    let passthrough = policy.isPassthrough
    NSLog(
        "RamaFFI: \(reason); \(passthrough ? "passing flow through (fail open)" : "blocking flow (fail closed)")"
    )
    return passthrough
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

/// Per-datagram peer at the FFI boundary. Carries the textual host
/// (in production: a numeric IP literal *without* a `%zone` suffix)
/// and the UDP port. `scopeId` is the IPv6 zone identifier
/// (interface index, as returned by `if_nametoindex(3)`); `0` means
/// "no scope" and is always the case for IPv4. The Swift core
/// translates to and from `NWEndpoint`; the FFI layer stays free of
/// the `Network` import.
struct RamaUdpPeer: Hashable {
    let host: String
    let port: UInt16
    let scopeId: UInt32

    init(host: String, port: UInt16, scopeId: UInt32 = 0) {
        self.host = host
        self.port = port
        self.scopeId = scopeId
    }
}

final class UdpSessionCallbackBox {
    /// Rust→Swift datagram. `peer` is the source the reply came
    /// from — the kernel-style endpoint that Rust's unconnected
    /// `tokio::net::UdpSocket::recv_from` returned for this
    /// datagram. Swift uses `peer` as the `sentBy` argument to
    /// `flow.writeDatagrams`, which preserves per-datagram peer
    /// attribution all the way back to the kernel. `nil` is the
    /// safety valve for paths without attribution.
    /// Both views are borrowed from Rust and valid only for this synchronous
    /// callback. The consumer must copy accepted payload/peer data before it
    /// returns. Keeping the views raw lets the bounded writer reject overload
    /// without first allocating and copying a datagram that it will drop.
    let onServerDatagram: (RamaBytesView, RamaUdpPeerView) -> Void
    let onClientReadDemand: (UInt64) -> Void
    let onServerClosed: () -> Void

    init(
        onServerDatagram: @escaping (RamaBytesView, RamaUdpPeerView) -> Void,
        onClientReadDemand: @escaping (UInt64) -> Void,
        onServerClosed: @escaping () -> Void
    ) {
        self.onServerDatagram = onServerDatagram
        self.onClientReadDemand = onClientReadDemand
        self.onServerClosed = onServerClosed
    }
}

/// Holds the Rust→Swift "promote requested" callback for a TCP
/// session.
///
/// Retained for the lifetime of the session; Rust may call
/// `onPromoteRequest` at most once per session (the
/// `PromoteHandle` CAS-guards the fire). The Swift consumer is
/// responsible for ACKing via `confirmPromoted` after the
/// cutover work completes.
///
/// Callbacks may fire from a Rust worker thread — the consumer
/// MUST hop onto its per-flow dispatch queue before touching
/// flow-scoped state.
final class TcpPromoteCallbackBox {
    let onPromoteRequest: () -> Void

    init(onPromoteRequest: @escaping () -> Void) {
        self.onPromoteRequest = onPromoteRequest
    }
}

/// Swift-visible publication / retirement gate for the raw promote callback
/// context handed to Rust.
///
/// Rust's `callback_active` mutex remains the load-bearing lifetime guarantee:
/// registration and session teardown cannot complete while a promote callback
/// is in flight. The linked Rust static library is not TSan-instrumented,
/// however, so Swift's ThreadSanitizer cannot observe that happens-before edge.
/// This gate mirrors ARC visibility on the instrumented side; Rust's
/// `callback_active` remains responsible for raw-pointer publication and swap:
///
/// - callback boxes are initialized and retained while holding the gate;
/// - the C trampoline takes a temporary +1 while holding the gate;
/// - replaced / final owner +1s are transferred back to ARC while holding the
///   gate, then released after unlocking.
///
/// Never hold this gate across a Rust FFI call or the user callback. That would
/// invert with Rust's `callback_active` mutex or serialize arbitrary callback
/// work globally.
private let tcpPromoteCallbackContextGate = NSLock()

private func makeTcpPromoteCallbackBox(
    onPromoteRequest: @escaping () -> Void
) -> Unmanaged<TcpPromoteCallbackBox> {
    tcpPromoteCallbackContextGate.lock()
    let box = Unmanaged.passRetained(
        TcpPromoteCallbackBox(onPromoteRequest: onPromoteRequest))
    tcpPromoteCallbackContextGate.unlock()
    return box
}

private func retainTcpPromoteCallbackBox(
    from context: UnsafeMutableRawPointer
) -> TcpPromoteCallbackBox {
    tcpPromoteCallbackContextGate.lock()
    let box = Unmanaged<TcpPromoteCallbackBox>
        .fromOpaque(context)
        .retain()
        .takeRetainedValue()
    tcpPromoteCallbackContextGate.unlock()
    return box
}

private func retireTcpPromoteCallbackBox(
    _ box: Unmanaged<TcpPromoteCallbackBox>?
) {
    guard let box else { return }

    tcpPromoteCallbackContextGate.lock()
    let ownedBox = box.takeRetainedValue()
    tcpPromoteCallbackContextGate.unlock()

    // Keep destruction (and arbitrary captured-value deinits) outside the
    // global gate while making the post-unlock release point explicit.
    withExtendedLifetime(ownedBox) {}
}

/// Bridge-level mirror of `RamaPromoteConfirmStatus`.
enum RamaPromoteConfirmStatusBridge: UInt8 {
    case ok = 0
    case failed = 1
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

func dataFromView(_ view: RamaBytesView) -> Data {
    guard let ptr = view.ptr, view.len > 0 else {
        return Data()
    }
    return Data(bytes: ptr, count: Int(view.len))
}

/// Decode a Rust→Swift `RamaUdpPeerView` into a `RamaUdpPeer?`.
///
/// Returns `nil` when `present == false`, when `host_utf8` is null
/// or empty, or when the bytes don't form valid UTF-8. The Rust
/// side guarantees UTF-8 for all peers it emits, so a failure here
/// is treated the same as `present == false` (no attribution).
func peerFromView(_ view: RamaUdpPeerView) -> RamaUdpPeer? {
    guard view.present, let ptr = view.host_utf8, view.host_utf8_len > 0 else {
        return nil
    }
    let bytes = UnsafeBufferPointer(start: ptr, count: Int(view.host_utf8_len))
    guard let host = String(bytes: bytes, encoding: .utf8) else { return nil }
    return RamaUdpPeer(host: host, port: view.port, scopeId: view.scope_id)
}

/// Run `body` with a `RamaUdpPeerView` borrowed from `peer`.
///
/// The view's `host_utf8` pointer is valid for the duration of the
/// call; the Rust side parses the UTF-8 bytes synchronously, so the
/// scratch buffer can live on the stack of `body`.
///
/// `peer == nil` runs `body` with an absent view (matches the FFI
/// "no attribution" semantics on the Rust side).
private func withUdpPeerView<R>(
    _ peer: RamaUdpPeer?,
    _ body: (RamaUdpPeerView) -> R
) -> R {
    guard let peer else {
        return body(
            RamaUdpPeerView(
                present: false, host_utf8: nil, host_utf8_len: 0, port: 0, scope_id: 0
            )
        )
    }
    var hostBytes = Array(peer.host.utf8)
    return hostBytes.withUnsafeMutableBufferPointer { buf in
        body(
            RamaUdpPeerView(
                present: true,
                host_utf8: UnsafePointer(buf.baseAddress),
                host_utf8_len: buf.count,
                port: peer.port,
                scope_id: peer.scopeId
            )
        )
    }
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
                        // Two more scoped UTF-8 buffers; like the others above
                        // they are valid only for the synchronous `body` call.
                        withUtf8OrNil(meta.remoteHostname) { remoteHostnamePtr, remoteHostnameLen in
                            withUtf8OrNil(meta.localInterfaceName) { ifaceNamePtr, ifaceNameLen in
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
                                    source_app_pid_is_set: meta.sourceAppPid != nil,
                                    remote_hostname_utf8: remoteHostnamePtr,
                                    remote_hostname_utf8_len: remoteHostnameLen,
                                    local_interface_name_utf8: ifaceNamePtr,
                                    local_interface_name_utf8_len: ifaceNameLen,
                                    local_interface_index: meta.localInterfaceIndex ?? 0,
                                    local_interface_index_is_set: meta.localInterfaceIndex != nil,
                                    local_interface_type: meta.localInterfaceType ?? 0,
                                    local_interface_type_is_set: meta.localInterfaceType != nil,
                                    is_bound: meta.isBound ?? false,
                                    is_bound_is_set: meta.isBound != nil
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
        UnsafeMutableRawPointer?, RamaBytesView, RamaUdpPeerView
    ) -> Void = { context, view, peerView in
        guard let context else { return }
        let box = Unmanaged<UdpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
        // RFC 768: zero-length UDP datagrams are valid; forward
        // unchanged. The matching filter on TCP (`onServerBytes`)
        // is correct because an empty TCP read is a non-event.
        box.onServerDatagram(view, peerView)
    }

private let ramaUdpOnServerClosedCallback: @convention(c) (UnsafeMutableRawPointer?) -> Void = {
    context in
    guard let context else { return }
    let box = Unmanaged<UdpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
    box.onServerClosed()
}

private let ramaUdpOnClientReadDemandCallback:
    @convention(c) (UnsafeMutableRawPointer?, UInt64) -> Void =
    { context, probeId in
        guard let context else { return }
        let box = Unmanaged<UdpSessionCallbackBox>.fromOpaque(context).takeUnretainedValue()
        box.onClientReadDemand(probeId)
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

// ── Promote C callback ────────────────────────────────────────────────────────

private let ramaTcpOnPromoteRequestCallback:
    @convention(c) (UnsafeMutableRawPointer?) -> Void = { context in
        guard let context else { return }
        let box = retainTcpPromoteCallbackBox(from: context)
        box.onPromoteRequest()
    }

// ── Owned-ingress release thunk ───────────────────────────────────────────────

/// Releases the physical TCP root retained on the zero-copy owned-ingress path
/// (`RamaBytesOwnedView.owner`). The root owns both stable `NSData` storage and
/// its aggregate/transit charge. Rust calls this exactly once — from an
/// arbitrary thread — when the last `Bytes` clone drops.
private let ramaReleaseRetainedTcpBuffer: @convention(c) (UnsafeMutableRawPointer?) -> Void = {
    context in
    guard let context else { return }
    Unmanaged<TcpRetainedBuffer>.fromOpaque(context).release()
}

/// Compatibility owner for callers which invoke the public `Data` API without
/// a writer-budget root (primarily direct FFI tests).
private let ramaReleaseRetainedNSData: @convention(c) (UnsafeMutableRawPointer?) -> Void = {
    context in
    guard let context else { return }
    Unmanaged<NSData>.fromOpaque(context).release()
}

/// Reader/writer lifetime guard for the Rust engine pointer.
///
/// FFI calls that only need a live engine enter as readers and may overlap.
/// `stop()` is the writer: it first publishes `nil` so new readers decline,
/// then waits for already-entered readers to leave before freeing/stopping the
/// Rust engine. This keeps the UAF protection the old `NSLock` provided
/// without serialising every admission decision behind one global mutex.
private final class EngineLifetimeGate {
    private let condition = NSCondition()
    private var enginePtr: OpaquePointer?
    private var readers = 0

    init(_ enginePtr: OpaquePointer) {
        self.enginePtr = enginePtr
    }

    func withEngine<R>(default defaultValue: @autoclosure () -> R, _ body: (OpaquePointer) -> R)
        -> R
    {
        condition.lock()
        guard let p = enginePtr else {
            condition.unlock()
            return defaultValue()
        }
        readers += 1
        condition.unlock()

        defer {
            condition.lock()
            readers -= 1
            if readers == 0 { condition.broadcast() }
            condition.unlock()
        }
        return body(p)
    }

    func stop(reason: Int32) {
        condition.lock()
        let p = enginePtr
        enginePtr = nil
        while readers > 0 {
            condition.wait()
        }
        condition.unlock()

        if let p {
            rama_transparent_proxy_engine_stop(p, reason)
        }
    }

    func freeIfStillOwned() {
        condition.lock()
        let p = enginePtr
        enginePtr = nil
        while readers > 0 {
            condition.wait()
        }
        condition.unlock()

        if let p {
            rama_transparent_proxy_engine_free(p)
        }
    }
}

final class RamaTransparentProxyEngineHandle: @unchecked Sendable {
    private let lifetime: EngineLifetimeGate

    init?(engineConfigJson: Data? = nil) {
        let ptr: OpaquePointer?
        if let engineConfigJson, !engineConfigJson.isEmpty {
            ptr = engineConfigJson.withUnsafeBytes { raw in
                let ptr = raw.bindMemory(to: UInt8.self).baseAddress
                return rama_transparent_proxy_engine_new_with_config(
                    RamaBytesView(ptr: ptr, len: raw.count)
                )
            }
        } else {
            ptr = rama_transparent_proxy_engine_new()
        }

        guard let ptr else {
            return nil
        }
        self.lifetime = EngineLifetimeGate(ptr)
    }

    deinit {
        lifetime.freeIfStillOwned()
    }

    static func initialize(storageDir: String?, appGroupDir: String?) -> Bool {
        return withUtf8OrNil(storageDir) { storagePtr, storageLen in
            withUtf8OrNil(appGroupDir) { appGroupPtr, appGroupLen in
                withUtf8OrNil(Bundle.main.bundleIdentifier) { bundlePtr, bundleLen in
                    var cConfig = RamaTransparentProxyInitConfig(
                        storage_dir_utf8: storagePtr,
                        storage_dir_utf8_len: storageLen,
                        app_group_dir_utf8: appGroupPtr,
                        app_group_dir_utf8_len: appGroupLen,
                        bundle_identifier_utf8: bundlePtr,
                        bundle_identifier_utf8_len: bundleLen
                    )
                    return withUnsafePointer(to: &cConfig) { cfgPtr in
                        rama_transparent_proxy_initialize(cfgPtr)
                    }
                }
            }
        }
    }

    func config() -> RamaTransparentProxyConfigBridge? {
        lifetime.withEngine(default: Optional<RamaTransparentProxyConfigBridge>.none) {
            p -> RamaTransparentProxyConfigBridge? in
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
                            remotePort: cRule.remote_port_is_set ? cRule.remote_port : nil,
                            localNetwork: stringFromUtf8(
                                cRule.local_network_utf8,
                                Int(cRule.local_network_utf8_len)
                            ),
                            localPrefix: cRule.local_prefix_is_set ? cRule.local_prefix : nil,
                            protocolRaw: cRule.protocol,
                            exclude: cRule.exclude
                        )
                    )
                }
            }

            return RamaTransparentProxyConfigBridge(
                tunnelRemoteAddress: tunnelRemoteAddress,
                rules: rules,
                tcpWritePumpMaxPendingBytes: Int(out.tcp_write_pump_max_pending_bytes),
                flowPressureSoftCap: out.flow_pressure_soft_cap,
                flowPressureLowWater: out.flow_pressure_low_water,
                flowPressureIdleFloorMs: out.flow_pressure_idle_floor_ms,
                liveFlowHardCap: out.live_flow_hard_cap,
                udpIdleTimeoutMs: rama_transparent_proxy_engine_udp_idle_timeout_ms(p),
                udpChannelCapacity: clampedFFISizeToInt(
                    rama_transparent_proxy_engine_udp_channel_capacity(p)),
                udpIngressPerFlowMaxBytes: clampedFFISizeToInt(
                    rama_transparent_proxy_engine_udp_ingress_per_flow_max_bytes(p)),
                udpIngressGlobalMaxBytes: clampedFFISizeToInt(
                    rama_transparent_proxy_engine_udp_ingress_global_max_bytes(p)),
                writerMemoryMaxBytes: clampedFFISizeToInt(
                    rama_transparent_proxy_engine_writer_memory_max_bytes(p)),
                writerMemoryMaxItems: clampedFFISizeToInt(
                    rama_transparent_proxy_engine_writer_memory_max_items(p)),
                tcpStartInFlightHardCap: out.tcp_start_in_flight_hard_cap,
                tcpStartInFlightSoftCap: out.tcp_start_in_flight_soft_cap,
                tcpStartLatencyBreakerP95Ms: out.tcp_start_latency_breaker_p95_ms,
                tcpStartLatencyBreakerCloseP95Ms: out.tcp_start_latency_breaker_close_p95_ms,
                tcpPressureConnectTimeoutMs: out.tcp_pressure_connect_timeout_ms,
                tcpBreakerConnectTimeoutMs: out.tcp_breaker_connect_timeout_ms,
                // 0 = Block (fail closed), 1 = Passthrough (fail open).
                flowRefusalPassthrough: out.flow_refusal_action == 1
            )
        }
    }

    func stop(reason: Int32) {
        lifetime.stop(reason: reason)
    }

    /// Notify the Rust handler that the system is going to sleep.
    /// Fire-and-forget: Rust drives the handler on its runtime.
    func notifySystemSleep() {
        lifetime.withEngine(default: ()) { p in
            rama_transparent_proxy_engine_notify_system_sleep(p)
        }
    }

    /// Symmetric to [`notifySystemSleep`].
    func notifySystemWake() {
        lifetime.withEngine(default: ()) { p in
            rama_transparent_proxy_engine_notify_system_wake(p)
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
        lifetime.withEngine(default: nil) { p in
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
    }

    func newTcpSession(
        meta: RamaTransparentProxyFlowMetaBridge,
        onServerBytes: @escaping (Data) -> RamaTcpDeliverStatusBridge,
        onClientReadDemand: @escaping () -> Void,
        onServerClosed: @escaping () -> Void,
        flowRefusalPolicy: FlowRefusalPolicy = FlowRefusalPolicy(
            passthrough: defaultFlowRefusalPassthrough)
    ) -> RamaTransparentProxyTcpSessionDecision {
        lifetime.withEngine(default: .passthrough) { p in
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
            guard let action = RamaTransparentProxyFlowActionBridge(rawValue: result.action.rawValue)
            else {
                callbackBox.release()
                return failOpenOnFlowRefusal(
                    "ffi returned unknown tcp flow action \(result.action.rawValue)",
                    policy: flowRefusalPolicy)
                    ? .passthrough : .blocked
            }
            if action == .intercept, result.session == nil {
                callbackBox.release()
                return failOpenOnFlowRefusal(
                    "ffi returned tcp intercept without a session pointer",
                    policy: flowRefusalPolicy)
                    ? .passthrough : .blocked
            }
            guard action == .intercept, let sessionPtr = result.session else {
                callbackBox.release()
                switch action {
                case .passthrough:
                    return .passthrough
                case .intercept:
                    return .blocked
                case .blocked:
                    return .blocked
                }
            }

            return .intercept(RamaTcpSessionHandle(sessionPtr: sessionPtr, callbackBox: callbackBox))
        }
    }

    func newUdpSession(
        meta: RamaTransparentProxyFlowMetaBridge,
        onServerDatagram: @escaping (RamaBytesView, RamaUdpPeerView) -> Void,
        onClientReadDemand: @escaping (UInt64) -> Void,
        onServerClosed: @escaping () -> Void,
        flowRefusalPolicy: FlowRefusalPolicy = FlowRefusalPolicy(
            passthrough: defaultFlowRefusalPassthrough)
    ) -> RamaTransparentProxyUdpSessionDecision {
        lifetime.withEngine(default: .passthrough) { p in
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
            guard let action = RamaTransparentProxyFlowActionBridge(rawValue: result.action.rawValue)
            else {
                callbackBox.release()
                return failOpenOnFlowRefusal(
                    "ffi returned unknown udp flow action \(result.action.rawValue)",
                    policy: flowRefusalPolicy)
                    ? .passthrough : .blocked
            }
            if action == .intercept, result.session == nil {
                callbackBox.release()
                return failOpenOnFlowRefusal(
                    "ffi returned udp intercept without a session pointer",
                    policy: flowRefusalPolicy)
                    ? .passthrough : .blocked
            }
            guard action == .intercept, let sessionPtr = result.session else {
                callbackBox.release()
                switch action {
                case .passthrough:
                    return .passthrough
                case .intercept:
                    return .blocked
                case .blocked:
                    return .blocked
                }
            }

            return .intercept(RamaUdpSessionHandle(sessionPtr: sessionPtr, callbackBox: callbackBox))
        }
    }
}

final class RamaTcpSessionHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var sessionPtr: OpaquePointer?
    private let callbackBox: Unmanaged<TcpSessionCallbackBox>
    /// Retained while the session is alive so Rust can call the egress write callbacks.
    private var egressCallbackBox: Unmanaged<TcpEgressCallbackBox>?
    /// Retained while the session is alive so Rust can call the
    /// `on_promote_request` callback when the in-Rust service
    /// invokes `PromoteHandle::into_passthrough`. `nil` until
    /// `registerPromoteCallback` is called.
    private var promoteCallbackBox: Unmanaged<TcpPromoteCallbackBox>?
    private var cancelled = false
#if DEBUG || RAMA_TESTING
    /// Per-session test seams. Compiled out of release builds so production has
    /// neither storage nor branches, and one test cannot park another session.
    private var beforePromoteRegisterFFIForTest: (() -> Void)?
    private var beforeSessionFreeFFIForTest: (() -> Void)?
#endif

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
        let promoteBox = promoteCallbackBox
        promoteCallbackBox = nil
#if DEBUG || RAMA_TESTING
        let beforeFreeFFI = beforeSessionFreeFFIForTest
        beforeSessionFreeFFIForTest = nil
#endif
        lock.unlock()

        // Free the Rust session before releasing the boxes:
        // `_session_free` invokes `cancel()` which serialises against
        // any in-flight bridge dispatch via the engine's
        // `callback_active` mutex (see `engine/mod.rs::guarded_*_sink`).
        // The engine guard is the load-bearing piece; this ordering
        // alone is necessary but insufficient.
        if let p {
#if DEBUG || RAMA_TESTING
            beforeFreeFFI?()
#endif
            rama_transparent_proxy_tcp_session_free(p)
        }
        callbackBox.release()
        egressBox?.release()
        retireTcpPromoteCallbackBox(promoteBox)
    }

    /// Deliver bytes from the intercepted flow to the Rust session.
    ///
    /// Returns the FFI delivery status. Callers MUST honor the status:
    ///   * `.accepted` — keep reading from the kernel.
    ///   * `.paused` — pause `flow.readData` until `onClientReadDemand` fires.
    ///   * `.closed` — terminate the read pump; no demand will follow.
    @discardableResult
    func onClientBytes(_ data: Data) -> RamaTcpDeliverStatusBridge {
        deliverOwnedData(data) { session, view in
            tcpDeliverStatus(
                rama_transparent_proxy_tcp_session_on_client_bytes_owned(session, view)
            )
        }
    }

    /// Production read-pump entry point. The FFI owner is the retained
    /// physical root, not a temporary slice `NSData`, so accepted Rust `Bytes`
    /// keep the exact aggregate charge alive without changing the C ABI.
    @discardableResult
    func onClientPayload(_ payload: TcpPayloadSlice) -> RamaTcpDeliverStatusBridge {
        deliverOwned(payload) { session, view in
            tcpDeliverStatus(
                rama_transparent_proxy_tcp_session_on_client_bytes_owned(session, view)
            )
        }
    }

    /// Hand `data` to Rust via the zero-copy owned-ingress path: bridge to
    /// `NSData` (whose `bytes` pointer is stable for its lifetime, unlike
    /// `Data.withUnsafeBytes`), retain it, and pass a release thunk so Rust
    /// can hold the buffer across its async bridge without copying.
    ///
    /// Ownership: Rust releases our retain IFF it returns `.accepted`. On
    /// `.paused` / `.closed` it leaves ownership with us, so we balance the
    /// retain here — the caller's `Data` value is untouched and can be
    /// replayed on `.paused`.
    private func deliverOwnedData(
        _ data: Data,
        _ deliver: (OpaquePointer, RamaBytesOwnedView) -> RamaTcpDeliverStatusBridge
    ) -> RamaTcpDeliverStatusBridge {
        guard !data.isEmpty else { return .accepted }

        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return .closed }

        let nsData = data as NSData
        // +1 retain transferred to Rust (released by the thunk on
        // `.accepted`, or balanced below otherwise). `nsData.bytes` stays
        // valid for the retained NSData's lifetime.
        let owner = Unmanaged.passRetained(nsData)
        let view = RamaBytesOwnedView(
            ptr: nsData.bytes.assumingMemoryBound(to: UInt8.self),
            len: nsData.length,
            owner: owner.toOpaque(),
            release: ramaReleaseRetainedNSData
        )
        let status = deliver(s, view)
        if status != .accepted {
            // Rust did not take ownership; drop the retain we passed.
            owner.release()
        }
        return status
    }

    private func deliverOwned(
        _ payload: TcpPayloadSlice,
        _ deliver: (OpaquePointer, RamaBytesOwnedView) -> RamaTcpDeliverStatusBridge
    ) -> RamaTcpDeliverStatusBridge {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return .closed }

        // Each accepted logical view transfers one +1 for the shared root.
        // A cursor and any sibling Rust/write views may retain further +1s;
        // the physical charge is released only after the final one disappears.
        let owner = Unmanaged.passRetained(payload.root)
        let view = RamaBytesOwnedView(
            ptr: payload.bytes,
            len: payload.count,
            owner: owner.toOpaque(),
            release: ramaReleaseRetainedTcpBuffer
        )
        let status = deliver(s, view)
        if status != .accepted {
            owner.release()
        }
        return status
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

        // Zero-initialized scratch buffer; only read when the FFI call
        // returns true, and in that case Rust overwrote every field.
        var opts = RamaTcpEgressConnectOptions()
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
            RamaLog.warn(
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
        deliverOwnedData(data) { session, view in
            tcpDeliverStatus(
                rama_transparent_proxy_tcp_session_on_egress_bytes_owned(session, view)
            )
        }
    }
    @discardableResult
    func onEgressPayload(_ payload: TcpPayloadSlice) -> RamaTcpDeliverStatusBridge {
        deliverOwned(payload) { session, view in
            tcpDeliverStatus(
                rama_transparent_proxy_tcp_session_on_egress_bytes_owned(session, view)
            )
        }
    }

    /// Signal that the egress `NWConnection` closed cleanly.
    func onEgressEof() {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        rama_transparent_proxy_tcp_session_on_egress_eof(s)
    }

    /// Signal that the egress `NWConnection` read failed.
    func onEgressError() {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        rama_transparent_proxy_tcp_session_on_egress_error(s)
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

    /// Register a callback fired by Rust when the in-Rust per-flow
    /// service invokes `PromoteHandle::into_passthrough` on this
    /// session.
    ///
    /// Idempotent: a later call replaces the previous registration
    /// and releases the previous Swift callback box. The callback
    /// may fire from any Tokio worker thread; the consumer is
    /// responsible for hopping to its per-flow dispatch queue
    /// before touching flow-scoped state.
    ///
    /// After the cutover work completes, the consumer MUST call
    /// `confirmPromoted(_:reason:)` to resolve Rust's pending
    /// future. If no callback is ever registered, the in-Rust
    /// `into_passthrough` resolves with `EgressUnavailable` and
    /// the layer falls through to the in-Rust data path.
    ///
    /// CONTRACT: `onPromoteRequest` MUST NOT synchronously call any
    /// method on this same session, including `cancel()`, another
    /// `registerPromoteCallback`, or `confirmPromoted`. Rust's
    /// `fire()` holds the session's `callback_active` lock across
    /// the C trampoline to keep this box alive, while session
    /// methods enter through this handle's lock. Concurrent or
    /// re-entrant entry can therefore invert those two locks and
    /// deadlock. Hop to a dispatch queue inside `onPromoteRequest`
    /// and return immediately, as the production callsite does.
    func registerPromoteCallback(_ onPromoteRequest: @escaping () -> Void) {
        lock.lock()
        guard !cancelled, let s = sessionPtr else {
            lock.unlock()
            return
        }

        let box = makeTcpPromoteCallbackBox(onPromoteRequest: onPromoteRequest)
        let previous = promoteCallbackBox
        promoteCallbackBox = box

        let callbacks = RamaTransparentProxyTcpPromoteCallbacks(
            context: box.toOpaque(),
            on_promote_request: ramaTcpOnPromoteRequestCallback
        )
#if DEBUG || RAMA_TESTING
        beforePromoteRegisterFFIForTest?()
#endif
        rama_transparent_proxy_tcp_session_register_promote_callbacks(s, callbacks)
        lock.unlock()

        // Rust has replaced the raw pointer under `callback_active`, so the old
        // owner can now retire safely. Do this outside both locks: releasing a
        // closure can run arbitrary captured-value deinits, including code that
        // re-enters this session.
        retireTcpPromoteCallbackBox(previous)
    }

#if DEBUG || RAMA_TESTING
    func setBeforePromoteRegisterFFIForTest(_ hook: (() -> Void)?) {
        lock.lock()
        beforePromoteRegisterFFIForTest = hook
        lock.unlock()
    }

    func setBeforeSessionFreeFFIForTest(_ hook: (() -> Void)?) {
        lock.lock()
        beforeSessionFreeFFIForTest = hook
        lock.unlock()
    }
#endif

    /// ACK an in-flight `PromoteHandle::into_passthrough` cutover.
    ///
    /// - `.ok` — Rust drops its ingress sender; the service sees
    ///   EOF after draining in-flight bytes; `into_passthrough`
    ///   resolves with `Ok(())`.
    /// - `.failed` — surfaces as `PromoteError::SwiftCutoverFailed
    ///   { reason }`; the in-Rust data path keeps running
    ///   unchanged.
    ///
    /// Calling without an in-flight promote (e.g. before any
    /// service ran `into_passthrough`, or after a previous
    /// confirm) is a no-op.
    func confirmPromoted(
        _ status: RamaPromoteConfirmStatusBridge,
        reason: String? = nil
    ) {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }

        let cStatus = status.rawValue
        if let reason, !reason.isEmpty {
            // Pass the raw UTF-8 bytes + actual byte count rather
            // than relying on `strlen` over a NUL-terminated copy
            // — reason strings could contain interior NULs, and
            // the Rust side reads exactly `len` bytes.
            let utf8 = Array(reason.utf8)
            utf8.withUnsafeBufferPointer { buf in
                let ptr = buf.baseAddress.map {
                    UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self)
                }
                rama_transparent_proxy_tcp_session_confirm_promoted(
                    s, cStatus, ptr, utf8.count)
            }
        } else {
            rama_transparent_proxy_tcp_session_confirm_promoted(
                s, cStatus, nil, 0)
        }
    }
}

final class RamaUdpSessionHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var sessionPtr: OpaquePointer?
    private let callbackBox: Unmanaged<UdpSessionCallbackBox>
    private var cancelled = false
    #if DEBUG || RAMA_TESTING
        private var testAfterCancelledBeforeRustClose: (@Sendable () -> Void)?
    #endif

    fileprivate init(sessionPtr: OpaquePointer, callbackBox: Unmanaged<UdpSessionCallbackBox>) {
        self.sessionPtr = sessionPtr
        self.callbackBox = callbackBox
    }

    deinit {
        lock.lock()
        let p = sessionPtr
        sessionPtr = nil
        cancelled = true
        lock.unlock()

        if let p {
            rama_transparent_proxy_udp_session_free(p)
        }
        callbackBox.release()
    }

    /// Deliver one client→service datagram with the peer the app
    /// addressed it to. The peer is what Swift's egress side uses to
    /// route to the matching per-peer `NWConnection`. Pass `nil`
    /// when the kernel did not provide an endpoint (rare; production
    /// always has one).
    func onClientDatagram(_ data: Data, peer: RamaUdpPeer?) {
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
            withUdpPeerView(peer) { peerView in
                rama_transparent_proxy_udp_session_on_client_datagram(s, view, peerView)
            }
        }
    }

    /// Activate the session.
    ///
    /// The Rust engine owns the egress UDP socket (one unconnected
    /// BSD socket per flow); Swift no longer supplies an egress
    /// sink. Safe to call multiple times — Rust ignores repeat calls.
    func activate() {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        rama_transparent_proxy_udp_session_activate(s)
    }

    /// Mark the exact leased Apple read complete. Its admission credit remains
    /// charged until the owning datagram is consumed, the flow closes, or the
    /// bounded delivery grace expires. Zero/stale IDs are harmless no-ops.
    func completeClientRead(probeId: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled, let s = sessionPtr else { return }
        rama_transparent_proxy_udp_session_on_client_read_complete(s, probeId)
    }

    #if DEBUG || RAMA_TESTING
        func testSetAfterCancelledBeforeRustClose(_ hook: (@Sendable () -> Void)?) {
            lock.lock()
            testAfterCancelledBeforeRustClose = hook
            lock.unlock()
        }
    #endif

    func onClientClose() {
        lock.lock()
        guard !cancelled, let s = sessionPtr else {
            lock.unlock()
            return
        }
        cancelled = true
        #if DEBUG || RAMA_TESTING
            let afterCancelled = testAfterCancelledBeforeRustClose
        #endif
        lock.unlock()

        #if DEBUG || RAMA_TESTING
            afterCancelled?()
        #endif

        // Rust close waits for any in-flight demand callback to leave its
        // demand gate. Do not hold this handle lock across that wait: a demand
        // callback may concurrently finish by attempting an ACK through the
        // same handle. The cancelled publication prevents any new FFI entry,
        // while this explicit lifetime keeps the callback box/session storage
        // alive until Rust has drained the callback and returned.
        withExtendedLifetime(self) {
            rama_transparent_proxy_udp_session_on_client_close(s)
        }
    }
}
