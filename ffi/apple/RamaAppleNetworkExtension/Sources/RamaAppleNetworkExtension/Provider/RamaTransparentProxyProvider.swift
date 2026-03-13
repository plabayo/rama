import Darwin
import Foundation
import NetworkExtension
import RamaAppleNEFFI

private enum FlowLogLevel {
    case trace
    case debug
    case error
}

private struct FlowLogMessage {
    let level: FlowLogLevel
    let text: String
}

/// Mirror of Apple's `NEAppProxyFlowError` values used to classify callback errors.
///
/// Source of truth for the numeric enum values:
/// - Xcode SDK header:
///   `NetworkExtension.framework/Headers/NEAppProxyFlow.h`
/// - Apple enum docs:
///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code
private enum AppProxyFlowErrorCode: Int {
    /// The flow is not connected.
    ///
    /// We treat this as a normal teardown/disconnect signal in read/write callbacks.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorNotConnected = 1`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/notconnected
    case notConnected = 1

    /// The remote peer reset the flow.
    ///
    /// We treat this as an expected remote-close outcome, not a provider bug.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorPeerReset = 2`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/peerreset
    case peerReset = 2

    /// The remote peer is unreachable.
    ///
    /// This is a network-path/connectivity issue and remains worth surfacing at debug level.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorHostUnreachable = 3`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/hostunreachable
    case hostUnreachable = 3

    /// An invalid argument was passed to an `NEAppProxyFlow` method.
    ///
    /// This suggests a provider bug or incorrect API usage and should be treated as actionable.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorInvalidArgument = 4`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/invalidargument
    case invalidArgument = 4

    /// The flow was aborted.
    ///
    /// This can happen during shutdown, but when not already closing it may still indicate
    /// a noteworthy runtime interruption.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorAborted = 5`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/aborted
    case aborted = 5

    /// The flow was refused/disallowed.
    ///
    /// This is treated as an environment or policy failure rather than an expected disconnect.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorRefused = 6`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/refused
    case refused = 6

    /// The flow timed out.
    ///
    /// This is a network/runtime condition and remains visible at debug level.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorTimedOut = 7`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/timedout
    case timedOut = 7

    /// An internal NetworkExtension error occurred.
    ///
    /// This is not expected during normal flow teardown and should be treated as actionable.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorInternal = 8`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/internal
    case `internal` = 8

    /// A UDP datagram exceeded the socket receive window.
    ///
    /// This is an operational misuse/limit condition and is treated as actionable.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorDatagramTooLarge = 9`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/datagramtoolarge
    case datagramTooLarge = 9

    /// A second read was started while another read was still pending.
    ///
    /// This should not occur in our serialized read loops and therefore indicates a logic bug.
    ///
    /// Normative source:
    /// - SDK header: `NEAppProxyFlowErrorReadAlreadyPending = 10`
    /// - Apple symbol docs:
    ///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code/readalreadypending
    case readAlreadyPending = 10
}

private let appProxyFlowErrorDomains: Set<String> = [
    "NEAppProxyFlowErrorDomain",
    "NEAppProxyErrorDomain",
]

private let expectedDisconnectPosixCodes: Set<Int32> = [
    ECONNABORTED,
    ECONNRESET,
    ENOTCONN,
    EPIPE,
]

/// Classify callback errors from `NEAppProxyFlow` read/write operations into expected
/// disconnects versus actionable failures.
///
/// Primary references:
/// - Normative error-code source:
///   `/Applications/Xcode.app/.../NetworkExtension.framework/Headers/NEAppProxyFlow.h`
/// - Apple enum docs:
///   https://developer.apple.com/documentation/networkextension/neappproxyflowerror-swift.struct/code
///
/// Notes for maintainers:
/// - The numeric `NEAppProxyFlowError` mapping used here comes from the SDK header shipped with
///   Xcode, which is the normative source for the per-code symbols.
/// - The Apple enum pages linked from each case are the intended human-readable references for
///   those symbols.
/// - We intentionally log disconnect-like outcomes at `trace` with “ended” wording so they are
///   distinguishable from provider faults during audits.
private func classifyFlowCallbackError(
    _ error: Error,
    operation: String,
    isClosing: Bool = false
) -> FlowLogMessage {
    let nsError = error as NSError
    let detail =
        "domain=\(nsError.domain) code=\(nsError.code) description=\(nsError.localizedDescription)"

    if appProxyFlowErrorDomains.contains(nsError.domain),
        let code = AppProxyFlowErrorCode(rawValue: nsError.code)
    {
        switch code {
        case .notConnected:
            let reason =
                isClosing ? "normal flow shutdown already in progress" : "flow already disconnected"
            return FlowLogMessage(
                level: .trace,
                text: "\(operation) ended during \(reason): \(detail)"
            )
        case .peerReset:
            return FlowLogMessage(
                level: .trace,
                text: "\(operation) ended after peer reset the flow: \(detail)"
            )
        case .aborted:
            let level: FlowLogLevel = isClosing ? .trace : .debug
            let reason =
                isClosing ? "flow shutdown already in progress" : "flow was aborted by the system"
            return FlowLogMessage(
                level: level,
                text: "\(operation) ended because \(reason): \(detail)"
            )
        case .hostUnreachable, .refused, .timedOut:
            return FlowLogMessage(
                level: .debug,
                text: "\(operation) failed because the network path was unavailable: \(detail)"
            )
        case .invalidArgument, .internal, .datagramTooLarge, .readAlreadyPending:
            return FlowLogMessage(
                level: .error,
                text: "\(operation) failed with an unexpected provider/runtime error: \(detail)"
            )
        }
    }

    if nsError.domain == NSPOSIXErrorDomain,
        expectedDisconnectPosixCodes.contains(Int32(nsError.code))
    {
        let reason = isClosing ? "normal flow shutdown already in progress" : "peer disconnected"
        return FlowLogMessage(
            level: .trace,
            text: "\(operation) ended during \(reason): \(detail)"
        )
    }

    return FlowLogMessage(
        level: .debug,
        text: "\(operation) failed with an unclassified callback error: \(detail)"
    )
}

private final class TcpClientWritePump {
    private let flow: NEAppProxyTCPFlow
    private let logger: (FlowLogMessage) -> Void
    private let queue = DispatchQueue(label: "rama.tproxy.tcp.write", qos: .utility)
    private var pending: [Data] = []
    private var writing = false
    private var closed = false

    init(flow: NEAppProxyTCPFlow, logger: @escaping (FlowLogMessage) -> Void) {
        self.flow = flow
        self.logger = logger
    }

    func enqueue(_ data: Data) {
        guard !data.isEmpty else { return }
        queue.async {
            if self.closed { return }
            self.pending.append(data)
            self.flushLocked()
        }
    }

    func close() {
        queue.async {
            self.closed = true
            self.pending.removeAll(keepingCapacity: false)
        }
    }

    private func flushLocked() {
        if writing || pending.isEmpty || closed {
            return
        }

        writing = true
        let chunk = pending.removeFirst()
        flow.write(chunk) { error in
            self.queue.async {
                self.writing = false
                if let error {
                    self.logger(
                        classifyFlowCallbackError(
                            error,
                            operation: "tcp flow.write",
                            isClosing: self.closed
                        )
                    )
                    self.closed = true
                    self.pending.removeAll(keepingCapacity: false)
                    self.flow.closeReadWithError(error)
                    self.flow.closeWriteWithError(error)
                    return
                }

                self.flushLocked()
            }
        }
    }
}

private final class UdpClientWritePump {
    private let flow: NEAppProxyUDPFlow
    private let logger: (FlowLogMessage) -> Void
    private let queue = DispatchQueue(label: "rama.tproxy.udp.write", qos: .utility)
    private var pending: [Data] = []
    private var writing = false
    private var closed = false
    private var sentByEndpoint: NWEndpoint?

    init(flow: NEAppProxyUDPFlow, logger: @escaping (FlowLogMessage) -> Void) {
        self.flow = flow
        self.logger = logger
    }

    func setSentByEndpoint(_ endpoint: NWEndpoint?) {
        queue.async {
            if endpoint != nil {
                self.sentByEndpoint = endpoint
            }
            self.flushLocked()
        }
    }

    func enqueue(_ data: Data) {
        guard !data.isEmpty else { return }
        queue.async {
            if self.closed { return }
            self.pending.append(data)
            self.flushLocked()
        }
    }

    func close() {
        queue.async {
            self.closed = true
            self.pending.removeAll(keepingCapacity: false)
        }
    }

    private func flushLocked() {
        if writing || pending.isEmpty || closed {
            return
        }

        guard let endpoint = sentByEndpoint else {
            return
        }

        writing = true
        let chunk = pending.removeFirst()
        flow.writeDatagrams([chunk], sentBy: [endpoint]) { error in
            self.queue.async {
                self.writing = false
                if let error {
                    self.logger(
                        classifyFlowCallbackError(
                            error,
                            operation: "udp flow.write",
                            isClosing: self.closed
                        )
                    )
                    self.closed = true
                    self.pending.removeAll(keepingCapacity: false)
                    self.flow.closeReadWithError(error)
                    self.flow.closeWriteWithError(error)
                    return
                }

                self.flushLocked()
            }
        }
    }
}

public final class RamaTransparentProxyProvider: NETransparentProxyProvider {
    private var engine: RamaTransparentProxyEngineHandle?
    private let stateQueue = DispatchQueue(label: "rama.tproxy.state")
    private var tcpSessions: [ObjectIdentifier: RamaTcpSessionHandle] = [:]
    private var udpSessions: [ObjectIdentifier: RamaUdpSessionHandle] = [:]

    public override func startProxy(
        options: [String: Any]?, completionHandler: @escaping (Error?) -> Void
    ) {
        let storageDir = Self.defaultRustStorageDirectory()?.path
        guard RamaTransparentProxyEngineHandle.initialize(storageDir: storageDir, appGroupDir: nil)
        else {
            let error = NSError(
                domain: "RamaTransparentProxy.Startup",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "rust initialization failed before provider startup completed",
                    NSLocalizedFailureReasonErrorKey:
                        "rama_transparent_proxy_initialize returned false",
                    NSLocalizedRecoverySuggestionErrorKey:
                        "Inspect extension bootstrap logs for entitlement, protected-storage, or Rust startup failures.",
                    "storageDir": storageDir ?? NSNull(),
                    "startupStage": "initialize",
                ]
            )
            completionHandler(error)
            return
        }
        logInfo("extension startProxy")

        guard let startup = RamaTransparentProxyEngineHandle.config() else {
            logError("failed to get transparent proxy config from rust")
            let error = NSError(
                domain: "RamaTransparentProxy.Startup",
                code: 2,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "rust startup configuration could not be loaded",
                    NSLocalizedFailureReasonErrorKey:
                        "rama_transparent_proxy_get_config returned nil",
                    NSLocalizedRecoverySuggestionErrorKey:
                        "Inspect extension bootstrap logs for Rust-side configuration or secret-loading failures.",
                    "storageDir": storageDir ?? NSNull(),
                    "startupStage": "config",
                ]
            )
            completionHandler(error)
            return
        }

        let settings = NETransparentProxyNetworkSettings(
            tunnelRemoteAddress: startup.tunnelRemoteAddress
        )
        var builtRules: [NENetworkRule] = []
        for (idx, rule) in startup.rules.enumerated() {
            if let built = Self.makeNetworkRule(rule) {
                builtRules.append(built)
                logInfo(
                    "include rule[\(idx)] remote=\(rule.remoteNetwork ?? "<any>") remotePrefix=\(rule.remotePrefix.map(String.init) ?? "<none>") local=\(rule.localNetwork ?? "<any>") localPrefix=\(rule.localPrefix.map(String.init) ?? "<none>") proto=\(rule.protocolRaw)"
                )
            } else {
                logError(
                    "invalid rule[\(idx)] remote=\(rule.remoteNetwork ?? "<any>") remotePrefix=\(rule.remotePrefix.map(String.init) ?? "<none>") local=\(rule.localNetwork ?? "<any>") localPrefix=\(rule.localPrefix.map(String.init) ?? "<none>") proto=\(rule.protocolRaw)"
                )
            }
        }
        settings.includedNetworkRules = builtRules
        logInfo("included network rules count=\(builtRules.count)")

        setTunnelNetworkSettings(settings) { error in
            if let error {
                self.logError("setTunnelNetworkSettings error: \(error)")
                completionHandler(error)
                return
            }

            self.logInfo("setTunnelNetworkSettings ok")
            self.engine = RamaTransparentProxyEngineHandle()
            self.logInfo("engine created")
            self.engine?.start()
            self.logInfo("engine started")
            completionHandler(nil)
        }
    }

    public override func stopProxy(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        logInfo("extension stopProxy reason=\(reason.rawValue)")
        self.engine?.stop(reason: Int32(reason.rawValue))
        self.engine = nil
        stateQueue.async {
            self.tcpSessions.removeAll(keepingCapacity: false)
            self.udpSessions.removeAll(keepingCapacity: false)
        }
        completionHandler()
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        if let tcp = flow as? NEAppProxyTCPFlow {
            let meta = Self.tcpMeta(flow: tcp)
            if !RamaTransparentProxyEngineHandle.shouldIntercept(meta: meta) {
                logDebug("handleNewFlow tcp bypassed by rust callback")
                return false
            }
            handleTcpFlow(tcp, meta: meta)
            return true
        }

        if let udp = flow as? NEAppProxyUDPFlow {
            let meta = Self.udpMeta(
                flow: udp,
                remoteEndpoint: nil,
                localEndpoint: Self.udpLocalEndpoint(flow: udp)
            )
            if !RamaTransparentProxyEngineHandle.shouldIntercept(meta: meta) {
                logDebug("handleNewFlow udp bypassed by rust callback")
                return false
            }
            handleUdpFlow(udp)
            return true
        }

        logDebug("handleNewFlow unsupported type=\(String(describing: type(of: flow)))")
        return false
    }

    private func handleTcpFlow(_ flow: NEAppProxyTCPFlow, meta: RamaTransparentProxyFlowMetaBridge)
    {
        let writer = TcpClientWritePump(flow: flow) { [weak self] message in
            self?.logFlowMessage(message)
        }
        let flowId = ObjectIdentifier(flow)

        guard
            let session = engine?.newTcpSession(
                meta: meta,
                onServerBytes: { data in
                    writer.enqueue(data)
                },
                onServerClosed: { [weak self] in
                    writer.close()
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    self?.stateQueue.async {
                        self?.tcpSessions.removeValue(forKey: flowId)
                    }
                }
            )
        else {
            logDebug("failed to create tcp session")
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        stateQueue.async {
            self.tcpSessions[flowId] = session
        }

        flow.open(withLocalEndpoint: nil) { error in
            if let error {
                self.logDebug("flow.open error: \(error)")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                session.onClientEof()
                self.stateQueue.async {
                    self.tcpSessions.removeValue(forKey: flowId)
                }
                return
            }
            self.logTrace("flow.open ok (tcp)")
            self.tcpReadLoop(flow: flow, session: session)
        }
    }

    private func handleUdpFlow(_ flow: NEAppProxyUDPFlow) {
        let writer = UdpClientWritePump(flow: flow) { [weak self] message in
            self?.logFlowMessage(message)
        }
        let flowId = ObjectIdentifier(flow)

        flow.open(withLocalEndpoint: nil) { error in
            if let error {
                self.logDebug("udp flow.open error: \(error)")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                return
            }
            self.logTrace("flow.open ok (udp)")
            self.udpReadLoop(flow: flow, writer: writer, session: nil, flowId: flowId)
        }
    }

    private func tcpReadLoop(flow: NEAppProxyTCPFlow, session: RamaTcpSessionHandle) {
        flow.readData { data, error in
            if let error {
                self.logFlowMessage(
                    classifyFlowCallbackError(error, operation: "tcp flow.read")
                )
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                session.onClientEof()
                self.stateQueue.async {
                    self.tcpSessions.removeValue(forKey: ObjectIdentifier(flow))
                }
                return
            }

            guard let data, !data.isEmpty else {
                self.logTrace("flow.readData eof")
                session.onClientEof()
                return
            }

            session.onClientBytes(data)
            self.tcpReadLoop(flow: flow, session: session)
        }
    }

    private func udpReadLoop(
        flow: NEAppProxyUDPFlow,
        writer: UdpClientWritePump,
        session: RamaUdpSessionHandle?,
        flowId: ObjectIdentifier
    ) {
        flow.readDatagrams { datagrams, endpoints, error in
            if let error {
                self.logFlowMessage(
                    classifyFlowCallbackError(error, operation: "udp flow.read")
                )
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                session?.onClientClose()
                self.stateQueue.async {
                    self.udpSessions.removeValue(forKey: ObjectIdentifier(flow))
                }
                return
            }

            guard let datagrams, !datagrams.isEmpty else {
                self.logTrace("flow.readDatagrams eof")
                session?.onClientClose()
                return
            }

            let endpoint = endpoints?.first
            writer.setSentByEndpoint(endpoint)

            var activeSession = session
            if activeSession == nil {
                let meta = Self.udpMeta(
                    flow: flow,
                    remoteEndpoint: endpoint,
                    localEndpoint: Self.udpLocalEndpoint(flow: flow)
                )
                if !RamaTransparentProxyEngineHandle.shouldIntercept(meta: meta) {
                    self.logTrace("udp flow bypassed by rust callback")
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return
                }

                activeSession = self.engine?.newUdpSession(
                    meta: meta,
                    onServerDatagram: { data in
                        writer.enqueue(data)
                    },
                    onServerClosed: { [weak self] in
                        writer.close()
                        flow.closeReadWithError(nil)
                        flow.closeWriteWithError(nil)
                        self?.stateQueue.async {
                            self?.udpSessions.removeValue(forKey: flowId)
                        }
                    }
                )

                guard let createdSession = activeSession else {
                    self.logDebug("failed to create udp session")
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return
                }

                self.stateQueue.async {
                    self.udpSessions[flowId] = createdSession
                }
            }

            guard let activeSession else {
                flow.closeReadWithError(nil)
                flow.closeWriteWithError(nil)
                return
            }

            for datagram in datagrams where !datagram.isEmpty {
                activeSession.onClientDatagram(datagram)
            }

            self.udpReadLoop(flow: flow, writer: writer, session: activeSession, flowId: flowId)
        }
    }

    private static func makeNetworkRule(_ rule: RamaTransparentProxyRuleBridge)
        -> NENetworkRule?
    {
        let remote = networkEndpoint(from: rule.remoteNetwork)
        let local = networkEndpoint(from: rule.localNetwork)
        let proto = networkRuleProtocol(rule.protocolRaw)

        // Host/domain-only rule (no local matcher): use destination-host initializer.
        // This avoids forcing CIDR for non-IP hosts (e.g. example.com).
        if let remote, local == nil, rule.remotePrefix == nil {
            return NENetworkRule(
                destinationHost: remote,
                protocol: proto
            )
        }

        guard
            let remotePrefix = resolvedPrefix(
                endpoint: remote,
                networkText: rule.remoteNetwork,
                explicitPrefix: rule.remotePrefix
            ),
            let localPrefix = resolvedPrefix(
                endpoint: local,
                networkText: rule.localNetwork,
                explicitPrefix: rule.localPrefix
            )
        else {
            return nil
        }

        return NENetworkRule(
            remoteNetwork: remote,
            remotePrefix: remotePrefix,
            localNetwork: local,
            localPrefix: localPrefix,
            protocol: proto,
            direction: .outbound
        )
    }

    private static func resolvedPrefix(
        endpoint: NWHostEndpoint?,
        networkText: String?,
        explicitPrefix: UInt8?
    ) -> Int? {
        guard endpoint != nil else { return 0 }
        if let explicitPrefix { return Int(explicitPrefix) }
        guard let networkText else { return nil }
        return inferredHostPrefix(networkText)
    }

    private static func inferredHostPrefix(_ text: String) -> Int? {
        var v4 = in_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            return 32
        }
        var v6 = in6_addr()
        if text.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            return 128
        }
        return nil
    }

    private static func networkEndpoint(from network: String?) -> NWHostEndpoint? {
        guard let network, !network.isEmpty else { return nil }
        return NWHostEndpoint(hostname: network, port: "0")
    }

    private static func networkRuleProtocol(_ raw: UInt32) -> NENetworkRule.`Protocol` {
        switch raw {
        case UInt32(RAMA_RULE_PROTOCOL_TCP.rawValue): return .TCP
        case UInt32(RAMA_RULE_PROTOCOL_UDP.rawValue): return .UDP
        default: return .any
        }
    }

    private static func tcpMeta(flow: NEAppProxyTCPFlow) -> RamaTransparentProxyFlowMetaBridge {
        let remote: Any?
        if #available(macOS 15.0, *) {
            remote = flow.remoteFlowEndpoint
        } else {
            remote = flow.remoteEndpoint
        }
        let remoteEndpoint = endpointHostPort(remote)
        let localEndpoint = endpointHostPort(bestEffortLocalEndpoint(flow))
        let appMeta = sourceAppMeta(flow)
        return RamaTransparentProxyFlowMetaBridge(
            protocolRaw: UInt32(RAMA_FLOW_PROTOCOL_TCP.rawValue),
            remoteHost: remoteEndpoint?.host,
            remotePort: remoteEndpoint?.port ?? 0,
            localHost: localEndpoint?.host,
            localPort: localEndpoint?.port ?? 0,
            sourceAppSigningIdentifier: appMeta.signingIdentifier,
            sourceAppBundleIdentifier: appMeta.bundleIdentifier
        )
    }

    private static func udpMeta(
        flow: NEAppProxyUDPFlow?,
        remoteEndpoint: Any?,
        localEndpoint: Any?
    ) -> RamaTransparentProxyFlowMetaBridge {
        let remote = endpointHostPort(remoteEndpoint)
        let local = endpointHostPort(localEndpoint)
        let appMeta = sourceAppMeta(flow)
        return RamaTransparentProxyFlowMetaBridge(
            protocolRaw: UInt32(RAMA_FLOW_PROTOCOL_UDP.rawValue),
            remoteHost: remote?.host,
            remotePort: remote?.port ?? 0,
            localHost: local?.host,
            localPort: local?.port ?? 0,
            sourceAppSigningIdentifier: appMeta.signingIdentifier,
            sourceAppBundleIdentifier: appMeta.bundleIdentifier
        )
    }

    private static func sourceAppMeta(_ flow: NEAppProxyFlow?) -> (
        signingIdentifier: String?, bundleIdentifier: String?
    ) {
        guard let flow else { return (nil, nil) }
        let raw = flow.metaData.sourceAppSigningIdentifier.trimmingCharacters(
            in: .whitespacesAndNewlines)
        guard !raw.isEmpty else { return (nil, nil) }
        // Apple documents this as "almost always equivalent to bundle identifier".
        return (raw, raw)
    }

    private static func udpLocalEndpoint(flow: NEAppProxyUDPFlow) -> Any? {
        if #available(macOS 15.0, *) {
            return flow.localFlowEndpoint
        }
        return bestEffortLocalEndpoint(flow)
    }

    private static func bestEffortLocalEndpoint(_ flow: NEAppProxyFlow) -> Any? {
        let object = flow as NSObject
        if object.responds(to: NSSelectorFromString("localEndpoint")) {
            return object.value(forKey: "localEndpoint")
        }
        if object.responds(to: NSSelectorFromString("localFlowEndpoint")) {
            return object.value(forKey: "localFlowEndpoint")
        }
        return nil
    }

    private static func endpointHostPort(_ endpoint: Any?) -> (host: String, port: UInt16)? {
        guard let endpoint else { return nil }

        if let hostEndpoint = endpoint as? NWHostEndpoint {
            let host = hostEndpoint.hostname.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !host.isEmpty, let port = UInt16(hostEndpoint.port) else {
                return nil
            }
            return (host, port)
        }

        let raw = String(describing: endpoint)
        guard !raw.isEmpty else { return nil }
        return parseEndpointString(raw)
    }

    private static func parseEndpointString(_ raw: String) -> (host: String, port: UInt16)? {
        // IPv6 endpoint descriptions may be formatted as:
        // - 2a02:...:1.53
        // - [2a02:...:1]:53
        // while IPv4/domain typically use host:port.

        if raw.hasPrefix("["), let closeIdx = raw.lastIndex(of: "]") {
            let host = String(raw[raw.index(after: raw.startIndex)..<closeIdx])
            let tail = raw[raw.index(after: closeIdx)...]
            if tail.first == ":" {
                let portText = String(tail.dropFirst())
                if let port = UInt16(portText), !host.isEmpty {
                    return (host, port)
                }
            }
        }

        if let idx = raw.lastIndex(of: ":") {
            let hostPart = String(raw[..<idx]).trimmingCharacters(
                in: CharacterSet(charactersIn: "[]"))
            let portPart = String(raw[raw.index(after: idx)...])
            if let port = UInt16(portPart), !hostPart.isEmpty {
                return (hostPart, port)
            }
        }

        if let idx = raw.lastIndex(of: ".") {
            let hostPart = String(raw[..<idx]).trimmingCharacters(
                in: CharacterSet(charactersIn: "[]"))
            let portPart = String(raw[raw.index(after: idx)...])
            if hostPart.contains(":"), let port = UInt16(portPart), !hostPart.isEmpty {
                return (hostPart, port)
            }
        }

        return nil
    }

    private func logTrace(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_TRACE.rawValue),
            message: message
        )
    }

    private func logDebug(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
            message: message
        )
    }

    private func logInfo(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_INFO.rawValue),
            message: message
        )
    }

    private func logError(_ message: String) {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_ERROR.rawValue),
            message: message
        )
    }

    private func logFlowMessage(_ message: FlowLogMessage) {
        switch message.level {
        case .trace:
            logTrace(message.text)
        case .debug:
            logDebug(message.text)
        case .error:
            logError(message.text)
        }
    }
}

extension RamaTransparentProxyProvider {
    fileprivate static func defaultRustStorageDirectory() -> URL? {
        guard
            let base = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first
        else {
            return nil
        }
        return
            base
            .appendingPathComponent("rama", isDirectory: true)
            .appendingPathComponent("tproxy", isDirectory: true)
    }
}
