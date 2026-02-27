import Darwin
import Foundation
import NetworkExtension
import RamaAppleNEFFI

private final class TcpClientWritePump {
    private let flow: NEAppProxyTCPFlow
    private let logger: (String) -> Void
    private let queue = DispatchQueue(label: "rama.tproxy.tcp.write", qos: .utility)
    private var pending: [Data] = []
    private var writing = false
    private var closed = false

    init(flow: NEAppProxyTCPFlow, logger: @escaping (String) -> Void) {
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
                    self.logger("flow.write error: \(error)")
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
    private let logger: (String) -> Void
    private let queue = DispatchQueue(label: "rama.tproxy.udp.write", qos: .utility)
    private var pending: [Data] = []
    private var writing = false
    private var closed = false
    private var sentByEndpoint: NWEndpoint?

    init(flow: NEAppProxyUDPFlow, logger: @escaping (String) -> Void) {
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
                    self.logger("udp writeDatagrams error: \(error)")
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
        guard RamaTransparentProxyEngineHandle.initialize() else {
            completionHandler(NSError(domain: "RamaTransparentProxy", code: 1))
            return
        }
        logInfo("extension startProxy")

        guard let startup = RamaTransparentProxyEngineHandle.config() else {
            logError("failed to get transparent proxy config from rust")
            completionHandler(NSError(domain: "RamaTransparentProxy", code: 2))
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
        let writer = TcpClientWritePump(flow: flow) { [weak self] msg in
            self?.logDebug(msg)
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
        let writer = UdpClientWritePump(flow: flow) { [weak self] msg in
            self?.logDebug(msg)
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
                self.logDebug("flow.readData error: \(error)")
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
                self.logDebug("flow.readDatagrams error: \(error)")
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
}
