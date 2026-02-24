import Foundation
import NetworkExtension

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
    private let logUrls = RamaTransparentProxyProvider.resolveLogUrls()
    private var engine: RamaTransparentProxyEngineHandle?
    private let stateQueue = DispatchQueue(label: "rama.tproxy.state")
    private var tcpSessions: [ObjectIdentifier: RamaTcpSessionHandle] = [:]
    private var udpSessions: [ObjectIdentifier: RamaUdpSessionHandle] = [:]

    public override func startProxy(
        options: [String: Any]?, completionHandler: @escaping (Error?) -> Void
    ) {
        log("extension startProxy")
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [
            NENetworkRule(
                remoteNetwork: nil,
                remotePrefix: 0,
                localNetwork: nil,
                localPrefix: 0,
                protocol: .any,
                direction: .outbound
            )
        ]
        setTunnelNetworkSettings(settings) { error in
            if let error {
                self.log("setTunnelNetworkSettings error: \(error)")
                completionHandler(error)
                return
            }

            self.log("setTunnelNetworkSettings ok")
            let cfg = RamaTransparentProxyConfig.loadConfigJSON()
            self.log("loaded config JSON")
            self.engine = RamaTransparentProxyEngineHandle(configJSON: cfg)
            self.log("engine created")
            self.engine?.start()
            self.log("engine started")
            completionHandler(nil)
        }
    }

    public override func stopProxy(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        log("extension stopProxy reason=\(reason.rawValue)")
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
            let remote = RamaTransparentProxyConfig.remoteEndpointString(flow: tcp) ?? "unknown"
            log("handleNewFlow tcp remote=\(remote)")
            handleTcpFlow(tcp)
            return true
        }

        if let udp = flow as? NEAppProxyUDPFlow {
            log("handleNewFlow udp")
            handleUdpFlow(udp)
            return true
        }

        log("handleNewFlow unsupported type=\(String(describing: type(of: flow)))")
        return false
    }

    private func handleTcpFlow(_ flow: NEAppProxyTCPFlow) {
        let metaJSON = RamaTransparentProxyConfig.tcpMetaJSON(flow: flow)
        let writer = TcpClientWritePump(flow: flow) { [weak self] msg in
            self?.log(msg)
        }
        let flowId = ObjectIdentifier(flow)

        guard
            let session = engine?.newTcpSession(
                metaJSON: metaJSON,
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
            log("failed to create tcp session")
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
            return
        }

        stateQueue.async {
            self.tcpSessions[flowId] = session
        }

        flow.open(withLocalEndpoint: nil) { error in
            if let error {
                self.log("flow.open error: \(error)")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                session.onClientEof()
                self.stateQueue.async {
                    self.tcpSessions.removeValue(forKey: flowId)
                }
                return
            }
            self.log("flow.open ok (tcp)")
            self.tcpReadLoop(flow: flow, session: session)
        }
    }

    private func handleUdpFlow(_ flow: NEAppProxyUDPFlow) {
        let writer = UdpClientWritePump(flow: flow) { [weak self] msg in
            self?.log(msg)
        }
        let flowId = ObjectIdentifier(flow)

        flow.open(withLocalEndpoint: nil) { error in
            if let error {
                self.log("udp flow.open error: \(error)")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                return
            }
            self.log("flow.open ok (udp)")
            self.udpReadLoop(flow: flow, writer: writer, session: nil, flowId: flowId)
        }
    }

    private func tcpReadLoop(flow: NEAppProxyTCPFlow, session: RamaTcpSessionHandle) {
        flow.readData { data, error in
            if let error {
                self.log("flow.readData error: \(error)")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                session.onClientEof()
                self.stateQueue.async {
                    self.tcpSessions.removeValue(forKey: ObjectIdentifier(flow))
                }
                return
            }

            guard let data, !data.isEmpty else {
                self.log("flow.readData eof")
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
                self.log("flow.readDatagrams error: \(error)")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                session?.onClientClose()
                self.stateQueue.async {
                    self.udpSessions.removeValue(forKey: ObjectIdentifier(flow))
                }
                return
            }

            guard let datagrams, !datagrams.isEmpty else {
                self.log("flow.readDatagrams eof")
                session?.onClientClose()
                return
            }

            let endpoint = endpoints?.first
            writer.setSentByEndpoint(endpoint)

            var activeSession = session
            if activeSession == nil {
                let metaJSON = RamaTransparentProxyConfig.udpMetaJSON(remoteEndpoint: endpoint)
                activeSession = self.engine?.newUdpSession(
                    metaJSON: metaJSON,
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
                    self.log("failed to create udp session")
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

    private func log(_ message: String) {
        let line = "[\(isoTimestamp())] \(message)\n"
        appendLog(line)
    }

    private func isoTimestamp() -> String {
        let formatter = ISO8601DateFormatter()
        return formatter.string(from: Date())
    }

    private func appendLog(_ line: String) {
        guard let data = line.data(using: .utf8) else { return }
        for url in logUrls {
            ensureParentDir(url)
            if !FileManager.default.fileExists(atPath: url.path) {
                FileManager.default.createFile(atPath: url.path, contents: nil)
            }
            if let handle = try? FileHandle(forWritingTo: url) {
                do {
                    try handle.seekToEnd()
                    try handle.write(contentsOf: data)
                    try handle.close()
                    continue
                } catch {
                    try? handle.close()
                }
            }
        }
    }

    private func ensureParentDir(_ url: URL) {
        let dir = url.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    private static func resolveLogUrls() -> [URL] {
        let env = ProcessInfo.processInfo.environment
        var urls: [URL] = []
        if let path = env["RAMA_LOG_PATH"], !path.isEmpty {
            urls.append(URL(fileURLWithPath: path))
        }
        if let groupId = env["RAMA_APP_GROUP_ID"], !groupId.isEmpty,
            let containerURL = FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: groupId)
        {
            urls.append(containerURL.appendingPathComponent("rama_tproxy_ext.log"))
        }
        let tmp = FileManager.default.temporaryDirectory
        urls.append(tmp.appendingPathComponent("rama_tproxy_ext.log"))
        urls.append(URL(fileURLWithPath: "/tmp/rama_tproxy_ext.log"))
        return urls
    }
}
