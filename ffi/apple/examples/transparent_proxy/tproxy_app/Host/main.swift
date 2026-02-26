import Foundation
import NetworkExtension

final class HostController {
    private let action: String
    private let logUrls: [URL]
    private var statusObserver: NSObjectProtocol?
    private var statusTimer: DispatchSourceTimer?
    private var activeManager: NETransparentProxyManager?

    init(action: String) {
        self.action = action
        self.logUrls = HostController.resolveLogUrls()
    }

    func run() {
        switch action {
        case "start":
            log("host starting")
            configureProxy(start: true)
            dispatchMain()
        case "stop":
            log("host stopping")
            configureProxy(start: false)
            dispatchMain()
        default:
            print("unknown action '\(action)' (use 'start' or 'stop')")
            log("unknown action '\(action)' (use 'start' or 'stop')")
            exit(2)
        }
    }

    private func configureProxy(start: Bool) {
        let extensionBundleId = "org.ramaproxy.example.tproxy.provider"

        log("calling NETransparentProxyManager.loadAllFromPreferences")
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error = error {
                print("loadAllFromPreferences error: \(error)")
                self.logError("loadAllFromPreferences error", error)
                self.terminate()
                return
            }

            let count = managers?.count ?? 0
            self.log("loadAllFromPreferences ok (count=\(count))")
            let manager = managers?.first ?? NETransparentProxyManager()
            self.log("using manager (existing=\(managers?.first != nil))")
            self.activeManager = manager
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = extensionBundleId
            proto.serverAddress = "127.0.0.1"
            proto.providerConfiguration = [:]

            manager.localizedDescription = "Rama Transparent Proxy Example"
            manager.protocolConfiguration = proto
            manager.isEnabled = true
            self.log("manager.isEnabled=\(manager.isEnabled)")
            self.installStatusObserver(manager: manager)
            self.startStatusTimer(manager: manager)

            self.log("saving preferences")
            manager.saveToPreferences { saveError in
                if let saveError = saveError {
                    print("saveToPreferences error: \(saveError)")
                    self.logError("saveToPreferences error", saveError)
                    self.terminate()
                    return
                }

                self.log("saveToPreferences ok; loading")
                manager.loadFromPreferences { loadError in
                    if let loadError = loadError {
                        print("loadFromPreferences error: \(loadError)")
                        self.logError("loadFromPreferences error", loadError)
                        self.terminate()
                        return
                    }

                    if start {
                        do {
                            self.log("calling startVPNTunnel")
                            try manager.connection.startVPNTunnel()
                            print("Transparent proxy started")
                            self.log("Transparent proxy started")
                            self.log(
                                "connection.status=\(self.statusString(manager.connection.status))")
                        } catch {
                            print("startVPNTunnel error: \(error)")
                            self.logError("startVPNTunnel error", error)
                            self.terminate()
                        }
                    } else {
                        self.log("calling stopVPNTunnel")
                        manager.connection.stopVPNTunnel()
                        print("Transparent proxy stopped")
                        self.log("Transparent proxy stopped")
                        self.terminate()
                    }
                }
            }
        }
    }

    private func terminate() {
        exit(0)
    }

    private func log(_ message: String) {
        let line = "[\(isoTimestamp())] \(message)\n"
        appendLog(line)
    }

    private func logError(_ prefix: String, _ error: Error) {
        let ns = error as NSError
        log("\(prefix): domain=\(ns.domain) code=\(ns.code) userInfo=\(ns.userInfo)")
    }

    private func installStatusObserver(manager: NETransparentProxyManager) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            self.log("status changed: \(self.statusString(manager.connection.status))")
        }
        log("installed status observer")
    }

    private func startStatusTimer(manager: NETransparentProxyManager) {
        statusTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 1.0, repeating: 5.0)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.log("status tick: \(self.statusString(manager.connection.status))")
        }
        timer.resume()
        statusTimer = timer
        log("started status timer")
    }

    private func statusString(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown"
        }
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
            urls.append(containerURL.appendingPathComponent("rama_tproxy_host.log"))
        }
        let tmp = FileManager.default.temporaryDirectory
        urls.append(tmp.appendingPathComponent("rama_tproxy_host.log"))
        urls.append(URL(fileURLWithPath: "/tmp/rama_tproxy_host.log"))
        return urls
    }
}

let action = CommandLine.arguments.dropFirst().first ?? "start"
let controller = HostController(action: action)
controller.run()
