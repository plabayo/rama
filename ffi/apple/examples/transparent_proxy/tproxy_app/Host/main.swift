import AppKit
import Foundation
import NetworkExtension

final class HostController: NSObject, NSApplicationDelegate {
    private let extensionBundleId = "org.ramaproxy.example.tproxy.provider"
    private let logUrls: [URL]

    private var statusItem: NSStatusItem?
    private var statusMenuItem: NSMenuItem?
    private var startMenuItem: NSMenuItem?
    private var stopMenuItem: NSMenuItem?

    private var activeManager: NETransparentProxyManager?
    private var statusObserver: NSObjectProtocol?
    private var statusTimer: DispatchSourceTimer?

    override init() {
        self.logUrls = HostController.resolveLogUrls()
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        log("host app launched")
        refreshManagerAndStatus()
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        statusTimer?.cancel()
        statusTimer = nil
        log("host app terminated")
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let manager = activeManager else {
            return .terminateNow
        }

        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            log("quit requested: stopping proxy first")
            stopProxy { sender.reply(toApplicationShouldTerminate: true) }
            return .terminateLater
        default:
            return .terminateNow
        }
    }

    @objc private func startProxyAction(_: Any?) {
        startProxy()
    }

    @objc private func stopProxyAction(_: Any?) {
        stopProxy(completion: nil)
    }

    @objc private func refreshAction(_: Any?) {
        refreshManagerAndStatus()
    }

    @objc private func openLogsAction(_: Any?) {
        openLogs()
    }

    @objc private func quitAction(_: Any?) {
        NSApplication.shared.terminate(nil)
    }

    private func setupStatusItem() {
        let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.title = "Rama TProxy"
        }

        let menu = NSMenu()

        let statusItemMenu = NSMenuItem(title: "Status: loading", action: nil, keyEquivalent: "")
        statusItemMenu.isEnabled = false
        menu.addItem(statusItemMenu)

        menu.addItem(NSMenuItem.separator())

        let startItem = NSMenuItem(title: "Start Proxy", action: #selector(startProxyAction(_:)), keyEquivalent: "s")
        startItem.target = self
        menu.addItem(startItem)

        let stopItem = NSMenuItem(title: "Stop Proxy", action: #selector(stopProxyAction(_:)), keyEquivalent: "x")
        stopItem.target = self
        menu.addItem(stopItem)

        let refreshItem = NSMenuItem(title: "Refresh Status", action: #selector(refreshAction(_:)), keyEquivalent: "r")
        refreshItem.target = self
        menu.addItem(refreshItem)

        menu.addItem(NSMenuItem.separator())

        let logsItem = NSMenuItem(title: "Open Logs", action: #selector(openLogsAction(_:)), keyEquivalent: "l")
        logsItem.target = self
        menu.addItem(logsItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit", action: #selector(quitAction(_:)), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = menu

        self.statusItem = statusItem
        self.statusMenuItem = statusItemMenu
        self.startMenuItem = startItem
        self.stopMenuItem = stopItem
    }

    private func refreshManagerAndStatus() {
        loadManager { [weak self] manager in
            guard let self else { return }
            guard let manager else {
                self.setStatus(status: .invalid, detail: "manager unavailable")
                return
            }

            self.activeManager = manager
            self.installStatusObserver(manager: manager)
            self.startStatusTimer(manager: manager)
            self.setStatus(status: manager.connection.status, detail: nil)
        }
    }

    private func startProxy() {
        loadOrCreateAndConfigureManager { [weak self] manager in
            guard let self else { return }
            guard let manager else {
                self.setStatus(status: .invalid, detail: "configuration failed")
                return
            }

            self.activeManager = manager
            self.installStatusObserver(manager: manager)
            self.startStatusTimer(manager: manager)

            do {
                self.log("calling startVPNTunnel")
                try manager.connection.startVPNTunnel()
                self.log("transparent proxy start requested")
                self.setStatus(status: manager.connection.status, detail: nil)
            } catch {
                self.logError("startVPNTunnel error", error)
                self.setStatus(status: .disconnected, detail: "start failed")
            }
        }
    }

    private func stopProxy(completion: (() -> Void)?) {
        loadManager { [weak self] manager in
            guard let self else {
                completion?()
                return
            }
            guard let manager else {
                self.setStatus(status: .invalid, detail: "manager unavailable")
                completion?()
                return
            }

            self.log("calling stopVPNTunnel")
            manager.connection.stopVPNTunnel()
            self.setStatus(status: manager.connection.status, detail: nil)
            completion?()
        }
    }

    private func loadManager(completion: @escaping (NETransparentProxyManager?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                self.logError("loadAllFromPreferences error", error)
                completion(nil)
                return
            }

            let manager = managers?.first
            self.log("loadAllFromPreferences ok (count=\(managers?.count ?? 0))")
            completion(manager)
        }
    }

    private func loadOrCreateAndConfigureManager(completion: @escaping (NETransparentProxyManager?) -> Void) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                self.logError("loadAllFromPreferences error", error)
                completion(nil)
                return
            }

            let manager = managers?.first ?? NETransparentProxyManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = self.extensionBundleId
            proto.serverAddress = "127.0.0.1"
            proto.providerConfiguration = [:]

            manager.localizedDescription = "Rama Transparent Proxy Example"
            manager.protocolConfiguration = proto
            manager.isEnabled = true

            self.log("saving preferences")
            manager.saveToPreferences { saveError in
                if let saveError {
                    self.logError("saveToPreferences error", saveError)
                    completion(nil)
                    return
                }

                self.log("saveToPreferences ok; loading")
                manager.loadFromPreferences { loadError in
                    if let loadError {
                        self.logError("loadFromPreferences error", loadError)
                        completion(nil)
                        return
                    }
                    completion(manager)
                }
            }
        }
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
            self.setStatus(status: manager.connection.status, detail: nil)
        }

        log("installed status observer")
    }

    private func startStatusTimer(manager: NETransparentProxyManager) {
        statusTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + 1.0, repeating: 5.0)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.setStatus(status: manager.connection.status, detail: nil)
        }
        timer.resume()
        statusTimer = timer
    }

    private func setStatus(status: NEVPNStatus, detail: String?) {
        let statusText = statusString(status)
        let title = detail.map { "Status: \(statusText) (\($0))" } ?? "Status: \(statusText)"
        statusMenuItem?.title = title

        switch status {
        case .connected:
            startMenuItem?.isEnabled = false
            stopMenuItem?.isEnabled = true
        case .connecting, .reasserting:
            startMenuItem?.isEnabled = false
            stopMenuItem?.isEnabled = true
        default:
            startMenuItem?.isEnabled = true
            stopMenuItem?.isEnabled = false
        }

        if let button = statusItem?.button {
            button.title = "Rama TProxy"
            button.toolTip = title
        }

        log("status=\(statusText)")
    }

    private func openLogs() {
        let fm = FileManager.default
        let existing = logUrls.filter { fm.fileExists(atPath: $0.path) }

        if existing.isEmpty {
            NSSound.beep()
            return
        }

        for url in existing {
            NSWorkspace.shared.open(url)
        }
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

    private func log(_ message: String) {
        let line = "[\(isoTimestamp())] \(message)\n"
        appendLog(line)
    }

    private func logError(_ prefix: String, _ error: Error) {
        let ns = error as NSError
        log("\(prefix): domain=\(ns.domain) code=\(ns.code) userInfo=\(ns.userInfo)")
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

let app = NSApplication.shared
let delegate = HostController()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
