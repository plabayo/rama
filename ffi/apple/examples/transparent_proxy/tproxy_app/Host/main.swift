import AppKit
import Foundation
import NetworkExtension
import OSLog

final class HostController: NSObject, NSApplicationDelegate {
    private let extensionBundleId = "org.ramaproxy.example.tproxy.provider"
    private let logSubsystem = "org.ramaproxy.example.tproxy"
    private let hostLogCategory = "host-app"
    private lazy var hostLogger = Logger(subsystem: logSubsystem, category: hostLogCategory)

    private var statusItem: NSStatusItem?
    private var statusMenuItem: NSMenuItem?
    private var startMenuItem: NSMenuItem?
    private var stopMenuItem: NSMenuItem?

    private var activeManager: NETransparentProxyManager?
    private var statusObserver: NSObjectProtocol?
    private var statusTimer: DispatchSourceTimer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        log("host app launched")
        startProxy()
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

    @objc private func quitAction(_: Any?) {
        NSApplication.shared.terminate(nil)
    }

    private func setupStatusItem() {
        let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.title = "🦙 tproxy demo"
        }

        let menu = NSMenu()

        let statusItemMenu = NSMenuItem(title: "Status: loading", action: nil, keyEquivalent: "")
        statusItemMenu.isEnabled = false
        menu.addItem(statusItemMenu)

        menu.addItem(NSMenuItem.separator())

        let startItem = NSMenuItem(
            title: "Start Proxy", action: #selector(startProxyAction(_:)), keyEquivalent: "s")
        startItem.target = self
        menu.addItem(startItem)

        let stopItem = NSMenuItem(
            title: "Stop Proxy", action: #selector(stopProxyAction(_:)), keyEquivalent: "x")
        stopItem.target = self
        menu.addItem(stopItem)

        let refreshItem = NSMenuItem(
            title: "Refresh Status", action: #selector(refreshAction(_:)), keyEquivalent: "r")
        refreshItem.target = self
        menu.addItem(refreshItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(
            title: "Quit", action: #selector(quitAction(_:)), keyEquivalent: "q")
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
            switch manager.connection.status {
            case .connected, .connecting, .reasserting:
                self.log("proxy already active; skipping start")
                self.setStatus(status: manager.connection.status, detail: nil)
                return
            default:
                break
            }

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

            let manager = self.selectManager(from: managers)
            self.log(
                "loadAllFromPreferences ok (count=\(managers?.count ?? 0), selected=\(manager != nil))"
            )
            completion(manager)
        }
    }

    private func loadOrCreateAndConfigureManager(
        completion: @escaping (NETransparentProxyManager?) -> Void
    ) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                self.logError("loadAllFromPreferences error", error)
                completion(nil)
                return
            }

            let manager = self.selectManager(from: managers) ?? NETransparentProxyManager()
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

    private func selectManager(from managers: [NETransparentProxyManager]?)
        -> NETransparentProxyManager?
    {
        guard let managers, !managers.isEmpty else {
            return nil
        }
        if let exact = managers.first(where: { manager in
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                return false
            }
            return proto.providerBundleIdentifier == self.extensionBundleId
        }) {
            return exact
        }
        return managers.first
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
            button.title = "🦙 tproxy demo"
            button.toolTip = title
        }

        log("status=\(statusText)")
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
        hostLogger.info("\(message, privacy: .public)")
    }

    private func logError(_ prefix: String, _ error: Error) {
        let ns = error as NSError
        hostLogger.error(
            "\(prefix, privacy: .public): domain=\(ns.domain, privacy: .public) code=\(ns.code, privacy: .public) userInfo=\(String(describing: ns.userInfo), privacy: .public)"
        )
    }
}

let app = NSApplication.shared
let delegate = HostController()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
