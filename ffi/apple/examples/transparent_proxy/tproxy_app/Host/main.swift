import AppKit
import Foundation
import NetworkExtension
import OSLog

private struct DemoProxySettings: Equatable {
    var htmlBadgeEnabled = true
    var htmlBadgeLabel = "proxied by rama"
    var excludeDomains = [
        "detectportal.firefox.com",
        "connectivitycheck.gstatic.com",
        "captive.apple.com",
    ]

    var isDefault: Bool {
        self == Self()
    }
}

final class HostController: NSObject, NSApplicationDelegate {
    private let extensionBundleId = "org.ramaproxy.example.tproxy.provider"
    private let managerDescription = "Rama Transparent Proxy Example"
    private let managerServerAddress = "127.0.0.1"
    private let logSubsystem = "org.ramaproxy.example.tproxy"
    private let hostLogCategory = "host-app"
    private lazy var hostLogger = Logger(subsystem: logSubsystem, category: hostLogCategory)

    private var statusItem: NSStatusItem?
    private var statusMenuItem: NSMenuItem?
    private var startMenuItem: NSMenuItem?
    private var stopMenuItem: NSMenuItem?
    private var badgeEnabledMenuItem: NSMenuItem?
    private var badgeLabelMenuItem: NSMenuItem?
    private var excludeDomainsMenuItem: NSMenuItem?
    private var resetDemoSettingsMenuItem: NSMenuItem?
    private var resetMenuItem: NSMenuItem?

    private var activeManager: NETransparentProxyManager?
    private var statusObserver: NSObjectProtocol?
    private var statusTimer: DispatchSourceTimer?
    private var lastStatus: NEVPNStatus?
    private var lastLoggedDisconnectSignature: String?
    private var demoSettings = DemoProxySettings()
    private lazy var resetProfileOnLaunch =
        ProcessInfo.processInfo.arguments.contains("--reset-profile-on-launch")

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        log("host app launched")
        if resetProfileOnLaunch {
            log("launch flag detected: resetting saved proxy profile before start")
        }
        startProxy(forceReinstall: resetProfileOnLaunch)
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

    @objc private func resetProfileAction(_: Any?) {
        resetProxyConfigurationAndStart()
    }

    @objc private func toggleHtmlBadgeAction(_: Any?) {
        demoSettings.htmlBadgeEnabled.toggle()
        updateDemoSettingsMenu()
        applyDemoSettings()
    }

    @objc private func editBadgeLabelAction(_: Any?) {
        guard let value = promptForText(
            title: "Badge Label",
            message: "Choose the HTML badge label shown on rewritten pages.",
            defaultValue: demoSettings.htmlBadgeLabel
        )?.trimmingCharacters(in: .whitespacesAndNewlines),
            !value.isEmpty
        else {
            return
        }

        demoSettings.htmlBadgeLabel = value
        updateDemoSettingsMenu()
        applyDemoSettings()
    }

    @objc private func editExcludeDomainsAction(_: Any?) {
        let defaultValue = demoSettings.excludeDomains.joined(separator: ", ")
        guard let value = promptForText(
            title: "Excluded Domains",
            message: "Comma-separated domains that should bypass the demo MITM behavior.",
            defaultValue: defaultValue
        )
        else {
            return
        }

        let domains = value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        demoSettings.excludeDomains = domains.isEmpty ? DemoProxySettings().excludeDomains : domains
        updateDemoSettingsMenu()
        applyDemoSettings()
    }

    @objc private func resetDemoSettingsAction(_: Any?) {
        demoSettings = DemoProxySettings()
        updateDemoSettingsMenu()
        applyDemoSettings()
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

        menu.addItem(NSMenuItem.separator())

        let badgeEnabledItem = NSMenuItem(
            title: "HTML Badge Enabled",
            action: #selector(toggleHtmlBadgeAction(_:)),
            keyEquivalent: ""
        )
        badgeEnabledItem.target = self
        menu.addItem(badgeEnabledItem)

        let badgeLabelItem = NSMenuItem(
            title: "Badge Label…",
            action: #selector(editBadgeLabelAction(_:)),
            keyEquivalent: ""
        )
        badgeLabelItem.target = self
        menu.addItem(badgeLabelItem)

        let excludeDomainsItem = NSMenuItem(
            title: "Excluded Domains…",
            action: #selector(editExcludeDomainsAction(_:)),
            keyEquivalent: ""
        )
        excludeDomainsItem.target = self
        menu.addItem(excludeDomainsItem)

        let resetDemoSettingsItem = NSMenuItem(
            title: "Reset Demo Settings",
            action: #selector(resetDemoSettingsAction(_:)),
            keyEquivalent: ""
        )
        resetDemoSettingsItem.target = self
        menu.addItem(resetDemoSettingsItem)

        menu.addItem(NSMenuItem.separator())

        let resetItem = NSMenuItem(
            title: "Reset Profile", action: #selector(resetProfileAction(_:)), keyEquivalent: "")
        resetItem.target = self
        menu.addItem(resetItem)

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
        self.badgeEnabledMenuItem = badgeEnabledItem
        self.badgeLabelMenuItem = badgeLabelItem
        self.excludeDomainsMenuItem = excludeDomainsItem
        self.resetDemoSettingsMenuItem = resetDemoSettingsItem
        self.resetMenuItem = resetItem
        updateDemoSettingsMenu()
    }

    private func refreshManagerAndStatus() {
        loadManager { [weak self] manager in
            guard let self else { return }
            guard let manager else {
                self.setStatus(status: .invalid, detail: "manager unavailable")
                return
            }

            self.syncDemoSettings(from: manager.protocolConfiguration as? NETunnelProviderProtocol)
            self.activeManager = manager
            self.installStatusObserver(manager: manager)
            self.startStatusTimer(manager: manager)
            self.setStatus(status: manager.connection.status, detail: nil)
        }
    }

    private func startProxy(forceReinstall: Bool = false) {
        loadOrCreateAndConfigureManager(forceReinstall: forceReinstall) { [weak self] manager in
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

    private func resetProxyConfigurationAndStart() {
        log("reset proxy configuration requested")
        stopProxy { [weak self] in
            guard let self else { return }
            self.startProxy(forceReinstall: true)
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
        forceReinstall: Bool = false,
        preserveCurrentDemoSettings: Bool = false,
        completion: @escaping (NETransparentProxyManager?) -> Void
    ) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                self.logError("loadAllFromPreferences error", error)
                completion(nil)
                return
            }

            let existingManager = self.selectManager(from: managers)
            if !preserveCurrentDemoSettings {
                self.syncDemoSettings(
                    from: existingManager?.protocolConfiguration as? NETunnelProviderProtocol
                )
            }
            if forceReinstall {
                let managersToRemove = self.matchingManagers(from: managers)
                if managersToRemove.isEmpty {
                    self.log("forced manager reinstall requested; no existing manager to remove")
                    let manager = NETransparentProxyManager()
                    _ = self.configure(manager: manager)
                    self.log("saving fresh preferences after forced reinstall")
                    self.save(manager: manager, fallbackManager: nil, completion: completion)
                    return
                }

                self.log(
                    "forced manager reinstall requested; removing \(managersToRemove.count) matching manager(s)"
                )
                self.removeManagersFromPreferences(managersToRemove) { removeSucceeded in
                    guard removeSucceeded else {
                        completion(nil)
                        return
                    }

                    let manager = NETransparentProxyManager()
                    _ = self.configure(manager: manager)
                    self.log("saving fresh preferences after forced reinstall")
                    self.save(manager: manager, fallbackManager: nil, completion: completion)
                }
                return
            }

            let manager = existingManager ?? NETransparentProxyManager()
            let isExisting = existingManager != nil
            let changed = self.configure(manager: manager)

            if isExisting, !changed {
                self.log("reusing installed manager without saving preferences")
                completion(manager)
                return
            }

            self.log(isExisting ? "saving updated preferences" : "saving new preferences")
            self.save(manager: manager, fallbackManager: existingManager, completion: completion)
        }
    }

    private func configure(manager: NETransparentProxyManager) -> Bool {
        var changed = false

        let proto = (manager.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()

        if proto.providerBundleIdentifier != extensionBundleId {
            proto.providerBundleIdentifier = extensionBundleId
            changed = true
        }

        if proto.serverAddress != managerServerAddress {
            proto.serverAddress = managerServerAddress
            changed = true
        }

        let expectedProviderConfiguration = currentProviderConfiguration()
        let existingEngineConfigJson = proto.providerConfiguration?["engineConfigJson"] as? String
        let expectedEngineConfigJson = expectedProviderConfiguration["engineConfigJson"] as? String
        if proto.providerConfiguration == nil
            || existingEngineConfigJson != expectedEngineConfigJson
        {
            proto.providerConfiguration = expectedProviderConfiguration
            changed = true
        }

        if manager.localizedDescription != managerDescription {
            manager.localizedDescription = managerDescription
            changed = true
        }

        if manager.protocolConfiguration == nil
            || !self.protocolMatchesExpected(manager.protocolConfiguration as? NETunnelProviderProtocol)
        {
            manager.protocolConfiguration = proto
            changed = true
        }

        if !manager.isEnabled {
            manager.isEnabled = true
            changed = true
        }

        return changed
    }

    private func protocolMatchesExpected(_ proto: NETunnelProviderProtocol?) -> Bool {
        guard let proto else {
            return false
        }

        return proto.providerBundleIdentifier == extensionBundleId
            && proto.serverAddress == managerServerAddress
            && (proto.providerConfiguration?["engineConfigJson"] as? String)
                == (currentProviderConfiguration()["engineConfigJson"] as? String)
    }

    private func currentProviderConfiguration() -> [String: Any] {
        guard let engineConfigJson = currentEngineConfigJson() else {
            return [:]
        }

        return ["engineConfigJson": engineConfigJson]
    }

    private func currentEngineConfigJson() -> String? {
        if demoSettings.isDefault {
            return nil
        }

        let config: [String: Any] = [
            "html_badge_enabled": demoSettings.htmlBadgeEnabled,
            "html_badge_label": demoSettings.htmlBadgeLabel,
            "exclude_domains": demoSettings.excludeDomains,
        ]

        guard JSONSerialization.isValidJSONObject(config),
            let data = try? JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]),
            let json = String(data: data, encoding: .utf8)
        else {
            logErrorText("failed to encode engineConfigJson from host args/env")
            return nil
        }

        log("engineConfigJson=\(json)")
        return json
    }

    private func syncDemoSettings(from proto: NETunnelProviderProtocol?) {
        demoSettings = Self.demoSettings(from: proto) ?? DemoProxySettings()
        updateDemoSettingsMenu()
    }

    private static func demoSettings(from proto: NETunnelProviderProtocol?) -> DemoProxySettings? {
        guard let json = proto?.providerConfiguration?["engineConfigJson"] as? String,
            let data = json.data(using: .utf8),
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return nil
        }

        var settings = DemoProxySettings()
        if let htmlBadgeEnabled = object["html_badge_enabled"] as? Bool {
            settings.htmlBadgeEnabled = htmlBadgeEnabled
        }
        if let htmlBadgeLabel = object["html_badge_label"] as? String,
            !htmlBadgeLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        {
            settings.htmlBadgeLabel = htmlBadgeLabel
        }
        if let excludeDomains = object["exclude_domains"] as? [String] {
            let domains = excludeDomains
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            if !domains.isEmpty {
                settings.excludeDomains = domains
            }
        }
        return settings
    }

    private func updateDemoSettingsMenu() {
        badgeEnabledMenuItem?.state = demoSettings.htmlBadgeEnabled ? .on : .off
        badgeLabelMenuItem?.title = "Badge Label… (\(demoSettings.htmlBadgeLabel))"
        excludeDomainsMenuItem?.title =
            "Excluded Domains… (\(demoSettings.excludeDomains.count))"
    }

    private func applyDemoSettings() {
        let shouldRestart = {
            guard let activeManager else {
                return false
            }
            switch activeManager.connection.status {
            case .connected, .connecting, .reasserting:
                return true
            default:
                return false
            }
        }()

        loadOrCreateAndConfigureManager(preserveCurrentDemoSettings: true) { [weak self] manager in
            guard let self else { return }
            guard let manager else {
                self.setStatus(status: .invalid, detail: "configuration failed")
                return
            }

            self.activeManager = manager
            self.installStatusObserver(manager: manager)
            self.startStatusTimer(manager: manager)
            if shouldRestart {
                self.log("demo settings changed; restarting proxy to apply")
                self.stopProxyAndWaitForDisconnect(manager: manager) { [weak self] in
                    self?.startProxy()
                }
                return
            }

            self.setStatus(status: manager.connection.status, detail: "demo settings saved")
        }
    }

    private func stopProxyAndWaitForDisconnect(
        manager: NETransparentProxyManager,
        completion: @escaping () -> Void
    ) {
        self.log("calling stopVPNTunnel")
        manager.connection.stopVPNTunnel()
        self.setStatus(status: manager.connection.status, detail: "applying demo settings")

        waitUntilDisconnected(manager: manager, remainingAttempts: 40, completion: completion)
    }

    private func waitUntilDisconnected(
        manager: NETransparentProxyManager,
        remainingAttempts: Int,
        completion: @escaping () -> Void
    ) {
        switch manager.connection.status {
        case .disconnected, .invalid:
            completion()
        case .disconnecting, .connected, .connecting, .reasserting:
            guard remainingAttempts > 0 else {
                log("disconnect wait timed out; attempting restart anyway")
                completion()
                return
            }

            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
                guard let self else { return }
                self.waitUntilDisconnected(
                    manager: manager,
                    remainingAttempts: remainingAttempts - 1,
                    completion: completion
                )
            }
        @unknown default:
            completion()
        }
    }

    private func promptForText(
        title: String,
        message: String,
        defaultValue: String
    ) -> String? {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .informational
        alert.addButton(withTitle: "Save")
        alert.addButton(withTitle: "Cancel")

        let textField = NSTextField(string: defaultValue)
        textField.frame = NSRect(x: 0, y: 0, width: 320, height: 24)
        alert.accessoryView = textField

        guard alert.runModal() == .alertFirstButtonReturn else {
            return nil
        }

        return textField.stringValue
    }

    private func save(
        manager: NETransparentProxyManager,
        fallbackManager: NETransparentProxyManager?,
        completion: @escaping (NETransparentProxyManager?) -> Void
    ) {
        manager.saveToPreferences { saveError in
            if let saveError {
                self.logError("saveToPreferences error", saveError)
                if let fallbackManager {
                    self.log("falling back to existing manager after save failure")
                    completion(fallbackManager)
                    return
                }
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

    private func matchingManagers(from managers: [NETransparentProxyManager]?)
        -> [NETransparentProxyManager]
    {
        guard let managers else {
            return []
        }

        return managers.filter { manager in
            if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                proto.providerBundleIdentifier == self.extensionBundleId
            {
                return true
            }

            return manager.localizedDescription == self.managerDescription
        }
    }

    private func removeManagersFromPreferences(
        _ managers: [NETransparentProxyManager],
        completion: @escaping (Bool) -> Void
    ) {
        guard let manager = managers.first else {
            completion(true)
            return
        }

        manager.removeFromPreferences { error in
            if let error {
                self.logError("removeFromPreferences error", error)
                completion(false)
                return
            }

            self.log("removeFromPreferences ok")
            self.removeManagersFromPreferences(Array(managers.dropFirst()), completion: completion)
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
        let effectiveDetail =
            detail ?? disconnectStatusDetail(for: status, error: lastDisconnectError())
        let title =
            effectiveDetail.map { "Status: \(statusText) (\($0))" } ?? "Status: \(statusText)"
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

        let previousStatusText = lastStatus.map(statusString)
        if previousStatusText != statusText {
            if let previousStatusText {
                log("status transition \(previousStatusText) -> \(statusText)")
            } else {
                log("status=\(statusText)")
            }
        }
        logDisconnectReasonIfNeeded(for: status)
        lastStatus = status
    }

    private func logDisconnectReasonIfNeeded(for status: NEVPNStatus) {
        guard isDisconnected(status) else {
            if !isDisconnecting(status) {
                lastLoggedDisconnectSignature = nil
            }
            return
        }

        guard let error = lastDisconnectError() else {
            if lastLoggedDisconnectSignature != "none" {
                log("status=disconnected reason=<none reported by NetworkExtension>")
                lastLoggedDisconnectSignature = "none"
            }
            return
        }

        let ns = error as NSError
        let signature = "\(ns.domain)#\(ns.code)#\(ns.localizedDescription)"
        guard lastLoggedDisconnectSignature != signature else {
            return
        }

        lastLoggedDisconnectSignature = signature
        if let hint = disconnectDebugHint(ns) {
            log("debug hint: \(hint)")
        }
        logDisconnectReason(error)
    }

    private func lastDisconnectError() -> Error? {
        guard let connection = activeManager?.connection as? NSObject else {
            return nil
        }

        let selector = NSSelectorFromString("lastDisconnectError")
        guard connection.responds(to: selector) else {
            return nil
        }

        return connection.value(forKey: "lastDisconnectError") as? Error
    }

    private func isDisconnected(_ status: NEVPNStatus) -> Bool {
        if case .disconnected = status {
            return true
        }
        return false
    }

    private func isDisconnecting(_ status: NEVPNStatus) -> Bool {
        if case .disconnecting = status {
            return true
        }
        return false
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

    private func logDisconnectReason(_ error: Error) {
        let ns = error as NSError
        let classification = classifyDisconnectReason(ns)
        hostLogger.error(
            "status=disconnected reason: classification=\(classification, privacy: .public) domain=\(ns.domain, privacy: .public) code=\(ns.code, privacy: .public) description=\(ns.localizedDescription, privacy: .public) userInfo=\(String(describing: ns.userInfo), privacy: .public)"
        )
    }

    private func logError(_ prefix: String, _ error: Error) {
        let ns = error as NSError
        hostLogger.error(
            "\(prefix, privacy: .public): domain=\(ns.domain, privacy: .public) code=\(ns.code, privacy: .public) description=\(ns.localizedDescription, privacy: .public) userInfo=\(String(describing: ns.userInfo), privacy: .public)"
        )
    }

    private func logErrorText(_ message: String) {
        hostLogger.error("\(message, privacy: .public)")
    }

    private func classifyDisconnectReason(_ error: NSError) -> String {
        switch error.domain {
        case "NEVPNConnectionErrorDomainPlugin":
            return
                "extension/plugin startup failure; provider likely failed before it could report its own NSError"
        case "NEVPNConnectionErrorDomain":
            return classifySystemDisconnectReason(code: error.code)
        default:
            return
                "provider-reported disconnect or nonstandard NetworkExtension error; inspect domain/code directly"
        }
    }

    private func classifySystemDisconnectReason(code: Int) -> String {
        switch code {
        case 1:
            return "system sleep interrupted the VPN session"
        case 2:
            return "no network was available to establish the VPN session"
        case 3:
            return "network conditions changed and the VPN session could not be maintained"
        case 4:
            return "VPN configuration was invalid"
        case 5:
            return "VPN server address resolution failed"
        case 6:
            return "VPN server did not respond"
        case 7:
            return "VPN server is no longer functioning"
        case 8:
            return "VPN authentication failed"
        case 9:
            return "client certificate is invalid"
        case 10:
            return "client certificate is not yet valid"
        case 11:
            return "client certificate expired"
        case 12:
            return "VPN plugin died unexpectedly"
        case 13:
            return "VPN configuration could not be found"
        case 14:
            return "VPN plugin is disabled or unavailable"
        case 15:
            return "VPN protocol negotiation failed"
        case 16:
            return "VPN server disconnected the session"
        case 17:
            return "VPN server certificate is invalid"
        case 18:
            return "VPN server certificate is not yet valid"
        case 19:
            return "VPN server certificate expired"
        default:
            return "unknown system VPN disconnect reason"
        }
    }

    private func disconnectStatusDetail(for status: NEVPNStatus, error: Error?) -> String? {
        guard isDisconnected(status), let error else {
            return nil
        }

        let ns = error as NSError
        switch (ns.domain, ns.code) {
        case ("NEVPNConnectionErrorDomainPlugin", 6):
            return "appex unavailable; reinstall app or reset profile"
        case ("NEVPNConnectionErrorDomainPlugin", 7):
            return "provider crashed; inspect extension logs/crash report"
        case ("NEVPNConnectionErrorDomain", 12):
            return "plugin died unexpectedly; inspect extension crash report"
        case ("NEVPNConnectionErrorDomain", 14):
            return "plugin disabled; reinstall app and recreate profile"
        default:
            return nil
        }
    }

    private func disconnectDebugHint(_ error: NSError) -> String? {
        switch (error.domain, error.code) {
        case ("NEVPNConnectionErrorDomainPlugin", 6):
            return
                "run `just install-tproxy-with-signing`; then check `pluginkit -mAvv | rg org.ramaproxy.example.tproxy`"
        case ("NEVPNConnectionErrorDomainPlugin", 7), ("NEVPNConnectionErrorDomain", 12):
            return
                "inspect `~/Library/Logs/DiagnosticReports/RamaTransparentProxyExampleExtension*.ips` and `log show --last 5m --style compact --predicate 'process == \"RamaTransparentProxyExampleExtension\" OR subsystem == \"org.ramaproxy.example.tproxy\"'`"
        case ("NEVPNConnectionErrorDomain", 14):
            return
                "plugin was disabled after a failure; reinstall with `just install-tproxy-with-signing` to reset registration and profile"
        default:
            return nil
        }
    }
}

let app = NSApplication.shared
let delegate = HostController()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
