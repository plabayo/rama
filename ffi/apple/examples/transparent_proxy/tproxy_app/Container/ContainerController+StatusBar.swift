import AppKit
import NetworkExtension

extension ContainerController {
    func setupStatusItem() {
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

        let rotateCAItem = NSMenuItem(
            title: "Rotate MITM CA",
            action: #selector(rotateCAAction(_:)),
            keyEquivalent: ""
        )
        rotateCAItem.target = self
        menu.addItem(rotateCAItem)

        let pingProviderItem = NSMenuItem(
            title: "Ping Provider",
            action: #selector(pingProviderAction(_:)),
            keyEquivalent: ""
        )
        pingProviderItem.target = self
        menu.addItem(pingProviderItem)

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
        self.rotateCAMenuItem = rotateCAItem
        self.pingProviderMenuItem = pingProviderItem
        self.resetMenuItem = resetItem
        updateDemoSettingsMenu()
    }

    func updateDemoSettingsMenu() {
        badgeEnabledMenuItem?.state = demoSettings.htmlBadgeEnabled ? .on : .off
        badgeLabelMenuItem?.title = "Badge Label… (\(demoSettings.htmlBadgeLabel))"
        excludeDomainsMenuItem?.title =
            "Excluded Domains… (\(demoSettings.excludeDomains.count))"
        rotateCAMenuItem?.title = "Rotate MITM CA"
    }

    func setStatus(status: NEVPNStatus, detail: String?) {
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

    func statusString(_ status: NEVPNStatus) -> String {
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

    func installStatusObserver(manager: NETransparentProxyManager) {
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

    func startStatusTimer(manager: NETransparentProxyManager) {
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

    func logDisconnectReasonIfNeeded(for status: NEVPNStatus) {
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

    func lastDisconnectError() -> Error? {
        guard let connection = activeManager?.connection as? NSObject else {
            return nil
        }

        let selector = NSSelectorFromString("lastDisconnectError")
        guard connection.responds(to: selector) else {
            return nil
        }

        return connection.value(forKey: "lastDisconnectError") as? Error
    }

    func isDisconnected(_ status: NEVPNStatus) -> Bool {
        if case .disconnected = status { return true }
        return false
    }

    func isDisconnecting(_ status: NEVPNStatus) -> Bool {
        if case .disconnecting = status { return true }
        return false
    }

    func disconnectStatusDetail(for status: NEVPNStatus, error: Error?) -> String? {
        guard isDisconnected(status), let error else {
            return nil
        }

        let ns = error as NSError
        switch (ns.domain, ns.code) {
        case ("NEVPNConnectionErrorDomainPlugin", 6):
            return "extension unavailable; reinstall the app and verify `systemextensionsctl list`"
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

    func disconnectDebugHint(_ error: NSError) -> String? {
        switch (error.domain, error.code) {
        case ("NEVPNConnectionErrorDomainPlugin", 6):
            return
                "reinstall with `just install-tproxy-with-signing` or `just install-tproxy-with-developer-id-signing-reset-profile`, then run `systemextensionsctl list`"
        case ("NEVPNConnectionErrorDomainPlugin", 7), ("NEVPNConnectionErrorDomain", 12):
            return
                "inspect `~/Library/Logs/DiagnosticReports/RamaTransparentProxyExampleExtension*.ips` and `log show --last 5m --style compact --predicate 'process == \"RamaTransparentProxyExampleExtension\" OR subsystem == \"org.ramaproxy.example.tproxy\"'`"
        case ("NEVPNConnectionErrorDomain", 14):
            return
                "extension was disabled after a failure; reinstall the app, then run `systemextensionsctl list` and retry"
        default:
            return nil
        }
    }
}
