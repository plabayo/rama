import Foundation
import NetworkExtension

extension ContainerController {
    func refreshManagerAndStatus() {
        loadManager { [weak self] manager in
            guard let self else { return }
            guard let manager else {
                self.setStatus(status: .invalid, detail: "manager unavailable")
                return
            }

            // Only restore demoSettings from NE preferences on first run.
            // After that, in-memory demoSettings is authoritative.
            if !self.settingsInitializedFromNE {
                self.syncDemoSettings(from: manager.protocolConfiguration as? NETunnelProviderProtocol)
                self.settingsInitializedFromNE = true
            }
            self.activeManager = manager
            self.installStatusObserver(manager: manager)
            self.startStatusTimer(manager: manager)
            self.setStatus(status: manager.connection.status, detail: nil)
        }
    }

    func startProxy(forceReinstall: Bool = false) {
        ensureSystemExtensionActivated { [weak self] success in
            guard let self else { return }
            guard success else {
                self.setStatus(status: .invalid, detail: "system extension unavailable")
                return
            }
            self.startProxyAfterProviderReady(forceReinstall: forceReinstall)
        }
    }

    func startProxyAfterProviderReady(forceReinstall: Bool = false) {
        self.loadOrCreateAndConfigureManager(forceReinstall: forceReinstall) {
            [weak self] manager in
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

    func resetProxyConfigurationAndStart() {
        log("reset proxy configuration requested")
        stopProxy { [weak self] in
            guard let self else { return }
            self.startProxy(forceReinstall: true)
        }
    }

    func stopProxy(completion: (() -> Void)?) {
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

            // Flush current in-memory settings to NE preferences before stopping so that
            // any live XPC-pushed changes are picked up on the next start.
            // preserveCurrentDemoSettings: true — use in-memory demoSettings, not NE values.
            self.loadOrCreateAndConfigureManager(preserveCurrentDemoSettings: true) {
                [weak self] _ in
                guard let self else {
                    completion?()
                    return
                }
                self.log("calling stopVPNTunnel")
                manager.connection.stopVPNTunnel()
                self.setStatus(status: manager.connection.status, detail: nil)
                completion?()
            }
        }
    }

    func applyDemoSettings() {
        // If the proxy is already running, push changes live via XPC only.
        // Calling loadOrCreateAndConfigureManager would save a new providerConfiguration
        // to NE preferences; NE detects the change and tears down the running provider.
        // Settings will be flushed to NE preferences when the proxy is stopped.
        let isActive: Bool = {
            guard let activeManager else { return false }
            switch activeManager.connection.status {
            case .connected, .connecting, .reasserting:
                return true
            default:
                return false
            }
        }()

        if isActive {
            log("proxy active: pushing settings update via XPC (skipping NE config save to avoid restart)")
            sendXpcUpdateSettings()
            setStatus(status: activeManager?.connection.status ?? .invalid, detail: "demo settings applied")
            return
        }

        // Proxy not running: persist the new settings to NE preferences.
        loadOrCreateAndConfigureManager(preserveCurrentDemoSettings: true) { [weak self] manager in
            guard let self else { return }
            guard let manager else {
                self.setStatus(status: .invalid, detail: "configuration failed")
                return
            }
            self.activeManager = manager
            self.installStatusObserver(manager: manager)
            self.startStatusTimer(manager: manager)
            self.setStatus(status: manager.connection.status, detail: "demo settings saved")
        }
    }

    func rotateMITMCAAndApply() {
        log("rotating MITM CA")
        clearCA()
        applyDemoSettings()
    }

    func sendProviderPing() {
        guard let manager = activeManager else {
            logErrorText("provider ping failed: no active manager")
            showPingError("No active manager. Is the proxy running?")
            return
        }

        guard let session = manager.connection as? NETunnelProviderSession else {
            logErrorText("provider ping failed: active connection is not a NETunnelProviderSession")
            showPingError("Active connection is not a tunnel session.")
            return
        }

        let payload: [String: Any] = [
            "op": "ping",
            "sent_at": ISO8601DateFormatter().string(from: Date()),
            "source": "container-app",
        ]

        let data: Data
        do {
            data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        } catch {
            logError("provider ping serialization failed", error)
            showPingError("Failed to serialize ping payload: \(error.localizedDescription)")
            return
        }

        log("sending provider message bytes=\(data.count)")
        do {
            try session.sendProviderMessage(data) { [weak self] reply in
                guard let self else { return }
                guard let reply else {
                    self.log("provider message completed without reply payload")
                    DispatchQueue.main.async { self.showPingError("Provider returned no reply.") }
                    return
                }

                if let text = String(data: reply, encoding: .utf8) {
                    self.log("provider message reply utf8=\(text)")
                } else {
                    self.log("provider message reply bytes=\(reply.count)")
                }
                DispatchQueue.main.async { self.flashPingSuccess() }
            }
        } catch {
            logError("provider ping sendProviderMessage failed", error)
            showPingError("Failed to send ping: \(error.localizedDescription)")
        }
    }

    func stopProxyAndWaitForDisconnect(
        manager: NETransparentProxyManager,
        completion: @escaping () -> Void
    ) {
        self.log("calling stopVPNTunnel")
        manager.connection.stopVPNTunnel()
        self.setStatus(status: manager.connection.status, detail: "applying demo settings")

        waitUntilDisconnected(manager: manager, remainingAttempts: 40, completion: completion)
    }

    func waitUntilDisconnected(
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

    func loadManager(completion: @escaping (NETransparentProxyManager?) -> Void) {
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

    func loadOrCreateAndConfigureManager(
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
            // Sync from NE preferences only on the very first call (app launch). After
            // that, in-memory demoSettings is the authoritative source so that live XPC
            // updates survive an unexpected provider stop followed by a manual restart,
            // without the stale NE values overwriting what the user already changed.
            if !preserveCurrentDemoSettings && !self.settingsInitializedFromNE {
                self.syncDemoSettings(
                    from: existingManager?.protocolConfiguration as? NETunnelProviderProtocol
                )
                self.settingsInitializedFromNE = true
            }
            if forceReinstall {
                let managersToRemove = self.matchingManagers(from: managers)
                if managersToRemove.isEmpty {
                    self.log("forced manager reinstall requested; no existing manager to remove")
                    let manager = NETransparentProxyManager()
                    do {
                        _ = try self.configure(manager: manager)
                    } catch {
                        self.logError("configure manager error", error)
                        completion(nil)
                        return
                    }
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
                    do {
                        _ = try self.configure(manager: manager)
                    } catch {
                        self.logError("configure manager error", error)
                        completion(nil)
                        return
                    }
                    self.log("saving fresh preferences after forced reinstall")
                    self.save(manager: manager, fallbackManager: nil, completion: completion)
                }
                return
            }

            let manager = existingManager ?? NETransparentProxyManager()
            let isExisting = existingManager != nil
            let changed: Bool
            do {
                changed = try self.configure(manager: manager)
            } catch {
                self.logError("configure manager error", error)
                completion(nil)
                return
            }

            if isExisting, !changed {
                self.log("reusing installed manager without saving preferences")
                completion(manager)
                return
            }

            self.log(isExisting ? "saving updated preferences" : "saving new preferences")
            self.save(manager: manager, fallbackManager: existingManager, completion: completion)
        }
    }

    func configure(manager: NETransparentProxyManager) throws -> Bool {
        var changed = false

        let proto =
            (manager.protocolConfiguration as? NETunnelProviderProtocol)
            ?? NETunnelProviderProtocol()

        if proto.providerBundleIdentifier != extensionBundleId {
            proto.providerBundleIdentifier = extensionBundleId
            changed = true
        }

        if proto.serverAddress != managerServerAddress {
            proto.serverAddress = managerServerAddress
            changed = true
        }

        if proto.disconnectOnSleep {
            proto.disconnectOnSleep = false
            changed = true
        }

        let expectedProviderConfiguration = try currentProviderConfiguration()
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
            || !self.protocolMatchesExpected(
                manager.protocolConfiguration as? NETunnelProviderProtocol)
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

    func protocolMatchesExpected(_ proto: NETunnelProviderProtocol?) -> Bool {
        guard let proto else {
            return false
        }

        let expectedEngineConfigJson = try? currentEngineConfigJson()
        guard let expectedEngineConfigJson else {
            return false
        }

        return proto.providerBundleIdentifier == extensionBundleId
            && proto.serverAddress == managerServerAddress
            && (proto.providerConfiguration?["engineConfigJson"] as? String)
                == expectedEngineConfigJson
    }

    func currentProviderConfiguration() throws -> [String: Any] {
        ["engineConfigJson": try currentEngineConfigJson()]
    }

    func currentEngineConfigJson() throws -> String {
        let payload = ProxyEngineConfigPayload(
            htmlBadgeEnabled: demoSettings.htmlBadgeEnabled,
            htmlBadgeLabel: demoSettings.htmlBadgeLabel,
            tcpConnectTimeoutMs: demoSettings.tcpConnectTimeoutMs,
            excludeDomains: demoSettings.excludeDomains,
            xpcServiceName: xpcServiceName,
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(payload)
        guard let json = String(data: data, encoding: .utf8) else {
            throw NSError(
                domain: "RamaTransparentProxyExampleContainer",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "failed to encode engineConfigJson as UTF-8"]
            )
        }

        log("engineConfigJson refreshed")
        return json
    }

    func syncDemoSettings(from proto: NETunnelProviderProtocol?) {
        demoSettings = Self.demoSettings(from: proto) ?? DemoProxySettings()
        updateDemoSettingsMenu()
    }

    static func demoSettings(from proto: NETunnelProviderProtocol?) -> DemoProxySettings? {
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
        if let tcpConnectTimeoutMs = object["tcp_connect_timeout_ms"] as? Int,
            tcpConnectTimeoutMs > 0
        {
            settings.tcpConnectTimeoutMs = tcpConnectTimeoutMs
        }
        if let excludeDomains = object["exclude_domains"] as? [String] {
            let domains =
                excludeDomains
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
            if !domains.isEmpty {
                settings.excludeDomains = domains
            }
        }
        return settings
    }

    func save(
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

    func selectManager(from managers: [NETransparentProxyManager]?)
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

    func matchingManagers(from managers: [NETransparentProxyManager]?)
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

    func removeManagersFromPreferences(
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
}
