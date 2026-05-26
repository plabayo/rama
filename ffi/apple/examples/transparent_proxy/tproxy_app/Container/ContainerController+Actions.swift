import AppKit

extension ContainerController {
    @objc func startProxyAction(_: Any?) {
        startProxy()
    }

    @objc func stopProxyAction(_: Any?) {
        stopProxy(completion: nil)
    }

    @objc func resetProfileAction(_: Any?) {
        resetProxyConfigurationAndStart()
    }

    @objc func rotateCAAction(_: Any?) {
        rotateMITMCAAndApply()
    }

    @objc func installCAAction(_: Any?) {
        installMITMCA()
    }

    @objc func clearCAAction(_: Any?) {
        clearCA()
    }

    @objc func pingProviderAction(_: Any?) {
        sendProviderPing()
    }

    @objc func toggleHtmlBadgeAction(_: Any?) {
        demoSettings.htmlBadgeEnabled.toggle()
        updateDemoSettingsMenu()
        applyDemoSettings()
    }

    @objc func editBadgeLabelAction(_: Any?) {
        guard
            let value = promptForText(
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

    @objc func editExcludeDomainsAction(_: Any?) {
        let defaultValue = demoSettings.excludeDomains.joined(separator: ", ")
        guard
            let value = promptForText(
                title: "Excluded Domains",
                message: "Comma-separated domains that should bypass the demo MITM behavior.",
                defaultValue: defaultValue
            )
        else {
            return
        }

        let domains =
            value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        demoSettings.excludeDomains = domains.isEmpty ? DemoProxySettings().excludeDomains : domains
        updateDemoSettingsMenu()
        applyDemoSettings()
    }

    @objc func resetDemoSettingsAction(_: Any?) {
        demoSettings = DemoProxySettings()
        updateDemoSettingsMenu()
        applyDemoSettings()
    }

    /// Flip the TLS keylog toggle via XPC. Runtime-only: the sysext
    /// holds a `ToggleableKeyLogSink`'s `AtomicBool` and flips it in
    /// place, so no proxy restart is required. State is never
    /// persisted — a sysext restart resets it to OFF.
    ///
    /// Sysext writes rotated session-key files (hourly buckets, 8 h
    /// retention) to `~root/Library/Application Support/rama/tproxy/keylog/`.
    @objc func toggleTlsKeylogAction(_: Any?) {
        guard isProviderActive() else {
            showProviderInactiveAlert(action: "Toggle TLS Keylog")
            return
        }
        guard !xpcServiceName.isEmpty else {
            logErrorText(
                "toggleTlsKeylog: xpcServiceName is empty — check ProviderMachServiceName in Info.plist"
            )
            showCommandErrorAlert(
                title: "TLS Keylog Toggle Failed",
                message: "XPC service name is empty. Reinstall the container app."
            )
            return
        }

        let requested = !demoSettings.tlsKeylogEnabled
        let client = ramaXpcClient
        log("toggleTlsKeylog: requesting enabled=\(requested) via XPC")
        Task { [weak self] in
            do {
                let reply = try await client.call(
                    RamaTproxySetTlsKeylog.self,
                    RamaTproxySetTlsKeylog.Request(enabled: requested)
                )
                await MainActor.run {
                    guard let self else { return }
                    self.demoSettings.tlsKeylogEnabled = reply.enabled
                    self.updateDemoSettingsMenu()
                    self.log("toggleTlsKeylog: sysext now enabled=\(reply.enabled)")
                }
            } catch {
                await MainActor.run {
                    self?.logError("toggleTlsKeylog: XPC failed", error)
                    self?.showCommandErrorAlert(
                        title: "TLS Keylog Toggle Failed",
                        message: error.localizedDescription
                    )
                }
            }
        }
    }

    @objc func refreshAction(_: Any?) {
        refreshManagerAndStatus()
    }

    @objc func quitAction(_: Any?) {
        NSApplication.shared.terminate(nil)
    }

    func promptForText(
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

    func showPingError(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Ping Failed"
        alert.informativeText = message
        alert.alertStyle = .critical
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    func flashPingSuccess() {
        guard let button = statusItem?.button else { return }
        button.title = "🟢 tproxy demo"
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak button] in
            button?.title = "🦙 tproxy demo"
        }
    }
}
