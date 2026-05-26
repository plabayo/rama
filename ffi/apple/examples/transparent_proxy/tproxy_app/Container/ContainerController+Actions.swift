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

    /// Flip the TLS keylog toggle. Baked at engine-construction time
    /// (it's a `KeyLogIntent` on the `TlsMitmRelay`), so a change
    /// while the proxy is connected requires the provider to
    /// restart — confirm with the user first. While inactive the
    /// change just goes into in-memory `demoSettings` and is
    /// persisted via the normal `applyDemoSettings` path; it takes
    /// effect on the next `Start Proxy`.
    @objc func toggleTlsKeylogAction(_: Any?) {
        let newValue = !demoSettings.tlsKeylogEnabled
        // Sysext writes to its Application Support container; mention
        // it in the dialog so users know where to grab the file from.
        let pathHint =
            "~root/Library/Application Support/rama/tproxy/sslkeylog.txt"

        let isActive: Bool = {
            guard let activeManager else { return false }
            switch activeManager.connection.status {
            case .connected, .connecting, .reasserting: return true
            default: return false
            }
        }()

        if !isActive {
            demoSettings.tlsKeylogEnabled = newValue
            updateDemoSettingsMenu()
            if newValue {
                log("TLS keylog ENABLED (proxy inactive); takes effect on next Start Proxy. Sysext path: \(pathHint)")
            } else {
                log("TLS keylog disabled (proxy inactive)")
            }
            applyDemoSettings()
            return
        }

        let alert = NSAlert()
        alert.messageText =
            newValue
            ? "Enable TLS Session Key Logging?"
            : "Disable TLS Session Key Logging?"
        let detail =
            newValue
            ? """
              The MITM relay's keylog sink is baked at engine \
              construction. Enabling it requires restarting the proxy \
              (your connection will briefly drop).

              Once enabled the sysext writes session keys to:

                  \(pathHint)

              Anyone with read access to that file can decrypt every \
              relayed flow while logging is on. Disable it when done.
              """
            : """
              Disabling the keylog requires restarting the proxy \
              (your connection will briefly drop). The existing key \
              file is not deleted.
              """
        alert.informativeText = detail
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Restart Proxy")
        alert.addButton(withTitle: "Cancel")

        guard alert.runModal() == .alertFirstButtonReturn else {
            log("TLS keylog toggle cancelled")
            return
        }

        guard let manager = activeManager else {
            // Active flipped to nil between the check and the
            // confirmation (manager invalidated). Fall through to
            // the inactive path.
            demoSettings.tlsKeylogEnabled = newValue
            updateDemoSettingsMenu()
            applyDemoSettings()
            return
        }

        demoSettings.tlsKeylogEnabled = newValue
        updateDemoSettingsMenu()
        log(
            newValue
                ? "TLS keylog ENABLED; restarting provider. Sysext path: \(pathHint)"
                : "TLS keylog disabled; restarting provider"
        )

        stopProxyAndWaitForDisconnect(manager: manager) { [weak self] in
            guard let self else { return }
            self.log("restarting provider after TLS keylog toggle")
            self.startProxyAfterProviderReady()
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
