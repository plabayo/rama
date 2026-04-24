import AppKit

extension HostController {
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
}
