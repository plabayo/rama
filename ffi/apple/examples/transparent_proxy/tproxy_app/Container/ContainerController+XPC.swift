import AppKit
import Foundation
import NetworkExtension
import RamaAppleXpcClient

extension ContainerController {
    /// One-shot connections, no persistent state.
    var ramaXpcClient: RamaXpcClient {
        RamaXpcClient(
            serviceName: xpcServiceName,
            expectedPeerSigningIdentifier: extensionBundleId)
    }

    /// `true` while the connection is `.connected` / `.connecting` /
    /// `.reasserting`. CA / settings XPC routes are gated on this so we
    /// never try to talk to a sysext that isn't up.
    func isProviderActive() -> Bool {
        guard let manager = activeManager else { return false }
        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            return true
        default:
            return false
        }
    }

    /// Refresh the menu's TLS-keylog checkmark from the sysext's
    /// authoritative state. Called after the provider transitions to
    /// `.connected` — the sysext's toggle is never persisted, so the
    /// state on fresh launches is always `false`, but pulling it
    /// keeps things truthful if the sysext was already running.
    func syncTlsKeylogStateFromSysext() {
        guard !xpcServiceName.isEmpty, isProviderActive() else { return }
        let client = ramaXpcClient
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let reply = try await client.call(RamaTproxyGetTlsKeylog.self)
                self.demoSettings.tlsKeylogEnabled = reply.enabled
                self.updateDemoSettingsMenu()
                self.log("syncTlsKeylogStateFromSysext: enabled=\(reply.enabled)")
            } catch {
                self.logError("syncTlsKeylogStateFromSysext: XPC failed", error)
            }
        }
    }

    /// Push the current demo settings to the running sysext.
    /// Fire-and-forget; only runs while the proxy is active.
    func sendXpcUpdateSettings(updateVerification: Bool = false) {
        guard !xpcServiceName.isEmpty else {
            log("sendXpcUpdateSettings: xpcServiceName is empty, skipping")
            return
        }

        let request = RamaTproxyUpdateSettings.Request(
            verify_upstream_certificates: updateVerification
                ? demoSettings.verifyUpstreamCertificates : nil,
            html_badge_enabled: demoSettings.htmlBadgeEnabled,
            html_badge_label: demoSettings.htmlBadgeLabel,
            exclude_domains: demoSettings.excludeDomains
        )

        log(
            "sendXpcUpdateSettings: dispatching update (badge=\(demoSettings.htmlBadgeEnabled), badge_label=\(demoSettings.htmlBadgeLabel), excludeDomains=\(demoSettings.excludeDomains.count))"
        )

        if updateVerification {
            upstreamVerificationRevision += 1
            upstreamVerificationPending = true
            updateDemoSettingsMenu()
        }
        let revision = upstreamVerificationRevision
        let client = ramaXpcClient
        Task { @MainActor [weak self] in
            guard let self else { return }
            defer {
                if updateVerification {
                    self.upstreamVerificationPending = false
                    self.updateDemoSettingsMenu()
                }
            }
            do {
                let reply = try await client.call(RamaTproxyUpdateSettings.self, request)
                if updateVerification && revision == self.upstreamVerificationRevision {
                    self.demoSettings.verifyUpstreamCertificates =
                        reply.verify_upstream_certificates
                }
                self.log("sendXpcUpdateSettings: ok=\(reply.ok)")
            } catch {
                self.logError("sendXpcUpdateSettings: failed", error)
                if updateVerification {
                    self.upstreamVerificationPending = false
                    self.syncUpstreamVerificationState()
                }
            }
        }
    }

    func showCommandErrorAlert(title: String, message: String) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = title
            alert.informativeText = message
            alert.alertStyle = .critical
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }

    func showProviderInactiveAlert(action: String) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = action
            alert.informativeText = "Start the proxy first."
            alert.alertStyle = .warning
            alert.addButton(withTitle: "OK")
            alert.runModal()
        }
    }
}

extension ContainerController {
    /// Only display a running provider's acknowledged policy.
    func syncUpstreamVerificationState() {
        guard isProviderActive(), !upstreamVerificationPending else { return }
        let revision = upstreamVerificationRevision
        let client = ramaXpcClient
        Task { @MainActor [weak self] in
            guard let self else { return }
            do {
                let reply = try await client.call(
                    RamaTproxyUpdateSettings.self,
                    RamaTproxyUpdateSettings.Request(
                        verify_upstream_certificates: nil,
                        html_badge_enabled: nil, html_badge_label: nil, exclude_domains: nil))
                guard revision == self.upstreamVerificationRevision else { return }
                self.demoSettings.verifyUpstreamCertificates = reply.verify_upstream_certificates
                self.updateDemoSettingsMenu()
            } catch { self.logError("sync upstream verification", error) }
        }
    }

    @objc func toggleUpstreamVerificationAction(_: Any?) {
        guard !upstreamVerificationPending else { return }
        upstreamVerificationRevision += 1
        let requested = !demoSettings.verifyUpstreamCertificates
        guard isProviderActive() else {
            demoSettings.verifyUpstreamCertificates = requested
            updateDemoSettingsMenu()
            applyDemoSettings()
            return
        }
        upstreamVerificationPending = true
        updateDemoSettingsMenu()
        let client = ramaXpcClient
        Task { @MainActor [weak self] in
            guard let self else { return }
            defer {
                self.upstreamVerificationPending = false
                self.updateDemoSettingsMenu()
            }
            do {
                let reply = try await client.call(
                    RamaTproxyUpdateSettings.self,
                    RamaTproxyUpdateSettings.Request(
                        verify_upstream_certificates: requested,
                        html_badge_enabled: nil, html_badge_label: nil, exclude_domains: nil))
                guard reply.ok else { throw NSError(domain: "RamaTproxy", code: 1) }
                self.demoSettings.verifyUpstreamCertificates = reply.verify_upstream_certificates
                self.updateDemoSettingsMenu()
            } catch {
                self.upstreamVerificationPending = false
                self.syncUpstreamVerificationState()
                self.showCommandErrorAlert(
                    title: "Upstream Verification Update Failed",
                    message: error.localizedDescription)
            }
        }
    }
}
