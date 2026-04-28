import Foundation
import NetworkExtension
import RamaAppleNetworkExtensionAsync
import RamaAppleXpcClient

extension ContainerController {
    fileprivate var ramaXpcClient: RamaXpcClient {
        RamaXpcClient(serviceName: xpcServiceName)
    }

    /// Lifecycle hook for `RamaXpcClient.call(... ensuringActive: …)`.
    /// Brings the sysext up on demand; returns a teardown that stops it
    /// again if we were the ones who started it.
    var ensureProviderActive: RamaXpcLifecycle {
        { [weak self] in
            guard let self else { return {} }
            return try await self.activateProviderIfNeeded()
        }
    }

    /// Push the current demo settings to the running sysext.
    /// Fire-and-forget; only runs when the proxy is already active.
    func sendXpcUpdateSettings() {
        guard !xpcServiceName.isEmpty else {
            log("sendXpcUpdateSettings: xpcServiceName is empty, skipping")
            return
        }

        let request = RamaTproxyUpdateSettings.Request(
            html_badge_enabled: demoSettings.htmlBadgeEnabled,
            html_badge_label: demoSettings.htmlBadgeLabel,
            exclude_domains: demoSettings.excludeDomains
        )

        log(
            "sendXpcUpdateSettings: dispatching update (badge=\(demoSettings.htmlBadgeEnabled), badge_label=\(demoSettings.htmlBadgeLabel), excludeDomains=\(demoSettings.excludeDomains.count))"
        )

        let client = ramaXpcClient
        Task { [weak self] in
            do {
                let reply = try await client.call(RamaTproxyUpdateSettings.self, request)
                self?.log("sendXpcUpdateSettings: ok=\(reply.ok)")
            } catch {
                self?.logError("sendXpcUpdateSettings: failed", error)
            }
        }
    }

    /// Activate the sysext + start a temporary tunnel if the provider
    /// isn't already running. The returned closure stops it again.
    private func activateProviderIfNeeded() async throws -> RamaXpcLifecycleTeardown {
        if let manager = activeManager, manager.isActive {
            return {}
        }

        try await ensureSystemExtensionActivatedAsync()
        let manager = try await loadOrCreateAndConfigureManagerAsync(
            preserveCurrentDemoSettings: true)
        self.activeManager = manager
        self.installStatusObserver(manager: manager)
        self.startStatusTimer(manager: manager)

        log("xpc lifecycle: starting temporary tunnel")
        try await manager.startAndWaitUntilConnected()

        return { [weak self, weak manager] in
            self?.log("xpc lifecycle: stopping temporary tunnel")
            manager?.connection.stopVPNTunnel()
        }
    }

    private func ensureSystemExtensionActivatedAsync() async throws {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Void, Error>) in
            ensureSystemExtensionActivated { activated in
                if activated {
                    continuation.resume()
                } else {
                    continuation.resume(
                        throwing: NSError(
                            domain: "RamaTransparentProxyExampleContainer",
                            code: 2,
                            userInfo: [
                                NSLocalizedDescriptionKey:
                                    "system extension not activated; approve it in System Settings and retry"
                            ]
                        ))
                }
            }
        }
    }

    private func loadOrCreateAndConfigureManagerAsync(
        preserveCurrentDemoSettings: Bool
    ) async throws -> NETransparentProxyManager {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<NETransparentProxyManager, Error>) in
            loadOrCreateAndConfigureManager(
                preserveCurrentDemoSettings: preserveCurrentDemoSettings
            ) { manager in
                if let manager {
                    continuation.resume(returning: manager)
                } else {
                    continuation.resume(
                        throwing: NSError(
                            domain: "RamaTransparentProxyExampleContainer",
                            code: 2,
                            userInfo: [NSLocalizedDescriptionKey: "provider configuration failed"]
                        ))
                }
            }
        }
    }
}
