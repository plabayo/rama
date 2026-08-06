import Foundation
import NetworkExtension
import OSLog
import RamaAppleNetworkExtension

/// Example-only provider customization used by the signed UDP integration
/// harness. The reusable Rama provider deliberately has no knowledge of test
/// modes, probe executables, or public endpoint diagnostics.
final class RamaTransparentProxyExampleProvider: RamaTransparentProxyProvider {
    private static let udpE2ELogger = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "org.ramaproxy.example.tproxy",
        category: "udp-e2e"
    )
    private static let udpE2EProbeBundleIdentifiers: Set<String> = [
        "com.apple.python3",
        "com.apple.nscurl",
    ]

    private let udpE2EStateLock = NSLock()
    private var udpE2EMode = false
    private var udpE2EBlockedEndpoints: Set<String> = []
    private var udpE2ESafetyWork: DispatchWorkItem?

    override func startProxy(
        options: [String: Any]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let e2eConfiguration = Self.udpE2EConfiguration(startOptions: options)
        setUdpE2EConfiguration(e2eConfiguration)
        super.startProxy(options: options) { [weak self] error in
            if error == nil, e2eConfiguration.enabled {
                self?.armUdpE2ESafetyTimeout()
            } else if error != nil {
                self?.disableUdpE2EMode()
            }
            completionHandler(error)
        }
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        disableUdpE2EMode()
        super.stopProxy(with: reason, completionHandler: completionHandler)
    }

    override func handleNewUdpFlow(
        _ flow: NEAppProxyUDPFlow,
        callback: UdpFlowCallbackSource,
        remoteEndpoint: EndpointHostPort?,
        localEndpoint: EndpointHostPort?
    ) -> Bool {
        let callbackReturn = super.handleNewUdpFlow(
            flow,
            callback: callback,
            remoteEndpoint: remoteEndpoint,
            localEndpoint: localEndpoint
        )
        logUdpE2EDecision(
            flow: flow,
            callback: callback.rawValue,
            endpoint: remoteEndpoint,
            callbackReturn: callbackReturn
        )
        return callbackReturn
    }

    private func logUdpE2EDecision(
        flow: NEAppProxyUDPFlow,
        callback: String,
        endpoint: EndpointHostPort?,
        callbackReturn: Bool
    ) {
        let configuration = udpE2EConfigurationSnapshot
        let rawSigningIdentifier = flow.metaData.sourceAppSigningIdentifier.trimmingCharacters(
            in: .whitespacesAndNewlines
        )
        guard configuration.enabled,
            let sourceAppBundleIdentifier = RamaTransparentProxyProvider.deriveBundleId(
                fromSigningId: rawSigningIdentifier.isEmpty ? nil : rawSigningIdentifier
            ),
            Self.udpE2EProbeBundleIdentifiers.contains(sourceAppBundleIdentifier)
        else {
            return
        }

        let initialRemote = endpoint?.description ?? "<unsupported-or-missing>"
        let decision = callbackReturn
            ? (configuration.blockedEndpoints.contains(initialRemote) ? "blocked" : "intercept")
            : "passthrough"

        let message =
            "udp_callback=\(callback) rama_decision=\(decision) "
            + "callback_return=\(callbackReturn) "
            + "initial_remote=\(initialRemote) source_app=\(sourceAppBundleIdentifier)"
        Self.udpE2ELogger.debug("\(message, privacy: .public)")
    }

    private var udpE2EConfigurationSnapshot: UdpE2EConfiguration {
        udpE2EStateLock.lock()
        defer { udpE2EStateLock.unlock() }
        return UdpE2EConfiguration(
            enabled: udpE2EMode,
            blockedEndpoints: udpE2EBlockedEndpoints
        )
    }

    private func setUdpE2EConfiguration(_ configuration: UdpE2EConfiguration) {
        udpE2EStateLock.lock()
        udpE2ESafetyWork?.cancel()
        udpE2ESafetyWork = nil
        udpE2EMode = configuration.enabled
        udpE2EBlockedEndpoints = configuration.blockedEndpoints
        udpE2EStateLock.unlock()
    }

    private func disableUdpE2EMode() {
        udpE2EStateLock.lock()
        udpE2EMode = false
        udpE2EBlockedEndpoints = []
        udpE2ESafetyWork?.cancel()
        udpE2ESafetyWork = nil
        udpE2EStateLock.unlock()
    }

    /// A SIGKILL cannot run the shell harness' EXIT trap. Bound the active
    /// runtime-only policy anyway; a later start uses the clean saved profile.
    private func armUdpE2ESafetyTimeout() {
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.disableUdpE2EMode()
            self.cancelProxyWithError(
                NSError(
                    domain: "org.ramaproxy.example.tproxy.udp-e2e",
                    code: 1,
                    userInfo: [
                        NSLocalizedDescriptionKey:
                            "temporary UDP E2E policy exceeded its safety lifetime"
                    ]
                )
            )
        }

        udpE2EStateLock.lock()
        udpE2ESafetyWork?.cancel()
        udpE2ESafetyWork = work
        udpE2EStateLock.unlock()

        DispatchQueue.global(qos: .utility).asyncAfter(
            deadline: .now() + .seconds(600),
            execute: work
        )
    }

    private static func udpE2EConfiguration(
        startOptions: [String: Any]?
    ) -> UdpE2EConfiguration {
        let configData: Data?
        if let data = startOptions?["engineConfigJson"] as? Data {
            configData = data
        } else if let string = startOptions?["engineConfigJson"] as? String {
            configData = Data(string.utf8)
        } else {
            configData = nil
        }

        guard let configData,
            let object = try? JSONSerialization.jsonObject(with: configData) as? [String: Any]
        else {
            return UdpE2EConfiguration(enabled: false, blockedEndpoints: [])
        }
        let blockedEndpoints = Set(object["udp_blocked_endpoints"] as? [String] ?? [])
        return UdpE2EConfiguration(
            enabled: object["udp_e2e_mode"] as? Bool ?? false,
            blockedEndpoints: blockedEndpoints
        )
    }

}

private struct UdpE2EConfiguration {
    let enabled: Bool
    let blockedEndpoints: Set<String>
}
