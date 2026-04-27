import Foundation
import NetworkExtension
import XPC

extension ContainerController {
    /// Send the current demo settings to the running sysext over XPC.
    ///
    /// Fire-and-forget; this only runs while the proxy is active so there is
    /// no auto-start lifecycle here. See `applyDemoSettings()` in
    /// `ContainerController+ProxyManager.swift` for the call site.
    ///
    /// Wire format follows the NSXPC-inspired `$selector` / `$arguments`
    /// convention handled by `XpcMessageRouter` on the Rust side:
    ///
    ///     {
    ///       "$selector": "updateSettings:withReply:",
    ///       "$arguments": [
    ///         {
    ///           "html_badge_enabled": <bool>,
    ///           "html_badge_label": <string>,
    ///           "exclude_domains": [<string>, ...]
    ///         }
    ///       ]
    ///     }
    func sendXpcUpdateSettings() {
        let serviceName = xpcServiceName

        guard !serviceName.isEmpty else {
            log("sendXpcUpdateSettings: xpcServiceName is empty, skipping")
            return
        }

        log("sendXpcUpdateSettings: xpcServiceName = \(serviceName)")

        let payload = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_bool(payload, "html_badge_enabled", demoSettings.htmlBadgeEnabled)
        xpc_dictionary_set_string(payload, "html_badge_label", demoSettings.htmlBadgeLabel)

        let domainsArray = xpc_array_create(nil, 0)
        for domain in demoSettings.excludeDomains {
            xpc_array_append_value(domainsArray, xpc_string_create(domain))
        }
        xpc_dictionary_set_value(payload, "exclude_domains", domainsArray)

        sendXpcRawRequest(
            serviceName: serviceName,
            selector: "updateSettings:withReply:",
            payload: payload
        ) { [weak self] result in
            switch result {
            case .success(let reply):
                self?.log("sendXpcUpdateSettings: reply: \(reply)")
            case .failure(let error):
                self?.logError("sendXpcUpdateSettings: failed", error)
            }
        }

        log(
            "sendXpcUpdateSettings: settings update sent (badge=\(demoSettings.htmlBadgeEnabled), badge_label=\(demoSettings.htmlBadgeLabel), excludeDomains=\(demoSettings.excludeDomains.count))"
        )
    }

    /// Send a typed XPC request to the sysext, ensuring the provider is
    /// running first. If the provider is not active, the system extension
    /// is activated (if needed), the tunnel is started temporarily, the
    /// request is sent, and the tunnel is stopped again on completion.
    ///
    /// `selector` is an NSXPC-style selector name (e.g.
    /// `"installRootCA:withReply:"`). `payload`, when supplied, becomes the
    /// first entry of `$arguments`; pass `nil` for routes whose Rust-side
    /// request type is empty.
    ///
    /// `completion` is called on the main queue with either the raw XPC
    /// reply (a dictionary containing `$result`) or an error.
    func sendXpcRequestEnsuringActive(
        selector: String,
        payload: xpc_object_t? = nil,
        completion: @escaping (Result<xpc_object_t, Error>) -> Void
    ) {
        let serviceName = xpcServiceName
        guard !serviceName.isEmpty else {
            DispatchQueue.main.async {
                completion(.failure(self.providerCommandError("xpcServiceName is empty")))
            }
            return
        }

        if isProviderActive() {
            log("xpc \(selector): provider already active; sending directly")
            sendXpcRawRequest(serviceName: serviceName, selector: selector, payload: payload) {
                result in
                DispatchQueue.main.async { completion(result) }
            }
            return
        }

        log("xpc \(selector): provider not active; activating sysext + starting temporarily")
        ensureSystemExtensionActivated { [weak self] activated in
            guard let self else { return }
            guard activated else {
                self.logErrorText(
                    "xpc \(selector): system extension activation failed; aborting")
                let error = self.providerCommandError(
                    "system extension is not activated; approve it in System Settings and retry")
                DispatchQueue.main.async { completion(.failure(error)) }
                return
            }
            self.startTemporaryAndSendXpc(
                serviceName: serviceName,
                selector: selector,
                payload: payload,
                completion: completion
            )
        }
    }

    // MARK: - Auto-start helpers

    private func startTemporaryAndSendXpc(
        serviceName: String,
        selector: String,
        payload: xpc_object_t?,
        completion: @escaping (Result<xpc_object_t, Error>) -> Void
    ) {
        loadOrCreateAndConfigureManager(preserveCurrentDemoSettings: true) { [weak self] manager in
            guard let self else { return }
            guard let manager else {
                DispatchQueue.main.async {
                    completion(.failure(self.providerCommandError(
                        "configuration failed before sending \(selector)")))
                }
                return
            }
            self.activeManager = manager
            self.installStatusObserver(manager: manager)
            self.startStatusTimer(manager: manager)
            do {
                self.log("xpc \(selector): calling startVPNTunnel")
                try manager.connection.startVPNTunnel()
            } catch {
                self.logError("xpc \(selector): startVPNTunnel failed", error)
                DispatchQueue.main.async { completion(.failure(error)) }
                return
            }
            self.waitUntilConnected(manager: manager, remainingAttempts: 80) {
                [weak self] connected in
                guard let self else { return }
                guard connected else {
                    self.log("xpc \(selector): connect timed out; stopping tunnel")
                    manager.connection.stopVPNTunnel()
                    let error = self.providerCommandError(
                        "provider failed to reach connected state for \(selector)")
                    DispatchQueue.main.async { completion(.failure(error)) }
                    return
                }
                self.sendXpcRawRequest(
                    serviceName: serviceName,
                    selector: selector,
                    payload: payload
                ) { [weak self] result in
                    guard let self else { return }
                    self.log("xpc \(selector): stopping temporary tunnel")
                    manager.connection.stopVPNTunnel()
                    DispatchQueue.main.async { completion(result) }
                }
            }
        }
    }

    // MARK: - Raw XPC send

    /// Open a one-shot XPC connection, send `$selector` + `$arguments`, and
    /// hand the reply (or an XPC error) back via `completion`. The caller is
    /// responsible for any auto-start lifecycle around this call.
    ///
    /// `completion` runs on an arbitrary queue.
    private func sendXpcRawRequest(
        serviceName: String,
        selector: String,
        payload: xpc_object_t?,
        completion: @escaping (Result<xpc_object_t, Error>) -> Void
    ) {
        let conn = xpc_connection_create_mach_service(serviceName, nil, 0)
        xpc_connection_set_event_handler(conn) { _ in
            // Stream events (peer death, invalidation) surface via the reply
            // handler below for our one-shot request shape, so this is
            // intentionally a no-op.
        }
        xpc_connection_activate(conn)

        let arguments = xpc_array_create(nil, 0)
        let arg = payload ?? xpc_dictionary_create(nil, nil, 0)
        xpc_array_append_value(arguments, arg)

        let msg = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(msg, "$selector", selector)
        xpc_dictionary_set_value(msg, "$arguments", arguments)

        log("xpc \(selector): sending request")
        xpc_connection_send_message_with_reply(conn, msg, nil) { [weak self] reply in
            defer { xpc_connection_cancel(conn) }
            let type = xpc_get_type(reply)
            if type == XPC_TYPE_ERROR {
                let desc = Self.xpcErrorDescription(reply)
                self?.logErrorText("xpc \(selector): reply error: \(desc)")
                completion(
                    .failure(
                        self?.providerCommandError("xpc reply error: \(desc)")
                            ?? NSError(
                                domain: "RamaTransparentProxyExampleContainer", code: 3,
                                userInfo: nil)))
                return
            }
            completion(.success(reply))
        }
    }

    // MARK: - Shared helpers

    func isProviderActive() -> Bool {
        guard let manager = activeManager else { return false }
        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            return true
        default:
            return false
        }
    }

    func waitUntilConnected(
        manager: NETransparentProxyManager,
        remainingAttempts: Int,
        completion: @escaping (Bool) -> Void
    ) {
        switch manager.connection.status {
        case .connected:
            completion(true)
        case .invalid:
            completion(false)
        case .disconnected, .disconnecting, .connecting, .reasserting:
            guard remainingAttempts > 0 else {
                completion(false)
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { [weak self] in
                guard let self else { return }
                self.waitUntilConnected(
                    manager: manager,
                    remainingAttempts: remainingAttempts - 1,
                    completion: completion
                )
            }
        @unknown default:
            completion(false)
        }
    }

    func providerCommandError(_ message: String) -> NSError {
        NSError(
            domain: "RamaTransparentProxyExampleContainer",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }

    private static func xpcErrorDescription(_ obj: xpc_object_t) -> String {
        // `xpc_copy_description` always returns a non-null malloc'd C string.
        let cstr = xpc_copy_description(obj)
        defer { free(cstr) }
        return String(cString: cstr)
    }
}
