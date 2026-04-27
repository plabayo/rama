import Foundation
import XPC

extension ContainerController {
    /// Send the current demo settings to the running sysext over XPC.
    ///
    /// The sysext registers its mach service under its bundle ID (`NEMachServiceName`).
    /// The message is fire-and-forget: no reply is inspected (success/failure is logged).
    ///
    /// Wire format follows the NSXPC-inspired `$selector` / `$arguments` convention
    /// handled by `XpcMessageRouter` on the Rust side:
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

        let conn = xpc_connection_create_mach_service(serviceName, nil, 0)

        xpc_connection_set_event_handler(conn) { [weak self] event in
            self?.log("xpc event: \(event)")
        }

        xpc_connection_activate(conn)

        // Build the settings payload (first $arguments entry).
        let payload = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_bool(payload, "html_badge_enabled", demoSettings.htmlBadgeEnabled)
        xpc_dictionary_set_string(payload, "html_badge_label", demoSettings.htmlBadgeLabel)

        let domainsArray = xpc_array_create(nil, 0)
        for domain in demoSettings.excludeDomains {
            xpc_array_append_value(domainsArray, xpc_string_create(domain))
        }
        xpc_dictionary_set_value(payload, "exclude_domains", domainsArray)

        // Wrap in the $arguments array.
        let arguments = xpc_array_create(nil, 0)
        xpc_array_append_value(arguments, payload)

        // Build the top-level call dictionary.
        let msg = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(msg, "$selector", "updateSettings:withReply:")
        xpc_dictionary_set_value(msg, "$arguments", arguments)

        xpc_connection_send_message_with_reply(conn, msg, nil) { [weak self] reply in
            self?.log("sendXpcUpdateSettings: reply: \(reply)")
            xpc_connection_cancel(conn)
        }

        log(
            "sendXpcUpdateSettings: settings update sent (badge=\(demoSettings.htmlBadgeEnabled), badge_label=\(demoSettings.htmlBadgeLabel), excludeDomains=\(demoSettings.excludeDomains.count))"
        )
    }
}
