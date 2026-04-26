import Foundation
import XPC

extension ContainerController {
    /// Send the current demo settings to the running sysext over XPC.
    ///
    /// The sysext registers its mach service under its bundle ID (`NEMachServiceName`).
    /// The message is fire-and-forget: no reply is expected.
    func sendXpcUpdateSettings() {
        let serviceName = xpcServiceName

        guard !serviceName.isEmpty else {
            log("sendXpcUpdateSettings: xpcServiceName is empty, skipping")
            return
        }

        log("sendXpcUpdateSettings: xpcServiceName = \(serviceName)")

        let conn = xpc_connection_create_mach_service(
            serviceName, nil, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))

        xpc_connection_set_event_handler(conn) { _ in }
        xpc_connection_activate(conn)

        let msg = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(msg, "op", "update_settings")
        xpc_dictionary_set_bool(msg, "html_badge_enabled", demoSettings.htmlBadgeEnabled)
        xpc_dictionary_set_string(msg, "html_badge_label", demoSettings.htmlBadgeLabel)

        let domainsArray = xpc_array_create(nil, 0)
        for domain in demoSettings.excludeDomains {
            xpc_array_append_value(domainsArray, xpc_string_create(domain))
        }
        xpc_dictionary_set_value(msg, "exclude_domains", domainsArray)

        xpc_connection_send_message(conn, msg)
        xpc_connection_cancel(conn)

        log(
            "sendXpcUpdateSettings: settings update sent (badge=\(demoSettings.htmlBadgeEnabled), badge_label=\(demoSettings.htmlBadgeLabel), excludeDomains=\(demoSettings.excludeDomains.count))"
        )
    }
}
