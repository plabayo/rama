// Developer harness helper. Compile with swiftc; only apply/restore need sudo.
// Save the exact Proxies dictionary, including absent keys, rather than parsing
// networksetup's localized display output. Never touch other service settings.
import Foundation
import SystemConfiguration

func fail(_ message: String) -> Never {
    fputs("egress proxy settings: \(message) (SCError=\(SCError()))\n", stderr)
    exit(1)
}
func equal(_ left: NSDictionary?, _ right: NSDictionary?) -> Bool {
    switch (left, right) {
    case (nil, nil): return true
    case (let left?, let right?): return left.isEqual(right)
    default: return false
    }
}
let args = CommandLine.arguments
guard args.count >= 3 else {
    fail("capture SERVICE SNAPSHOT PAC_URL | apply SNAPSHOT | restore SNAPSHOT")
}
let command = args[1]
guard let prefs = SCPreferencesCreate(nil, "rama egress policy developer test" as CFString, nil)
else { fail("cannot read preferences") }
// Capture is read-only and needs no privileged advisory lock. Apply compares
// the snapshot against current preferences under the lock before any mutation.
if command != "capture", !SCPreferencesLock(prefs, true) { fail("cannot lock preferences") }
defer { if command != "capture" { SCPreferencesUnlock(prefs) } }
if command == "capture" {
    guard args.count == 5,
        let services = SCNetworkServiceCopyAll(prefs) as? [SCNetworkService]
    else { fail("capture arguments/services") }
    let matches = services.filter { (SCNetworkServiceGetName($0) as String?) == args[2] }
    guard matches.count == 1, let service = matches.first,
        let proxy = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies),
        let serviceID = SCNetworkServiceGetServiceID(service)
    else { fail("service name must match exactly one proxy-capable service") }
    let original = SCNetworkProtocolGetConfiguration(proxy) as NSDictionary?
    var applied = original as? [String: Any] ?? [:]
    applied[kSCPropNetProxiesProxyAutoConfigEnable as String] = 1
    applied[kSCPropNetProxiesProxyAutoConfigURLString as String] = args[4]
    // Isolate PAC selection from pre-existing explicit proxy/discovery settings.
    for key in [
        kSCPropNetProxiesHTTPEnable, kSCPropNetProxiesHTTPSEnable, kSCPropNetProxiesSOCKSEnable,
        kSCPropNetProxiesProxyAutoDiscoveryEnable,
    ] {
        applied[key as String] = 0
    }
    let snapshot: [String: Any] = [
        "service": serviceID as String,
        "present": original != nil, "original": original ?? [:], "applied": applied,
    ]
    let data = try PropertyListSerialization.data(
        fromPropertyList: snapshot, format: .xml, options: 0)
    try data.write(to: URL(fileURLWithPath: args[3]), options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: args[3])
} else {
    guard args.count == 3, command == "apply" || command == "restore" else {
        fail("unknown command")
    }
    let data = try Data(contentsOf: URL(fileURLWithPath: args[2]))
    guard
        let snapshot = try PropertyListSerialization.propertyList(from: data, format: nil)
            as? [String: Any],
        let id = snapshot["service"] as? String, let present = snapshot["present"] as? Bool,
        let original = snapshot["original"] as? NSDictionary,
        let applied = snapshot["applied"] as? NSDictionary,
        let service = SCNetworkServiceCopy(prefs, id as CFString),
        let proxy = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies)
    else { fail("invalid snapshot or removed service") }
    let current = SCNetworkProtocolGetConfiguration(proxy) as NSDictionary?
    let before: NSDictionary? = present ? original : nil
    if command == "restore", equal(current, before) { exit(0) }
    guard equal(current, command == "apply" ? before : applied) else {
        fail(
            "proxy settings changed independently; refusing to overwrite them. Keep the snapshot for manual recovery"
        )
    }
    let target = command == "apply" ? applied : before
    guard SCNetworkProtocolSetConfiguration(proxy, target as CFDictionary?),
        SCPreferencesCommitChanges(prefs), SCPreferencesApplyChanges(prefs)
    else { fail("cannot commit/apply proxy settings") }
    guard let verification = SCPreferencesCreate(nil, "rama egress verify" as CFString, nil),
        let savedService = SCNetworkServiceCopy(verification, id as CFString),
        let savedProxy = SCNetworkServiceCopyProtocol(savedService, kSCNetworkProtocolTypeProxies),
        equal(SCNetworkProtocolGetConfiguration(savedProxy) as NSDictionary?, target)
    else { fail("persisted configuration verification failed") }
}
