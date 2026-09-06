import AppKit
import Foundation
import NetworkExtension
import OSLog

final class ContainerController: NSObject, NSApplicationDelegate, @unchecked Sendable {
    lazy var xpcServiceName: String = {
        return Bundle.main.object(
            forInfoDictionaryKey: "ProviderMachServiceName"
        ) as? String ?? ""
    }()

    lazy var extensionBundleId: String = {
        guard let bundleId = Bundle.main.bundleIdentifier, !bundleId.isEmpty else {
            return ""
        }
        return "\(bundleId).provider"
    }()

    let managerDescription = "Rama Transparent Proxy Example"
    let managerServerAddress = "127.0.0.1"
    // Must match the Rust sysext (`tproxy_rs/src/tls/mod.rs`); `just
    // check-spec-parity` fails the build on drift.
    static let secretAccount = "org.ramaproxy.example.tproxy"
    static let secretServiceKeyPEM = "rama-tproxy-demo-ca-key"
    static let secretServiceCertPEM = "rama-tproxy-demo-ca-crt"
    /// Secure-Enclave-wrapped key blob stored next to the (now-encrypted)
    /// PEMs. The container cannot decrypt these but can still delete them
    /// by service name, which is what the rotate flow needs.
    static let secretServiceSEKey = "rama-tproxy-demo-ca-se-key"
    static let secretServiceKeys = [
        secretServiceKeyPEM,
        secretServiceCertPEM,
        secretServiceSEKey,
    ]
    lazy var containerLogger = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "org.ramaproxy.example.tproxy",
        category: "container")
    lazy var logFileURL: URL = {
        let base = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Logs", isDirectory: true)
        return base.appendingPathComponent("RamaTransparentProxyExampleContainer.log")
    }()

    var statusItem: NSStatusItem?
    var statusMenuItem: NSMenuItem?
    var startMenuItem: NSMenuItem?
    var stopMenuItem: NSMenuItem?
    var badgeEnabledMenuItem: NSMenuItem?
    var badgeLabelMenuItem: NSMenuItem?
    var excludeDomainsMenuItem: NSMenuItem?
    var resetDemoSettingsMenuItem: NSMenuItem?
    var rotateCAMenuItem: NSMenuItem?
    var installCAMenuItem: NSMenuItem?
    var clearCAMenuItem: NSMenuItem?
    var pingProviderMenuItem: NSMenuItem?
    /// Toggle for the SSLKEYLOG sink baked into the MITM relay
    /// at engine-construction time. Flipping it while the proxy
    /// is connected restarts the provider (the action confirms
    /// first).
    var tlsKeylogMenuItem: NSMenuItem?
    var resetMenuItem: NSMenuItem?

    var activeManager: NETransparentProxyManager?
    var statusObserver: NSObjectProtocol?
    var statusTimer: DispatchSourceTimer?
    var lastStatus: NEVPNStatus?
    var lastLoggedDisconnectSignature: String?
    var demoSettings = DemoProxySettings()
    /// Optional test-only runtime policy override accepted as
    /// `--udp-passthrough-ports=PORT,PORT`. An explicitly empty value clears
    /// the list. It is sent via `startVPNTunnel(options:)`, not persisted.
    lazy var requestedUdpPassthroughPorts: [UInt16]? = {
        let prefix = "--udp-passthrough-ports="
        guard
            let argument = ProcessInfo.processInfo.arguments.first(where: {
                $0.hasPrefix(prefix)
            })
        else {
            return nil
        }
        let value = String(argument.dropFirst(prefix.count))
        return Self.parseUdpPassthroughPorts(value)
    }()
    /// Optional test-only exact block list accepted as
    /// `--udp-blocked-endpoints=HOST:PORT,HOST:PORT`.
    lazy var requestedUdpBlockedEndpoints: [String]? = {
        let prefix = "--udp-blocked-endpoints="
        guard
            let argument = ProcessInfo.processInfo.arguments.first(where: {
                $0.hasPrefix(prefix)
            })
        else {
            return nil
        }
        let value = String(argument.dropFirst(prefix.count))
        return Self.parseUdpBlockedEndpoints(value)
    }()
    /// Canonical signed-evidence run identity. Launch-only and non-secret.
    lazy var requestedEvidenceRunUuid: String? = {
        let prefix = "--evidence-run-uuid="
        let arguments = ProcessInfo.processInfo.arguments.filter { $0.hasPrefix(prefix) }
        guard arguments.count == 1, let argument = arguments.first else {
            return nil
        }
        let value = String(argument.dropFirst(prefix.count))
        guard value.count == 36, UUID(uuidString: value)?.uuidString.lowercased() == value
        else { return nil }
        return value
    }()
    /// Exact endpoints eligible for Rust's signed-E2E diagnostic.
    lazy var requestedUdpE2EDiagnosticEndpoints: [String]? = {
        let prefix = "--udp-e2e-diagnostic-endpoints="
        let arguments = ProcessInfo.processInfo.arguments.filter { $0.hasPrefix(prefix) }
        guard arguments.count == 1, let argument = arguments.first else {
            return nil
        }
        let value = String(argument.dropFirst(prefix.count))
        guard let endpoints = Self.parseUdpBlockedEndpoints(value),
            !endpoints.isEmpty, endpoints.count <= 512,
            Set(endpoints).count == endpoints.count
        else { return nil }
        return endpoints
    }()
    /// The signed harness uses one narrowly-scoped launch to restart the
    /// persisted profile with no temporary UDP policy or evidence identity.
    lazy var isPersistedDefaultRestart: Bool = {
        let arguments = ProcessInfo.processInfo.arguments
        let passthrough = arguments.filter { $0.hasPrefix("--udp-passthrough-ports=") }
        let blocked = arguments.filter { $0.hasPrefix("--udp-blocked-endpoints=") }
        let hasAnyEvidenceArgument = arguments.contains(where: {
            $0.hasPrefix("--evidence-run-uuid=")
                || $0.hasPrefix("--udp-e2e-diagnostic-endpoints=")
        })
        return passthrough.count == 1 && blocked.count == 1
            && requestedUdpPassthroughPorts == []
            && requestedUdpBlockedEndpoints == []
            && !hasAnyEvidenceArgument
    }()

    /// Distinguishes a malformed supplied argument from an absent argument.
    /// Invalid test policy must fail closed instead of silently running the E2E
    /// against the normal policy and producing misleading assertions.
    lazy var invalidUdpOverrideArgument: String? = {
        let arguments = ProcessInfo.processInfo.arguments
        if arguments.contains(where: { $0.hasPrefix("--udp-passthrough-ports=") }),
            requestedUdpPassthroughPorts == nil
        {
            return "--udp-passthrough-ports"
        }
        if arguments.contains(where: { $0.hasPrefix("--udp-blocked-endpoints=") }),
            requestedUdpBlockedEndpoints == nil
        {
            return "--udp-blocked-endpoints"
        }
        if arguments.contains(where: { $0.hasPrefix("--evidence-run-uuid=") }),
            requestedEvidenceRunUuid == nil
        {
            return "--evidence-run-uuid"
        }
        if arguments.contains(where: { $0.hasPrefix("--udp-e2e-diagnostic-endpoints=") }),
            requestedUdpE2EDiagnosticEndpoints == nil
        {
            return "--udp-e2e-diagnostic-endpoints"
        }
        let hasAnyEvidenceArgument = requestedEvidenceRunUuid != nil
            || requestedUdpE2EDiagnosticEndpoints != nil
        let hasCompleteEvidenceIdentity = requestedEvidenceRunUuid != nil
            && requestedUdpE2EDiagnosticEndpoints != nil
        let hasUdpOverrideArgument = arguments.contains(where: {
            $0.hasPrefix("--udp-passthrough-ports=")
                || $0.hasPrefix("--udp-blocked-endpoints=")
        })
        if hasUdpOverrideArgument && isPersistedDefaultRestart {
            return nil
        }
        if (hasAnyEvidenceArgument || hasUdpOverrideArgument)
            && !hasCompleteEvidenceIdentity
        {
            return "incomplete UDP E2E evidence identity"
        }
        return nil
    }()

    private static func parseUdpPassthroughPorts(_ value: String) -> [UInt16]? {
        guard !value.isEmpty else { return [] }
        let components = value.split(separator: ",", omittingEmptySubsequences: false)
        let ports = components.compactMap { component -> UInt16? in
            let text = String(component).trimmingCharacters(in: .whitespacesAndNewlines)
            return UInt16(text)
        }
        guard ports.count == components.count else { return nil }
        return ports
    }

    private static func parseUdpBlockedEndpoints(_ value: String) -> [String]? {
        guard !value.isEmpty else { return [] }
        let endpoints = value.split(separator: ",", omittingEmptySubsequences: false)
            .map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }
        guard endpoints.allSatisfy(isValidHostPort) else { return nil }
        return endpoints
    }

    private static func isValidHostPort(_ endpoint: String) -> Bool {
        guard !endpoint.isEmpty else { return false }
        if endpoint.hasPrefix("[") {
            guard let closingBracket = endpoint.firstIndex(of: "]"),
                endpoint.index(after: endpoint.startIndex) < closingBracket
            else {
                return false
            }
            let colon = endpoint.index(after: closingBracket)
            guard colon < endpoint.endIndex, endpoint[colon] == ":" else { return false }
            let portStart = endpoint.index(after: colon)
            guard let port = UInt16(endpoint[portStart...]) else { return false }
            return port > 0
        }

        guard let colon = endpoint.lastIndex(of: ":"), colon > endpoint.startIndex else {
            return false
        }
        let host = endpoint[..<colon]
        let portStart = endpoint.index(after: colon)
        guard let port = UInt16(endpoint[portStart...]) else { return false }
        return !host.contains(":") && port > 0
    }
    /// True after demoSettings has been initialised from NE preferences at least once.
    /// Prevents subsequent loadOrCreateAndConfigureManager calls from overwriting in-memory
    /// settings with stale NE values (e.g. after an unexpected provider stop + restart).
    var settingsInitializedFromNE = false
    var systemExtensionActivationCompletions: [(Bool) -> Void] = []
    var systemExtensionActivationInFlight = false
    lazy var resetProfileOnLaunch =
        ProcessInfo.processInfo.arguments.contains("--reset-profile-on-launch")
    lazy var cleanSecretsOnLaunch =
        ProcessInfo.processInfo.arguments.contains("--clean-secrets")

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        log("container app launched")
        if let invalidUdpOverrideArgument {
            log("invalid temporary UDP policy argument: \(invalidUdpOverrideArgument)")
            setStatus(status: .invalid, detail: "invalid UDP E2E argument")
            return
        }
        if let requestedUdpPassthroughPorts {
            log(
                "temporary test UDP pass-through ports=\(requestedUdpPassthroughPorts.map(String.init).joined(separator: ","))"
            )
        }
        if let requestedUdpBlockedEndpoints {
            log(
                "temporary test UDP blocked endpoints=\(requestedUdpBlockedEndpoints.joined(separator: ","))"
            )
        }
        if isPersistedDefaultRestart {
            log("udp_e2e_restore_profile=persisted-default evidence_identity=absent")
        }
        if let requestedEvidenceRunUuid, let requestedUdpE2EDiagnosticEndpoints {
            log(
                "temporary UDP E2E evidence run=\(requestedEvidenceRunUuid) endpoints=\(requestedUdpE2EDiagnosticEndpoints.count)"
            )
        }
        if cleanSecretsOnLaunch {
            log("launch flag detected: clearing MITM CA before start")
            clearStoredCAForLaunch()
        }
        if resetProfileOnLaunch {
            log("launch flag detected: resetting saved proxy profile before start")
        }
        ensureSystemExtensionActivated { [weak self] success in
            guard let self else { return }
            guard success else {
                self.setStatus(status: .invalid, detail: "system extension unavailable")
                return
            }
            self.startProxy(forceReinstall: self.resetProfileOnLaunch)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        statusTimer?.cancel()
        statusTimer = nil
        log("container app terminated")
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let manager = activeManager else {
            return .terminateNow
        }

        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            log("quit requested: stopping proxy first")
            stopProxy { sender.reply(toApplicationShouldTerminate: true) }
            return .terminateLater
        default:
            return .terminateNow
        }
    }
}

extension Data {
    fileprivate var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}

if CommandLine.arguments.dropFirst().contains(where: { $0.hasPrefix("--allocator-stats") }) {
    AllocatorStatsCommand.run(arguments: Array(CommandLine.arguments.dropFirst()), bundle: .main)
}

let app = NSApplication.shared
let delegate = ContainerController()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
