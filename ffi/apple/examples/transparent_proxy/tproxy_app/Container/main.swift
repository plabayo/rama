import AppKit
import Foundation
import NetworkExtension
import OSLog

final class ContainerController: NSObject, NSApplicationDelegate {
    lazy var extensionBundleId: String = {
        guard let bundleId = Bundle.main.bundleIdentifier, !bundleId.isEmpty else {
            return ""
        }
        return "\(bundleId).provider"
    }()
    let managerDescription = "Rama Transparent Proxy Example"
    let managerServerAddress = "127.0.0.1"
    static let secretAccount = "org.ramaproxy.example.tproxy"
    static let secretServiceKeyPEM = "tls-root-selfsigned-ca-key"
    static let secretServiceCertPEM = "tls-root-selfsigned-ca-crt"
    static let secretServiceKeys = [secretServiceKeyPEM, secretServiceCertPEM]
    lazy var containerLogger = Logger(subsystem: "org.ramaproxy.example.tproxy", category: "container")
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
    var pingProviderMenuItem: NSMenuItem?
    var resetMenuItem: NSMenuItem?

    var activeManager: NETransparentProxyManager?
    var statusObserver: NSObjectProtocol?
    var statusTimer: DispatchSourceTimer?
    var lastStatus: NEVPNStatus?
    var lastLoggedDisconnectSignature: String?
    var demoSettings = DemoProxySettings()
    var systemExtensionActivationCompletions: [(Bool) -> Void] = []
    var systemExtensionActivationInFlight = false
    lazy var resetProfileOnLaunch =
        ProcessInfo.processInfo.arguments.contains("--reset-profile-on-launch")
    lazy var cleanSecretsOnLaunch =
        ProcessInfo.processInfo.arguments.contains("--clean-secrets")

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupStatusItem()
        log("container app launched")
        if cleanSecretsOnLaunch {
            log("launch flag detected: cleaning MITM CA secrets before start")
            cleanSecrets()
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

let app = NSApplication.shared
let delegate = ContainerController()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
