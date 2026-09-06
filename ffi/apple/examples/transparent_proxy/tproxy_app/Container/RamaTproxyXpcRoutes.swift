import Foundation
import NetworkExtension
import RamaAppleXpcClient

/// Typed XPC routes exposed by the sysext's router in
/// `tproxy_rs/src/demo_xpc_server.rs`. Selectors, field names and
/// shapes must stay in sync with the Rust `serde` types on each route.

enum RamaTproxyUpdateSettings: RamaXpcRoute {
    static let selector = "updateSettings:withReply:"

    struct Request: Encodable {
        let html_badge_enabled: Bool?
        let html_badge_label: String?
        let exclude_domains: [String]?
    }

    struct Reply: Decodable {
        let ok: Bool
    }
}

enum RamaTproxyInstallRootCA: RamaXpcRoute {
    static let selector = "installRootCA:withReply:"
    typealias Reply = RamaTproxyRootCaReply
}

enum RamaTproxyUninstallRootCA: RamaXpcRoute {
    static let selector = "uninstallRootCA:withReply:"
    typealias Reply = RamaTproxyRootCaReply
}

enum RamaTproxyRotateRootCA: RamaXpcRoute {
    static let selector = "rotateRootCA:withReply:"

    struct Reply: Decodable {
        let ok: Bool
        let error: String?
        let previous_cert_der_b64: String?
        let new_cert_der_b64: String?
    }
}

/// Shared reply for install/uninstall (matches Rust `RootCaCommandReply`).
struct RamaTproxyRootCaReply: Decodable {
    let ok: Bool
    let error: String?
    let cert_der_b64: String?
}

enum RamaTproxySetTlsKeylog: RamaXpcRoute {
    static let selector = "setTlsKeylog:withReply:"

    struct Request: Encodable {
        let enabled: Bool
    }

    typealias Reply = RamaTproxyTlsKeylogReply
}

enum RamaTproxyGetTlsKeylog: RamaXpcRoute {
    static let selector = "getTlsKeylog:withReply:"
    typealias Reply = RamaTproxyTlsKeylogReply
}

/// State observed *after* the call; the GUI mirrors this into the menu.
struct RamaTproxyTlsKeylogReply: Decodable {
    let enabled: Bool
}

enum RamaTproxyGetAllocatorStats: RamaXpcRoute {
    static let selector = "getAllocatorStats:withReply:"

    struct Reply: Codable, Sendable {
        let available: Bool
        let allocator: String
        let pid: UInt32
        let sampled_at_unix_ms: UInt64?
        let stats: Stats?
        let error: String?
    }

    struct Setting<Value: Codable & Sendable>: Codable, Sendable {
        let value: Value?
        let error: String?
    }

    struct Stats: Codable, Sendable {
        let epoch: UInt64
        let allocated: UInt64
        let active: UInt64
        let resident: UInt64
        let metadata: UInt64
        let mapped: UInt64
        let retained: UInt64
        let pdirty: UInt64
        let pmuzzy: UInt64
        let page_size: UInt64
        let narenas: UInt32
        let background_thread: Setting<Bool>
        let opt_background_thread: Setting<Bool>
        let opt_dirty_decay_ms: Setting<Int64>
        let opt_muzzy_decay_ms: Setting<Int64>
        let arenas_dirty_decay_ms: Setting<Int64>
        let arenas_muzzy_decay_ms: Setting<Int64>
    }
}

/// A standalone diagnostic invocation. The process deadline also bounds an
/// unresponsive XPC peer; completion always exits before NSApplication exists.
enum AllocatorStatsCommand {
    static func run(arguments: [String], bundle: Bundle) -> Never {
        guard arguments == ["--allocator-stats"] else {
            fail("--allocator-stats must be used alone", code: 2)
        }
        guard let serviceName = bundle.object(forInfoDictionaryKey: "ProviderMachServiceName")
                as? String, !serviceName.isEmpty,
            let bundleId = bundle.bundleIdentifier, !bundleId.isEmpty
        else {
            fail("missing signed container bundle identity", code: 1)
        }
        let client = RamaXpcClient(
            serviceName: serviceName,
            expectedPeerSigningIdentifier: "\(bundleId).provider")
        // Both completion paths run on one queue so at most one JSON document
        // is emitted, including a reply racing with the deadline.
        let completion = DispatchQueue(label: "org.ramaproxy.allocator-stats-command")
        completion.asyncAfter(deadline: .now() + 10) {
            fail("allocator statistics XPC request timed out after 10 seconds", code: 1)
        }
        // Reading preferences does not create/save a manager or start a tunnel.
        // Reject inactive providers before looking up their Mach service.
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                let detail = String(describing: error)
                completion.async { fail(detail, code: 1) }
                return
            }
            let active = managers?.contains { manager in
                guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                    proto.providerBundleIdentifier == "\(bundleId).provider"
                else { return false }
                return manager.connection.status == .connected
                    || manager.connection.status == .connecting
                    || manager.connection.status == .reasserting
            } ?? false
            guard active else {
                completion.async { fail("the matching provider is not active", code: 1) }
                return
            }
            Task.detached {
                do {
                    let reply = try await client.call(RamaTproxyGetAllocatorStats.self)
                    let encoder = JSONEncoder()
                    encoder.outputFormatting = [.sortedKeys]
                    let data = try encoder.encode(reply)
                    completion.async {
                        finish(data, code: reply.available ? 0 : 1)
                    }
                } catch {
                    let detail = String(describing: error)
                    completion.async { fail(detail, code: 1) }
                }
            }
        }
        dispatchMain()
    }

    private static func fail(_ error: String, code: Int32) -> Never {
        // JSONSerialization escapes arbitrary error text. This fixed shape
        // contains only values guaranteed to be representable as JSON.
        let data = (try? JSONSerialization.data(
            withJSONObject: ["available": false, "error": error], options: [.sortedKeys]))
            ?? Data(#"{"available":false,"error":"unable to encode diagnostic error"}"#.utf8)
        finish(data, code: code)
    }

    private static func finish(_ data: Data, code: Int32) -> Never {
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
        exit(code)
    }
}
