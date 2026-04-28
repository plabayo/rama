import Foundation
import RamaAppleXpcClient

/// Demo XPC routes exposed by the sysext's `XpcMessageRouter` in
/// `tproxy_rs/src/demo_xpc_server.rs`.
///
/// Each enum mirrors a single typed Rust route declared with
/// `with_typed_route::<Request, Reply, _>(selector, …)`. Selectors,
/// field names and value shapes must stay in sync with the Rust side —
/// the wire format is plain JSON-over-XPC under the hood
/// (see `RamaXpcCoder`).

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

/// Shared shape for the install/uninstall replies. Matches the Rust
/// `RootCaCommandReply` struct.
struct RamaTproxyRootCaReply: Decodable {
    let ok: Bool
    let error: String?
    let cert_der_b64: String?
}
