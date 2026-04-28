import Foundation
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
