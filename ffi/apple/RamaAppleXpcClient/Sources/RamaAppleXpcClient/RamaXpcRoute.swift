import Foundation

/// Typed XPC route declaration.
///
/// One enum/struct per logical RPC endpoint. The associated `Request` and
/// `Reply` types describe the JSON-shaped payload exchanged with the
/// `XpcMessageRouter` on the Rust side; field names and shapes must match
/// the corresponding `serde::Deserialize` / `serde::Serialize` types
/// declared on the route handler.
///
/// Example:
///
/// ```swift
/// enum InstallRootCA: RamaXpcRoute {
///     static let selector = "installRootCA:withReply:"
///     struct Reply: Decodable {
///         let ok: Bool
///         let error: String?
///         let cert_der_b64: String?
///     }
/// }
///
/// let reply = try await client.call(InstallRootCA.self)
/// ```
///
/// Routes that take no request payload can omit `Request` and the
/// associated type defaults to ``RamaXpcEmpty``, which encodes as the
/// empty dictionary.
public protocol RamaXpcRoute {
    associatedtype Request: Encodable = RamaXpcEmpty
    associatedtype Reply: Decodable

    /// NSXPC-style selector name. Mirrors the value passed to
    /// `XpcMessageRouter::with_typed_route` on the Rust side
    /// (e.g. `"installRootCA:withReply:"`).
    static var selector: String { get }
}

/// Empty `Encodable` request payload used as the default `Request`
/// associated type for routes that take no arguments.
///
/// Encodes as an empty JSON object on the wire, which the Rust side
/// deserializes to its corresponding empty struct.
public struct RamaXpcEmpty: Encodable, Sendable {
    public init() {}
}
