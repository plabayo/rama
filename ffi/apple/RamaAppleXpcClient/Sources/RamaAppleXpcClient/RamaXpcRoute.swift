import Foundation

/// Typed XPC route. One enum/struct per RPC; `Request` and `Reply`
/// must match the Rust-side `serde` types on the matching route in
/// `XpcMessageRouter::with_typed_route`. Defaulting `Request` to
/// `RamaXpcEmpty` covers argument-less routes.
public protocol RamaXpcRoute {
    associatedtype Request: Encodable = RamaXpcEmpty
    associatedtype Reply: Decodable

    /// NSXPC-style selector, e.g. `"installRootCA:withReply:"`.
    static var selector: String { get }
}

/// Default `Request` for routes with no arguments. Encodes as `{}`.
public struct RamaXpcEmpty: Encodable, Sendable {
    public init() {}
}
