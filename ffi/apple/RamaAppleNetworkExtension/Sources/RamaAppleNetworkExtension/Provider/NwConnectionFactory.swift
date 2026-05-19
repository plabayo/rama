/// NwConnectionFactory.swift
///
/// This file intentionally imports only `Network` (not `NetworkExtension`) so that
/// the bare `NWEndpoint` name unambiguously refers to `Network.NWEndpoint` (the
/// Swift enum).  Files that also import `NetworkExtension` would see two candidates
/// for `NWEndpoint` — the deprecated ObjC class from NetworkExtension and the Swift
/// enum from Network — causing a compile-time ambiguity.
///
/// Keeping NWConnection creation here avoids that conflict.

import Foundation
import Network

/// The surface of `NWConnection` that the per-flow code in
/// `RamaTransparentProxyProvider` actually uses.
///
/// Abstracted behind a protocol so the per-flow state machine
/// (`handleTcpFlow` / `handleUdpFlow`, the egress read / write pumps) can
/// be unit-tested against a mock implementation that drives state
/// transitions on demand. Real production code passes an `NWConnection`,
/// which conforms via the trivial extension below.
protocol NwConnectionLike: AnyObject {
    var state: NWConnection.State { get }
    // The protocol's `stateUpdateHandler` is intentionally NOT marked
    // `@Sendable`. `NWConnection`'s real declaration *is* `@Sendable`, so
    // this is a contravariant relaxation that Swift currently accepts
    // with a warning (and Swift 6 mode would reject). The relaxation
    // keeps the assignment sites in `handleTcpFlow` / `handleUdpFlow`
    // free of fresh `@Sendable` propagation onto every closure they
    // capture into — those captures (the per-flow context, the session
    // handle, the `NEAppProxyFlow`, …) are confined to the flow's
    // serial `flowQueue` and are not actually Sendable. When the
    // module migrates to Swift 6 those captures must be revisited
    // together; until then, narrowing the protocol's sendability is
    // the local cost.
    var stateUpdateHandler: ((NWConnection.State) -> Void)? { get set }

    func start(queue: DispatchQueue)
    func cancel()

    /// Mirrors `NWConnection.send`. The protocol uses explicit arguments
    /// (no defaults) because Swift protocols cannot declare default
    /// parameter values; every call site supplies all four arguments
    /// even when the values match `NWConnection`'s own defaults.
    func send(
        content: Data?,
        contentContext: NWConnection.ContentContext,
        isComplete: Bool,
        completion: NWConnection.SendCompletion
    )

    /// Mirrors `NWConnection.receive`. Used by the TCP egress read pump.
    func receive(
        minimumIncompleteLength: Int,
        maximumLength: Int,
        completion: @escaping @Sendable (Data?, NWConnection.ContentContext?, Bool, NWError?) -> Void
    )
}

extension NWConnection: NwConnectionLike {}

/// Factory used to construct egress `NWConnection`s.
///
/// Returns `nil` when the connection cannot be constructed (e.g. invalid
/// port). The provider treats `nil` as a connect failure and tears the
/// session down.
typealias NwConnectionFactoryFn =
    (_ host: String, _ port: UInt16, _ params: NWParameters) -> (any NwConnectionLike)?

/// Default factory: produces a real `NWConnection`.
///
/// Returns `nil` when the port is invalid (`NWEndpoint.Port(rawValue:)` rejects 0).
/// Callers must surface that as a connect failure rather than silently substituting
/// a default port — connecting to the wrong destination is worse than not connecting.
func makeNwConnection(host: String, port: UInt16, using params: NWParameters) -> NWConnection? {
    guard let port = NWEndpoint.Port(rawValue: port) else {
        return nil
    }
    return NWConnection(host: NWEndpoint.Host(host), port: port, using: params)
}

/// `NwConnectionFactoryFn`-typed adapter that returns the default
/// `NWConnection` produced by `makeNwConnection`.
let defaultNwConnectionFactory: NwConnectionFactoryFn = { host, port, params in
    makeNwConnection(host: host, port: port, using: params)
}
