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
/// Abstracted behind a protocol so `TcpFlowSession` / `UdpFlowSession`
/// can be driven by `MockNwConnection` in unit tests instead of by
/// a real `NWConnection`. Production conforms via the trivial
/// extension below.
protocol NwConnectionLike: AnyObject {
    var state: NWConnection.State { get }

    /// Status of the connection's current network path, or `nil` when it
    /// has none yet. Mirrors `NWConnection.currentPath?.status`. The
    /// post-wake reconcile (`TransparentProxyCore.handleSystemWake`) reads
    /// this after a short settle to tell a connection whose path survived
    /// a no-op (Power-Nap) sleep (`.satisfied`) from one stranded on a path
    /// the system tore down across a network-changing sleep — the latter
    /// can sit in `.ready` over a dead path without ever firing
    /// `.waiting`/`.failed`, which is the wedge this signal lets us reap.
    var currentPathStatus: NWPath.Status? { get }

    // Matches `NWConnection`'s real `@Sendable` declaration so the
    // conformance is Swift-6 clean. Assigned closures capture the
    // per-flow session (an `@unchecked Sendable` class), so `@Sendable`
    // holds without further propagation.
    var stateUpdateHandler: (@Sendable (NWConnection.State) -> Void)? { get set }

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

extension NWConnection: NwConnectionLike {
    /// `NWConnection.currentPath?.status`. A `.ready` connection whose
    /// underlying path the system tore down (network change across a
    /// sleep) reports a non-`.satisfied` status here even while its
    /// `state` lags at `.ready`.
    var currentPathStatus: NWPath.Status? { currentPath?.status }
}

extension NwConnectionLike {
    /// Cancel the connection AND release its `stateUpdateHandler` in
    /// one atomic-by-discipline step. The handler closure transitively
    /// retains the per-flow context graph (kernel `NEAppProxyTCPFlow`,
    /// `tearDownPostReady`, the per-flow `DispatchQueue`); leaving it
    /// attached after `cancel()` pins that graph alive until Apple's
    /// framework gets around to deallocating its `NWConnection`
    /// internals — which observably does NOT happen for hundreds of
    /// connections under sustained churn (heap audit: `__NWPath`,
    /// `MutableParametersStorage`, `Endpoint.addressStorage` grow
    /// unboundedly; kernel emits 4,390 `nw_path_necp_check_for_updates
    /// Failed (22)` per 5 min of stress while polling NECP sessions
    /// the kernel has already destroyed).
    ///
    /// Dropping the handler before `cancel()` also suppresses Apple's
    /// final `.cancelled` callback. None of the production teardown
    /// paths depend on observing it — they already pivot to
    /// `.cancelled` on the synchronous initiator side via
    /// `ctx.connection = nil` and registry removal.
    ///
    /// **Use everywhere a teardown path cancels an egress connection
    /// in this crate**. Plain `cancel()` is for protocol conformance;
    /// production code paths go through `TcpFlowTeardown` which
    /// nils `ctx.connection` after each call for idempotency, so the
    /// "already cancelled" log noise (1,177 events / 5 min of stress
    /// pre-fix) stays at zero.
    func cancelAndDetach() {
        self.stateUpdateHandler = nil
        self.cancel()
    }
}

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
