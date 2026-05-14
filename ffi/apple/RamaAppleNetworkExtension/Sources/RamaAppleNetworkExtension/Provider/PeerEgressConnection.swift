/// PeerEgressConnection.swift
///
/// Peer-endpoint conversion helpers used when bridging the Swift
/// kernel-side flow (NetworkExtension) to the Rust-side transport.
///
/// `NEAppProxyUDPFlow` is unconnected from the kernel's perspective —
/// one socket, many peers, per-datagram source/destination endpoints
/// carried by `flow.readDatagrams` / `flow.writeDatagrams`. The
/// matching transport layer lives in Rust (a single
/// `tokio::net::UdpSocket` per flow); these helpers translate
/// between the kernel's `NetworkExtension.NWEndpoint` class shape
/// and the FFI-portable `RamaUdpPeer` struct.
///
/// This file deliberately does NOT import `Network` (where the
/// modern `NWEndpoint` enum lives). The kernel-flow APIs we bridge
/// to use the historical `NetworkExtension.NWEndpoint` class, and
/// importing both modules in the same file makes the bare name
/// `NWEndpoint` ambiguous.

import Foundation
import NetworkExtension

extension RamaUdpPeer {
    /// Build a `NetworkExtension.NWHostEndpoint` suitable for
    /// `flow.writeDatagrams(_:sentBy:)`. `NWHostEndpoint` is the
    /// concrete IP+port subclass of `NWEndpoint` we always emit.
    func toNetworkExtensionEndpoint() -> NWHostEndpoint {
        NWHostEndpoint(hostname: host, port: "\(port)")
    }
}

/// Extract a `RamaUdpPeer` from a kernel-side `NWEndpoint`.
///
/// In production these are always `NWHostEndpoint` (kernel-resolved
/// IP+port). Future endpoint subclasses return `nil` — the caller
/// treats that as "no attribution" and the datagram still flows.
func ramaUdpPeer(from neEndpoint: NWEndpoint) -> RamaUdpPeer? {
    if let host = neEndpoint as? NWHostEndpoint {
        guard !host.hostname.isEmpty, let port = UInt16(host.port) else { return nil }
        return RamaUdpPeer(host: host.hostname, port: port)
    }
    return nil
}
