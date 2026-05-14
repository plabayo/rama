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
import RamaAppleNEFFI

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
/// `NEAppProxyUDPFlow` is documented in terms of `NWEndpoint`
/// (the abstract base of the legacy NetworkExtension class
/// hierarchy), but in practice every endpoint surfaced for
/// `readDatagrams` / `writeDatagrams` is the concrete
/// `NWHostEndpoint` (IP literal + port string). We narrow here
/// because the downstream FFI carries IP+port; anything else is
/// returned as `nil` (datagram still flows, just without peer
/// attribution). The unexpected-subclass branch fires a
/// process-once debug log so a future Apple SDK that broadens
/// the surface becomes immediately visible in `log show`.
private var unexpectedEndpointLoggedFlag = false
private let unexpectedEndpointLoggedLock = NSLock()

func ramaUdpPeer(from neEndpoint: NWEndpoint) -> RamaUdpPeer? {
    if let host = neEndpoint as? NWHostEndpoint {
        guard !host.hostname.isEmpty, let port = UInt16(host.port) else { return nil }
        return RamaUdpPeer(host: host.hostname, port: port)
    }
    unexpectedEndpointLoggedLock.lock()
    let alreadyLogged = unexpectedEndpointLoggedFlag
    unexpectedEndpointLoggedFlag = true
    unexpectedEndpointLoggedLock.unlock()
    if !alreadyLogged {
        RamaTransparentProxyEngineHandle.log(
            level: UInt32(RAMA_LOG_LEVEL_DEBUG.rawValue),
            message:
                "udp readDatagrams returned an NWEndpoint subclass other than NWHostEndpoint (\(type(of: neEndpoint))); peer attribution dropped for affected datagrams. This is the first occurrence in this process — subsequent occurrences will not be logged."
        )
    }
    return nil
}
