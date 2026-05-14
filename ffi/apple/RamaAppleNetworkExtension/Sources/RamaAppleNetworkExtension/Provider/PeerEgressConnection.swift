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
    ///
    /// For IPv6 link-local peers carrying a `scopeId`, the
    /// numeric interface index is resolved back to the textual
    /// interface name (`en0`, `lo0`, …) via `if_indextoname(3)`
    /// and appended to the hostname as `%name`, matching the
    /// kernel-supplied form. If the resolution fails (interface
    /// gone, name buffer too small), the hostname is emitted
    /// without the scope suffix — the datagram still flows but
    /// the kernel may drop it as unscoped link-local.
    func toNetworkExtensionEndpoint() -> NWHostEndpoint {
        let hostname: String
        if scopeId != 0, let name = interfaceNameForIndex(scopeId) {
            hostname = "\(host)%\(name)"
        } else {
            hostname = host
        }
        return NWHostEndpoint(hostname: hostname, port: "\(port)")
    }
}

/// `if_indextoname(3)` Swift wrapper. Returns the kernel-visible
/// textual interface name for a numeric scope id, or `nil` on
/// failure.
private func interfaceNameForIndex(_ index: UInt32) -> String? {
    // `IF_NAMESIZE` is 16 on Darwin (includes NUL terminator).
    var buf = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
    let ptr = buf.withUnsafeMutableBufferPointer { $0.baseAddress }
    guard let ptr, if_indextoname(index, ptr) != nil else { return nil }
    return String(cString: ptr)
}

/// `if_nametoindex(3)` Swift wrapper. Returns the numeric scope
/// id for a textual interface name, or `0` on failure (matches
/// the libc convention and the "no scope" sentinel).
private func interfaceIndexForName(_ name: String) -> UInt32 {
    name.withCString { ptr in if_nametoindex(ptr) }
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
        // Split off `%zone` for IPv6 link-local addresses. The
        // kernel surfaces these as `fe80::1%en0`; the FFI carries
        // the bare IP plus a numeric scope id so the round-trip
        // is exact (the interface name is not stable across
        // reboots but its index resolves to the same name within
        // a single boot via `if_nametoindex` / `if_indextoname`).
        if let percent = host.hostname.firstIndex(of: "%") {
            let ip = String(host.hostname[..<percent])
            let zone = String(host.hostname[host.hostname.index(after: percent)...])
            let scopeId = interfaceIndexForName(zone)
            // If zone-name resolution fails (interface gone), we
            // still pass the IP through without scope — the
            // sending side will likely fail, which is the same
            // failure mode the kernel would have surfaced.
            return RamaUdpPeer(host: ip, port: port, scopeId: scopeId)
        }
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
