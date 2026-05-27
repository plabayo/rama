import Foundation
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// Pins the IPv6-zone-id round-trip across the Swift↔Rust FFI:
///
///     NWHostEndpoint("fe80::1%lo0")
///       → ramaUdpPeer(from:)    (Swift, parses %zone, looks up scope id)
///       → RamaUdpPeer(scopeId)  (carries numeric index over FFI)
///       → toNetworkExtensionEndpoint()  (Swift, resolves index → name)
///       → NWHostEndpoint("fe80::1%lo0")
///
/// Without this, a regression that drops `scopeId` from `RamaUdpPeer`
/// or that hard-codes `0` somewhere in the conversion would only
/// surface for link-local IPv6 UDP on multi-interface hardware —
/// exactly the kind of bug that ships and stays shipped.
///
/// `lo0` is used because it is the one interface guaranteed to exist
/// on every macOS host with a stable index (1) and a stable name.
final class UdpPeerScopeRoundTripTests: XCTestCase {

    private func loopbackInterfaceName() -> String? {
        // `if_indextoname(1)` → "lo0" on Darwin. Resolve dynamically
        // rather than hard-coding so a future loopback rename (or
        // running these tests on a non-Darwin Swift) does not break.
        var buf = [CChar](repeating: 0, count: Int(IF_NAMESIZE))
        return buf.withUnsafeMutableBufferPointer { bp -> String? in
            guard let base = bp.baseAddress, if_indextoname(1, base) != nil else {
                return nil
            }
            return String(cString: base)
        }
    }

    /// `fe80::1%lo0` from the kernel → `RamaUdpPeer.scopeId == 1` →
    /// back to `NWHostEndpoint("fe80::1%lo0")`. Pins both directions
    /// against `if_nametoindex` / `if_indextoname`.
    func testIpv6LinkLocalZoneRoundTripsThroughFFIShape() {
        guard let ifname = loopbackInterfaceName() else {
            XCTFail("interface index 1 has no name — unexpected on macOS")
            return
        }

        let original = NWHostEndpoint(hostname: "fe80::1%\(ifname)", port: "5353")
        guard let peer = ramaUdpPeer(from: original) else {
            XCTFail("ramaUdpPeer should parse a scoped link-local IPv6 endpoint")
            return
        }
        XCTAssertEqual(peer.host, "fe80::1", "host_utf8 must NOT carry the zone suffix")
        XCTAssertEqual(peer.port, 5353)
        XCTAssertEqual(peer.scopeId, 1, "scope id must resolve via if_nametoindex")

        let echoed = peer.toNetworkExtensionEndpoint()
        XCTAssertEqual(
            echoed.hostname, "fe80::1%\(ifname)",
            "hostname must reattach the zone suffix on the way out"
        )
        XCTAssertEqual(echoed.port, "5353")
    }

    /// Non-scoped IPv6 must round-trip with `scopeId = 0` and no
    /// surprise `%zone` suffix on the way back.
    func testIpv6UnicastNoZoneRoundTrip() {
        let original = NWHostEndpoint(hostname: "2001:db8::1", port: "5353")
        guard let peer = ramaUdpPeer(from: original) else {
            XCTFail("ramaUdpPeer should parse a non-scoped IPv6 endpoint")
            return
        }
        XCTAssertEqual(peer.host, "2001:db8::1")
        XCTAssertEqual(peer.scopeId, 0)

        let echoed = peer.toNetworkExtensionEndpoint()
        XCTAssertEqual(echoed.hostname, "2001:db8::1")
        XCTAssertFalse(echoed.hostname.contains("%"))
    }

    /// IPv4 must always carry `scopeId = 0` and survive the round-
    /// trip untouched.
    func testIpv4RoundTrip() {
        let original = NWHostEndpoint(hostname: "192.0.2.1", port: "5353")
        guard let peer = ramaUdpPeer(from: original) else {
            XCTFail("ramaUdpPeer should parse an IPv4 endpoint")
            return
        }
        XCTAssertEqual(peer.host, "192.0.2.1")
        XCTAssertEqual(peer.scopeId, 0)

        let echoed = peer.toNetworkExtensionEndpoint()
        XCTAssertEqual(echoed.hostname, "192.0.2.1")
    }

    /// An unknown interface name (no matching index in the kernel)
    /// must NOT crash — `if_nametoindex` returns `0`, which the FFI
    /// treats as "no scope". The hostname round-trip then drops the
    /// suffix, which is the correct best-effort behaviour: the kernel
    /// would refuse such an endpoint anyway.
    func testIpv6UnknownZoneNameDegradesGracefully() {
        let original = NWHostEndpoint(hostname: "fe80::1%nonexistent999", port: "5353")
        guard let peer = ramaUdpPeer(from: original) else {
            XCTFail("ramaUdpPeer should still produce a peer with degraded scope")
            return
        }
        XCTAssertEqual(peer.host, "fe80::1")
        XCTAssertEqual(peer.scopeId, 0, "unknown zone resolves to 0 (no scope)")

        let echoed = peer.toNetworkExtensionEndpoint()
        XCTAssertEqual(
            echoed.hostname, "fe80::1",
            "with scopeId = 0 the round-trip emits the bare IP"
        )
    }
}
