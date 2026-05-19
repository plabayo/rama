import Foundation
import NetworkExtension
import XCTest

@testable import RamaAppleNetworkExtension

/// Pins the macOS-15 `NWConcreteHostEndpoint` shape fallback in
/// `ramaUdpPeer(from:)`.
///
/// Background: on macOS 15+ Apple ships a private concrete class
/// (`NWConcreteHostEndpoint`) that does NOT inherit from
/// `NWHostEndpoint` but still exposes the same `hostname: String`
/// and `port: String` KVC keys. The metadata path already had a
/// KVC fallback (`endpointHostPort` in the provider); the UDP
/// read path did not, so peer attribution silently degraded to
/// `nil` on macOS 15+ — which then meant the write-pump head
/// could orphan-stall (see `UdpClientWritePumpOrphanTests`).
///
/// Since we cannot directly construct the private Apple class,
/// the test simulates the shape with an `NWEndpoint` subclass
/// that overrides `hostname` / `port` via KVC. The fallback's
/// `responds(to:)` + `value(forKey:)` path treats this identically
/// to the real macOS-15 concrete class.
final class UdpPeerKVCFallbackTests: XCTestCase {

    /// Subclass of `NWEndpoint` that does NOT also subclass
    /// `NWHostEndpoint`. Exposes `hostname` / `port` via @objc
    /// dynamic so KVC `responds(to:)` + `value(forKey:)` resolve.
    /// Matches the runtime contract `NWConcreteHostEndpoint`
    /// presents on macOS 15+.
    @objc(KVCConcreteEndpointStandIn)
    final class KVCConcreteEndpointStandIn: NWEndpoint {
        @objc dynamic let hostname: String
        @objc dynamic let port: String

        init(hostname: String, port: String) {
            self.hostname = hostname
            self.port = port
            super.init()
        }

        required init?(coder: NSCoder) {
            fatalError("not used")
        }
    }

    /// An `NWEndpoint` that is *neither* `NWHostEndpoint` *nor*
    /// answers the `hostname` / `port` KVC keys — the truly
    /// unrecognised case. The defensive log should fire once and
    /// the peer must come out nil.
    @objc(OpaqueEndpointStandIn)
    final class OpaqueEndpointStandIn: NWEndpoint {
        // Deliberately no `hostname` / `port` properties.
        required override init() { super.init() }
        required init?(coder: NSCoder) { fatalError("not used") }
    }

    /// A `KVCConcreteEndpointStandIn` carrying an IPv4 host must
    /// produce a `RamaUdpPeer` exactly like the `NWHostEndpoint`
    /// fast path would.
    func testIPv4ViaKVCFallback() {
        let ep = KVCConcreteEndpointStandIn(hostname: "10.0.0.4", port: "5353")
        guard let peer = ramaUdpPeer(from: ep) else {
            XCTFail("KVC fallback must produce a peer for an IPv4 host+port")
            return
        }
        XCTAssertEqual(peer.host, "10.0.0.4")
        XCTAssertEqual(peer.port, 5353)
        XCTAssertEqual(peer.scopeId, 0)
    }

    /// A `KVCConcreteEndpointStandIn` carrying an IPv6 link-local
    /// host with `%zone` must extract the scope id via
    /// `if_nametoindex` exactly like the fast path. Uses `lo0`
    /// (interface index 1 on every macOS host).
    func testIPv6LinkLocalScopedViaKVCFallback() {
        let ep = KVCConcreteEndpointStandIn(hostname: "fe80::1%lo0", port: "5353")
        guard let peer = ramaUdpPeer(from: ep) else {
            XCTFail("KVC fallback must produce a peer for a scoped IPv6 host+port")
            return
        }
        XCTAssertEqual(peer.host, "fe80::1")
        XCTAssertEqual(peer.port, 5353)
        XCTAssertEqual(peer.scopeId, 1, "lo0 is interface index 1 on Darwin")
    }

    /// A truly opaque `NWEndpoint` subclass — neither
    /// `NWHostEndpoint` nor KVC-conformant — must return nil and
    /// not crash.
    func testTrulyUnknownSubclassReturnsNil() {
        let ep = OpaqueEndpointStandIn()
        XCTAssertNil(
            ramaUdpPeer(from: ep),
            "endpoint that exposes neither subclass nor KVC keys must return nil"
        )
    }

    /// Empty hostname must still be rejected even via the KVC
    /// fallback (matches the fast path's `!hostname.isEmpty` guard).
    func testKVCFallbackRejectsEmptyHostname() {
        let ep = KVCConcreteEndpointStandIn(hostname: "", port: "5353")
        XCTAssertNil(ramaUdpPeer(from: ep))
    }

    /// Non-numeric port must still be rejected via the KVC
    /// fallback (matches the fast path's `UInt16(port)` guard).
    func testKVCFallbackRejectsNonNumericPort() {
        let ep = KVCConcreteEndpointStandIn(hostname: "10.0.0.4", port: "not-a-port")
        XCTAssertNil(ramaUdpPeer(from: ep))
    }
}
