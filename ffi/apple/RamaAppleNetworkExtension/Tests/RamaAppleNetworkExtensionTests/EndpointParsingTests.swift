import XCTest

@testable import RamaAppleNetworkExtension

/// Direct unit tests for the endpoint-parsing helpers that the
/// provider used to expose as private static methods. Pulled out so
/// the rare-input cases (IPv6 bracket forms, the legacy dot-suffix
/// representation, invalid ports) can be pinned without going through
/// the full provider plumbing.
final class EndpointParsingTests: XCTestCase {

    // MARK: - inferredHostPrefix

    func testInferredHostPrefixIPv4() {
        XCTAssertEqual(inferredHostPrefix("10.0.0.1"), 32)
        XCTAssertEqual(inferredHostPrefix("127.0.0.1"), 32)
        XCTAssertEqual(inferredHostPrefix("255.255.255.255"), 32)
        XCTAssertEqual(inferredHostPrefix("0.0.0.0"), 32)
    }

    func testInferredHostPrefixIPv6() {
        XCTAssertEqual(inferredHostPrefix("::1"), 128)
        XCTAssertEqual(inferredHostPrefix("2001:db8::1"), 128)
        // macOS `inet_pton(AF_INET6, ...)` accepts scoped IPv6
        // literals with a zone id. Pinned so a future SDK change
        // doesn't quietly flip this.
        XCTAssertEqual(inferredHostPrefix("fe80::1%en0"), 128)
        XCTAssertEqual(inferredHostPrefix("2a02:1234:5678:9abc:def0:1234:5678:9abc"), 128)
    }

    func testInferredHostPrefixHostnameReturnsNil() {
        XCTAssertNil(inferredHostPrefix("example.com"))
        XCTAssertNil(inferredHostPrefix("localhost"))
        XCTAssertNil(inferredHostPrefix("api.aikido.dev"))
        XCTAssertNil(inferredHostPrefix(""))
    }

    func testInferredHostPrefixMalformed() {
        XCTAssertNil(inferredHostPrefix("999.999.999.999"))
        XCTAssertNil(inferredHostPrefix("10.0.0"))
        XCTAssertNil(inferredHostPrefix("10.0.0.1/24"), "CIDR notation is not an address")
        XCTAssertNil(inferredHostPrefix(":::"))
    }

    // MARK: - parseEndpointString

    func testParseEndpointStringIPv4HostPort() {
        let result = parseEndpointString("10.0.0.1:8080")
        XCTAssertEqual(result?.host, "10.0.0.1")
        XCTAssertEqual(result?.port, 8080)
    }

    func testParseEndpointStringHostname() {
        let result = parseEndpointString("example.com:443")
        XCTAssertEqual(result?.host, "example.com")
        XCTAssertEqual(result?.port, 443)
    }

    func testParseEndpointStringIPv6Bracketed() {
        let result = parseEndpointString("[2001:db8::1]:443")
        XCTAssertEqual(result?.host, "2001:db8::1")
        XCTAssertEqual(result?.port, 443)
    }

    func testParseEndpointStringIPv6BracketedLoopback() {
        let result = parseEndpointString("[::1]:53")
        XCTAssertEqual(result?.host, "::1")
        XCTAssertEqual(result?.port, 53)
    }

    func testParseEndpointStringIPv6LegacyDotSuffix() {
        // The legacy NetworkExtension representation puts the port
        // after a dot rather than a colon when no brackets are
        // present. Real example pulled from NEFlowMetaData on a UDP
        // flow to a DNS server.
        let result = parseEndpointString("2a02:1234:5678::1.53")
        XCTAssertEqual(result?.host, "2a02:1234:5678::1")
        XCTAssertEqual(result?.port, 53)
    }

    func testParseEndpointStringPortBoundaries() {
        // UInt16.max = 65535 — valid.
        let high = parseEndpointString("10.0.0.1:65535")
        XCTAssertEqual(high?.port, 65535)

        // 65536 — overflow, rejected.
        XCTAssertNil(parseEndpointString("10.0.0.1:65536"))

        // 0 — valid as a U16 but rare in production. parseEndpointString
        // accepts it (callers like `tcpMeta` reject port 0 separately
        // when deciding whether to dial).
        let zero = parseEndpointString("10.0.0.1:0")
        XCTAssertEqual(zero?.port, 0)
    }

    func testParseEndpointStringInvalidShapes() {
        XCTAssertNil(parseEndpointString(""))
        XCTAssertNil(parseEndpointString("just-a-hostname"))
        XCTAssertNil(parseEndpointString("10.0.0.1"), "no port suffix")
        XCTAssertNil(parseEndpointString("10.0.0.1:abc"), "non-numeric port")
        XCTAssertNil(parseEndpointString(":8080"), "empty host")
        XCTAssertNil(parseEndpointString("[2001:db8::1]"), "no port after bracket")
        XCTAssertNil(parseEndpointString("[2001:db8::1]xx443"), "missing colon between bracket and port")
    }

    func testParseEndpointStringBracketStrippingOnLegacyForms() {
        // The unbracketed `host:port` branch also strips stray
        // brackets that some kernel-side serializations include.
        let result = parseEndpointString("[10.0.0.1]:443")
        XCTAssertEqual(result?.host, "10.0.0.1")
        XCTAssertEqual(result?.port, 443)
    }
}
