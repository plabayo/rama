import XCTest

@testable import RamaAppleNetworkExtension

final class BundleIdDerivationTests: XCTestCase {
    /// The team-prefix form `<10-char team id>.<bundle id>` is the
    /// common Apple signing identifier for App Store / Developer ID
    /// distributed apps. Strip the prefix to recover the bundle id
    /// per-app policy code expects.
    func testStripsTeamIdPrefix() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.deriveBundleId(
                fromSigningId: "7VPF8GD6J4.com.aikido.endpoint.proxy.l4.dist.extension"),
            "com.aikido.endpoint.proxy.l4.dist.extension"
        )
        XCTAssertEqual(
            RamaTransparentProxyProvider.deriveBundleId(
                fromSigningId: "ABCDEFGHIJ.com.example.app"),
            "com.example.app"
        )
    }

    /// System / unsigned processes (and many open-source apps) carry
    /// just the bundle id with no team prefix. Pass through unchanged.
    func testKeepsBareBundleId() {
        XCTAssertEqual(
            RamaTransparentProxyProvider.deriveBundleId(fromSigningId: "org.mozilla.firefox"),
            "org.mozilla.firefox"
        )
        XCTAssertEqual(
            RamaTransparentProxyProvider.deriveBundleId(
                fromSigningId: "com.fortinet.forticlient.ztagent"),
            "com.fortinet.forticlient.ztagent"
        )
    }

    /// Strings that resemble a team prefix but aren't exactly 10
    /// uppercase-alnum chars must NOT be stripped; otherwise we'd
    /// silently lose the leading component of legitimate bundle ids.
    func testDoesNotStripNonTeamPrefixes() {
        // 9 chars before the dot.
        XCTAssertEqual(
            RamaTransparentProxyProvider.deriveBundleId(fromSigningId: "ABCDEF123.com.example"),
            "ABCDEF123.com.example"
        )
        // 11 chars.
        XCTAssertEqual(
            RamaTransparentProxyProvider.deriveBundleId(fromSigningId: "ABCDEFGHIJK.com.example"),
            "ABCDEFGHIJK.com.example"
        )
        // Lowercase in prefix.
        XCTAssertEqual(
            RamaTransparentProxyProvider.deriveBundleId(fromSigningId: "abcdefghij.com.example"),
            "abcdefghij.com.example"
        )
        // Non-alphanumeric in prefix.
        XCTAssertEqual(
            RamaTransparentProxyProvider.deriveBundleId(fromSigningId: "ABCDE-FGHI.com.example"),
            "ABCDE-FGHI.com.example"
        )
    }

    func testEmptyAndNilInputs() {
        XCTAssertNil(RamaTransparentProxyProvider.deriveBundleId(fromSigningId: nil))
        XCTAssertNil(RamaTransparentProxyProvider.deriveBundleId(fromSigningId: ""))
    }
}
