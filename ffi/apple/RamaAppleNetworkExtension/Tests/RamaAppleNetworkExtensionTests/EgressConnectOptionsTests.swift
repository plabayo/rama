import XCTest

@testable import RamaAppleNEFFI
@testable import RamaAppleNetworkExtension

/// Pin the C-style `has_<name>` / `<name>` → optional Swift
/// accessors on `RamaTcpEgressConnectOptions`. The C struct
/// can't carry `Optional` directly; the convention is a `bool
/// has_X` companion flag, and historic call sites all wrote
/// the same `flatMap { $0.has_X ? $0.X : nil }` quadruple
/// inline. These accessors collapse that to a single property
/// — these tests pin the flag-discriminated mapping so a
/// regression that silently always-defaults (or always-uses)
/// shows up here first.
final class EgressConnectOptionsTests: XCTestCase {

    /// Helper: build an `RamaTcpEgressConnectOptions` with the
    /// `has_*` flags set explicitly. All three numeric fields
    /// carry distinct values so a "wrong field" regression
    /// surfaces as a wrong number, not just a nil-vs-non-nil
    /// flip.
    private func makeOpts(
        hasConnect: Bool, connect: UInt32,
        hasLinger: Bool, linger: UInt32,
        hasGrace: Bool, grace: UInt32
    ) -> RamaTcpEgressConnectOptions {
        RamaTcpEgressConnectOptions(
            parameters: RamaNwEgressParameters(
                has_service_class: false, service_class: 0,
                has_multipath_service_type: false, multipath_service_type: 0,
                has_required_interface_type: false, required_interface_type: 0,
                has_attribution: false, attribution: 0,
                prohibited_interface_types_mask: 0,
                preserve_original_meta_data: true,
                allow_system_proxy: false
            ),
            has_connect_timeout_ms: hasConnect,
            connect_timeout_ms: connect,
            has_linger_close_ms: hasLinger,
            linger_close_ms: linger,
            has_egress_eof_grace_ms: hasGrace,
            egress_eof_grace_ms: grace
        )
    }

    /// All three flags set → all three accessors return their
    /// respective values.
    func testAccessorsReturnValueWhenHasFlagIsTrue() {
        let opts = makeOpts(
            hasConnect: true, connect: 12_345,
            hasLinger: true, linger: 6_789,
            hasGrace: true, grace: 999
        )
        XCTAssertEqual(opts.connectTimeoutMs, 12_345)
        XCTAssertEqual(opts.lingerCloseMs, 6_789)
        XCTAssertEqual(opts.egressEofGraceMs, 999)
    }

    /// All three flags clear → all three accessors return nil.
    /// The underlying `<name>` field's literal value (zero
    /// here) MUST NOT leak through — that's the whole reason
    /// the `has_*` flag exists.
    func testAccessorsReturnNilWhenHasFlagIsFalse() {
        let opts = makeOpts(
            hasConnect: false, connect: 1,
            hasLinger: false, linger: 2,
            hasGrace: false, grace: 3
        )
        XCTAssertNil(opts.connectTimeoutMs)
        XCTAssertNil(opts.lingerCloseMs)
        XCTAssertNil(opts.egressEofGraceMs)
    }

    /// Mixed: each accessor reads ONLY its own flag and value
    /// pair. A regression that crosses field wires (e.g.
    /// `lingerCloseMs` accidentally reading
    /// `egress_eof_grace_ms`) shows up here.
    func testEachAccessorReadsOnlyItsOwnFieldPair() {
        // Only `linger` is set; the other two are clear with
        // non-zero numeric fields. If `connectTimeoutMs` or
        // `egressEofGraceMs` ignored its `has_*` flag, it
        // would return 42 / 84 instead of nil.
        let opts = makeOpts(
            hasConnect: false, connect: 42,
            hasLinger: true, linger: 100,
            hasGrace: false, grace: 84
        )
        XCTAssertNil(opts.connectTimeoutMs)
        XCTAssertEqual(opts.lingerCloseMs, 100)
        XCTAssertNil(opts.egressEofGraceMs)
    }
}
