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
        hasGrace: Bool, grace: UInt32,
        keepaliveEnabled: Bool = true,
        hasIdle: Bool = false, idle: UInt32 = 0,
        hasInterval: Bool = false, interval: UInt32 = 0,
        hasCount: Bool = false, count: UInt32 = 0
    ) -> RamaTcpEgressConnectOptions {
        // Zero-init then assign, so adding fields to the C struct does
        // not break this helper (a memberwise literal would).
        var opts = RamaTcpEgressConnectOptions()
        opts.parameters.preserve_original_meta_data = true
        opts.has_connect_timeout_ms = hasConnect
        opts.connect_timeout_ms = connect
        opts.has_linger_close_ms = hasLinger
        opts.linger_close_ms = linger
        opts.has_egress_eof_grace_ms = hasGrace
        opts.egress_eof_grace_ms = grace
        opts.tcp_keepalive_enabled = keepaliveEnabled
        opts.has_tcp_keepalive_idle_secs = hasIdle
        opts.tcp_keepalive_idle_secs = idle
        opts.has_tcp_keepalive_interval_secs = hasInterval
        opts.tcp_keepalive_interval_secs = interval
        opts.has_tcp_keepalive_count = hasCount
        opts.tcp_keepalive_count = count
        return opts
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

    // MARK: - Keepalive accessors

    /// `tcp_keepalive_enabled` has no `has_*` companion — it's always
    /// meaningful — so `tcpKeepaliveEnabled` reads it verbatim. Pin both
    /// polarities so a regression that hard-codes one shows up here.
    func testKeepaliveEnabledAccessorReadsFlagVerbatim() {
        XCTAssertTrue(
            makeOpts(
                hasConnect: false, connect: 0, hasLinger: false, linger: 0,
                hasGrace: false, grace: 0, keepaliveEnabled: true
            ).tcpKeepaliveEnabled)
        XCTAssertFalse(
            makeOpts(
                hasConnect: false, connect: 0, hasLinger: false, linger: 0,
                hasGrace: false, grace: 0, keepaliveEnabled: false
            ).tcpKeepaliveEnabled)
    }

    /// The three keepalive timing knobs are `has_*`-discriminated like
    /// the connect/linger/grace fields. Distinct values surface a
    /// crossed-wire regression as a wrong number.
    func testKeepaliveTimingAccessorsReturnValueWhenHasFlagIsTrue() {
        let opts = makeOpts(
            hasConnect: false, connect: 0, hasLinger: false, linger: 0,
            hasGrace: false, grace: 0,
            keepaliveEnabled: true,
            hasIdle: true, idle: 21,
            hasInterval: true, interval: 7,
            hasCount: true, count: 9
        )
        XCTAssertEqual(opts.tcpKeepaliveIdleSec, 21)
        XCTAssertEqual(opts.tcpKeepaliveIntervalSec, 7)
        XCTAssertEqual(opts.tcpKeepaliveCount, 9)
    }

    /// All timing flags clear → all three accessors return nil so the
    /// caller falls back to the Swift defaults; the literal numeric
    /// values must not leak through.
    func testKeepaliveTimingAccessorsReturnNilWhenHasFlagIsFalse() {
        let opts = makeOpts(
            hasConnect: false, connect: 0, hasLinger: false, linger: 0,
            hasGrace: false, grace: 0,
            keepaliveEnabled: true,
            hasIdle: false, idle: 11,
            hasInterval: false, interval: 12,
            hasCount: false, count: 13
        )
        XCTAssertNil(opts.tcpKeepaliveIdleSec)
        XCTAssertNil(opts.tcpKeepaliveIntervalSec)
        XCTAssertNil(opts.tcpKeepaliveCount)
    }

    // MARK: - TCP tuning accessors

    /// Each tuning accessor is `has_*`-discriminated. Set flags with
    /// non-default values → the accessors return them.
    func testTuningAccessorsReturnValueWhenHasFlagIsTrue() {
        var opts = RamaTcpEgressConnectOptions()
        opts.has_tcp_no_push = true
        opts.tcp_no_push = true
        opts.has_tcp_no_options = true
        opts.tcp_no_options = true
        opts.has_tcp_retransmit_fin_drop = true
        opts.tcp_retransmit_fin_drop = true
        opts.has_tcp_disable_ack_stretching = true
        opts.tcp_disable_ack_stretching = true
        opts.has_tcp_enable_fast_open = true
        opts.tcp_enable_fast_open = true
        opts.has_tcp_disable_ecn = true
        opts.tcp_disable_ecn = true
        opts.has_tcp_maximum_segment_size = true
        opts.tcp_maximum_segment_size = 1_360
        opts.has_tcp_connection_drop_time_secs = true
        opts.tcp_connection_drop_time_secs = 17
        opts.has_tcp_persist_timeout_secs = true
        opts.tcp_persist_timeout_secs = 29
        XCTAssertEqual(opts.tcpNoPush, true)
        XCTAssertEqual(opts.tcpNoOptions, true)
        XCTAssertEqual(opts.tcpRetransmitFinDrop, true)
        XCTAssertEqual(opts.tcpDisableAckStretching, true)
        XCTAssertEqual(opts.tcpEnableFastOpen, true)
        XCTAssertEqual(opts.tcpDisableEcn, true)
        XCTAssertEqual(opts.tcpMaximumSegmentSize, 1_360)
        XCTAssertEqual(opts.tcpConnectionDropTimeSec, 17)
        XCTAssertEqual(opts.tcpPersistTimeoutSec, 29)
    }

    /// `tcp_no_delay` has no `has_*` companion (always meaningful, like
    /// keepalive) — the accessor reads it verbatim in both polarities.
    func testNoDelayAccessorReadsFlagVerbatim() {
        var opts = RamaTcpEgressConnectOptions()
        opts.tcp_no_delay = true
        XCTAssertTrue(opts.tcpNoDelay)
        opts.tcp_no_delay = false
        XCTAssertFalse(opts.tcpNoDelay)
    }

    /// Flags clear with non-default wire values → every accessor
    /// returns nil; the literal values must not leak through.
    func testTuningAccessorsReturnNilWhenHasFlagIsFalse() {
        var opts = RamaTcpEgressConnectOptions()
        opts.tcp_no_push = true
        opts.tcp_no_options = true
        opts.tcp_retransmit_fin_drop = true
        opts.tcp_disable_ack_stretching = true
        opts.tcp_enable_fast_open = true
        opts.tcp_disable_ecn = true
        opts.tcp_maximum_segment_size = 1_360
        opts.tcp_connection_drop_time_secs = 17
        opts.tcp_persist_timeout_secs = 29
        XCTAssertNil(opts.tcpNoPush)
        XCTAssertNil(opts.tcpNoOptions)
        XCTAssertNil(opts.tcpRetransmitFinDrop)
        XCTAssertNil(opts.tcpDisableAckStretching)
        XCTAssertNil(opts.tcpEnableFastOpen)
        XCTAssertNil(opts.tcpDisableEcn)
        XCTAssertNil(opts.tcpMaximumSegmentSize)
        XCTAssertNil(opts.tcpConnectionDropTimeSec)
        XCTAssertNil(opts.tcpPersistTimeoutSec)
    }
}
