import Foundation
import RamaAppleNEFFI

/// Typed accessors for `RamaTcpEgressConnectOptions`.
///
/// The FFI struct exposes each optional field as a
/// `has_<name>` / `<name>` pair (since C has no `Optional`).
/// Call sites doing
///
///     egressOpts.flatMap { $0.has_connect_timeout_ms
///                          ? $0.connect_timeout_ms : nil } ?? default
///
/// drift easily — every new field would add another copy of
/// the same `flatMap`/`has_X`/`X`/`??` quadruple, and a
/// rename or typo silently flips the field to "always
/// default". These accessors collapse the pattern to
///
///     egressOpts?.connectTimeoutMs ?? default
///
/// so the only thing the call site says is the name + the
/// fallback. The fall-back-to-default decision moves to the
/// caller (different sites want different defaults).
extension RamaTcpEgressConnectOptions {
    /// Connect timeout for the egress NWConnection, in
    /// milliseconds. `nil` when the engine didn't set one
    /// (caller should fall back to a sensible default —
    /// 30 000 ms in `TcpFlowSession.startEgressConnection`).
    var connectTimeoutMs: UInt32? {
        has_connect_timeout_ms ? connect_timeout_ms : nil
    }

    /// Wall-clock cap on the egress writer's linger after
    /// FIN, in milliseconds. `nil` when the engine didn't
    /// set one (caller should fall back to
    /// `defaultLingerCloseMs`).
    var lingerCloseMs: UInt32? {
        has_linger_close_ms ? linger_close_ms : nil
    }

    /// Grace window between the egress read pump observing
    /// EOF and the backstop `connection.cancelAndDetach()`
    /// firing, in milliseconds. `nil` when the engine
    /// didn't set one (caller should fall back to
    /// `defaultEgressEofGraceMs`).
    var egressEofGraceMs: UInt32? {
        has_egress_eof_grace_ms ? egress_eof_grace_ms : nil
    }

    /// Whether to enable TCP keepalive. No `has_*` companion — Rust
    /// always sends a meaningful value (default `true`).
    var tcpKeepaliveEnabled: Bool {
        tcp_keepalive_enabled
    }

    /// Keepalive idle period (s); `nil` ⇒ `defaultTcpKeepaliveIdleSec`.
    var tcpKeepaliveIdleSec: Int? {
        has_tcp_keepalive_idle_secs ? Int(tcp_keepalive_idle_secs) : nil
    }

    /// Keepalive probe interval (s); `nil` ⇒ `defaultTcpKeepaliveIntervalSec`.
    var tcpKeepaliveIntervalSec: Int? {
        has_tcp_keepalive_interval_secs ? Int(tcp_keepalive_interval_secs) : nil
    }

    /// Keepalive probe count; `nil` ⇒ `defaultTcpKeepaliveCount`.
    var tcpKeepaliveCount: Int? {
        has_tcp_keepalive_count ? Int(tcp_keepalive_count) : nil
    }

    /// `noDelay` (TCP_NODELAY). No `has_*` companion — Rust always sends a
    /// meaningful value (default `true`; the relay is the only Nagle
    /// decision-maker in the path).
    var tcpNoDelay: Bool {
        tcp_no_delay
    }

    /// `noPush` (TCP_NOPUSH); `nil` ⇒ Network.framework default.
    var tcpNoPush: Bool? {
        has_tcp_no_push ? tcp_no_push : nil
    }

    /// `noOptions`; `nil` ⇒ Network.framework default.
    var tcpNoOptions: Bool? {
        has_tcp_no_options ? tcp_no_options : nil
    }

    /// `retransmitFinDrop`; `nil` ⇒ Network.framework default.
    var tcpRetransmitFinDrop: Bool? {
        has_tcp_retransmit_fin_drop ? tcp_retransmit_fin_drop : nil
    }

    /// `disableAckStretching`; `nil` ⇒ Network.framework default.
    var tcpDisableAckStretching: Bool? {
        has_tcp_disable_ack_stretching ? tcp_disable_ack_stretching : nil
    }

    /// `enableFastOpen` (TFO); `nil` ⇒ Network.framework default.
    var tcpEnableFastOpen: Bool? {
        has_tcp_enable_fast_open ? tcp_enable_fast_open : nil
    }

    /// `disableECN`; `nil` ⇒ Network.framework default.
    var tcpDisableEcn: Bool? {
        has_tcp_disable_ecn ? tcp_disable_ecn : nil
    }

    /// `maximumSegmentSize` (bytes); `nil` ⇒ path default.
    var tcpMaximumSegmentSize: Int? {
        has_tcp_maximum_segment_size ? Int(tcp_maximum_segment_size) : nil
    }

    /// `connectionDropTime` (s); `nil` ⇒ Network.framework default.
    var tcpConnectionDropTimeSec: Int? {
        has_tcp_connection_drop_time_secs ? Int(tcp_connection_drop_time_secs) : nil
    }

    /// `persistTimeout` (s); `nil` ⇒ Network.framework default.
    var tcpPersistTimeoutSec: Int? {
        has_tcp_persist_timeout_secs ? Int(tcp_persist_timeout_secs) : nil
    }
}
