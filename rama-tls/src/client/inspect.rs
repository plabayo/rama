//! Policy and outcomes shared by record-framed and QUIC ClientHello inspection.

use rama_core::{extensions::Extension, io::peek::PeekStopReason};

/// How ClientHello peeking handles recognized TLS that cannot be parsed.
///
/// Covers malformed headers/messages, reassembly-limit violations, and EOF
/// before a complete hello. QUIC also applies it to unsupported versions.
/// A parse failure does not necessarily mean the
/// destination would reject the connection. Timeouts use [`PeekTimeoutPolicy`]
/// separately; transport read errors always return an error.
///
/// [`PeekTimeoutPolicy`]: rama_core::io::peek::PeekTimeoutPolicy
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MalformedTlsPolicy {
    /// Reject the connection instead of invoking the fallback. Use this for
    /// routes whose policy depends on inspecting a valid ClientHello or SNI.
    Reject,
    /// Stop inspecting (the default) and invoke the configured fallback, replaying every
    /// consumed wire byte unchanged. The functional API returns `None` for the
    /// hello. Reassembly limits remain enforced; the fallback can forward the
    /// connection without inspection. A strict SNI route is not guaranteed.
    #[default]
    Fallback,
}

/// The inspection outcome attached when a ClientHello peeker dispatches a connection.
///
/// TCP and QUIC peek services insert this extension before dispatching, including a
/// clear status on valid or non-TLS input so an earlier failure is shadowed.
/// The functional helper with explicit policies returns it separately and does
/// not require an extension-bearing stream.
#[derive(Debug, Clone, Copy, Default, Extension)]
#[extension(tags(tls))]
pub struct ClientHelloPeekStatus {
    /// Why inspection failed and selected fallback, if it did.
    /// `Rejected` includes malformed messages, unsupported QUIC versions, and
    /// TLS reassembly-limit violations.
    /// `Eof` means recognized TLS ended before a complete hello; `Timeout`
    /// means the configured deadline expired without a verdict. A buffer limit
    /// or QUIC inspection budget is reported as `MaxPeekSizeReached`.
    /// Stop reasons describe each transport's inspection process: a handshake-size
    /// violation is `Rejected` for TLS records and `MaxPeekSizeReached` for QUIC.
    /// Both follow the same malformed-TLS policy. No failure is recorded for a
    /// valid ClientHello or traffic that was not identified as TLS.
    pub failure: Option<PeekStopReason>,
}
