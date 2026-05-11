//! Tunable knobs for the FastCGI server.
//!
//! All defaults are **graceful**: parsing accepts mildly non-conforming input
//! (mirroring nginx / php-fpm behaviour) and applies DoS-resistant caps.
//! Toggle the `strict_*` flags to reject malformed input instead, useful for
//! locked-down environments.

use std::time::Duration;

/// Configuration for [`FastCgiServer`][crate::server::FastCgiServer].
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// Maximum total bytes accepted across all `FCGI_PARAMS` records for a
    /// single request. Excess data terminates the connection.
    ///
    /// Default: 1 MiB.
    pub max_params_bytes: usize,

    /// Optional total cap on bytes accepted across all `FCGI_STDIN` records.
    /// `None` means unbounded (defer enforcement to the inner service).
    ///
    /// Default: `None`.
    pub max_stdin_bytes: Option<u64>,

    /// Optional total cap on bytes accepted across all `FCGI_DATA` records
    /// (Filter role only). `None` means unbounded.
    ///
    /// Default: `None`.
    pub max_data_bytes: Option<u64>,

    /// Optional idle timeout between FastCGI records on the read side.
    /// Catches slow-loris clients that hold a connection open without
    /// progressing the request.
    ///
    /// Default: `None`.
    pub read_timeout: Option<Duration>,

    /// Optional write timeout per response chunk.
    ///
    /// Default: `None`.
    pub write_timeout: Option<Duration>,

    /// Reject `FCGI_BEGIN_REQUEST` bodies whose content length differs from
    /// the canonical 8. By default the server tolerates `content_length >= 8`
    /// and ignores the extras (forward-compat with hypothetical extensions).
    ///
    /// Default: `false`.
    pub strict_begin_body_size: bool,

    /// When a record arrives for a different request id while a request is
    /// in flight, reply with `FCGI_END_REQUEST{CantMpxConn}` for that id and
    /// continue serving the current request. When disabled, the server still
    /// behaves gracefully (drops the stray record) but does not signal the
    /// peer.
    ///
    /// Default: `true`.
    pub respond_cant_mpx_conn: bool,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            max_params_bytes: 1024 * 1024,
            max_stdin_bytes: None,
            max_data_bytes: None,
            read_timeout: None,
            write_timeout: None,
            strict_begin_body_size: false,
            respond_cant_mpx_conn: true,
        }
    }
}

impl ServerOptions {
    /// Create a new [`ServerOptions`] with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum total bytes accepted across all `FCGI_PARAMS` records.
    #[must_use]
    pub fn with_max_params_bytes(mut self, n: usize) -> Self {
        self.max_params_bytes = n;
        self
    }

    /// Set the maximum total bytes accepted across all `FCGI_STDIN` records.
    #[must_use]
    pub fn with_max_stdin_bytes(mut self, n: u64) -> Self {
        self.max_stdin_bytes = Some(n);
        self
    }

    /// Set the idle read timeout between FastCGI records.
    #[must_use]
    pub fn with_read_timeout(mut self, d: Duration) -> Self {
        self.read_timeout = Some(d);
        self
    }

    /// Set the per-chunk write timeout.
    #[must_use]
    pub fn with_write_timeout(mut self, d: Duration) -> Self {
        self.write_timeout = Some(d);
        self
    }
}
