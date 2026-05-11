//! Tunable knobs for the FastCGI client.

use std::time::Duration;

/// Configuration for [`FastCgiClient`][crate::client::FastCgiClient] and
/// [`send_on`][crate::client::send_on].
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Maximum total bytes accepted across all `FCGI_STDOUT` records from the
    /// backend. Excess data terminates the request with an error.
    ///
    /// Default: 16 MiB.
    pub max_stdout_bytes: usize,

    /// Maximum total bytes accepted across all `FCGI_STDERR` records from the
    /// backend. Excess bytes are truncated (logged at debug level).
    ///
    /// Default: 256 KiB.
    pub max_stderr_bytes: usize,

    /// Optional idle timeout between FastCGI records on the read side.
    ///
    /// Default: `None`.
    pub read_timeout: Option<Duration>,

    /// Optional write timeout per record on the write side.
    ///
    /// Default: `None`.
    pub write_timeout: Option<Duration>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            max_stdout_bytes: 16 * 1024 * 1024,
            max_stderr_bytes: 256 * 1024,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

impl ClientOptions {
    /// Create a new [`ClientOptions`] with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum stdout bytes accepted.
        pub fn max_stdout_bytes(mut self, n: usize) -> Self {
            self.max_stdout_bytes = n;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum stderr bytes accepted.
        pub fn max_stderr_bytes(mut self, n: usize) -> Self {
            self.max_stderr_bytes = n;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Optional idle read timeout enforced at the IO layer.
        pub fn read_timeout(mut self, d: Option<Duration>) -> Self {
            self.read_timeout = d;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Optional write timeout enforced at the IO layer.
        pub fn write_timeout(mut self, d: Option<Duration>) -> Self {
            self.write_timeout = d;
            self
        }
    }
}
