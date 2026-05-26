//! TLS keylog facility used by every TLS implementation supported by
//! rama (and exposed for your own).
//!
//! The trait at the center is [`KeyLogSink`]: a non-blocking,
//! `Send + Sync` consumer of one NSS-format keylog line per call. The
//! TLS crates feed each handshake's `set_keylog_callback` into a sink
//! held behind `Arc<dyn KeyLogSink>` (the only erasure point); every
//! sink wrapper above that — [`FileKeyLogSink`], [`RotatingFileKeyLogSink`],
//! [`ToggleableKeyLogSink`] — is statically dispatched.
//!
//! Lines arrive at the sink **including their trailing newline**;
//! implementations persist bytes verbatim.

mod file;
mod rotating;
mod sink;

pub use self::file::{FileKeyLogSink, normalize_path};
pub use self::rotating::{
    DEFAULT_PREFIX as ROTATING_DEFAULT_PREFIX, RotatingFileKeyLogSink, RotationPeriod,
};
pub use self::sink::{KeyLogSink, NoopKeyLogSink};
