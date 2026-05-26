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
mod toggle;

pub use self::file::{FileKeyLogSink, normalize_path};
pub use self::rotating::{
    DEFAULT_PREFIX as ROTATING_DEFAULT_PREFIX, RotatingFileKeyLogSink, RotationPeriod,
};
pub use self::sink::{KeyLogSink, NoopKeyLogSink};
pub use self::toggle::{KeyLogToggle, ToggleableKeyLogSink};

use std::sync::Arc;

use rama_core::error::BoxError;

use super::KeyLogIntent;

/// Resolve a [`KeyLogIntent`] into a concrete sink, opening files
/// as needed.
///
/// * [`KeyLogIntent::Disabled`] and an unset `SSLKEYLOGFILE` on
///   [`KeyLogIntent::Environment`] both return `Ok(None)`.
/// * [`KeyLogIntent::File`] opens the path via
///   [`FileKeyLogSink::try_open`] (cached + dedup'd by path).
/// * [`KeyLogIntent::Custom`] returns the supplied sink unchanged.
pub fn open_intent_sink(
    intent: &KeyLogIntent,
) -> Result<Option<Arc<dyn KeyLogSink>>, BoxError> {
    match intent {
        KeyLogIntent::Disabled => Ok(None),
        KeyLogIntent::Environment => Ok(FileKeyLogSink::try_from_env()?
            .map(|s| Arc::new(s) as Arc<dyn KeyLogSink>)),
        KeyLogIntent::File(path) => Ok(Some(
            Arc::new(FileKeyLogSink::try_open(path)?) as Arc<dyn KeyLogSink>
        )),
        KeyLogIntent::Custom(sink) => Ok(Some(Arc::clone(sink))),
    }
}
