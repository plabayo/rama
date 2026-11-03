//! HTTP facts used by early-data recovery policies.

use crate::{Request, header};
use rama_core::{error::BoxError, extensions::Extension};
use std::{error::Error, fmt};

/// Transport evidence that this request was actually sent with TLS early keys.
///
/// Published on the response, using the actual outgoing request. A forwarded
/// `Early-Data` field prevents original-client 425 recovery even if a layer
/// inserted that field after the retry policy cloned the request.
#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(http))]
#[non_exhaustive]
pub struct EarlyDataAttempt {
    original: bool,
}

impl EarlyDataAttempt {
    /// Record an actual early transmission of `request`.
    ///
    /// Only a transport which observed this request's early stream admission
    /// may call this. A configured early-data option or pending handshake alone
    /// is not evidence that this request used early keys.
    #[must_use]
    pub fn sent_early<B>(request: &Request<B>) -> Self {
        Self {
            original: !request.headers().contains_key(header::EARLY_DATA),
        }
    }

    /// Whether the outgoing request lacked an inherited replay-exposure field.
    #[must_use]
    pub const fn permits_425_recovery(&self) -> bool {
        self.original
    }
}

/// TLS rejected the early stream carrying this particular HTTP request.
///
/// This is distinct from an HTTP 425 response and from a connection-wide early
/// rejection observed by a request which never sent early. The failed transport
/// must be retired before recovery reconnects.
#[derive(Debug)]
#[non_exhaustive]
pub struct EarlyDataRejected {
    source: BoxError,
}

impl EarlyDataRejected {
    /// Wrap a transport rejection after verifying this request used early keys.
    pub fn new(source: impl Into<BoxError>) -> Self {
        Self {
            source: source.into(),
        }
    }
}

impl fmt::Display for EarlyDataRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TLS rejected this HTTP request's early data")
    }
}

impl Error for EarlyDataRejected {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
