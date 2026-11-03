//! HTTP facts used by early-data recovery policies.
//!
//! These extensions do not depend on the Retry layer. A custom client service
//! can grant an attempt-local [`EarlyDataPermit`](rama_net::tls::EarlyDataPermit),
//! retain a replayable request, and inspect [`EarlyDataAttempt`] or
//! [`EarlyDataRejected`] after sending. Recover at most once, with
//! [`ForbidEarlyData`](rama_net::tls::ForbidEarlyData) retained for subsequent
//! attempts. Only original requests with actual early-send evidence may recover
//! HTTP 425; gateways pass that response back to its original owner.
//!
//! Custom servers and gateways can inspect [`EarlyDataReceived`] and await its
//! confirmation without any retry middleware. Inherited `Early-Data` exposure
//! remains independent of the current connection's handshake.

use crate::{Request, header};
use rama_core::{
    error::BoxError,
    extensions::{Extension, Extensions, ExtensionsRef, Ingress},
};
use std::{error::Error, fmt, future::Future, pin::Pin, sync::Arc};

/// Transport evidence that this request was actually sent with TLS early keys.
///
/// Published on the response, using the actual outgoing request. A forwarded
/// `Early-Data` field prevents original-client 425 recovery even if a layer
/// inserted that field after the retry policy cloned the request. An ingress
/// request is also classified as forwarded, even when a custom gateway omitted
/// the forwarding marker.
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
            original: !request.headers().contains_key(header::EARLY_DATA)
                && !request.extensions().contains::<Ingress<Extensions>>(),
        }
    }

    /// Whether the request originated here and lacked an inherited exposure field.
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

/// Transport evidence that this request contained bytes received with early keys.
///
/// Presence records replay exposure even after the handshake completes. It is
/// independent of an inherited `Early-Data` field, whose exposure a local
/// handshake cannot discharge. Only transports observing actual receipt may
/// construct this extension; a pending handshake alone is insufficient.
/// The callback may retain a connection handle until all extension copies are
/// dropped. Keep only the request metadata needed when retaining requests long-term.
#[derive(Clone, Extension)]
#[extension(tags(http))]
#[non_exhaustive]
pub struct EarlyDataReceived {
    confirm: Arc<Confirmation>,
}

type Confirmation =
    dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send>> + Send + Sync;

impl fmt::Debug for EarlyDataReceived {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EarlyDataReceived").finish_non_exhaustive()
    }
}

impl EarlyDataReceived {
    /// Record actual early receipt with a cancellation-safe handshake wait.
    ///
    /// The callback must resolve only after successful peer authentication.
    /// Repeated or cancelled waits must leave the connection usable.
    pub fn new<F, Fut>(confirm: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), BoxError>> + Send + 'static,
    {
        Self {
            confirm: Arc::new(move || Box::pin(confirm())),
        }
    }

    /// Wait until this connection's handshake is confirmed.
    ///
    /// This does not clear an inherited `Early-Data` field or make an arbitrary
    /// replay-sensitive operation safe across connections.
    pub async fn confirmed(&self) -> Result<(), BoxError> {
        (self.confirm)().await
    }
}
