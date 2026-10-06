use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;

use super::{ThrottleConfig, ThrottleMode, Throttleable};
use crate::client::{ConnectionError, ConnectorService, EstablishedClientConnection};

/// A [`Service`] that throttles the connection its inner connector
/// establishes: an IO [`Stream`] is wrapped in a [`ThrottledIo`], other
/// connections throttle their own streams (see [`Throttleable`]).
///
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::io::Io
/// [`ThrottledIo`]: super::ThrottledIo
#[derive(Debug, Clone)]
pub struct OutgoingThrottleService<S> {
    inner: S,
    config: ThrottleConfig,
}

impl<S> OutgoingThrottleService<S> {
    define_inner_service_accessors!();
}

impl<S, Input> Service<Input> for OutgoingThrottleService<S>
where
    S: ConnectorService<Input, Connection: Throttleable<Throttled: Send + 'static>>,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<<S::Connection as Throttleable>::Throttled, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
        let conn = conn.throttle(&self.config);
        Ok(EstablishedClientConnection { input, conn })
    }
}

/// A [`Layer`] that throttles the connection a [`Service`] (connector)
/// establishes: an IO [`Stream`] is wrapped in a [`ThrottledIo`], other
/// connections throttle their own streams (see [`Throttleable`]).
///
/// Directions are relative to the established connection: `read`
/// throttles ingress from the upstream, `write` paces egress toward it.
///
/// [`Layer`]: rama_core::Layer
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::io::Io
/// [`ThrottledIo`]: super::ThrottledIo
#[derive(Debug, Clone, Default)]
pub struct OutgoingThrottleLayer {
    config: ThrottleConfig,
}

impl OutgoingThrottleLayer {
    /// Create a new [`OutgoingThrottleLayer`] throttling both directions
    /// with the given [`ThrottleMode`].
    ///
    /// [`ThrottleMode::PerConn`] gives each direction its own
    /// (independent) bucket; [`ThrottleMode::Shared`] spends both
    /// directions from the same aggregate budget.
    #[must_use]
    pub fn symmetric(mode: ThrottleMode) -> Self {
        Self::new(Some(mode.clone()), Some(mode))
    }

    /// Create a new [`OutgoingThrottleLayer`] throttling only the read
    /// (ingress from upstream) direction.
    #[must_use]
    pub fn read_only(mode: ThrottleMode) -> Self {
        Self::new(Some(mode), None)
    }

    /// Create a new [`OutgoingThrottleLayer`] throttling only the write
    /// (egress to upstream) direction.
    #[must_use]
    pub fn write_only(mode: ThrottleMode) -> Self {
        Self::new(None, Some(mode))
    }

    /// Create a new [`OutgoingThrottleLayer`] with per-direction modes.
    #[must_use]
    pub fn new(read: Option<ThrottleMode>, write: Option<ThrottleMode>) -> Self {
        Self {
            config: ThrottleConfig::new(read, write),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the grant quantum in bytes: the budget reserved per
        /// IO operation (clamped to the burst capacity; defaults to a
        /// tenth of a period worth of bytes, at most 16 KiB).
        pub fn quantum(mut self, quantum: Option<u64>) -> Self {
            self.config.maybe_set_quantum(quantum);
            self
        }
    }
}

impl<S> Layer<S> for OutgoingThrottleLayer {
    type Service = OutgoingThrottleService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OutgoingThrottleService {
            inner,
            config: self.config.clone(),
        }
    }
}
