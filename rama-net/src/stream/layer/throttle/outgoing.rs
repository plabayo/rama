use super::{ThrottleMode, ThrottledIo};
use crate::client::{ConnectionError, ConnectorService, EstablishedClientConnection};

use rama_core::{Layer, Service, io::Io};
use rama_utils::macros::define_inner_service_accessors;

/// A [`Service`] that wraps a [`Service`]'s output IO [`Stream`] with
/// a byte-rate throttle. See [`ThrottledIo`].
///
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::io::Io
#[derive(Debug, Clone)]
pub struct OutgoingThrottleService<S> {
    inner: S,
    config: super::ThrottleConfig,
}

impl<S> OutgoingThrottleService<S> {
    define_inner_service_accessors!();
}

impl<S, Input> Service<Input> for OutgoingThrottleService<S>
where
    S: ConnectorService<Input, Connection: Io + Unpin>,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<ThrottledIo<S::Connection>, Input>;
    type Error = ConnectionError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection { input, conn } = self.inner.connect(input).await?;
        let conn = self.config.wrap(conn);
        Ok(EstablishedClientConnection { input, conn })
    }
}

/// A [`Layer`] that wraps a [`Service`]'s output IO [`Stream`] with
/// a byte-rate throttle. See [`ThrottledIo`].
///
/// Directions are relative to the established connection: `read`
/// throttles ingress from the upstream, `write` paces egress toward it.
///
/// [`Layer`]: rama_core::Layer
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::io::Io
#[derive(Debug, Clone, Default)]
pub struct OutgoingThrottleLayer {
    config: super::ThrottleConfig,
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
        Self {
            config: super::ThrottleConfig {
                read: Some(mode.clone()),
                write: Some(mode),
                quantum: None,
            },
        }
    }

    /// Create a new [`OutgoingThrottleLayer`] throttling only the read
    /// (ingress from upstream) direction.
    #[must_use]
    pub fn read_only(mode: ThrottleMode) -> Self {
        Self {
            config: super::ThrottleConfig {
                read: Some(mode),
                write: None,
                quantum: None,
            },
        }
    }

    /// Create a new [`OutgoingThrottleLayer`] throttling only the write
    /// (egress to upstream) direction.
    #[must_use]
    pub fn write_only(mode: ThrottleMode) -> Self {
        Self {
            config: super::ThrottleConfig {
                read: None,
                write: Some(mode),
                quantum: None,
            },
        }
    }

    /// Create a new [`OutgoingThrottleLayer`] with per-direction modes.
    #[must_use]
    pub fn new(read: Option<ThrottleMode>, write: Option<ThrottleMode>) -> Self {
        Self {
            config: super::ThrottleConfig {
                read,
                write,
                quantum: None,
            },
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Override the grant quantum in bytes: the budget reserved per
        /// IO operation (clamped to the burst capacity; defaults to a
        /// tenth of a period worth of bytes, at most 16 KiB).
        pub fn quantum(mut self, quantum: Option<u64>) -> Self {
            self.config.quantum = quantum;
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
