use super::{ThrottleMode, ThrottledIo};

use rama_core::{Layer, Service, io::Io};
use rama_utils::macros::define_inner_service_accessors;

/// A [`Service`] that wraps a [`Service`]'s input IO [`Stream`] with
/// a byte-rate throttle. See [`ThrottledIo`].
///
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::io::Io
#[derive(Debug, Clone)]
pub struct ThrottleService<S> {
    inner: S,
    config: super::ThrottleConfig,
}

impl<S> ThrottleService<S> {
    define_inner_service_accessors!();
}

impl<S, IO> Service<IO> for ThrottleService<S>
where
    S: Service<ThrottledIo<IO>>,
    IO: Io,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        stream: IO,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.inner.serve(self.config.wrap(stream))
    }
}

/// A [`Layer`] that wraps a [`Service`]'s input IO [`Stream`] with
/// a byte-rate throttle. See [`ThrottledIo`].
///
/// Directions are relative to the wrapped connection: `read` throttles
/// ingress from the peer (back-pressuring it through transport flow
/// control), `write` paces egress toward it.
///
/// [`Layer`]: rama_core::Layer
/// [`Service`]: rama_core::Service
/// [`Stream`]: rama_core::io::Io
#[derive(Debug, Clone, Default)]
pub struct ThrottleLayer {
    config: super::ThrottleConfig,
}

impl ThrottleLayer {
    /// Create a new [`ThrottleLayer`] throttling both directions with
    /// the given [`ThrottleMode`].
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

    /// Create a new [`ThrottleLayer`] throttling only the read
    /// (ingress) direction.
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

    /// Create a new [`ThrottleLayer`] throttling only the write
    /// (egress) direction.
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

    /// Create a new [`ThrottleLayer`] with per-direction modes.
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

impl<S> Layer<S> for ThrottleLayer {
    type Service = ThrottleService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ThrottleService {
            inner,
            config: self.config.clone(),
        }
    }
}
