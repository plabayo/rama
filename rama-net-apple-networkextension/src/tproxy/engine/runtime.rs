use std::{future::Future, time::Duration};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::rt::{OwnedRuntime, OwnedRuntimeHandle};

/// Async runtime owned by a [`TransparentProxyEngine`].
///
/// This is the shared [`rama_core::rt::OwnedRuntime`] used across Rama. It
/// wraps either a plain Tokio runtime or, when `dial9` is enabled, a traced
/// runtime while retaining the exact telemetry handle used for spawned work.
///
/// [`TransparentProxyEngine`]: super::TransparentProxyEngine
#[derive(Debug)]
pub struct TransparentProxyAsyncRuntime {
    inner: OwnedRuntime,
}

impl TransparentProxyAsyncRuntime {
    /// Wrap a plain Tokio runtime.
    #[must_use]
    pub fn from_tokio(runtime: tokio::runtime::Runtime) -> Self {
        Self {
            inner: OwnedRuntime::from_tokio(runtime),
        }
    }

    /// Wrap a dial9 traced runtime.
    #[cfg(feature = "dial9")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
    #[must_use]
    pub fn from_dial9(runtime: ::dial9_tokio_telemetry::TracedRuntime) -> Self {
        Self {
            inner: OwnedRuntime::from_dial9(runtime),
        }
    }

    /// Return the Tokio runtime handle.
    #[must_use]
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.inner.tokio_runtime().handle().clone()
    }

    /// Return the shared Rama runtime handle, including its dial9 session.
    #[must_use]
    pub fn owned_handle(&self) -> OwnedRuntimeHandle {
        self.inner.handle()
    }

    /// Borrow the underlying Tokio runtime.
    #[must_use]
    pub fn tokio_runtime(&self) -> &tokio::runtime::Runtime {
        self.inner.tokio_runtime()
    }

    /// Enter the runtime context on the calling thread.
    pub fn enter(&self) -> tokio::runtime::EnterGuard<'_> {
        self.inner.enter()
    }

    /// Block on an owned task on this runtime.
    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.block_on_task(future)
    }

    pub(super) fn block_on_borrowed<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        self.inner.block_on(future)
    }

    /// Block on an owned task on this runtime.
    pub fn block_on_task<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.block_on_task(future)
    }

    /// Spawn an owned task on this runtime.
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.spawn(future)
    }

    pub(crate) fn shutdown_bounded(self, grace: Duration) {
        self.inner.shutdown_bounded(grace);
    }
}

/// Factory that constructs the [`TransparentProxyAsyncRuntime`] used
/// by a [`TransparentProxyEngine`](super::TransparentProxyEngine).
pub trait TransparentProxyAsyncRuntimeFactory {
    type Error: Into<BoxError>;

    fn create_async_runtime(
        self,
        cfg: Option<&[u8]>,
    ) -> Result<TransparentProxyAsyncRuntime, Self::Error>;
}

impl<Error, F> TransparentProxyAsyncRuntimeFactory for F
where
    Error: Into<BoxError>,
    F: FnOnce(Option<&[u8]>) -> Result<TransparentProxyAsyncRuntime, Error>,
{
    type Error = Error;

    #[inline(always)]
    fn create_async_runtime(
        self,
        cfg: Option<&[u8]>,
    ) -> Result<TransparentProxyAsyncRuntime, Self::Error> {
        (self)(cfg)
    }
}

/// Default factory: builds a multi-threaded tokio runtime, or a
/// `dial9-tokio-telemetry::TracedRuntime` when a [`Dial9Config`] has
/// been supplied via [`with_dial9_config`].
///
/// [`Dial9Config`]: dial9_tokio_telemetry::Dial9Config
/// [`with_dial9_config`]: DefaultTransparentProxyAsyncRuntimeFactory::with_dial9_config
#[derive(Debug, Default)]
pub struct DefaultTransparentProxyAsyncRuntimeFactory {
    #[cfg(feature = "dial9")]
    dial9_config: Option<::dial9_tokio_telemetry::Dial9Config>,
}

impl DefaultTransparentProxyAsyncRuntimeFactory {
    /// Build a default factory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a [`Dial9Config`] so the runtime is built as a
    /// `dial9-tokio-telemetry::TracedRuntime`.
    ///
    /// Use [`Dial9ConfigBuilder::build_or_disabled`] when constructing
    /// the config so a misconfigured trace destination falls back to
    /// a plain runtime instead of failing the engine build.
    ///
    /// [`Dial9Config`]: dial9_tokio_telemetry::Dial9Config
    /// [`Dial9ConfigBuilder::build_or_disabled`]: dial9_tokio_telemetry::Dial9ConfigBuilder::build_or_disabled
    #[cfg(feature = "dial9")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
    #[must_use]
    pub fn with_dial9_config(mut self, cfg: ::dial9_tokio_telemetry::Dial9Config) -> Self {
        self.dial9_config = Some(cfg);
        self
    }
}

impl TransparentProxyAsyncRuntimeFactory for DefaultTransparentProxyAsyncRuntimeFactory {
    type Error = BoxError;

    fn create_async_runtime(
        self,
        _: Option<&[u8]>,
    ) -> Result<TransparentProxyAsyncRuntime, Self::Error> {
        #[cfg(feature = "dial9")]
        if let Some(cfg) = self.dial9_config {
            let rt = ::dial9_tokio_telemetry::TracedRuntime::try_new(cfg)
                .context("build dial9 traced runtime")?;
            return Ok(TransparentProxyAsyncRuntime::from_dial9(rt));
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("build default tokio runtime")?;
        Ok(TransparentProxyAsyncRuntime::from_tokio(rt))
    }
}
