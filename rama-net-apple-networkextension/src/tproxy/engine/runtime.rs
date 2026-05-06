use std::future::Future;

use rama_core::error::{BoxError, ErrorContext as _};

/// Async runtime owned by a [`TransparentProxyEngine`].
///
/// Wraps either a plain `tokio::runtime::Runtime` or — when the
/// `dial9` feature is enabled and a [`Dial9Config`] is supplied to the
/// factory — a `dial9_tokio_telemetry::TracedRuntime`. Engine code
/// drives the runtime through this wrapper so the same call sites
/// work on both.
///
/// [`TransparentProxyEngine`]: super::TransparentProxyEngine
/// [`Dial9Config`]: dial9_tokio_telemetry::Dial9Config
#[derive(Debug)]
pub struct TransparentProxyAsyncRuntime {
    inner: RuntimeInner,
}

#[derive(Debug)]
enum RuntimeInner {
    Plain(tokio::runtime::Runtime),
    #[cfg(feature = "dial9")]
    Traced(::dial9_tokio_telemetry::TracedRuntime),
}

impl TransparentProxyAsyncRuntime {
    /// Wrap a plain tokio runtime.
    #[must_use]
    pub fn from_tokio(runtime: tokio::runtime::Runtime) -> Self {
        Self {
            inner: RuntimeInner::Plain(runtime),
        }
    }

    /// Wrap a `dial9-tokio-telemetry` traced runtime.
    ///
    /// Holding the [`TracedRuntime`] keeps its inner `TelemetryGuard`
    /// alive for the engine's lifetime, which is what keeps the
    /// background trace-writer running.
    ///
    /// [`TracedRuntime`]: dial9_tokio_telemetry::TracedRuntime
    #[cfg(feature = "dial9")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
    #[must_use]
    pub fn from_dial9(runtime: ::dial9_tokio_telemetry::TracedRuntime) -> Self {
        Self {
            inner: RuntimeInner::Traced(runtime),
        }
    }

    /// Tokio runtime handle, cloneable across threads.
    #[must_use]
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.tokio_runtime().handle().clone()
    }

    /// Borrow the inner `tokio::runtime::Runtime`.
    ///
    /// Use [`block_on`](Self::block_on) and [`spawn`](Self::spawn) for
    /// the dial9-instrumented entry points. This accessor exists for
    /// callers that need to drive `block_on` with non-`'static`
    /// futures (where the dial9 spawn-then-await indirection cannot
    /// be applied) or otherwise need direct access to the runtime.
    #[must_use]
    pub fn tokio_runtime(&self) -> &tokio::runtime::Runtime {
        match &self.inner {
            RuntimeInner::Plain(rt) => rt,
            #[cfg(feature = "dial9")]
            RuntimeInner::Traced(rt) => rt.runtime(),
        }
    }

    /// Enter the runtime context on the calling thread.
    pub fn enter(&self) -> tokio::runtime::EnterGuard<'_> {
        match &self.inner {
            RuntimeInner::Plain(rt) => rt.enter(),
            #[cfg(feature = "dial9")]
            RuntimeInner::Traced(rt) => rt.runtime().enter(),
        }
    }

    /// Block on a future on this runtime.
    ///
    /// On the dial9 path this routes through the telemetry handle's
    /// `spawn`, so the awaited future is wake-tracked when telemetry
    /// is enabled and falls through to plain `tokio::spawn` when not.
    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match &self.inner {
            RuntimeInner::Plain(rt) => rt.block_on(future),
            #[cfg(feature = "dial9")]
            RuntimeInner::Traced(rt) => rt.block_on(future),
        }
    }

    /// Spawn a future on this runtime from a thread that already has a
    /// runtime context (i.e. inside an async block running on this
    /// runtime, or after [`enter`](Self::enter)).
    ///
    /// On the dial9 path this routes through
    /// `dial9_tokio_telemetry::spawn` so the future is wake-tracked.
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        #[cfg(feature = "dial9")]
        {
            ::dial9_tokio_telemetry::spawn(future)
        }
        #[cfg(not(feature = "dial9"))]
        {
            self.handle().spawn(future)
        }
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
