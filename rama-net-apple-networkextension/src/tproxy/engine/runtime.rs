use std::{future::Future, time::Duration};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::rt::{OwnedRuntime, OwnedRuntimeHandle};

/// Async runtime owned by a [`TransparentProxyEngine`].
///
/// This is the shared [`rama_core::rt::OwnedRuntime`] used across Rama. It
/// wraps either a plain Tokio runtime or, when `dial9` is enabled, a
/// dial9-instrumented runtime against a recorder it keeps alive.
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

    /// Wrap a dial9-instrumented runtime and its recorder.
    #[cfg(feature = "dial9")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
    #[must_use]
    pub fn from_dial9(attached: ::dial9::AttachedRuntime) -> Self {
        Self {
            inner: OwnedRuntime::from_dial9(attached),
        }
    }

    /// Return a cloneable handle to this runtime.
    ///
    /// The handle retains the runtime's dial9 telemetry session and can safely
    /// spawn instrumented work from arbitrary threads.
    #[must_use]
    pub fn handle(&self) -> OwnedRuntimeHandle {
        self.inner.handle()
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

/// Default factory for a multi-thread Tokio runtime.
///
/// With the `dial9` feature it resolves the `DIAL9_*` environment when creating
/// the runtime and instruments it against the resulting recorder. The
/// environment default is telemetry-disabled unless `DIAL9_ENABLED` requests it.
#[derive(Debug, Default)]
pub struct DefaultTransparentProxyAsyncRuntimeFactory {
    #[cfg(feature = "dial9")]
    dial9_recorder: FactoryDial9Recorder,
    #[cfg(feature = "dial9")]
    dial9_attach_options: Option<::dial9::TokioAttachOptions>,
}

#[cfg(feature = "dial9")]
#[derive(Debug, Default)]
enum FactoryDial9Recorder {
    #[default]
    FromEnv,
    Disabled,
    Custom(Box<::dial9::Recorder>),
}

impl DefaultTransparentProxyAsyncRuntimeFactory {
    /// Build a default factory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "dial9")]
    rama_utils::macros::generate_set_and_with! {
        /// Set the [`Recorder`] the runtime is recorded into.
        ///
        /// This defaults to resolving the `DIAL9_*` environment when creating
        /// the runtime. Use
        /// [`without_dial9_recorder`](Self::without_dial9_recorder) for a plain
        /// Tokio runtime. Use [`dial9::recorder_or_disabled`] when a
        /// custom recorder should fall back to a plain runtime on configuration
        /// failure.
        ///
        /// [`Recorder`]: dial9::Recorder
        /// [`dial9::recorder_or_disabled`]: dial9::recorder_or_disabled
        #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
        pub fn dial9_recorder(
            mut self,
            dial9_recorder: Option<::dial9::Recorder>,
        ) -> Self {
            self.dial9_recorder = match dial9_recorder {
                Some(recorder) => FactoryDial9Recorder::Custom(Box::new(recorder)),
                None => FactoryDial9Recorder::Disabled,
            };
            self
        }
    }

    #[cfg(feature = "dial9")]
    rama_utils::macros::generate_set_and_with! {
        /// Set the dial9 tracing options for the engine's runtime, such as the
        /// runtime name a multi-extension trace is disambiguated by.
        ///
        /// Applies alongside
        /// [`with_dial9_recorder`](Self::with_dial9_recorder). The environment
        /// path takes its options from the `DIAL9_*` variables, so combining
        /// options with it is rejected when the runtime is created; with
        /// telemetry explicitly disabled the options are moot.
        #[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
        pub fn dial9_attach_options(
            mut self,
            dial9_attach_options: ::dial9::TokioAttachOptions,
        ) -> Self {
            self.dial9_attach_options = Some(dial9_attach_options);
            self
        }
    }
}

impl TransparentProxyAsyncRuntimeFactory for DefaultTransparentProxyAsyncRuntimeFactory {
    type Error = BoxError;

    fn create_async_runtime(
        self,
        _: Option<&[u8]>,
    ) -> Result<TransparentProxyAsyncRuntime, Self::Error> {
        #[cfg(feature = "dial9")]
        {
            if self.dial9_attach_options.is_some()
                && matches!(self.dial9_recorder, FactoryDial9Recorder::FromEnv)
            {
                return Err(rama_core::error::extra::OpaqueError::from_static_str(
                    "dial9 attach options require an explicit dial9 recorder; the environment path configures itself from `DIAL9_*`",
                )
                .into());
            }

            match self.dial9_recorder {
                FactoryDial9Recorder::Disabled => {}
                FactoryDial9Recorder::FromEnv => {
                    let attached = ::dial9::recorder_from_env()
                        .context("build dial9 instrumented runtime from environment")?;
                    return Ok(TransparentProxyAsyncRuntime::from_dial9(attached));
                }
                FactoryDial9Recorder::Custom(recorder) => {
                    use ::dial9::Dial9HandleTokioExt as _;

                    let mut builder = tokio::runtime::Builder::new_multi_thread();
                    builder.enable_all();
                    let runtime = recorder
                        .handle()
                        .attach_tokio_runtime(
                            builder,
                            self.dial9_attach_options.unwrap_or_default(),
                        )
                        .context("attach dial9 recorder to engine runtime")?;
                    return Ok(TransparentProxyAsyncRuntime::from_dial9((
                        *recorder, runtime,
                    )));
                }
            }
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("build default tokio runtime")?;
        Ok(TransparentProxyAsyncRuntime::from_tokio(rt))
    }
}

#[cfg(all(test, feature = "dial9"))]
mod tests {
    use super::*;

    #[test]
    fn default_factory_defers_dial9_environment_resolution() {
        let factory = DefaultTransparentProxyAsyncRuntimeFactory::default();
        assert!(matches!(
            factory.dial9_recorder,
            FactoryDial9Recorder::FromEnv
        ));

        let factory = factory.without_dial9_recorder();
        assert!(matches!(
            factory.dial9_recorder,
            FactoryDial9Recorder::Disabled
        ));
    }

    #[test]
    fn dial9_attach_options_require_an_explicit_recorder() {
        let factory = DefaultTransparentProxyAsyncRuntimeFactory::new()
            .with_dial9_attach_options(::dial9::TokioAttachOptions::default());
        factory.create_async_runtime(None).unwrap_err();
    }
}
