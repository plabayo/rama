use rama_core::error::{BoxError, ErrorContext as _};

pub type TransparentProxyAsyncRuntime = tokio::runtime::Runtime;

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

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct DefaultTransparentProxyAsyncRuntimeFactory;

impl TransparentProxyAsyncRuntimeFactory for DefaultTransparentProxyAsyncRuntimeFactory {
    type Error = BoxError;

    fn create_async_runtime(
        self,
        _: Option<&[u8]>,
    ) -> Result<TransparentProxyAsyncRuntime, Self::Error> {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("build default tokio runtime")
    }
}
