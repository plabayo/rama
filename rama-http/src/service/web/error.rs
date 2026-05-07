use std::{convert::Infallible, error::Error, fmt};

use http::StatusCode;
use rama_core::{Layer, Service};
use rama_http_types::Response;

use crate::service::web::response::IntoResponse;

pub trait AsResponseError: Error + Send + Sync + 'static {
    fn as_response(&self) -> Response;
}

impl<T> AsResponseError for T
where
    T: IntoResponse + Clone + Error + Send + Sync + 'static,
{
    fn as_response(&self) -> Response {
        self.clone().into_response()
    }
}

#[derive(Debug)]
pub struct DowncastResponseError(fn(&(dyn Error + 'static)) -> Option<Response>);

impl fmt::Display for DowncastResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DowncastResponseError")
    }
}

impl Error for DowncastResponseError {}

impl DowncastResponseError {
    fn converter<T: AsResponseError>(err: &(dyn Error + 'static)) -> Option<Response> {
        err.downcast_ref::<T>().map(|v| v.as_response())
    }

    pub const fn new<T: AsResponseError>(_err: &T) -> &'static Self {
        &Self(Self::converter::<T>)
    }

    pub fn try_as_response(mut err: &(dyn Error + 'static)) -> Option<Response> {
        while let Some(src) = err.source() {
            if let Some(src) = src.downcast_ref::<Self>() {
                return src.0(err);
            }
            err = src;
        }
        None
    }
}

#[derive(Default, Clone, Copy)]
#[non_exhaustive]
pub struct ImplErrorMode;

#[derive(Default, Clone, Copy)]
#[non_exhaustive]
pub struct AsRefMode;

pub struct DowncastResponseService<S, M> {
    inner: S,
    _mode: M,
}

impl<S, I> Service<I> for DowncastResponseService<S, ImplErrorMode>
where
    S: Service<I, Output: IntoResponse, Error: Error + 'static>,
    I: Send + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, input: I) -> Result<Self::Output, Self::Error> {
        Ok(self.inner.serve(input).await.map_or_else(
            |err| {
                if let Some(resp) = DowncastResponseError::try_as_response(&err) {
                    resp
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            },
            IntoResponse::into_response,
        ))
    }
}

impl<S, I> Service<I> for DowncastResponseService<S, AsRefMode>
where
    S: Service<I, Output: IntoResponse, Error: AsRef<dyn Error + Send + Sync>>,
    I: Send + 'static,
{
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, input: I) -> Result<Self::Output, Self::Error> {
        Ok(self.inner.serve(input).await.map_or_else(
            |err| {
                if let Some(resp) = DowncastResponseError::try_as_response(err.as_ref()) {
                    resp
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                }
            },
            IntoResponse::into_response,
        ))
    }
}

#[derive(Debug, Default, Clone)]
pub struct DowncastResponseLayer<M>(M);

impl DowncastResponseLayer<()> {
    pub fn as_ref() -> DowncastResponseLayer<AsRefMode> {
        Default::default()
    }

    pub fn impl_error() -> DowncastResponseLayer<ImplErrorMode> {
        Default::default()
    }

    pub fn auto<M: Default>() -> DowncastResponseLayer<M> {
        Default::default()
    }
}

impl<S, M: Copy> Layer<S> for DowncastResponseLayer<M> {
    type Service = DowncastResponseService<S, M>;

    fn layer(&self, inner: S) -> Self::Service {
        DowncastResponseService {
            inner,
            _mode: self.0,
        }
    }
}
