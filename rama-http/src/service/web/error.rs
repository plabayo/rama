use std::{error::Error, fmt};

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
