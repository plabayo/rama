use std::error::Error;

use derive_more::Display;
use rama_http_types::Response;

use crate::service::web::response::IntoResponse;

pub trait IntoResponseError: Error + Send + Sync + 'static {
    fn as_response(&self) -> Response;
}

impl<T> IntoResponseError for T
where
    T: IntoResponse + Clone + Error + Send + Sync + 'static,
{
    fn as_response(&self) -> Response {
        self.clone().into_response()
    }
}

#[derive(Debug, Display)]
pub struct ResponseError(Box<dyn IntoResponseError>);

impl Error for ResponseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.0)
    }
}

impl ResponseError {
    pub fn new(err: impl IntoResponseError) -> Self {
        Self(Box::new(err))
    }

    pub fn as_response(&self) -> Response {
        self.0.as_response()
    }
}
