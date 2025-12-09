use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response};
use rama_utils::macros::impl_deref;

/// An HTML response.
///
/// Will automatically get `Content-Type: application/javascript; charset=utf-8`.
#[derive(Debug, Clone, Copy)]
pub struct Script<T>(pub T);

impl_deref!(Script);

impl<T> IntoResponse for Script<T>
where
    T: Into<Body>,
{
    fn into_response(self) -> Response {
        (
            Headers::single(ContentType::javascript_utf8()),
            self.0.into(),
        )
            .into_response()
    }
}

impl<T> From<T> for Script<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}
