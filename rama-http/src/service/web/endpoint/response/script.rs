use super::{Headers, IntoResponse};
use crate::headers::ContentType;
use crate::{Body, Response};
use rama_utils::macros::impl_deref;
use std::fmt;

/// An HTML response.
///
/// Will automatically get `Content-Type: application/javascript; charset=utf-8`.
pub struct Script<T>(pub T);

impl<T: fmt::Debug> fmt::Debug for Script<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Script").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Script<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Copy> Copy for Script<T> {}

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
