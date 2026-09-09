use rama_utils::macros::impl_deref;

use super::{Headers, IntoResponse};
use crate::{Body, Response, headers::ContentType};

/// An SVG image response.
///
/// Will automatically get `Content-Type: image/svg+xml`.
#[derive(Debug, Clone, Copy)]
pub struct Svg<T>(pub T);

impl_deref!(Svg);

impl<T> IntoResponse for Svg<T>
where
    T: Into<Body>,
{
    fn into_response(self) -> Response {
        (Headers::single(ContentType::svg()), self.0.into()).into_response()
    }
}

impl<T> From<T> for Svg<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{body::util::BodyExt, headers::HeaderMapExt};
    #[tokio::test]
    async fn svg_preserves_content_and_sets_its_media_type() {
        let response = Svg("<svg xmlns=\"http://www.w3.org/2000/svg\"/>").into_response();
        assert_eq!(
            response.headers().typed_get::<ContentType>(),
            Some(ContentType::svg())
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>"
        );
    }
}
