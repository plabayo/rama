use rama_core::futures::Stream;
use rama_core::stream::json::JsonWriteStream;
use rama_error::BoxError;
use serde::Serialize;

use crate::headers::ContentType;
use crate::service::web::response::Headers;
use crate::{Body, Response};

use super::IntoResponse;

impl<S, T, E> IntoResponse for JsonWriteStream<S>
where
    S: Stream<Item = Result<T, E>> + Send + 'static,
    T: Serialize,
    E: Into<BoxError>,
{
    #[inline(always)]
    fn into_response(self) -> Response {
        (
            Headers::single(ContentType::ndjson()),
            Body::from_stream(self),
        )
            .into_response()
    }
}
