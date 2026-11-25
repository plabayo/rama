use std::future::ready;

use rama_core::stream::json::{ArrayParseConfig, JsonArrayReadStream};
use rama_http_types::{BodyDataStream, header};

use super::{
    json::InvalidJsonContentType,
    json_content_type::{JsonContentTypePolicy, JsonPayload, accepts_json_content_type},
};
use crate::{
    Body, Request,
    request::Parts,
    service::web::extract::{
        FromRequest, FromRequestBody, OptionalFromRequest, OptionalFromRequestBody,
    },
};

/// Extracts array elements as they arrive, using the request’s [`ArrayParseConfig`] extension when present.
///
/// Any `Content-Type` is accepted unless a [`JsonContentTypePolicy`] extension says otherwise.
pub type JsonArrayItems<T> = JsonArrayReadStream<T, BodyDataStream>;

impl<T> FromRequest for JsonArrayItems<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = InvalidJsonContentType;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let future = <Self as FromRequestBody>::from_request_body(&parts, body);
        future.await
    }
}

impl<T> FromRequestBody for JsonArrayItems<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    fn from_request_body(
        parts: &Parts,
        body: Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        if !accepts_json_content_type(parts, JsonPayload::Document, JsonContentTypePolicy::Any) {
            return ready(Err(InvalidJsonContentType));
        }
        let config = parts
            .extensions
            .get_ref::<ArrayParseConfig>()
            .copied()
            .unwrap_or_default();
        std::future::ready(Ok(body.into_json_array_stream_with_config(config)))
    }
}

impl<T> OptionalFromRequest for JsonArrayItems<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = InvalidJsonContentType;

    async fn from_request(req: Request) -> Result<Option<Self>, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let future = <Self as OptionalFromRequestBody>::from_optional_request_body(&parts, body);
        future.await
    }
}

impl<T> OptionalFromRequestBody for JsonArrayItems<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    fn from_optional_request_body(
        parts: &Parts,
        body: Body,
    ) -> impl Future<Output = Result<Option<Self>, <Self as OptionalFromRequest>::Rejection>>
    + Send
    + 'static {
        let future = if parts.headers.get(header::CONTENT_TYPE).is_some() {
            Some(<Self as FromRequestBody>::from_request_body(parts, body))
        } else {
            None
        };

        async move {
            match future {
                Some(future) => future.await.map(Some),
                None => Ok(None),
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use rama_core::stream::StreamExt as _;
    use rama_http_types::StatusCode;
    use serde::{Deserialize, Serialize};

    use super::{ArrayParseConfig, FromRequest, JsonArrayItems};
    use crate::service::{client::HttpClientExt as _, web::Router};

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct User {
        id: i32,
    }

    #[tokio::test]
    async fn extractor() {
        let app = Router::new().with_post("/", |mut stream: JsonArrayItems<User>| async move {
            assert_eq!(stream.next().await.unwrap().unwrap(), User { id: 1 });
            assert_eq!(stream.next().await.unwrap().unwrap(), User { id: 2 });
            assert_eq!(stream.next().await.unwrap().unwrap(), User { id: 3 });

            assert!(stream.next().await.is_none());
        });

        let res = app
            .post("http://example.com")
            .body(r#"[{"id":1},{"id":2},{"id":3}]"#)
            .send()
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn extractor_uses_request_limit() {
        let config =
            ArrayParseConfig::default().with_max_element_bytes(NonZeroUsize::new(1).unwrap());
        let request = crate::Request::builder()
            .extension(config)
            .body(crate::Body::from("[12]"))
            .unwrap();
        let mut stream = JsonArrayItems::<u8>::from_request(request).await.unwrap();
        stream.next().await.unwrap().unwrap_err();
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn optional_terminal_extractor_present() {
        let request = crate::Request::builder()
            .header(crate::header::CONTENT_TYPE, "application/json")
            .body(crate::Body::from(r#"[{"id":42}]"#))
            .unwrap();

        let mut stream =
            <Option<JsonArrayItems<User>> as crate::service::web::extract::FromRequest>::from_request(
                request,
            )
            .await
            .unwrap()
            .expect("content type makes optional JSON array present");

        assert_eq!(stream.next().await.unwrap().unwrap(), User { id: 42 });
        assert!(stream.next().await.is_none());
    }
}
