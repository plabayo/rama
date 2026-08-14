use super::{FromOwnedRequestParts, FromRequest};
use crate::{Request, request::Parts};
use std::convert::Infallible;

impl FromRequest for Request {
    type Rejection = Infallible;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        Ok(req)
    }
}

impl FromOwnedRequestParts for Parts {
    type Rejection = Infallible;

    fn from_owned_request_parts(
        parts: Parts,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        std::future::ready(Ok(parts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Body, Method, StatusCode,
        body::util::BodyExt,
        header,
        service::web::{WebService, extract::Json, response},
    };
    use rama_core::Service;

    #[tokio::test]
    async fn owned_parts_compose_with_json_body_extractor() {
        #[derive(serde::Deserialize)]
        struct Input {
            value: String,
        }

        let service = WebService::default().with_post(
            "/items",
            async |parts: Parts, Json(input): Json<Input>| -> response::Result<String> {
                assert_eq!(parts.method, Method::POST);
                assert_eq!(parts.uri.to_string(), "/items");
                assert_eq!(parts.headers.get("x-request-id").unwrap(), "parts-test");
                Ok(input.value)
            },
        );
        let request = Request::builder()
            .method(Method::POST)
            .uri("/items")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-request-id", "parts-test")
            .body(Body::from(r#"{"value":"payload"}"#))
            .unwrap();

        let response = service.serve(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "payload");
    }
}
