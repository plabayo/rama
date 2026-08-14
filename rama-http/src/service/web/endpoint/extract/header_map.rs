use super::FromOwnedRequestParts;
use crate::{HeaderMap, request::Parts};
use std::convert::Infallible;

/// Move all headers out of request parts without cloning the map.
impl FromOwnedRequestParts for HeaderMap {
    type Rejection = Infallible;

    fn from_owned_request_parts(
        parts: Parts,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        std::future::ready(Ok(parts.headers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Body, Request, StatusCode,
        body::util::BodyExt,
        header,
        service::web::{
            WebService,
            extract::{Body as ExtractBody, FromRequest, Json, State},
        },
    };
    use rama_core::Service;

    #[tokio::test]
    async fn extracts_all_request_headers_as_terminal_extractor() {
        let request = Request::builder()
            .header(header::ACCEPT, "application/json")
            .header(header::COOKIE, "session=secret")
            .header("x-custom-header", "custom-value")
            .body(Body::empty())
            .unwrap();

        let headers = HeaderMap::from_request(request).await.unwrap();

        assert_eq!(headers.len(), 3);
        assert_eq!(headers.get(header::ACCEPT).unwrap(), "application/json");
        assert_eq!(headers.get(header::COOKIE).unwrap(), "session=secret");
        assert_eq!(headers.get("x-custom-header").unwrap(), "custom-value");
    }

    #[tokio::test]
    async fn extracts_owned_headers_from_consumed_request_parts() {
        let request = Request::builder()
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(Body::empty())
            .unwrap();
        let (parts, _) = request.into_parts();

        let headers = HeaderMap::from_owned_request_parts(parts).await.unwrap();

        assert_eq!(headers.get(header::AUTHORIZATION).unwrap(), "Bearer secret");
    }

    #[tokio::test]
    async fn composes_after_regular_parts_and_before_json_body_extractor() {
        #[derive(serde::Deserialize)]
        struct Input {
            message: String,
        }

        let service = WebService::new_with_state("prefix".to_owned()).with_post(
            "/",
            async |State(prefix): State<String>, headers: HeaderMap, Json(input): Json<Input>| {
                assert_eq!(headers.get(header::AUTHORIZATION).unwrap(), "Bearer secret");
                assert_eq!(headers.get(header::ORIGIN).unwrap(), "https://example.com");
                format!("{prefix}: {}", input.message)
            },
        );
        let request = Request::builder()
            .method(crate::Method::POST)
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer secret")
            .header(header::ORIGIN, "https://example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"message":"body remains available"}"#))
            .unwrap();

        let response = service.serve(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "prefix: body remains available");
    }

    #[tokio::test]
    async fn composes_with_optional_body_extractor() {
        #[derive(serde::Deserialize)]
        struct Input {
            _message: String,
        }

        let service = WebService::default().with_post(
            "/",
            async |headers: HeaderMap, body: Option<Json<Input>>| {
                assert_eq!(headers.get(header::AUTHORIZATION).unwrap(), "Bearer secret");
                assert!(body.is_none());
            },
        );
        let request = Request::builder()
            .method(crate::Method::POST)
            .uri("/")
            .header(header::AUTHORIZATION, "Bearer secret")
            .body(Body::empty())
            .unwrap();

        let response = service.serve(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn preserves_body_extractor_rejections() {
        #[derive(serde::Deserialize)]
        struct Input {
            _message: String,
        }

        let service = WebService::default()
            .with_post("/", async |_headers: HeaderMap, Json(_): Json<Input>| {
                StatusCode::OK
            });
        let request = Request::builder()
            .method(crate::Method::POST)
            .uri("/")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(r#"{"message":"invalid content type"}"#))
            .unwrap();

        let response = service.serve(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn owned_parts_rejection_precedes_body_rejection() {
        struct RejectingHeaders;

        impl FromOwnedRequestParts for RejectingHeaders {
            type Rejection = StatusCode;

            fn from_owned_request_parts(
                _parts: Parts,
            ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
                std::future::ready(Err(StatusCode::UNAUTHORIZED))
            }
        }

        #[derive(serde::Deserialize)]
        struct Input {
            _message: String,
        }

        let service = WebService::default().with_post(
            "/",
            async |_headers: RejectingHeaders, Json(_): Json<Input>| StatusCode::OK,
        );
        let request = Request::builder()
            .method(crate::Method::POST)
            .uri("/")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(r#"{"message":"invalid content type"}"#))
            .unwrap();

        let response = service.serve(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn composes_with_streaming_body_extractor() {
        let service = WebService::default().with_post(
            "/",
            async |headers: HeaderMap, ExtractBody(body): ExtractBody| {
                assert_eq!(headers.get("x-request-id").unwrap(), "123");
                body.collect().await.unwrap().to_bytes()
            },
        );
        let request = Request::builder()
            .method(crate::Method::POST)
            .uri("/")
            .header("x-request-id", "123")
            .body(Body::from("stream me"))
            .unwrap();

        let response = service.serve(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "stream me");
    }
}
