use super::FromOwnedRequestParts;
use crate::request::Parts;
use rama_net::uri::Uri;
use std::convert::Infallible;

impl FromOwnedRequestParts for Uri {
    type Rejection = Infallible;

    fn from_owned_request_parts(
        parts: Parts,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        std::future::ready(Ok(parts.uri))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Body, Method, Request, StatusCode,
        body::util::BodyExt,
        header,
        service::web::{
            WebService,
            extract::{Form, Text},
        },
    };
    use rama_core::Service;

    #[tokio::test]
    async fn owned_uri_composes_with_text_body_extractor() {
        let service = WebService::default()
            .with_post("/items", async |uri: Uri, Text(body): Text| {
                format!("{uri}: {body}")
            });
        let request = Request::builder()
            .method(Method::POST)
            .uri("/items?source=test")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("payload"))
            .unwrap();

        let response = service.serve(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "/items?source=test: payload");
    }

    #[tokio::test]
    async fn owned_uri_remains_available_after_form_reads_its_query() {
        #[derive(serde::Deserialize)]
        struct Input {
            source: String,
        }

        let service = WebService::default()
            .with_get("/items", async |uri: Uri, Form(input): Form<Input>| {
                format!("{uri}: {}", input.source)
            });
        let request = Request::builder()
            .method(Method::GET)
            .uri("/items?source=query")
            .body(Body::empty())
            .unwrap();

        let response = service.serve(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "/items?source=query: query");
    }
}
