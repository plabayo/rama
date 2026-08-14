use super::FromOwnedRequestParts;
use crate::request::Parts;
use rama_core::extensions::Extensions;
use std::convert::Infallible;

impl FromOwnedRequestParts for Extensions {
    type Rejection = Infallible;

    fn from_owned_request_parts(
        parts: Parts,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        std::future::ready(Ok(parts.extensions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Body, Method, Request, StatusCode,
        body::util::BodyExt,
        header,
        service::web::{WebService, extract::Text},
    };
    use rama_core::Service;

    #[derive(Debug)]
    struct RequestLabel(&'static str);

    impl rama_core::extensions::Extension for RequestLabel {}

    #[tokio::test]
    async fn owned_extensions_compose_with_text_body_extractor() {
        let service = WebService::default().with_post(
            "/",
            async |extensions: Extensions, Text(body): Text| {
                let label = extensions.get_ref::<RequestLabel>().unwrap();
                format!("{}: {body}", label.0)
            },
        );
        let request = Request::builder()
            .method(Method::POST)
            .header(header::CONTENT_TYPE, "text/plain")
            .extension(RequestLabel("extension"))
            .body(Body::from("payload"))
            .unwrap();

        let response = service.serve(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "extension: payload");
    }
}
