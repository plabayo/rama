use super::BytesRejection;
use crate::Request;
use crate::body::util::BodyExt;
use crate::service::web::extract::FromRequest;
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use rama_utils::macros::impl_deref;

/// Extractor to get the response body, collected as [`String`].
#[derive(Debug, Clone)]
pub struct Text(pub String);

impl_deref!(Text: String);

define_http_rejection! {
    #[status = UNSUPPORTED_MEDIA_TYPE]
    #[body = "Text requests must have `Content-Type: text/plain`"]
    /// Rejection type for [`Text`]
    /// used if the `Content-Type` header is missing
    /// or its value is not `text/plain`.
    pub struct InvalidTextContentType;
}

define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to decode text payload"]
    /// Rejection type used if the [`Text`]
    /// was not valid UTF-8.
    pub struct InvalidUtf8Text(Error);
}

composite_http_rejection! {
    /// Rejection used for [`Text`]
    ///
    /// Contains one variant for each way the [`Text`] extractor
    /// can fail.
    pub enum TextRejection {
        InvalidTextContentType,
        InvalidUtf8Text,
        BytesRejection,
    }
}

impl FromRequest for Text {
    type Rejection = TextRejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        if !crate::service::web::extract::has_any_content_type(req.headers(), &[&mime::TEXT_PLAIN])
        {
            return Err(InvalidTextContentType.into());
        }

        let body = req.into_body();
        match body.collect().await {
            Ok(c) => match String::from_utf8(c.to_bytes().to_vec()) {
                Ok(s) => Ok(Self(s)),
                Err(err) => Err(InvalidUtf8Text::from_err(err).into()),
            },
            Err(err) => Err(BytesRejection::from_err(err).into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::web::WebService;
    use crate::{Method, Request, StatusCode, header};
    use rama_core::{Context, Service};

    #[tokio::test]
    async fn test_text() {
        let service = WebService::default().post("/", async |Text(body): Text| {
            assert_eq!(body, "test");
        });

        let req = Request::builder()
            .method(Method::POST)
            .header(header::CONTENT_TYPE, "text/plain")
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_text_missing_content_type() {
        let service = WebService::default().post("/", async |Text(_): Text| StatusCode::OK);

        let req = Request::builder()
            .method(Method::POST)
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_text_incorrect_content_type() {
        let service = WebService::default().post("/", async |Text(_): Text| StatusCode::OK);

        let req = Request::builder()
            .method(Method::POST)
            .header(header::CONTENT_TYPE, "application/json")
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_text_invalid_utf8() {
        let service = WebService::default().post("/", async |Text(_): Text| StatusCode::OK);

        let req = Request::builder()
            .method(Method::POST)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(vec![0, 159, 146, 150].into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
