use super::BytesRejection;
use crate::http::dep::http_body_util::BodyExt;
use crate::http::service::web::extract::FromRequest;
use crate::http::Request;
use crate::service::Context;

/// Extractor to get the response body, collected as [`String`].
#[derive(Debug, Clone)]
pub struct Text(pub String);

impl_deref!(Text: String);

crate::__define_http_rejection! {
    #[status = UNSUPPORTED_MEDIA_TYPE]
    #[body = "Text requests must have `Content-Type: text/plain`"]
    /// Rejection type for [`Text`]
    /// used if the `Content-Type` header is missing
    /// or its value is not `text/plain`.
    pub struct InvalidTextContentType;
}

crate::__define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to decode text payload"]
    /// Rejection type used if the [`Text`]
    /// was not valid UTF-8.
    pub struct InvalidUtf8Text(Error);
}

crate::__composite_http_rejection! {
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

impl<S> FromRequest<S> for Text
where
    S: Send + Sync + 'static,
{
    type Rejection = TextRejection;

    async fn from_request(_ctx: Context<S>, req: Request) -> Result<Self, Self::Rejection> {
        if !crate::http::service::web::extract::has_any_content_type(
            req.headers(),
            &[&mime::TEXT_PLAIN],
        ) {
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
    use crate::http::{self, StatusCode};
    use crate::{http::service::web::WebService, service::Service};

    #[tokio::test]
    async fn test_text() {
        let service = WebService::default().post("/", |Text(body): Text| async move {
            assert_eq!(body, "test");
        });

        let req = http::Request::builder()
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_text_missing_content_type() {
        let service = WebService::default().post("/", |Text(_): Text| async move {
            unreachable!();
        });

        let req = http::Request::builder()
            .method(http::Method::POST)
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_text_incorrect_content_type() {
        let service = WebService::default().post("/", |Text(_): Text| async move {
            unreachable!();
        });

        let req = http::Request::builder()
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_text_invalid_utf8() {
        let service = WebService::default().post("/", |Text(_): Text| async move {
            unreachable!();
        });

        let req = http::Request::builder()
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .body(vec![0, 159, 146, 150].into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
