use rama_core::bytes::Bytes;

use super::BytesRejection;
use crate::body::util::BodyExt;
use crate::service::web::extract::{FromRequest, FromRequestBody};
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use crate::{Method, Request};

pub use crate::service::web::endpoint::response::Form;

define_http_rejection! {
    #[status = UNSUPPORTED_MEDIA_TYPE]
    #[body = "Form requests must have `Content-Type: application/x-www-form-urlencoded`"]
    /// Rejection type for [`Form`]
    /// used if the `Content-Type` header is missing
    /// or its value is not `application/x-www-form-urlencoded`.
    pub struct InvalidFormContentType;
}

define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to deserialize form"]
    /// Rejection type used if the [`Form`]
    /// deserialize the form into the target type.
    pub struct FailedToDeserializeForm(Error);
}

composite_http_rejection! {
    /// Rejection used for [`Form`]
    ///
    /// Contains one variant for each way the [`Form`] extractor
    /// can fail.
    pub enum FormRejection {
        InvalidFormContentType,
        FailedToDeserializeForm,
        BytesRejection,
    }
}

impl<T> FromRequest for Form<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = FormRejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let future = Self::from_request_body(&parts, body);
        future.await
    }
}

impl<T> FromRequestBody for Form<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    fn from_request_body(
        parts: &crate::request::Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        let query_result: Option<Result<Self, FormRejection>> =
            if matches!(parts.method, Method::GET | Method::HEAD) {
                Some(
                    parts
                        .uri
                        .query_params()
                        .map(Self)
                        .map_err(|err| FailedToDeserializeForm::from_err(err).into()),
                )
            } else {
                None
            };
        let body_bytes = extract_form_body_bytes(parts, body);

        async move {
            if let Some(result) = query_result {
                return result;
            }

            let bytes = body_bytes.await?;
            Ok(Self(match serde_html_form::from_bytes(&bytes) {
                Ok(value) => value,
                Err(err) => return Err(FailedToDeserializeForm::from_err(err).into()),
            }))
        }
    }
}

// Kept non-generic so body collection is compiled once rather than once per form type.
fn extract_form_body_bytes(
    parts: &crate::request::Parts,
    body: crate::Body,
) -> impl Future<Output = Result<Bytes, FormRejection>> + Send + 'static {
    let has_valid_content_type = crate::service::web::extract::has_any_content_type(
        &parts.headers,
        &[&crate::mime::APPLICATION_WWW_FORM_URLENCODED],
    );

    async move {
        if !has_valid_content_type {
            return Err(InvalidFormContentType.into());
        }

        body.collect()
            .await
            .map_err(BytesRejection::from_err)
            .map(|body| body.to_bytes())
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::web::WebService;
    use crate::{Body, Method, Request, StatusCode};
    use rama_core::Service;

    #[tokio::test]
    async fn test_form_post_form_urlencoded() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
        }

        let service = WebService::default().with_post("/", async |Form(body): Form<Input>| {
            assert_eq!(body.name, "Devan");
            assert_eq!(body.age, 29);
        });

        let req = Request::builder()
            .uri("/")
            .method(Method::POST)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(r#"name=Devan&age=29"#.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_form_post_form_urlencoded_missing_data_fail() {
        #[derive(Debug, serde::Deserialize)]
        #[expect(dead_code)]
        struct Input {
            name: String,
            age: u8,
        }

        let service =
            WebService::default().with_post("/", async |Form(_): Form<Input>| StatusCode::OK);

        let req = Request::builder()
            .uri("/")
            .method(Method::POST)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(r#"age=29"#.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_form_get_form_urlencoded_fail() {
        #[derive(Debug, serde::Deserialize)]
        #[expect(dead_code)]
        struct Input {
            name: String,
            age: u8,
        }

        let service =
            WebService::default().with_get("/", async |Form(_): Form<Input>| StatusCode::OK);

        let req = Request::builder()
            .uri("/")
            .method(Method::GET)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(r#"name=Devan&age=29"#.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_form_get() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
        }

        let service = WebService::default().with_get("/", async |Form(body): Form<Input>| {
            assert_eq!(body.name, "Devan");
            assert_eq!(body.age, 29);
        });

        let req = Request::builder()
            .uri("/?name=Devan&age=29")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_form_get_fail_missing_data() {
        #[derive(Debug, serde::Deserialize)]
        #[expect(dead_code)]
        struct Input {
            name: String,
            age: u8,
        }

        let service =
            WebService::default().with_get("/", async |Form(_): Form<Input>| StatusCode::OK);

        let req = Request::builder()
            .uri("/?name=Devan")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_form_head_uses_query() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
        }

        let service = WebService::default().with_head("/", async |Form(input): Form<Input>| {
            assert_eq!(input.name, "Devan");
            assert_eq!(input.age, 29);
        });

        let req = Request::builder()
            .uri("/?name=Devan&age=29")
            .method(Method::HEAD)
            .body(Body::empty())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_form_head_missing_query_data_fails() {
        #[derive(Debug, serde::Deserialize)]
        #[expect(dead_code)]
        struct Input {
            name: String,
            age: u8,
        }

        let service =
            WebService::default().with_head("/", async |Form(_): Form<Input>| StatusCode::OK);

        let req = Request::builder()
            .uri("/?name=Devan")
            .method(Method::HEAD)
            .body(Body::empty())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
