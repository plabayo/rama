use rama_core::bytes::Bytes;

use super::BytesRejection;
use crate::body::util::BodyExt;
use crate::service::web::extract::FromRequest;
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
        // Extracted into separate fn so it's only compiled once for all T.
        async fn extract_form_body_bytes(req: Request) -> Result<Bytes, FormRejection> {
            if !crate::service::web::extract::has_any_content_type(
                req.headers(),
                &[&crate::mime::APPLICATION_WWW_FORM_URLENCODED],
            ) {
                return Err(InvalidFormContentType.into());
            }

            let body = req.into_body();
            let bytes = body.collect().await.map_err(BytesRejection::from_err)?;

            Ok(bytes.to_bytes())
        }

        if req.method() == Method::GET {
            let query = req.uri().query().unwrap_or_default();
            let value = match serde_html_form::from_bytes(query.as_bytes()) {
                Ok(value) => value,
                Err(err) => return Err(FailedToDeserializeForm::from_err(err).into()),
            };
            Ok(Self(value))
        } else {
            let b = extract_form_body_bytes(req).await?;
            Ok(Self(match serde_html_form::from_bytes(&b) {
                Ok(value) => value,
                Err(err) => return Err(FailedToDeserializeForm::from_err(err).into()),
            }))
        }
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
        #[allow(dead_code)]
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
        #[allow(dead_code)]
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
        #[allow(dead_code)]
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
}
