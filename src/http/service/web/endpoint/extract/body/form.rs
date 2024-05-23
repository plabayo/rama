use super::BytesRejection;
use crate::http::dep::http_body_util::BodyExt;
use crate::http::service::web::extract::FromRequest;
use crate::http::{Method, Request};
use crate::service::Context;

pub use crate::http::response::Form;

crate::__define_http_rejection! {
    #[status = UNSUPPORTED_MEDIA_TYPE]
    #[body = "Form requests must have `Content-Type: application/x-www-form-urlencoded`"]
    /// Rejection type for [`Form`]
    /// used if the `Content-Type` header is missing
    /// or its value is not `application/x-www-form-urlencoded`.
    pub struct InvalidFormContentType;
}

crate::__define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to deserialize form"]
    /// Rejection type used if the [`Form`]
    /// deserialize the form into the target type.
    pub struct FailedToDeserializeForm(Error);
}

crate::__composite_http_rejection! {
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

impl<S, T> FromRequest<S> for Form<T>
where
    S: Send + Sync + 'static,
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = FormRejection;

    async fn from_request(_ctx: Context<S>, req: Request) -> Result<Self, Self::Rejection> {
        if req.method() == Method::GET {
            let query = req.uri().query().unwrap_or_default();
            let value = match serde_html_form::from_bytes(query.as_bytes()) {
                Ok(value) => value,
                Err(err) => return Err(FailedToDeserializeForm::from_err(err).into()),
            };
            Ok(Form(value))
        } else {
            if !crate::http::service::web::extract::has_any_content_type(
                req.headers(),
                &[&mime::APPLICATION_WWW_FORM_URLENCODED],
            ) {
                return Err(InvalidFormContentType.into());
            }

            let body = req.into_body();
            match body.collect().await {
                Ok(c) => {
                    let value = match serde_html_form::from_bytes(&c.to_bytes()) {
                        Ok(value) => value,
                        Err(err) => return Err(FailedToDeserializeForm::from_err(err).into()),
                    };
                    Ok(Form(value))
                }
                Err(err) => Err(BytesRejection::from_err(err).into()),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::http;
    use crate::http::StatusCode;
    use crate::{http::service::web::WebService, service::Service};

    #[tokio::test]
    async fn test_form_post_form_urlencoded() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
        }

        let service = WebService::default().post("/", |Form(body): Form<Input>| async move {
            assert_eq!(body.name, "Devan");
            assert_eq!(body.age, 29);
        });

        let req = http::Request::builder()
            .uri("/")
            .method(http::Method::POST)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(r#"name=Devan&age=29"#.into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
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

        let service = WebService::default().post("/", |Form(_): Form<Input>| async move {
            panic!("should not reach here");
        });

        let req = http::Request::builder()
            .uri("/")
            .method(http::Method::POST)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(r#"age=29"#.into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
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

        let service = WebService::default().get("/", |Form(_): Form<Input>| async move {
            panic!("should not reach here");
        });

        let req = http::Request::builder()
            .uri("/")
            .method(http::Method::GET)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(r#"name=Devan&age=29"#.into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_form_get() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
        }

        let service = WebService::default().get("/", |Form(body): Form<Input>| async move {
            assert_eq!(body.name, "Devan");
            assert_eq!(body.age, 29);
        });

        let req = http::Request::builder()
            .uri("/?name=Devan&age=29")
            .method(http::Method::GET)
            .body(http::Body::empty())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
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

        let service = WebService::default().get("/", |Form(_): Form<Input>| async move {
            panic!("should not reach here");
        });

        let req = http::Request::builder()
            .uri("/?name=Devan")
            .method(http::Method::GET)
            .body(http::Body::empty())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
