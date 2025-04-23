use bytes::Bytes;

use super::BytesRejection;
use crate::Request;
use crate::dep::http_body_util::BodyExt;
use crate::service::web::extract::FromRequest;
use crate::utils::macros::{composite_http_rejection, define_http_rejection};

pub use crate::response::Json;

define_http_rejection! {
    #[status = UNSUPPORTED_MEDIA_TYPE]
    #[body = "Json requests must have `Content-Type: application/json`"]
    /// Rejection type for [`Json`]
    /// used if the `Content-Type` header is missing
    /// or its value is not `application/json`.
    pub struct InvalidJsonContentType;
}

define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Failed to deserialize json payload"]
    /// Rejection type used if the [`Json`]
    /// deserialize the payload into the target type.
    pub struct FailedToDeserializeJson(Error);
}

composite_http_rejection! {
    /// Rejection used for [`Json`]
    ///
    /// Contains one variant for each way the [`Json`] extractor
    /// can fail.
    pub enum JsonRejection {
        InvalidJsonContentType,
        FailedToDeserializeJson,
        BytesRejection,
    }
}

impl<T> FromRequest for Json<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = JsonRejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        // Extracted into separate fn so it's only compiled once for all T.
        async fn extract_json_bytes(req: Request) -> Result<Bytes, JsonRejection> {
            if !crate::service::web::extract::has_any_content_type(
                req.headers(),
                &[&mime::APPLICATION_JSON],
            ) {
                return Err(InvalidJsonContentType.into());
            }

            let body = req.into_body();

            match body.collect().await {
                Ok(c) => Ok(c.to_bytes()),
                Err(err) => Err(BytesRejection::from_err(err).into()),
            }
        }

        let b = extract_json_bytes(req).await?;
        match serde_json::from_slice(&b) {
            Ok(s) => Ok(Self(s)),
            Err(err) => Err(FailedToDeserializeJson::from_err(err).into()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::StatusCode;
    use crate::service::web::WebService;
    use rama_core::{Context, Service};

    #[tokio::test]
    async fn test_json() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
            alive: Option<bool>,
        }

        let service = WebService::default().post("/", async |Json(body): Json<Input>| {
            assert_eq!(body.name, "glen");
            assert_eq!(body.age, 42);
            assert_eq!(body.alive, None);
        });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(
                rama_http_types::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(r#"{"name": "glen", "age": 42}"#.into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_json_missing_content_type() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            _name: String,
            _age: u8,
            _alive: Option<bool>,
        }

        let service = WebService::default().post("/", async |Json(_): Json<Input>| StatusCode::OK);

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, "text/plain")
            .body(r#"{"name": "glen", "age": 42}"#.into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_json_invalid_body_encoding() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            _name: String,
            _age: u8,
            _alive: Option<bool>,
        }

        let service = WebService::default().post("/", async |Json(_): Json<Input>| StatusCode::OK);

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(
                rama_http_types::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(r#"deal with it, or not?!"#.into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
