use super::BytesRejection;
use crate::Request;
use crate::body::util::BodyExt;
use crate::service::web::extract::{
    FromRequest, FromRequestBody, OptionalFromRequest, OptionalFromRequestBody,
};
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use rama_core::bytes::Bytes;
use rama_http_types::{HeaderMap, header};

pub use crate::service::web::endpoint::response::Json;

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
        let (parts, body) = req.into_parts();
        let future = <Self as FromRequestBody>::from_request_body(&parts, body);
        future.await
    }
}

impl<T> FromRequestBody for Json<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    fn from_request_body(
        parts: &crate::request::Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        let bytes = extract_json_bytes(parts, body);

        async move {
            let bytes = bytes.await?;

            match serde_json::from_slice(&bytes) {
                Ok(s) => Ok(Self(s)),
                Err(err) => Err(FailedToDeserializeJson::from_err(err).into()),
            }
        }
    }
}

// Kept non-generic so body collection is compiled once rather than once per JSON type.
fn extract_json_bytes(
    parts: &crate::request::Parts,
    body: crate::Body,
) -> impl Future<Output = Result<Bytes, JsonRejection>> + Send + 'static {
    let has_valid_content_type = json_content_type(&parts.headers);

    async move {
        if !has_valid_content_type {
            return Err(InvalidJsonContentType.into());
        }

        body.collect()
            .await
            .map_err(BytesRejection::from_err)
            .map(|body| body.to_bytes())
            .map_err(Into::into)
    }
}

impl<T> OptionalFromRequest for Json<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = JsonRejection;

    async fn from_request(req: Request) -> Result<Option<Self>, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let future = <Self as OptionalFromRequestBody>::from_optional_request_body(&parts, body);
        future.await
    }
}

impl<T> OptionalFromRequestBody for Json<T>
where
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    fn from_optional_request_body(
        parts: &crate::request::Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Option<Self>, <Self as OptionalFromRequest>::Rejection>>
    + Send
    + 'static {
        let future = if parts.headers.get(header::CONTENT_TYPE).is_some() {
            Some(<Self as FromRequestBody>::from_request_body(parts, body))
        } else {
            None
        };

        async move {
            match future {
                Some(future) => future.await.map(Some),
                None => Ok(None),
            }
        }
    }
}

fn json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|content_type| content_type.to_str().ok())
        .and_then(|content_type| content_type.parse::<crate::mime::Mime>().ok())
        .is_some_and(|mime| {
            mime.type_() == "application"
                && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"))
        })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::StatusCode;
    use crate::service::web::WebService;
    use rama_core::Service;

    #[tokio::test]
    async fn test_json() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
            alive: Option<bool>,
        }

        let service = WebService::default().with_post("/", async |Json(body): Json<Input>| {
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
        let resp = service.serve(req).await.unwrap();
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

        let service =
            WebService::default().with_post("/", async |Json(_): Json<Input>| StatusCode::OK);

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, "text/plain")
            .body(r#"{"name": "glen", "age": 42}"#.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
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

        let service =
            WebService::default().with_post("/", async |Json(_): Json<Input>| StatusCode::OK);

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(
                rama_http_types::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            )
            .body(r#"deal with it, or not?!"#.into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_optional_json_terminal_extractor_present() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            message: String,
        }

        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(crate::Body::from(r#"{"message":"present"}"#))
            .unwrap();

        let Json(input) = <Option<Json<Input>> as FromRequest>::from_request(request)
            .await
            .unwrap()
            .expect("content type makes optional JSON present");

        assert_eq!(input.message, "present");
    }
}
