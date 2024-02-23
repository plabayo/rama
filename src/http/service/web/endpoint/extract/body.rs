use super::FromRequest;
use crate::http::{self, dep::http_body_util::BodyExt, StatusCode};
use crate::service::Context;
use std::convert::Infallible;
use std::ops::{Deref, DerefMut};

/// Extractor to get the response body.
#[derive(Debug)]
pub struct Body(pub http::Body);

impl<S> FromRequest<S> for Body
where
    S: Send + Sync + 'static,
{
    type Rejection = Infallible;

    async fn from_request(_ctx: Context<S>, req: http::Request) -> Result<Self, Self::Rejection> {
        Ok(Self(req.into_body()))
    }
}

impl Deref for Body {
    type Target = http::Body;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Body {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Extractor to get the response body, collected as [`Bytes`].
///
/// [`Bytes`]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
#[derive(Debug, Clone)]
pub struct Bytes(pub bytes::Bytes);

impl<S> FromRequest<S> for Bytes
where
    S: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request(_ctx: Context<S>, req: http::Request) -> Result<Self, Self::Rejection> {
        let body = req.into_body();
        match body.collect().await {
            Ok(c) => Ok(Self(c.to_bytes())),
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    }
}

impl Deref for Bytes {
    type Target = bytes::Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Extractor to get the response body, collected as [`String`].
#[derive(Debug, Clone)]
pub struct Text(pub String);

impl<S> FromRequest<S> for Text
where
    S: Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request(_ctx: Context<S>, req: http::Request) -> Result<Self, Self::Rejection> {
        let body = req.into_body();
        match body.collect().await {
            Ok(c) => {
                let b = c.to_bytes();
                match String::from_utf8(b.to_vec()) {
                    Ok(s) => Ok(Self(s)),
                    Err(_) => Err(StatusCode::BAD_REQUEST),
                }
            }
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    }
}

impl Deref for Text {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Text {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Extractor to get the response body, collected as [`String`].
pub struct Json<T>(pub T);

impl<T: std::fmt::Debug> std::fmt::Debug for Json<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Json").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Json<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, T> FromRequest<S> for Json<T>
where
    S: Send + Sync + 'static,
    T: serde::de::DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request(_ctx: Context<S>, req: http::Request) -> Result<Self, Self::Rejection> {
        let body = req.into_body();
        match body.collect().await {
            Ok(c) => {
                let b = c.to_bytes();
                match serde_json::from_slice(&b) {
                    Ok(s) => Ok(Self(s)),
                    Err(_) => Err(StatusCode::BAD_REQUEST),
                }
            }
            Err(_) => Err(StatusCode::BAD_REQUEST),
        }
    }
}

impl<T> Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Json<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{http::service::web::WebService, service::Service};

    #[tokio::test]
    async fn test_body() {
        let service = WebService::default().get("/", |Body(body): Body| async move {
            let body = body.collect().await.unwrap().to_bytes();
            assert_eq!(body, "test");
        });

        let req = http::Request::builder()
            .method(http::Method::GET)
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_bytes() {
        let service = WebService::default().get("/", |Bytes(body): Bytes| async move {
            assert_eq!(body, "test");
        });

        let req = http::Request::builder()
            .method(http::Method::GET)
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_text() {
        let service = WebService::default().get("/", |Text(body): Text| async move {
            assert_eq!(body, "test");
        });

        let req = http::Request::builder()
            .method(http::Method::GET)
            .body("test".into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_json() {
        #[derive(Debug, serde::Deserialize)]
        struct Input {
            name: String,
            age: u8,
            alive: Option<bool>,
        }

        let service = WebService::default().get("/", |Json(body): Json<Input>| async move {
            assert_eq!(body.name, "glen");
            assert_eq!(body.age, 42);
            assert_eq!(body.alive, None);
        });

        let req = http::Request::builder()
            .method(http::Method::GET)
            .body(r#"{"name": "glen", "age": 42}"#.into())
            .unwrap();
        let resp = service.serve(Context::default(), req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
