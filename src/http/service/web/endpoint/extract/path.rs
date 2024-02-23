use super::FromRequestParts;
use crate::http::service::web::matcher::UriParams;
use crate::http::{dep::http::request::Parts, StatusCode};
use crate::service::Context;
use serde::de::DeserializeOwned;
use std::ops::{Deref, DerefMut};

/// Extractor to get a Arc::clone of the state from the context.
#[derive(Debug, Default)]
pub struct Path<T>(pub T);

impl<T: Clone> Clone for Path<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S, T> FromRequestParts<S> for Path<T>
where
    S: Send + Sync + 'static,
    T: DeserializeOwned + Send + Sync + 'static,
{
    type Rejection = StatusCode;

    async fn from_request_parts(ctx: &Context<S>, _parts: &Parts) -> Result<Self, Self::Rejection> {
        match ctx.get::<UriParams>() {
            Some(params) => match params.deserialize::<T>() {
                Ok(value) => Ok(Self(value)),
                Err(_) => Err(StatusCode::BAD_REQUEST),
            },
            None => Err(StatusCode::BAD_REQUEST),
        }
    }
}

impl<T> Deref for Path<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Path<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::http::service::web::extract::FromRequest;
    use crate::http::service::web::WebService;
    use crate::http::{Body, Request};
    use crate::service::Service;

    #[tokio::test]
    async fn test_host_from_request() {
        #[derive(serde::Deserialize)]
        struct Params {
            foo: String,
            bar: u32,
        }

        let svc = WebService::default().get(
            "/a/:foo/:bar/b/*",
            |ctx: Context<()>, req: Request| async move {
                let params = match Path::<Params>::from_request(ctx, req).await {
                    Ok(Path(params)) => params,
                    Err(rejection) => return Ok(rejection),
                };

                assert_eq!(params.foo, "hello");
                assert_eq!(params.bar, 42);
                Ok(StatusCode::OK)
            },
        );

        let builder = Request::builder()
            .method("GET")
            .uri("http://example.com/a/hello/42/b/extra");
        let req = builder.body(Body::empty()).unwrap();

        svc.serve(Context::default(), req).await.unwrap();
    }
}
