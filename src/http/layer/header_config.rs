//! Extract a header config from a request or response and insert it into the [`Extensions`] of its [`Context`].
//!
//! [`Extensions`]: crate::service::context::Extensions
//! [`Context`]: crate::service::Context
//!
//! # Example
//!
//! ```rust
//! use rama::http::layer::header_config::{HeaderConfigLayer, HeaderConfigService};
//! use rama::http::service::web::{WebService, extract::Extension};
//! use rama::http::{Body, Request, StatusCode};
//! use rama::service::{Context, Service, Layer};
//! use serde::Deserialize;
//!
//! #[derive(Debug, Deserialize, Clone)]
//! struct Config {
//!     s: String,
//!     n: i32,
//!     m: Option<i32>,
//!     b: bool,
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let service = HeaderConfigLayer::<Config>::required("x-proxy-config".to_owned())
//!         .layer(WebService::default()
//!             .get("/", |Extension(cfg): Extension<Config>| async move {
//!                 assert_eq!(cfg.s, "E&G");
//!                 assert_eq!(cfg.n, 1);
//!                 assert!(cfg.m.is_none());
//!                 assert!(cfg.b);
//!             }),
//!         );
//!
//!     let request = Request::builder()
//!         .header("x-proxy-config", "s=E%26G&n=1&b=true")
//!         .body(Body::empty())
//!         .unwrap();
//!
//!     let resp = service.serve(Context::default(), request).await.unwrap();
//!     assert_eq!(resp.status(), StatusCode::OK);
//! }
//! ```

use crate::http::header::AsHeaderName;
use serde::de::DeserializeOwned;
use std::marker::PhantomData;

use crate::{
    error::BoxError,
    http::{
        utils::{HeaderValueErr, HeaderValueGetter},
        Request,
    },
    service::{Context, Layer, Service},
};

/// Extract a header config from a request or response without consuming it.
pub fn extract_header_config<H, T, G>(request: &G, header_name: H) -> Result<T, HeaderValueErr>
where
    H: AsHeaderName + Copy,
    T: DeserializeOwned + Clone + Send + Sync + 'static,
    G: HeaderValueGetter,
{
    let value = request.header_str(header_name)?;
    let config = serde_html_form::from_str::<T>(value)
        .map_err(|_| HeaderValueErr::HeaderInvalid(header_name.as_str().to_owned()))?;
    Ok(config)
}

/// A [`Service`] which extracts a header config from a request or response
/// and inserts it into the [`Extensions`] of that object.
///
/// [`Extensions`]: crate::service::context::Extensions
#[derive(Debug)]
pub struct HeaderConfigService<T, S> {
    inner: S,
    key: String,
    optional: bool,
    _marker: PhantomData<T>,
}

impl<T, S> HeaderConfigService<T, S> {
    /// Create a new [`HeaderConfigService`] with the given inner service
    /// and header name, on which to extract the config,
    /// and which will fail if the header is missing.
    pub fn required(inner: S, key: String) -> Self {
        Self::new(inner, key, false)
    }

    /// Create a new [`HeaderConfigService`] with the given inner service
    /// and header name, on which to extract the config,
    /// and which will gracefully accept if the header is missing.
    pub fn optional(inner: S, key: String) -> Self {
        Self::new(inner, key, true)
    }

    #[inline]
    pub(crate) fn new(inner: S, key: String, optional: bool) -> Self {
        Self {
            inner,
            key,
            optional,
            _marker: PhantomData,
        }
    }
}

impl<T, S> Clone for HeaderConfigService<T, S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            key: self.key.clone(),
            optional: self.optional,
            _marker: PhantomData,
        }
    }
}

impl<T, S, State, Body, E> Service<State, Request<Body>> for HeaderConfigService<T, S>
where
    S: Service<State, Request<Body>, Error = E>,
    T: DeserializeOwned + Clone + Send + Sync + 'static,
    State: Send + Sync + 'static,
    Body: Send + Sync + 'static,
    E: Into<BoxError> + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        request: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let config = match extract_header_config::<_, T, _>(&request, &self.key) {
            Ok(config) => config,
            Err(err) => {
                if self.optional
                    && matches!(err, crate::http::utils::HeaderValueErr::HeaderMissing(_))
                {
                    tracing::debug!(error = %err, "failed to extract header config");
                    return self.inner.serve(ctx, request).await.map_err(Into::into);
                } else {
                    return Err(err.into());
                }
            }
        };
        ctx.insert(config);
        self.inner.serve(ctx, request).await.map_err(Into::into)
    }
}

/// Layer which extracts a header config for the given HeaderName
/// from a request or response and inserts it into the [`Extensions`] of that object.
///
/// [`Extensions`]: crate::service::context::Extensions
#[derive(Debug)]
pub struct HeaderConfigLayer<T> {
    key: String,
    optional: bool,
    _marker: PhantomData<T>,
}

impl<T> HeaderConfigLayer<T> {
    /// Create a new [`HeaderConfigLayer`] with the given header name,
    /// on which to extract the config,
    /// and which will fail if the header is missing.
    pub fn required(key: String) -> Self {
        Self {
            key,
            optional: false,
            _marker: PhantomData,
        }
    }

    /// Create a new [`HeaderConfigLayer`] with the given header name,
    /// on which to extract the config,
    /// and which will gracefully accept if the header is missing.
    pub fn optional(key: String) -> Self {
        Self {
            key,
            optional: true,
            _marker: PhantomData,
        }
    }
}

impl<T, S> Layer<S> for HeaderConfigLayer<T> {
    type Service = HeaderConfigService<T, S>;

    fn layer(&self, inner: S) -> Self::Service {
        HeaderConfigService::new(inner, self.key.clone(), self.optional)
    }
}

#[cfg(test)]
mod test {
    use serde::Deserialize;

    use crate::http::Method;

    use super::*;

    #[tokio::test]
    async fn test_header_config_required_happy_path() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-config", "s=E%26G&n=1&b=true")
            .body(())
            .unwrap();

        let inner_service =
            crate::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                let cfg: &Config = ctx.get().unwrap();
                assert_eq!(cfg.s, "E&G");
                assert_eq!(cfg.n, 1);
                assert!(cfg.m.is_none());
                assert!(cfg.b);

                Ok::<_, std::convert::Infallible>(())
            });

        let service =
            HeaderConfigService::<Config, _>::required(inner_service, "x-proxy-config".to_owned());

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_optional_found() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-config", "s=E%26G&n=1&b=true")
            .body(())
            .unwrap();

        let inner_service =
            crate::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                let cfg: &Config = ctx.get().unwrap();
                assert_eq!(cfg.s, "E&G");
                assert_eq!(cfg.n, 1);
                assert!(cfg.m.is_none());
                assert!(cfg.b);

                Ok::<_, std::convert::Infallible>(())
            });

        let service =
            HeaderConfigService::<Config, _>::optional(inner_service, "x-proxy-config".to_owned());

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_optional_missing() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service =
            crate::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                assert!(ctx.get::<Config>().is_none());

                Ok::<_, std::convert::Infallible>(())
            });

        let service =
            HeaderConfigService::<Config, _>::optional(inner_service, "x-proxy-config".to_owned());

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_required_missing_header() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service = crate::service::service_fn(|_: Request<()>| async move {
            Ok::<_, std::convert::Infallible>(())
        });

        let service =
            HeaderConfigService::<Config, _>::required(inner_service, "x-proxy-config".to_owned());

        let result = service.serve(Context::default(), request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_header_config_required_invalid_config() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-config", "s=bar&n=1&b=invalid")
            .body(())
            .unwrap();

        let inner_service = crate::service::service_fn(|_: Request<()>| async move {
            Ok::<_, std::convert::Infallible>(())
        });

        let service =
            HeaderConfigService::<Config, _>::required(inner_service, "x-proxy-config".to_owned());

        let result = service.serve(Context::default(), request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_header_config_optional_invalid_config() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-config", "s=bar&n=1&b=invalid")
            .body(())
            .unwrap();

        let inner_service = crate::service::service_fn(|_: Request<()>| async move {
            Ok::<_, std::convert::Infallible>(())
        });

        let service =
            HeaderConfigService::<Config, _>::optional(inner_service, "x-proxy-config".to_owned());

        let result = service.serve(Context::default(), request).await;
        assert!(result.is_err());
    }

    #[derive(Debug, Deserialize, Clone)]
    struct Config {
        s: String,
        n: i32,
        m: Option<i32>,
        b: bool,
    }
}
