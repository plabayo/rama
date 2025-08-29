//! Extract a header config from a request or response and insert it into the [`Extensions`] of its [`Context`].
//!
//! [`Extensions`]: rama_core::context::Extensions
//! [`Context`]: rama_core::Context
//!
//! # Example
//!
//! ```rust
//! use rama_http::layer::header_config::{HeaderConfigLayer, HeaderConfigService};
//! use rama_http::service::web::{WebService};
//! use rama_http::{Body, Request, StatusCode, HeaderName};
//! use rama_core::{Context, Service, Layer};
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
//!     let service = HeaderConfigLayer::<Config>::required(HeaderName::from_static("x-proxy-config"))
//!         .into_layer(WebService::default()
//!             .get("/", async |ctx: Context| {
//!                 let cfg = ctx.get::<Config>().unwrap();
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

use crate::{HeaderName, header::AsHeaderName};
use crate::{
    Request,
    utils::{HeaderValueErr, HeaderValueGetter},
};
use rama_core::telemetry::tracing;
use rama_core::{Context, Layer, Service, error::BoxError};
use rama_utils::macros::define_inner_service_accessors;
use serde::de::DeserializeOwned;
use std::{fmt, marker::PhantomData};

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
/// [`Extensions`]: rama_core::context::Extensions
pub struct HeaderConfigService<T, S> {
    inner: S,
    header_name: HeaderName,
    optional: bool,
    _marker: PhantomData<fn() -> T>,
}

impl<T, S> HeaderConfigService<T, S> {
    /// Create a new [`HeaderConfigService`].
    ///
    /// Alias for [`HeaderConfigService::required`] if `!optional`
    /// and [`HeaderConfigService::optional`] if `optional`.
    pub const fn new(inner: S, header_name: HeaderName, optional: bool) -> Self {
        Self {
            inner,
            header_name,
            optional,
            _marker: PhantomData,
        }
    }

    define_inner_service_accessors!();

    /// Create a new [`HeaderConfigService`] with the given inner service
    /// and header name, on which to extract the config,
    /// and which will fail if the header is missing.
    pub const fn required(inner: S, header_name: HeaderName) -> Self {
        Self::new(inner, header_name, false)
    }

    /// Create a new [`HeaderConfigService`] with the given inner service
    /// and header name, on which to extract the config,
    /// and which will gracefully accept if the header is missing.
    pub const fn optional(inner: S, header_name: HeaderName) -> Self {
        Self::new(inner, header_name, true)
    }
}

impl<T, S: fmt::Debug> fmt::Debug for HeaderConfigService<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HeaderConfigService")
            .field("inner", &self.inner)
            .field("header_name", &self.header_name)
            .field("optional", &self.optional)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T, S> Clone for HeaderConfigService<T, S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            header_name: self.header_name.clone(),
            optional: self.optional,
            _marker: PhantomData,
        }
    }
}

impl<T, S, Body, E> Service<Request<Body>> for HeaderConfigService<T, S>
where
    S: Service<Request<Body>, Error = E>,
    T: DeserializeOwned + Clone + Send + Sync + 'static,
    Body: Send + Sync + 'static,
    E: Into<BoxError> + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context,
        request: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let config = match extract_header_config::<_, T, _>(&request, &self.header_name) {
            Ok(config) => config,
            Err(err) => {
                if self.optional && matches!(err, crate::utils::HeaderValueErr::HeaderMissing(_)) {
                    tracing::debug!("failed to extract header config: {err:?}");
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
/// [`Extensions`]: rama_core::context::Extensions
pub struct HeaderConfigLayer<T> {
    header_name: HeaderName,
    optional: bool,
    _marker: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for HeaderConfigLayer<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HeaderConfigLayer")
            .field("header_name", &self.header_name)
            .field("optional", &self.optional)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T> Clone for HeaderConfigLayer<T> {
    fn clone(&self) -> Self {
        Self {
            header_name: self.header_name.clone(),
            optional: self.optional,
            _marker: PhantomData,
        }
    }
}

impl<T> HeaderConfigLayer<T> {
    /// Create a new [`HeaderConfigLayer`] with the given header name,
    /// on which to extract the config,
    /// and which will fail if the header is missing.
    pub fn required(header_name: HeaderName) -> Self {
        Self {
            header_name,
            optional: false,
            _marker: PhantomData,
        }
    }

    /// Create a new [`HeaderConfigLayer`] with the given header name,
    /// on which to extract the config,
    /// and which will gracefully accept if the header is missing.
    pub fn optional(header_name: HeaderName) -> Self {
        Self {
            header_name,
            optional: true,
            _marker: PhantomData,
        }
    }
}

impl<T, S> Layer<S> for HeaderConfigLayer<T> {
    type Service = HeaderConfigService<T, S>;

    fn layer(&self, inner: S) -> Self::Service {
        HeaderConfigService::new(inner, self.header_name.clone(), self.optional)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HeaderConfigService::new(inner, self.header_name, self.optional)
    }
}

#[cfg(test)]
mod test {
    use serde::Deserialize;

    use crate::Method;

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
            rama_core::service::service_fn(async |ctx: Context, _req: Request<()>| {
                let cfg: &Config = ctx.get().unwrap();
                assert_eq!(cfg.s, "E&G");
                assert_eq!(cfg.n, 1);
                assert!(cfg.m.is_none());
                assert!(cfg.b);

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderConfigService::<Config, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-config"),
        );

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
            rama_core::service::service_fn(async |ctx: Context, _req: Request<()>| {
                let cfg: &Config = ctx.get().unwrap();
                assert_eq!(cfg.s, "E&G");
                assert_eq!(cfg.n, 1);
                assert!(cfg.m.is_none());
                assert!(cfg.b);

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderConfigService::<Config, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-config"),
        );

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
            rama_core::service::service_fn(async |ctx: Context, _req: Request<()>| {
                assert!(ctx.get::<Config>().is_none());

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderConfigService::<Config, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-config"),
        );

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_required_missing_header() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |_: Request<()>| {
            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderConfigService::<Config, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-config"),
        );

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

        let inner_service = rama_core::service::service_fn(async |_: Request<()>| {
            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderConfigService::<Config, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-config"),
        );

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

        let inner_service = rama_core::service::service_fn(async |_: Request<()>| {
            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderConfigService::<Config, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-config"),
        );

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
