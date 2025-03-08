//! Extract a header config from a request or response and insert it into the [`Extensions`] of its [`Context`].
//!
//! [`Extensions`]: rama_core::context::Extensions
//! [`Context`]: rama_core::Context
//!
//! # Example
//!
//! ```rust
//! use rama_http::layer::header_from_str_config::HeaderFromStrConfigLayer;
//! use rama_http::service::web::{WebService};
//! use rama_http::{Body, Request, StatusCode, HeaderName};
//! use rama_core::{Context, Service, Layer};
//! use serde::Deserialize;
//!
//! #[tokio::main]
//! async fn main() {
//!     let service = HeaderFromStrConfigLayer::<String>::required(HeaderName::from_static("x-proxy-labels"))
//!         .with_repeat(true)
//!         .layer(WebService::default()
//!             .get("/", |ctx: Context<()>| async move {
//!                 // For production-like code you should prefer a custom type
//!                 // to avoid possible conflicts. Ideally these are also as
//!                 // cheap as possible to allocate.
//!                 let labels: &Vec<String> = ctx.get().unwrap();
//!                 assert_eq!("a+b+c", labels.join("+"));
//!             }),
//!         );
//!
//!     let request = Request::builder()
//!         .header("x-proxy-labels", "a, b")
//!         .header("x-proxy-labels", "c")
//!         .body(Body::empty())
//!         .unwrap();
//!
//!     let resp = service.serve(Context::default(), request).await.unwrap();
//!     assert_eq!(resp.status(), StatusCode::OK);
//! }
//! ```

use crate::HeaderName;
use crate::{
    Request,
    utils::{HeaderValueErr, HeaderValueGetter},
};
use rama_core::{Context, Layer, Service, error::BoxError};
use rama_utils::macros::define_inner_service_accessors;
use std::str::FromStr;
use std::{fmt, marker::PhantomData};

/// A [`Service`] which extracts a header CSV config from a request or response
/// and inserts it into the [`Extensions`] of that object.
///
/// [`Extensions`]: rama_core::context::Extensions
pub struct HeaderFromStrConfigService<T, S> {
    inner: S,
    header_name: HeaderName,
    optional: bool,
    repeat: bool,
    _marker: PhantomData<fn() -> T>,
}

impl<T, S> HeaderFromStrConfigService<T, S> {
    define_inner_service_accessors!();

    /// Create a new [`HeaderFromStrConfigService`] with the given inner service
    /// and header name, on which to extract the config,
    /// and which will fail if the header is missing.
    pub const fn required(inner: S, header_name: HeaderName) -> Self {
        Self {
            inner,
            header_name,
            optional: false,
            repeat: false,
            _marker: PhantomData,
        }
    }

    /// Create a new [`HeaderFromStrConfigService`] with the given inner service
    /// and header name, on which to extract the config,
    /// and which will gracefully accept if the header is missing.
    pub const fn optional(inner: S, header_name: HeaderName) -> Self {
        Self {
            inner,
            header_name,
            optional: true,
            repeat: false,
            _marker: PhantomData,
        }
    }

    /// Toggle repeat on/off. When repeat is enabled the
    /// data config will be parsed and inserted as a [`Vec`].
    pub fn set_repeat(&mut self, repeat: bool) -> &mut Self {
        self.repeat = repeat;
        self
    }

    /// Toggle repeat on/off. When repeat is enabled the
    /// data config will be parsed and inserted as a [`Vec`].
    pub fn with_repeat(mut self, repeat: bool) -> Self {
        self.repeat = repeat;
        self
    }
}

impl<T, S: fmt::Debug> fmt::Debug for HeaderFromStrConfigService<T, S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HeaderFromStrConfigService")
            .field("inner", &self.inner)
            .field("header_name", &self.header_name)
            .field("optional", &self.optional)
            .field("repeat", &self.repeat)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T, S> Clone for HeaderFromStrConfigService<T, S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            header_name: self.header_name.clone(),
            optional: self.optional,
            repeat: self.repeat,
            _marker: PhantomData,
        }
    }
}

impl<T, S, State, Body, E> Service<State, Request<Body>> for HeaderFromStrConfigService<T, S>
where
    S: Service<State, Request<Body>, Error = E>,
    T: FromStr<Err: Into<BoxError> + Send + Sync + 'static> + Send + Sync + 'static + Clone,
    State: Clone + Send + Sync + 'static,
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
        if self.repeat {
            let headers = request.headers().get_all(&self.header_name);
            let result: Result<Vec<T>, _> = headers
                .into_iter()
                .flat_map(|value| {
                    value.to_str().into_iter().flat_map(|string| {
                        string
                            .split(',')
                            .filter_map(|x| match x.trim() {
                                "" => None,
                                y => Some(y),
                            })
                            .map(|x| x.parse::<T>().map_err(Into::into))
                    })
                })
                .collect();
            let values = result?;
            if values.is_empty() {
                if !self.optional {
                    return Err(HeaderValueErr::HeaderMissing(self.header_name.to_string()).into());
                }
            } else {
                ctx.insert(values);
            }
        } else {
            match request.header_str(&self.header_name) {
                Ok(s) => {
                    let cfg: T = s.parse().map_err(Into::into)?;
                    ctx.insert(cfg);
                }
                Err(HeaderValueErr::HeaderMissing(_)) if self.optional => (),
                Err(err) => {
                    return Err(err.into());
                }
            }
        }

        self.inner.serve(ctx, request).await.map_err(Into::into)
    }
}

/// Layer which extracts a header CSv config for the given HeaderName
/// from a request or response and inserts it into the [`Extensions`] of that object.
///
/// [`Extensions`]: rama_core::context::Extensions
pub struct HeaderFromStrConfigLayer<T> {
    header_name: HeaderName,
    optional: bool,
    repeat: bool,
    _marker: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for HeaderFromStrConfigLayer<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HeaderFromStrConfigLayer")
            .field("header_name", &self.header_name)
            .field("optional", &self.optional)
            .field("repeat", &self.repeat)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T> Clone for HeaderFromStrConfigLayer<T> {
    fn clone(&self) -> Self {
        Self {
            header_name: self.header_name.clone(),
            optional: self.optional,
            repeat: self.repeat,
            _marker: PhantomData,
        }
    }
}

impl<T> HeaderFromStrConfigLayer<T> {
    /// Create a new [`HeaderFromStrConfigLayer`] with the given header name,
    /// on which to extract the config,
    /// and which will fail if the header is missing.
    pub fn required(header_name: HeaderName) -> Self {
        Self {
            header_name,
            optional: false,
            repeat: false,
            _marker: PhantomData,
        }
    }

    /// Create a new [`HeaderFromStrConfigLayer`] with the given header name,
    /// on which to extract the config,
    /// and which will gracefully accept if the header is missing.
    pub fn optional(header_name: HeaderName) -> Self {
        Self {
            header_name,
            optional: true,
            repeat: false,
            _marker: PhantomData,
        }
    }

    /// Toggle repeat on/off. When repeat is enabled the
    /// data config will be parsed and inserted as a [`Vec`].
    pub fn set_repeat(&mut self, repeat: bool) -> &mut Self {
        self.repeat = repeat;
        self
    }

    /// Toggle repeat on/off. When repeat is enabled the
    /// data config will be parsed and inserted as a [`Vec`].
    pub fn with_repeat(mut self, repeat: bool) -> Self {
        self.repeat = repeat;
        self
    }
}

impl<T, S> Layer<S> for HeaderFromStrConfigLayer<T> {
    type Service = HeaderFromStrConfigService<T, S>;

    fn layer(&self, inner: S) -> Self::Service {
        HeaderFromStrConfigService {
            inner,
            header_name: self.header_name.clone(),
            optional: self.optional,
            repeat: self.repeat,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::Method;

    #[tokio::test]
    async fn test_header_config_required_happy_path() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-id", "42")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                let id: &usize = ctx.get().unwrap();
                assert_eq!(*id, 42);

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<usize, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_required_repeat_happy_path() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-labels", "foo,bar ,baz, fin ")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                let labels: &Vec<String> = ctx.get().unwrap();
                assert_eq!("foo+bar+baz+fin", labels.join("+"));

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<String, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_required_repeat_happy_path_multi_header() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-labels", "foo,bar ")
            .header("x-Proxy-Labels", "baz ")
            .header("X-PROXY-LABELS", " fin")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                let labels: &Vec<String> = ctx.get().unwrap();
                assert_eq!("foo+bar+baz+fin", labels.join("+"));

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<String, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_optional_found() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-id", "42")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                let id: usize = *ctx.get().unwrap();
                assert_eq!(id, 42);

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<usize, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_repeat_optional_found() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-labels", "foo,bar ,baz, fin ")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                let labels: &Vec<String> = ctx.get().unwrap();
                assert_eq!("foo+bar+baz+fin", labels.join("+"));

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<String, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

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
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                assert!(ctx.get::<usize>().is_none());
                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<usize, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_repeat_optional_missing() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                assert!(ctx.get::<Vec<String>>().is_none());

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<String, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        service.serve(Context::default(), request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_required_missing_header() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|_ctx: Context<()>, _req: Request<()>| async move {
                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<usize, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        let result = service.serve(Context::default(), request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_header_config_repeat_required_missing() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                assert!(ctx.get::<Vec<String>>().is_none());

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<String, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        let result = service.serve(Context::default(), request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_header_config_required_invalid_config() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-id", "foo")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|_ctx: Context<()>, _req: Request<()>| async move {
                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<usize, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        let result = service.serve(Context::default(), request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_header_config_repeat_required_invalid_config() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-labels", "42,foo")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                assert!(ctx.get::<Vec<String>>().is_none());

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<usize, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        let result = service.serve(Context::default(), request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_header_config_optional_invalid_config() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-id", "foo")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|_ctx: Context<()>, _req: Request<()>| async move {
                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<usize, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        let result = service.serve(Context::default(), request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_header_config_repeat_optional_invalid_config() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-labels", "42,foo")
            .body(())
            .unwrap();

        let inner_service =
            rama_core::service::service_fn(|ctx: Context<()>, _req: Request<()>| async move {
                assert!(ctx.get::<Vec<String>>().is_none());

                Ok::<_, std::convert::Infallible>(())
            });

        let service = HeaderFromStrConfigService::<usize, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        let result = service.serve(Context::default(), request).await;
        assert!(result.is_err());
    }
}
