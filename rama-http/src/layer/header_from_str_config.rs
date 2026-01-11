//! Extract a header config from a request or response and insert it into [`Extensions`].
//!
//! [`Extensions`]: rama_core::extensions::Extensions
//!
//! # Example
//!
//! ```rust
//! use rama_http::layer::header_from_str_config::HeaderFromStrConfigLayer;
//! use rama_http::service::web::{WebService};
//! use rama_http::{Body, Request, StatusCode, HeaderName};
//! use rama_core::{extensions::ExtensionsRef, Service, Layer};
//! use serde::Deserialize;
//!
//! #[tokio::main]
//! async fn main() {
//!     let service = HeaderFromStrConfigLayer::<String>::required(HeaderName::from_static("x-proxy-labels"))
//!         .with_repeat(true)
//!         .into_layer(WebService::default()
//!             .with_get("/", async |req: Request| {
//!                 // For production-like code you should prefer a custom type
//!                 // to avoid possible conflicts. Ideally these are also as
//!                 // cheap as possible to allocate.
//!                 let labels: &Vec<String> = req.extensions().get().unwrap();
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
//!     let resp = service.serve(request).await.unwrap();
//!     assert_eq!(resp.status(), StatusCode::OK);
//! }
//! ```

use crate::HeaderName;
use crate::{
    Request,
    utils::{HeaderValueErr, HeaderValueGetter},
};
use rama_core::extensions::ExtensionsMut;
use rama_core::{Layer, Service, error::BoxError};
use rama_utils::macros::define_inner_service_accessors;
use std::iter::FromIterator;
use std::str::FromStr;
use std::{fmt, marker::PhantomData};

/// A [`Service`] which extracts a header CSV config from a request or response
/// and inserts it into the [`Extensions`] of that object.
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct HeaderFromStrConfigService<T, S, C = Vec<T>> {
    inner: S,
    header_name: HeaderName,
    optional: bool,
    repeat: bool,
    _marker: PhantomData<fn() -> (T, C)>,
}

impl<T, S, C> HeaderFromStrConfigService<T, S, C> {
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

    rama_utils::macros::generate_set_and_with! {
        /// Toggle repeat on/off. When repeat is enabled the
        /// data config will be parsed and inserted as a container of type `C` (defaults to `Vec<T>`).
        pub fn repeat(mut self, repeat: bool) -> Self {
            self.repeat = repeat;
            self
        }
    }
}

impl<T, S, C> fmt::Debug for HeaderFromStrConfigService<T, S, C>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HeaderFromStrConfigService")
            .field("inner", &self.inner)
            .field("header_name", &self.header_name)
            .field("optional", &self.optional)
            .field("repeat", &self.repeat)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn() -> (T, C)>()),
            )
            .finish()
    }
}

impl<T, S, C> Clone for HeaderFromStrConfigService<T, S, C>
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

impl<T, S, Body, E, C> Service<Request<Body>> for HeaderFromStrConfigService<T, S, C>
where
    S: Service<Request<Body>, Error = E>,
    T: FromStr<Err: Into<BoxError> + Send + Sync + 'static>
        + Send
        + Sync
        + Clone
        + std::fmt::Debug
        + 'static,
    C: FromIterator<T> + Send + Sync + Clone + std::fmt::Debug + 'static,
    Body: Send + Sync + 'static,
    E: Into<BoxError> + Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut request: Request<Body>) -> Result<Self::Output, Self::Error> {
        if self.repeat {
            let headers = request.headers().get_all(&self.header_name);
            let mut parsed_values = headers
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
                .peekable();

            if parsed_values.peek().is_none() {
                if !self.optional {
                    return Err(HeaderValueErr::HeaderMissing(self.header_name.to_string()).into());
                }
            } else {
                let values = parsed_values.collect::<Result<C, _>>()?;
                request.extensions_mut().insert(values);
            }
        } else {
            match request.header_str(&self.header_name) {
                Ok(s) => {
                    let cfg: T = s.parse().map_err(Into::into)?;
                    request.extensions_mut().insert(cfg);
                }
                Err(HeaderValueErr::HeaderMissing(_)) if self.optional => (),
                Err(err) => {
                    return Err(err.into());
                }
            }
        }

        self.inner.serve(request).await.map_err(Into::into)
    }
}

/// Layer which extracts a header CSV config for the given HeaderName
/// from a request or response and inserts it into the [`Extensions`] of that object.
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct HeaderFromStrConfigLayer<T, C = Vec<T>> {
    header_name: HeaderName,
    optional: bool,
    repeat: bool,
    _marker: PhantomData<fn() -> (T, C)>,
}

impl<T, C: fmt::Debug> fmt::Debug for HeaderFromStrConfigLayer<T, C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("HeaderFromStrConfigLayer")
            .field("header_name", &self.header_name)
            .field("optional", &self.optional)
            .field("repeat", &self.repeat)
            .field(
                "_marker",
                &format_args!("{}", std::any::type_name::<fn() -> (T, C)>()),
            )
            .finish()
    }
}

impl<T, C> Clone for HeaderFromStrConfigLayer<T, C> {
    fn clone(&self) -> Self {
        Self {
            header_name: self.header_name.clone(),
            optional: self.optional,
            repeat: self.repeat,
            _marker: PhantomData,
        }
    }
}

impl<T, C> HeaderFromStrConfigLayer<T, C> {
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

    rama_utils::macros::generate_set_and_with! {
        /// Toggle repeat on/off. When repeat is enabled the
        /// data config will be parsed and inserted as a container of type `C` (defaults to `Vec<T>`).
        pub fn repeat(mut self, repeat: bool) -> Self {
            self.repeat = repeat;
            self
        }
    }
}

impl<T, S, C> Layer<S> for HeaderFromStrConfigLayer<T, C> {
    type Service = HeaderFromStrConfigService<T, S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        HeaderFromStrConfigService {
            inner,
            header_name: self.header_name.clone(),
            optional: self.optional,
            repeat: self.repeat,
            _marker: PhantomData,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        HeaderFromStrConfigService {
            inner,
            header_name: self.header_name,
            optional: self.optional,
            repeat: self.repeat,
            _marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod test {
    use rama_core::extensions::ExtensionsRef;

    use super::*;
    use crate::Method;
    use ahash::HashSet;
    use std::collections::LinkedList;

    #[tokio::test]
    async fn test_header_config_required_happy_path() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-id", "42")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            let id: &usize = req.extensions().get().unwrap();
            assert_eq!(*id, 42);

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<usize, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_required_repeat_happy_path() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-labels", "foo,bar ,baz, fin ")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            let labels: &Vec<String> = req.extensions().get().unwrap();
            assert_eq!("foo+bar+baz+fin", labels.join("+"));

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<String, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_required_repeat_custom_container() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-labels", "foo,bar,baz,foo")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            let labels: &HashSet<String> = req.extensions().get().unwrap();
            assert_eq!(3, labels.len());
            assert!(labels.contains("foo"));
            assert!(labels.contains("bar"));
            assert!(labels.contains("baz"));

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<String, _, HashSet<String>>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_required_repeat_linked_list() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-labels", "foo,bar,baz")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            let labels: &LinkedList<String> = req.extensions().get().unwrap();
            let mut iter = labels.iter();
            assert_eq!(Some("foo"), iter.next().map(|x| x.as_str()));
            assert_eq!(Some("bar"), iter.next().map(|x| x.as_str()));
            assert_eq!(Some("baz"), iter.next().map(|x| x.as_str()));
            assert_eq!(None, iter.next());

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<String, _, LinkedList<String>>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        service.serve(request).await.unwrap();
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

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            let labels: &Vec<String> = req.extensions().get().unwrap();
            assert_eq!("foo+bar+baz+fin", labels.join("+"));

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<String, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_optional_found() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-id", "42")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            let id: usize = *req.extensions().get().unwrap();
            assert_eq!(id, 42);

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<usize, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_repeat_optional_found() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .header("x-proxy-labels", "foo,bar ,baz, fin ")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            let labels: &Vec<String> = req.extensions().get().unwrap();
            assert_eq!("foo+bar+baz+fin", labels.join("+"));

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<String, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_optional_missing() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            assert!(req.extensions().get::<usize>().is_none());
            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<usize, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_repeat_optional_missing() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            assert!(req.extensions().get::<Vec<String>>().is_none());

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<String, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn test_header_config_required_missing_header() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |_req: Request<()>| {
            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<usize, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        let result = service.serve(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_header_config_repeat_required_missing() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://www.example.com")
            .body(())
            .unwrap();

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            assert!(req.extensions().get::<Vec<String>>().is_none());

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<String, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        let result = service.serve(request).await;
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

        let inner_service = rama_core::service::service_fn(async |_req: Request<()>| {
            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<usize, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        let result = service.serve(request).await;
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

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            assert!(req.extensions().get::<Vec<String>>().is_none());

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<usize, _>::required(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        let result = service.serve(request).await;
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

        let inner_service = rama_core::service::service_fn(async |_req: Request<()>| {
            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<usize, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-id"),
        );

        let result = service.serve(request).await;
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

        let inner_service = rama_core::service::service_fn(async |req: Request<()>| {
            assert!(req.extensions().get::<Vec<String>>().is_none());

            Ok::<_, std::convert::Infallible>(())
        });

        let service = HeaderFromStrConfigService::<usize, _>::optional(
            inner_service,
            HeaderName::from_static("x-proxy-labels"),
        )
        .with_repeat(true);

        let result = service.serve(request).await;
        assert!(result.is_err());
    }
}
