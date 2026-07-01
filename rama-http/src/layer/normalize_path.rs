//! Middleware that normalizes paths.
//!
//! Any trailing slashes from request paths will be removed. For example, a request with `/foo/`
//! will be changed to `/foo` before reaching the inner service.
//!
//! # Example
//!
//! ```
//! use std::{iter::once, convert::Infallible};
//! use rama_core::error::BoxError;
//! use rama_core::service::service_fn;
//! use rama_core::{Layer, Service};
//! use rama_http::{Body, Request, Response, StatusCode};
//! use rama_http::layer::normalize_path::NormalizePathLayer;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     // `req.uri().path()` will not have trailing slashes
//!     # Ok(Response::new(Body::default()))
//! }
//!
//! let mut service = (
//!     // trim trailing slashes from paths
//!     NormalizePathLayer::trim_trailing_slash(),
//! ).into_layer(service_fn(handle));
//!
//! // call the service
//! let request = Request::builder()
//!     // `handle` will see `/foo`
//!     .uri("/foo/")
//!     .body(Body::default())?;
//!
//! service.serve(request).await?;
//! #
//! # Ok(())
//! # }
//! ```

use crate::{Request, Response};
use rama_core::{Layer, Service};
use rama_utils::macros::define_inner_service_accessors;

/// Different modes of normalizing paths
#[derive(Debug, Copy, Clone)]
enum NormalizeMode {
    /// Normalizes paths by trimming the trailing slashes, e.g. /foo/ -> /foo
    Trim,
    /// Normalizes paths by appending trailing slash, e.g. /foo -> /foo/
    Append,
}

/// Layer that applies [`NormalizePath`] which normalizes paths.
///
/// See the [module docs](self) for more details.
#[derive(Debug, Clone)]
pub struct NormalizePathLayer {
    mode: NormalizeMode,
}

impl Default for NormalizePathLayer {
    fn default() -> Self {
        Self {
            mode: NormalizeMode::Trim,
        }
    }
}

impl NormalizePathLayer {
    /// Create a new [`NormalizePathLayer`].
    ///
    /// Any trailing slashes from request paths will be removed. For example, a request with `/foo/`
    /// will be changed to `/foo` before reaching the inner service.
    #[must_use]
    pub fn trim_trailing_slash() -> Self {
        Self {
            mode: NormalizeMode::Trim,
        }
    }

    /// Create a new [`NormalizePathLayer`].
    ///
    /// Request paths without trailing slash will be appended with a trailing slash. For example, a request with `/foo`
    /// will be changed to `/foo/` before reaching the inner service.
    #[must_use]
    pub fn append_trailing_slash() -> Self {
        Self {
            mode: NormalizeMode::Append,
        }
    }
}

impl<S> Layer<S> for NormalizePathLayer {
    type Service = NormalizePath<S>;

    fn layer(&self, inner: S) -> Self::Service {
        NormalizePath {
            mode: self.mode,
            inner,
        }
    }
}

/// Middleware that normalizes paths.
///
/// See the [module docs](self) for more details.
#[derive(Debug, Clone)]
pub struct NormalizePath<S> {
    mode: NormalizeMode,
    inner: S,
}

impl<S> NormalizePath<S> {
    /// Create a new [`NormalizePath`].
    ///
    /// Alias for [`Self::trim_trailing_slash`].
    #[inline]
    pub fn new(inner: S) -> Self {
        Self::trim_trailing_slash(inner)
    }

    /// Create a new [`NormalizePath`].
    ///
    /// Any trailing slashes from request paths will be removed. For example, a request with `/foo/`
    /// will be changed to `/foo` before reaching the inner service.
    pub fn trim_trailing_slash(inner: S) -> Self {
        Self {
            inner,
            mode: NormalizeMode::Trim,
        }
    }

    /// Create a new [`NormalizePath`].
    ///
    /// Request paths without trailing slash will be appended with a trailing slash. For example, a request with `/foo`
    /// will be changed to `/foo/` before reaching the inner service.
    pub fn append_trailing_slash(inner: S) -> Self {
        Self {
            inner,
            mode: NormalizeMode::Append,
        }
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for NormalizePath<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        mut req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        match self.mode {
            NormalizeMode::Trim => {
                req.uri_mut().path_mut().trim_trailing_slash();
            }
            NormalizeMode::Append => {
                req.uri_mut().path_mut().append_trailing_slash();
            }
        }
        self.inner.serve(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::Layer;
    use rama_core::service::service_fn;
    use rama_net::uri::Uri;
    use std::convert::Infallible;

    #[tokio::test]
    async fn works() {
        async fn handle(request: Request<()>) -> Result<Response<String>, Infallible> {
            Ok(Response::new(request.uri().to_string()))
        }

        let svc = NormalizePathLayer::trim_trailing_slash().into_layer(service_fn(handle));

        let body = svc
            .serve(Request::builder().uri("/foo/").body(()).unwrap())
            .await
            .unwrap()
            .into_body();

        assert_eq!(body, "/foo");
    }

    #[test]
    fn is_noop_if_no_trailing_slash() {
        let mut uri = "/foo".parse::<Uri>().unwrap();
        uri.path_mut().trim_trailing_slash();
        assert_eq!(uri, "/foo");
    }

    #[test]
    fn maintains_query() {
        let mut uri = "/foo/?a=a".parse::<Uri>().unwrap();
        uri.path_mut().trim_trailing_slash();
        assert_eq!(uri, "/foo?a=a");
    }

    #[test]
    fn removes_multiple_trailing_slashes() {
        let mut uri = "/foo////".parse::<Uri>().unwrap();
        uri.path_mut().trim_trailing_slash();
        assert_eq!(uri, "/foo");
    }

    #[test]
    fn removes_multiple_trailing_slashes_even_with_query() {
        let mut uri = "/foo////?a=a".parse::<Uri>().unwrap();
        uri.path_mut().trim_trailing_slash();
        assert_eq!(uri, "/foo?a=a");
    }

    #[test]
    fn is_noop_on_index() {
        let mut uri = "/".parse::<Uri>().unwrap();
        uri.path_mut().trim_trailing_slash();
        assert_eq!(uri, "/");
    }

    #[test]
    fn removes_multiple_trailing_slashes_on_index() {
        let mut uri = "////".parse::<Uri>().unwrap();
        uri.path_mut().trim_trailing_slash();
        assert_eq!(uri, "/");
    }

    #[test]
    fn removes_multiple_trailing_slashes_on_index_even_with_query() {
        let mut uri = "////?a=a".parse::<Uri>().unwrap();
        uri.path_mut().trim_trailing_slash();
        assert_eq!(uri, "/?a=a");
    }

    #[test]
    fn removes_multiple_preceding_slashes_even_with_query() {
        let mut uri = "///foo//?a=a".parse::<Uri>().unwrap();
        uri.path_mut().trim_trailing_slash();
        assert_eq!(uri, "/foo?a=a");
    }

    #[test]
    fn removes_multiple_preceding_slashes() {
        let mut uri = "///foo".parse::<Uri>().unwrap();
        uri.path_mut().trim_trailing_slash();
        assert_eq!(uri, "/foo");
    }

    #[tokio::test]
    async fn append_works() {
        async fn handle(request: Request<()>) -> Result<Response<String>, Infallible> {
            Ok(Response::new(request.uri().to_string()))
        }

        let svc = NormalizePathLayer::append_trailing_slash().into_layer(service_fn(handle));

        let body = svc
            .serve(Request::builder().uri("/foo").body(()).unwrap())
            .await
            .unwrap()
            .into_body();

        assert_eq!(body, "/foo/");
    }

    #[test]
    fn is_noop_if_trailing_slash() {
        let mut uri = "/foo/".parse::<Uri>().unwrap();
        uri.path_mut().append_trailing_slash();
        assert_eq!(uri, "/foo/");
    }

    #[test]
    fn append_maintains_query() {
        let mut uri = "/foo?a=a".parse::<Uri>().unwrap();
        uri.path_mut().append_trailing_slash();
        assert_eq!(uri, "/foo/?a=a");
    }

    #[test]
    fn append_only_keeps_one_slash() {
        let mut uri = "/foo////".parse::<Uri>().unwrap();
        uri.path_mut().append_trailing_slash();
        assert_eq!(uri, "/foo/");
    }

    #[test]
    fn append_only_keeps_one_slash_even_with_query() {
        let mut uri = "/foo////?a=a".parse::<Uri>().unwrap();
        uri.path_mut().append_trailing_slash();
        assert_eq!(uri, "/foo/?a=a");
    }

    #[test]
    fn append_is_noop_on_index() {
        let mut uri = "/".parse::<Uri>().unwrap();
        uri.path_mut().append_trailing_slash();
        assert_eq!(uri, "/");
    }

    #[test]
    fn append_removes_multiple_trailing_slashes_on_index() {
        let mut uri = "////".parse::<Uri>().unwrap();
        uri.path_mut().append_trailing_slash();
        assert_eq!(uri, "/");
    }

    #[test]
    fn append_removes_multiple_trailing_slashes_on_index_even_with_query() {
        let mut uri = "////?a=a".parse::<Uri>().unwrap();
        uri.path_mut().append_trailing_slash();
        assert_eq!(uri, "/?a=a");
    }

    #[test]
    fn append_removes_multiple_preceding_slashes_even_with_query() {
        let mut uri = "///foo//?a=a".parse::<Uri>().unwrap();
        uri.path_mut().append_trailing_slash();
        assert_eq!(uri, "/foo/?a=a");
    }

    #[test]
    fn append_removes_multiple_preceding_slashes() {
        let mut uri = "///foo".parse::<Uri>().unwrap();
        uri.path_mut().append_trailing_slash();
        assert_eq!(uri, "/foo/");
    }
}
