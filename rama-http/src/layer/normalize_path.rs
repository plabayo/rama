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
//! use rama_core::{Context, Layer, Service};
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
//! service.serve(Context::default(), request).await?;
//! #
//! # Ok(())
//! # }
//! ```

use crate::{Request, Response, Uri};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::borrow::Cow;
use std::fmt;

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
pub struct NormalizePath<S> {
    mode: NormalizeMode,
    inner: S,
}

impl<S: fmt::Debug> fmt::Debug for NormalizePath<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("NormalizePath")
            .field("mode", &self.mode)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Clone> Clone for NormalizePath<S> {
    fn clone(&self) -> Self {
        Self {
            mode: self.mode,
            inner: self.inner.clone(),
        }
    }
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
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        ctx: Context,
        mut req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        match self.mode {
            NormalizeMode::Trim => trim_trailing_slash(req.uri_mut()),
            NormalizeMode::Append => append_trailing_slash(req.uri_mut()),
        }
        self.inner.serve(ctx, req)
    }
}

fn trim_trailing_slash(uri: &mut Uri) {
    if !uri.path().ends_with('/') && !uri.path().starts_with("//") {
        return;
    }

    let new_path = format!("/{}", uri.path().trim_matches('/'));

    let mut parts = uri.clone().into_parts();

    let new_path_and_query = if let Some(path_and_query) = &parts.path_and_query {
        let new_path = if new_path.is_empty() {
            "/"
        } else {
            new_path.as_str()
        };

        let new_path_and_query = if let Some(query) = path_and_query.query() {
            Cow::Owned(format!("{new_path}?{query}"))
        } else {
            new_path.into()
        }
        .parse()
        .unwrap();

        Some(new_path_and_query)
    } else {
        None
    };

    parts.path_and_query = new_path_and_query;
    if let Ok(new_uri) = Uri::from_parts(parts) {
        *uri = new_uri;
    }
}

fn append_trailing_slash(uri: &mut Uri) {
    if uri.path().ends_with("/") && !uri.path().ends_with("//") {
        return;
    }

    let trimmed = uri.path().trim_matches('/');
    let new_path = if trimmed.is_empty() {
        "/".to_owned()
    } else {
        format!("/{trimmed}/")
    };

    let mut parts = uri.clone().into_parts();

    let new_path_and_query = if let Some(path_and_query) = &parts.path_and_query {
        let new_path_and_query = if let Some(query) = path_and_query.query() {
            Cow::Owned(format!("{new_path}?{query}"))
        } else {
            new_path.into()
        }
        .parse()
        .unwrap();

        Some(new_path_and_query)
    } else {
        Some(new_path.parse().unwrap())
    };

    parts.path_and_query = new_path_and_query;
    if let Ok(new_uri) = Uri::from_parts(parts) {
        *uri = new_uri;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::Layer;
    use rama_core::service::service_fn;
    use std::convert::Infallible;

    #[tokio::test]
    async fn works() {
        async fn handle(request: Request<()>) -> Result<Response<String>, Infallible> {
            Ok(Response::new(request.uri().to_string()))
        }

        let svc = NormalizePathLayer::trim_trailing_slash().into_layer(service_fn(handle));

        let body = svc
            .serve(
                Context::default(),
                Request::builder().uri("/foo/").body(()).unwrap(),
            )
            .await
            .unwrap()
            .into_body();

        assert_eq!(body, "/foo");
    }

    #[test]
    fn is_noop_if_no_trailing_slash() {
        let mut uri = "/foo".parse::<Uri>().unwrap();
        trim_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo");
    }

    #[test]
    fn maintains_query() {
        let mut uri = "/foo/?a=a".parse::<Uri>().unwrap();
        trim_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo?a=a");
    }

    #[test]
    fn removes_multiple_trailing_slashes() {
        let mut uri = "/foo////".parse::<Uri>().unwrap();
        trim_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo");
    }

    #[test]
    fn removes_multiple_trailing_slashes_even_with_query() {
        let mut uri = "/foo////?a=a".parse::<Uri>().unwrap();
        trim_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo?a=a");
    }

    #[test]
    fn is_noop_on_index() {
        let mut uri = "/".parse::<Uri>().unwrap();
        trim_trailing_slash(&mut uri);
        assert_eq!(uri, "/");
    }

    #[test]
    fn removes_multiple_trailing_slashes_on_index() {
        let mut uri = "////".parse::<Uri>().unwrap();
        trim_trailing_slash(&mut uri);
        assert_eq!(uri, "/");
    }

    #[test]
    fn removes_multiple_trailing_slashes_on_index_even_with_query() {
        let mut uri = "////?a=a".parse::<Uri>().unwrap();
        trim_trailing_slash(&mut uri);
        assert_eq!(uri, "/?a=a");
    }

    #[test]
    fn removes_multiple_preceding_slashes_even_with_query() {
        let mut uri = "///foo//?a=a".parse::<Uri>().unwrap();
        trim_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo?a=a");
    }

    #[test]
    fn removes_multiple_preceding_slashes() {
        let mut uri = "///foo".parse::<Uri>().unwrap();
        trim_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo");
    }

    #[tokio::test]
    async fn append_works() {
        async fn handle(
            _ctx: Context,
            request: Request<()>,
        ) -> Result<Response<String>, Infallible> {
            Ok(Response::new(request.uri().to_string()))
        }

        let svc = NormalizePathLayer::append_trailing_slash().into_layer(service_fn(handle));

        let body = svc
            .serve(
                Context::default(),
                Request::builder().uri("/foo").body(()).unwrap(),
            )
            .await
            .unwrap()
            .into_body();

        assert_eq!(body, "/foo/");
    }

    #[test]
    fn is_noop_if_trailing_slash() {
        let mut uri = "/foo/".parse::<Uri>().unwrap();
        append_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo/");
    }

    #[test]
    fn append_maintains_query() {
        let mut uri = "/foo?a=a".parse::<Uri>().unwrap();
        append_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo/?a=a");
    }

    #[test]
    fn append_only_keeps_one_slash() {
        let mut uri = "/foo////".parse::<Uri>().unwrap();
        append_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo/");
    }

    #[test]
    fn append_only_keeps_one_slash_even_with_query() {
        let mut uri = "/foo////?a=a".parse::<Uri>().unwrap();
        append_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo/?a=a");
    }

    #[test]
    fn append_is_noop_on_index() {
        let mut uri = "/".parse::<Uri>().unwrap();
        append_trailing_slash(&mut uri);
        assert_eq!(uri, "/");
    }

    #[test]
    fn append_removes_multiple_trailing_slashes_on_index() {
        let mut uri = "////".parse::<Uri>().unwrap();
        append_trailing_slash(&mut uri);
        assert_eq!(uri, "/");
    }

    #[test]
    fn append_removes_multiple_trailing_slashes_on_index_even_with_query() {
        let mut uri = "////?a=a".parse::<Uri>().unwrap();
        append_trailing_slash(&mut uri);
        assert_eq!(uri, "/?a=a");
    }

    #[test]
    fn append_removes_multiple_preceding_slashes_even_with_query() {
        let mut uri = "///foo//?a=a".parse::<Uri>().unwrap();
        append_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo/?a=a");
    }

    #[test]
    fn append_removes_multiple_preceding_slashes() {
        let mut uri = "///foo".parse::<Uri>().unwrap();
        append_trailing_slash(&mut uri);
        assert_eq!(uri, "/foo/");
    }
}
