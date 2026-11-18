//! Add the `Server` and `Date` headers to a response, if they are missing.
//!
//! See [`AddRequiredResponseHeaders`] for the exact behaviour.

use crate::{
    Request, Response,
    header::{DATE, SERVER},
    headers::{DateNow, HeaderMapExt, Server},
};
use rama_core::{Layer, Service, extensions::ExtensionsRef};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// [`Layer`] that wraps a service in [`AddRequiredResponseHeaders`].
///
/// See [`AddRequiredResponseHeaders`] for the headers it adds.
#[derive(Debug, Clone)]
pub struct AddRequiredResponseHeadersLayer {
    overwrite: bool,
    server: Server,
}

impl Default for AddRequiredResponseHeadersLayer {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl AddRequiredResponseHeadersLayer {
    /// Create a new [`AddRequiredResponseHeadersLayer`]
    /// which only adds missing headers and uses the default `Server`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            overwrite: false,
            server: Server::rama(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether the `Server` and `Date` headers
        /// replace values already present on the response.
        ///
        /// When `false` (the default) only missing headers are added.
        pub fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`Server`] header to add.
        ///
        /// Defaults to [`Server::rama`] (`rama/<version>`).
        pub fn server(mut self, server: Server) -> Self {
            self.server = server;
            self
        }
    }
}

impl<S> Layer<S> for AddRequiredResponseHeadersLayer {
    type Service = AddRequiredResponseHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddRequiredResponseHeaders {
            inner,
            overwrite: self.overwrite,
            server: self.server.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        AddRequiredResponseHeaders {
            inner,
            overwrite: self.overwrite,
            server: self.server,
        }
    }
}

/// Middleware that adds the `Server` and `Date` headers to the response
/// returned by the inner service.
///
/// - `Server`: the configured value, or [`Server::rama`] by default.
/// - `Date`: the current time, formatted as an HTTP-date.
///
/// Existing headers are kept unless overwriting is enabled,
/// see [`AddRequiredResponseHeaders::set_overwrite`].
/// The request is passed through unchanged and errors
/// of the inner service are returned as-is.
#[derive(Clone, ExtensionsRef)]
pub struct AddRequiredResponseHeaders<S> {
    inner: S,
    overwrite: bool,
    server: Server,
}

impl<S> AddRequiredResponseHeaders<S> {
    /// Wrap `inner` in a new [`AddRequiredResponseHeaders`]
    /// which only adds missing headers and uses the default `Server`.
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            overwrite: false,
            server: Server::rama(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether the `Server` and `Date` headers
        /// replace values already present on the response.
        ///
        /// When `false` (the default) only missing headers are added.
        pub fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`Server`] header to add.
        ///
        /// Defaults to [`Server::rama`] (`rama/<version>`).
        pub fn server(mut self, server: Server) -> Self {
            self.server = server;
            self
        }
    }

    define_inner_service_accessors!();
}

impl<S> fmt::Debug for AddRequiredResponseHeaders<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddRequiredResponseHeaders")
            .field("inner", &self.inner)
            .field("overwrite", &self.overwrite)
            .field("server", &self.server)
            .finish()
    }
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for AddRequiredResponseHeaders<S>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let mut resp = self.inner.serve(req).await?;

        let headers = resp.headers_mut();
        if self.overwrite || !headers.contains_key(SERVER) {
            headers.typed_insert(self.server.clone());
        }
        if self.overwrite || !headers.contains_key(DATE) {
            headers.typed_insert(DateNow::new());
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Body, HeaderValue, headers::Date};
    use rama_core::{Layer, service::service_fn};
    use std::convert::Infallible;

    #[tokio::test]
    async fn add_required_response_headers() {
        let svc = AddRequiredResponseHeadersLayer::default().into_layer(service_fn(
            async |req: Request| {
                assert!(!req.headers().contains_key(SERVER));
                assert!(!req.headers().contains_key(DATE));
                Ok::<_, Infallible>(Response::new(Body::empty()))
            },
        ));

        let req = Request::new(Body::empty());
        let resp = svc.serve(req).await.unwrap();

        assert_eq!(resp.headers().typed_get::<Server>(), Some(Server::rama()));
        assert!(resp.headers().typed_get::<Date>().is_some());
    }

    #[tokio::test]
    async fn add_required_response_headers_custom_server() {
        let svc = AddRequiredResponseHeadersLayer::default()
            .with_server(Server::from_static("foo"))
            .into_layer(service_fn(async |req: Request| {
                assert!(!req.headers().contains_key(SERVER));
                assert!(!req.headers().contains_key(DATE));
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));

        let req = Request::new(Body::empty());
        let resp = svc.serve(req).await.unwrap();

        assert_eq!(
            resp.headers().get(SERVER).and_then(|v| v.to_str().ok()),
            Some("foo")
        );
        assert!(resp.headers().contains_key(DATE));
    }

    #[tokio::test]
    async fn add_required_response_headers_overwrite() {
        let svc = AddRequiredResponseHeadersLayer::new()
            .with_overwrite(true)
            .into_layer(service_fn(async |req: Request| {
                assert!(!req.headers().contains_key(SERVER));
                assert!(!req.headers().contains_key(DATE));
                Ok::<_, Infallible>(
                    Response::builder()
                        .header(SERVER, "foo")
                        .header(DATE, "bar")
                        .body(Body::empty())
                        .unwrap(),
                )
            }));

        let req = Request::new(Body::empty());
        let resp = svc.serve(req).await.unwrap();

        assert_eq!(resp.headers().typed_get::<Server>(), Some(Server::rama()));
        assert!(resp.headers().typed_get::<Date>().is_some());
    }

    #[tokio::test]
    async fn add_required_response_headers_overwrite_custom_ua() {
        let svc = AddRequiredResponseHeadersLayer::new()
            .with_overwrite(true)
            .with_server(Server::from_static("foo"))
            .into_layer(service_fn(async |req: Request| {
                assert!(!req.headers().contains_key(SERVER));
                assert!(!req.headers().contains_key(DATE));
                Ok::<_, Infallible>(
                    Response::builder()
                        .header(SERVER, "foo")
                        .header(DATE, "bar")
                        .body(Body::empty())
                        .unwrap(),
                )
            }));

        let req = Request::new(Body::empty());
        let resp = svc.serve(req).await.unwrap();

        assert_eq!(
            resp.headers().get(SERVER).and_then(|v| v.to_str().ok()),
            Some("foo")
        );
        assert!(resp.headers().typed_get::<Date>().is_some());
    }

    #[tokio::test]
    async fn add_required_response_headers_keeps_existing() {
        let svc =
            AddRequiredResponseHeadersLayer::new().into_layer(service_fn(async |_req: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .header(SERVER, "foo")
                        .header(DATE, "bar")
                        .body(Body::empty())
                        .unwrap(),
                )
            }));

        let resp = svc.serve(Request::new(Body::empty())).await.unwrap();

        assert_eq!(
            resp.headers().get(SERVER),
            Some(&HeaderValue::from_static("foo"))
        );
        assert_eq!(
            resp.headers().get(DATE),
            Some(&HeaderValue::from_static("bar"))
        );
    }

    #[tokio::test]
    async fn add_required_response_headers_dynamic_server() {
        let server: Server = format!("srv/{}", 42).parse().unwrap();
        let svc = AddRequiredResponseHeadersLayer::new()
            .with_server(server.clone())
            .into_layer(service_fn(async |_req: Request| {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));

        let resp = svc.serve(Request::new(Body::empty())).await.unwrap();

        assert_eq!(resp.headers().typed_get::<Server>(), Some(server));
    }
}
