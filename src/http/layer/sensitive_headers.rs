//! Middlewares that mark headers as [sensitive].
//!
//! [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
//!
//! # Example
//!
//! ```
//! use rama::http::layer::sensitive_headers::SetSensitiveHeadersLayer;
//! use rama::http::{Body, Request, Response, header::AUTHORIZATION};
//! use rama::service::{Context, Service, ServiceBuilder, service_fn};
//! use rama::error::BoxError;
//! use std::{iter::once, convert::Infallible};
//!
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let mut service = ServiceBuilder::new()
//!     // Mark the `Authorization` header as sensitive so it doesn't show in logs
//!     //
//!     // `SetSensitiveHeadersLayer` will mark the header as sensitive on both the
//!     // request and response.
//!     //
//!     // The middleware is constructed from an iterator of headers to easily mark
//!     // multiple headers at once.
//!     .layer(SetSensitiveHeadersLayer::new(once(AUTHORIZATION)))
//!     .service(service_fn(handle));
//!
//! // Call the service.
//! let response = service
//!     .serve(Context::default(), Request::new(Body::empty()))
//!     .await?;
//! # Ok(())
//! # }
//! ```

use crate::http::{HeaderName, Request, Response};
use crate::service::{Context, Layer, Service};
use std::sync::Arc;

/// Mark headers as [sensitive] on both requests and responses.
///
/// Produces [`SetSensitiveHeaders`] services.
///
/// See the [module docs](crate::http::layer::sensitive_headers) for more details.
///
/// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
#[derive(Clone, Debug)]
pub struct SetSensitiveHeadersLayer {
    headers: Arc<[HeaderName]>,
}

impl SetSensitiveHeadersLayer {
    /// Create a new [`SetSensitiveHeadersLayer`].
    pub fn new<I>(headers: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        let headers = headers.into_iter().collect::<Vec<_>>();
        Self::from_shared(headers.into())
    }

    /// Create a new [`SetSensitiveHeadersLayer`] from a shared slice of headers.
    pub fn from_shared(headers: Arc<[HeaderName]>) -> Self {
        Self { headers }
    }
}

impl<S> Layer<S> for SetSensitiveHeadersLayer {
    type Service = SetSensitiveHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetSensitiveRequestHeaders::from_shared(
            SetSensitiveResponseHeaders::from_shared(inner, self.headers.clone()),
            self.headers.clone(),
        )
    }
}

/// Mark headers as [sensitive] on both requests and responses.
///
/// See the [module docs](crate::http::layer::sensitive_headers) for more details.
///
/// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
pub type SetSensitiveHeaders<S> = SetSensitiveRequestHeaders<SetSensitiveResponseHeaders<S>>;

/// Mark request headers as [sensitive].
///
/// Produces [`SetSensitiveRequestHeaders`] services.
///
/// See the [module docs](crate::http::layer::sensitive_headers) for more details.
///
/// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
#[derive(Clone, Debug)]
pub struct SetSensitiveRequestHeadersLayer {
    headers: Arc<[HeaderName]>,
}

impl SetSensitiveRequestHeadersLayer {
    /// Create a new [`SetSensitiveRequestHeadersLayer`].
    pub fn new<I>(headers: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        let headers = headers.into_iter().collect::<Vec<_>>();
        Self::from_shared(headers.into())
    }

    /// Create a new [`SetSensitiveRequestHeadersLayer`] from a shared slice of headers.
    pub fn from_shared(headers: Arc<[HeaderName]>) -> Self {
        Self { headers }
    }
}

impl<S> Layer<S> for SetSensitiveRequestHeadersLayer {
    type Service = SetSensitiveRequestHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetSensitiveRequestHeaders {
            inner,
            headers: self.headers.clone(),
        }
    }
}

/// Mark request headers as [sensitive].
///
/// See the [module docs](crate::http::layer::sensitive_headers) for more details.
///
/// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
#[derive(Clone, Debug)]
pub struct SetSensitiveRequestHeaders<S> {
    inner: S,
    headers: Arc<[HeaderName]>,
}

impl<S> SetSensitiveRequestHeaders<S> {
    /// Create a new [`SetSensitiveRequestHeaders`].
    pub fn new<I>(inner: S, headers: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        let headers = headers.into_iter().collect::<Vec<_>>();
        Self::from_shared(inner, headers.into())
    }

    /// Create a new [`SetSensitiveRequestHeaders`] from a shared slice of headers.
    pub fn from_shared(inner: S, headers: Arc<[HeaderName]>) -> Self {
        Self { inner, headers }
    }

    define_inner_service_accessors!();

    /// Returns a new [`Layer`] that wraps services with a `SetSensitiveRequestHeaders` middleware.
    ///
    /// [`Layer`]: crate::service::Layer
    pub fn layer<I>(headers: I) -> SetSensitiveRequestHeadersLayer
    where
        I: IntoIterator<Item = HeaderName>,
    {
        SetSensitiveRequestHeadersLayer::new(headers)
    }
}

impl<ReqBody, ResBody, State, S> Service<State, Request<ReqBody>> for SetSensitiveRequestHeaders<S>
where
    State: Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let headers = req.headers_mut();
        for header in &*self.headers {
            if let http::header::Entry::Occupied(mut entry) = headers.entry(header) {
                for value in entry.iter_mut() {
                    value.set_sensitive(true);
                }
            }
        }

        self.inner.serve(ctx, req).await
    }
}

/// Mark response headers as [sensitive].
///
/// Produces [`SetSensitiveResponseHeaders`] services.
///
/// See the [module docs](crate::http::layer::sensitive_headers) for more details.
///
/// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
#[derive(Clone, Debug)]
pub struct SetSensitiveResponseHeadersLayer {
    headers: Arc<[HeaderName]>,
}

impl SetSensitiveResponseHeadersLayer {
    /// Create a new [`SetSensitiveResponseHeadersLayer`].
    pub fn new<I>(headers: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        let headers = headers.into_iter().collect::<Vec<_>>();
        Self::from_shared(headers.into())
    }

    /// Create a new [`SetSensitiveResponseHeadersLayer`] from a shared slice of headers.
    pub fn from_shared(headers: Arc<[HeaderName]>) -> Self {
        Self { headers }
    }
}

impl<S> Layer<S> for SetSensitiveResponseHeadersLayer {
    type Service = SetSensitiveResponseHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetSensitiveResponseHeaders {
            inner,
            headers: self.headers.clone(),
        }
    }
}

/// Mark response headers as [sensitive].
///
/// See the [module docs](crate::http::layer::sensitive_headers) for more details.
///
/// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
#[derive(Clone, Debug)]
pub struct SetSensitiveResponseHeaders<S> {
    inner: S,
    headers: Arc<[HeaderName]>,
}

impl<S> SetSensitiveResponseHeaders<S> {
    /// Create a new [`SetSensitiveResponseHeaders`].
    pub fn new<I>(inner: S, headers: I) -> Self
    where
        I: IntoIterator<Item = HeaderName>,
    {
        let headers = headers.into_iter().collect::<Vec<_>>();
        Self::from_shared(inner, headers.into())
    }

    /// Create a new [`SetSensitiveResponseHeaders`] from a shared slice of headers.
    pub fn from_shared(inner: S, headers: Arc<[HeaderName]>) -> Self {
        Self { inner, headers }
    }

    define_inner_service_accessors!();

    /// Returns a new [`Layer`] that wraps services with a `SetSensitiveResponseHeaders` middleware.
    ///
    /// [`Layer`]: crate::service::Layer
    pub fn layer<I>(headers: I) -> SetSensitiveResponseHeadersLayer
    where
        I: IntoIterator<Item = HeaderName>,
    {
        SetSensitiveResponseHeadersLayer::new(headers)
    }
}

impl<ReqBody, ResBody, State, S> Service<State, Request<ReqBody>> for SetSensitiveResponseHeaders<S>
where
    State: Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let mut res = self.inner.serve(ctx, req).await?;

        let headers = res.headers_mut();
        for header in self.headers.iter() {
            if let http::header::Entry::Occupied(mut entry) = headers.entry(header) {
                for value in entry.iter_mut() {
                    value.set_sensitive(true);
                }
            }
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::header;
    use crate::service::ServiceBuilder;

    #[tokio::test]
    async fn multiple_value_header() {
        async fn response_set_cookie(req: http::Request<()>) -> Result<http::Response<()>, ()> {
            let mut iter = req.headers().get_all(header::COOKIE).iter().peekable();

            assert!(iter.peek().is_some());

            for value in iter {
                assert!(value.is_sensitive())
            }

            let mut resp = http::Response::new(());
            resp.headers_mut().append(
                header::CONTENT_TYPE,
                http::HeaderValue::from_static("text/html"),
            );
            resp.headers_mut().append(
                header::SET_COOKIE,
                http::HeaderValue::from_static("cookie-1"),
            );
            resp.headers_mut().append(
                header::SET_COOKIE,
                http::HeaderValue::from_static("cookie-2"),
            );
            resp.headers_mut().append(
                header::SET_COOKIE,
                http::HeaderValue::from_static("cookie-3"),
            );
            Ok(resp)
        }

        let service = ServiceBuilder::new()
            .layer(SetSensitiveRequestHeadersLayer::new(vec![header::COOKIE]))
            .layer(SetSensitiveResponseHeadersLayer::new(vec![
                header::SET_COOKIE,
            ]))
            .service_fn(response_set_cookie);

        let mut req = http::Request::new(());
        req.headers_mut()
            .append(header::COOKIE, http::HeaderValue::from_static("cookie+1"));
        req.headers_mut()
            .append(header::COOKIE, http::HeaderValue::from_static("cookie+2"));

        let resp = service.serve(Context::default(), req).await.unwrap();

        assert!(!resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .is_sensitive());

        let mut iter = resp.headers().get_all(header::SET_COOKIE).iter().peekable();

        assert!(iter.peek().is_some());

        for value in iter {
            assert!(value.is_sensitive())
        }
    }
}
