//! Middlewares that mark headers as [sensitive].
//!
//! [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
//!
//! # Example
//!
//! ```
//! use rama_http::layer::sensitive_headers::SetSensitiveHeadersLayer;
//! use rama_http::{Body, Request, Response, header::AUTHORIZATION};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//! use std::{iter::once, convert::Infallible};
//!
//! async fn handle(req: Request) -> Result<Response, Infallible> {
//!     // ...
//!     # Ok(Response::new(Body::empty()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let mut service = (
//!     // Mark the `Authorization` header as sensitive so it doesn't show in logs
//!     //
//!     // `SetSensitiveHeadersLayer` will mark the header as sensitive on both the
//!     // request and response.
//!     //
//!     // The middleware is constructed from an iterator of headers to easily mark
//!     // multiple headers at once.
//!     SetSensitiveHeadersLayer::new(once(AUTHORIZATION)),
//! ).into_layer(service_fn(handle));
//!
//! // Call the service.
//! let response = service
//!     .serve(Context::default(), Request::new(Body::empty()))
//!     .await?;
//! # Ok(())
//! # }
//! ```

use crate::{HeaderName, Request, Response, header};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::sync::Arc;

/// Mark headers as [sensitive] on both requests and responses.
///
/// Produces [`SetSensitiveHeaders`] services.
///
/// See the [module docs](crate::layer::sensitive_headers) for more details.
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

    fn into_layer(self, inner: S) -> Self::Service {
        SetSensitiveRequestHeaders::from_shared(
            SetSensitiveResponseHeaders::from_shared(inner, self.headers.clone()),
            self.headers,
        )
    }
}

/// Mark headers as [sensitive] on both requests and responses.
///
/// See the [module docs](crate::layer::sensitive_headers) for more details.
///
/// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
pub type SetSensitiveHeaders<S> = SetSensitiveRequestHeaders<SetSensitiveResponseHeaders<S>>;

/// Mark request headers as [sensitive].
///
/// Produces [`SetSensitiveRequestHeaders`] services.
///
/// See the [module docs](crate::layer::sensitive_headers) for more details.
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

    fn into_layer(self, inner: S) -> Self::Service {
        SetSensitiveRequestHeaders {
            inner,
            headers: self.headers,
        }
    }
}

/// Mark request headers as [sensitive].
///
/// See the [module docs](crate::layer::sensitive_headers) for more details.
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
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for SetSensitiveRequestHeaders<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let headers = req.headers_mut();
        for header in &*self.headers {
            if let header::Entry::Occupied(mut entry) = headers.entry(header) {
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
/// See the [module docs](crate::layer::sensitive_headers) for more details.
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

    fn into_layer(self, inner: S) -> Self::Service {
        SetSensitiveResponseHeaders {
            inner,
            headers: self.headers,
        }
    }
}

/// Mark response headers as [sensitive].
///
/// See the [module docs](crate::layer::sensitive_headers) for more details.
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
}

impl<ReqBody, ResBody, S> Service<Request<ReqBody>> for SetSensitiveResponseHeaders<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let mut res = self.inner.serve(ctx, req).await?;

        let headers = res.headers_mut();
        for header in self.headers.iter() {
            if let header::Entry::Occupied(mut entry) = headers.entry(header) {
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
    use crate::{HeaderValue, Request, Response, header};
    use rama_core::service::service_fn;

    #[tokio::test]
    async fn multiple_value_header() {
        async fn response_set_cookie(req: Request<()>) -> Result<Response<()>, ()> {
            let mut iter = req.headers().get_all(header::COOKIE).iter().peekable();

            assert!(iter.peek().is_some());

            for value in iter {
                assert!(value.is_sensitive())
            }

            let mut resp = Response::new(());
            resp.headers_mut()
                .append(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
            resp.headers_mut()
                .append(header::SET_COOKIE, HeaderValue::from_static("cookie-1"));
            resp.headers_mut()
                .append(header::SET_COOKIE, HeaderValue::from_static("cookie-2"));
            resp.headers_mut()
                .append(header::SET_COOKIE, HeaderValue::from_static("cookie-3"));
            Ok(resp)
        }

        let service = (
            SetSensitiveRequestHeadersLayer::new(vec![header::COOKIE]),
            SetSensitiveResponseHeadersLayer::new(vec![header::SET_COOKIE]),
        )
            .into_layer(service_fn(response_set_cookie));

        let mut req = Request::new(());
        req.headers_mut()
            .append(header::COOKIE, HeaderValue::from_static("cookie+1"));
        req.headers_mut()
            .append(header::COOKIE, HeaderValue::from_static("cookie+2"));

        let resp = service.serve(Context::default(), req).await.unwrap();

        assert!(
            !resp
                .headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .is_sensitive()
        );

        let mut iter = resp.headers().get_all(header::SET_COOKIE).iter().peekable();

        assert!(iter.peek().is_some());

        for value in iter {
            assert!(value.is_sensitive())
        }
    }
}
