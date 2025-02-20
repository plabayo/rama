//! Set and propagate request ids.
//!
//! # Example
//!
//! ```
//! use rama_http::layer::request_id::{
//!     SetRequestIdLayer, PropagateRequestIdLayer, MakeRequestId, RequestId,
//! };
//! use rama_http::{Body, Request, Response, header::HeaderName};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//! use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let handler = service_fn(|request: Request| async move {
//! #     Ok::<_, std::convert::Infallible>(Response::new(request.into_body()))
//! # });
//! #
//! // A `MakeRequestId` that increments an atomic counter
//! #[derive(Clone, Default)]
//! struct MyMakeRequestId {
//!     counter: Arc<AtomicU64>,
//! }
//!
//! impl MakeRequestId for MyMakeRequestId {
//!     fn make_request_id<B>(&self, request: &Request<B>) -> Option<RequestId> {
//!         let request_id = self.counter
//!             .fetch_add(1, Ordering::AcqRel)
//!             .to_string()
//!             .parse()
//!             .unwrap();
//!
//!         Some(RequestId::new(request_id))
//!     }
//! }
//!
//! let x_request_id = HeaderName::from_static("x-request-id");
//!
//! let mut svc = (
//!     // set `x-request-id` header on all requests
//!     SetRequestIdLayer::new(
//!         x_request_id.clone(),
//!         MyMakeRequestId::default(),
//!     ),
//!     // propagate `x-request-id` headers from request to response
//!     PropagateRequestIdLayer::new(x_request_id),
//! ).layer(handler);
//!
//! let request = Request::new(Body::empty());
//! let response = svc.serve(Context::default(), request).await?;
//!
//! assert_eq!(response.headers()["x-request-id"], "0");
//! #
//! # Ok(())
//! # }
//! ```

use std::fmt;

use crate::{
    Request, Response,
    header::{HeaderName, HeaderValue},
};
use nanoid::nanoid;
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use uuid::Uuid;

pub(crate) const X_REQUEST_ID: &str = "x-request-id";

/// Trait for producing [`RequestId`]s.
///
/// Used by [`SetRequestId`].
pub trait MakeRequestId: Send + Sync + 'static {
    /// Try and produce a [`RequestId`] from the request.
    fn make_request_id<B>(&self, request: &Request<B>) -> Option<RequestId>;
}

/// An identifier for a request.
#[derive(Debug, Clone)]
pub struct RequestId(HeaderValue);

impl RequestId {
    /// Create a new `RequestId` from a [`HeaderValue`].
    pub const fn new(header_value: HeaderValue) -> Self {
        Self(header_value)
    }

    /// Gets a reference to the underlying [`HeaderValue`].
    pub fn header_value(&self) -> &HeaderValue {
        &self.0
    }

    /// Consumes `self`, returning the underlying [`HeaderValue`].
    pub fn into_header_value(self) -> HeaderValue {
        self.0
    }
}

impl From<HeaderValue> for RequestId {
    fn from(value: HeaderValue) -> Self {
        Self::new(value)
    }
}

/// Set request id headers and extensions on requests.
///
/// This layer applies the [`SetRequestId`] middleware.
///
/// See the [module docs](self) and [`SetRequestId`] for more details.
pub struct SetRequestIdLayer<M> {
    header_name: HeaderName,
    make_request_id: M,
}

impl<M: fmt::Debug> fmt::Debug for SetRequestIdLayer<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SetRequestIdLayer")
            .field("header_name", &self.header_name)
            .field("make_request_id", &self.make_request_id)
            .finish()
    }
}

impl<M: Clone> Clone for SetRequestIdLayer<M> {
    fn clone(&self) -> Self {
        Self {
            header_name: self.header_name.clone(),
            make_request_id: self.make_request_id.clone(),
        }
    }
}

impl<M> SetRequestIdLayer<M> {
    /// Create a new `SetRequestIdLayer`.
    pub const fn new(header_name: HeaderName, make_request_id: M) -> Self
    where
        M: MakeRequestId,
    {
        SetRequestIdLayer {
            header_name,
            make_request_id,
        }
    }

    /// Create a new `SetRequestIdLayer` that uses `x-request-id` as the header name.
    pub const fn x_request_id(make_request_id: M) -> Self
    where
        M: MakeRequestId,
    {
        SetRequestIdLayer::new(HeaderName::from_static(X_REQUEST_ID), make_request_id)
    }
}

impl<S, M> Layer<S> for SetRequestIdLayer<M>
where
    M: Clone + MakeRequestId,
{
    type Service = SetRequestId<S, M>;

    fn layer(&self, inner: S) -> Self::Service {
        SetRequestId::new(
            inner,
            self.header_name.clone(),
            self.make_request_id.clone(),
        )
    }
}

/// Set request id headers and extensions on requests.
///
/// See the [module docs](self) for an example.
///
/// If [`MakeRequestId::make_request_id`] returns `Some(_)` and the request doesn't already have a
/// header with the same name, then the header will be inserted.
///
/// Additionally [`RequestId`] will be inserted into [`Request::extensions`] so other
/// services can access it.
pub struct SetRequestId<S, M> {
    inner: S,
    header_name: HeaderName,
    make_request_id: M,
}

impl<S: fmt::Debug, M: fmt::Debug> fmt::Debug for SetRequestId<S, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRequestId")
            .field("inner", &self.inner)
            .field("header_name", &self.header_name)
            .field("make_request_id", &self.make_request_id)
            .finish()
    }
}

impl<S: Clone, M: Clone> Clone for SetRequestId<S, M> {
    fn clone(&self) -> Self {
        SetRequestId {
            inner: self.inner.clone(),
            header_name: self.header_name.clone(),
            make_request_id: self.make_request_id.clone(),
        }
    }
}

impl<S, M> SetRequestId<S, M> {
    /// Create a new `SetRequestId`.
    pub const fn new(inner: S, header_name: HeaderName, make_request_id: M) -> Self
    where
        M: MakeRequestId,
    {
        Self {
            inner,
            header_name,
            make_request_id,
        }
    }

    /// Create a new `SetRequestId` that uses `x-request-id` as the header name.
    pub const fn x_request_id(inner: S, make_request_id: M) -> Self
    where
        M: MakeRequestId,
    {
        Self::new(
            inner,
            HeaderName::from_static(X_REQUEST_ID),
            make_request_id,
        )
    }

    define_inner_service_accessors!();
}

impl<State, S, M, ReqBody, ResBody> Service<State, Request<ReqBody>> for SetRequestId<S, M>
where
    State: Clone + Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    M: MakeRequestId,
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
        if let Some(request_id) = req.headers().get(&self.header_name) {
            if req.extensions().get::<RequestId>().is_none() {
                let request_id = request_id.clone();
                req.extensions_mut().insert(RequestId::new(request_id));
            }
        } else if let Some(request_id) = self.make_request_id.make_request_id(&req) {
            req.extensions_mut().insert(request_id.clone());
            req.headers_mut()
                .insert(self.header_name.clone(), request_id.0);
        }

        self.inner.serve(ctx, req).await
    }
}

/// Propagate request ids from requests to responses.
///
/// This layer applies the [`PropagateRequestId`] middleware.
///
/// See the [module docs](self) and [`PropagateRequestId`] for more details.
#[derive(Debug, Clone)]
pub struct PropagateRequestIdLayer {
    header_name: HeaderName,
}

impl PropagateRequestIdLayer {
    /// Create a new `PropagateRequestIdLayer`.
    pub const fn new(header_name: HeaderName) -> Self {
        PropagateRequestIdLayer { header_name }
    }

    /// Create a new `PropagateRequestIdLayer` that uses `x-request-id` as the header name.
    pub const fn x_request_id() -> Self {
        Self::new(HeaderName::from_static(X_REQUEST_ID))
    }
}

impl<S> Layer<S> for PropagateRequestIdLayer {
    type Service = PropagateRequestId<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PropagateRequestId::new(inner, self.header_name.clone())
    }
}

/// Propagate request ids from requests to responses.
///
/// See the [module docs](self) for an example.
///
/// If the request contains a matching header that header will be applied to responses. If a
/// [`RequestId`] extension is also present it will be propagated as well.
pub struct PropagateRequestId<S> {
    inner: S,
    header_name: HeaderName,
}

impl<S> PropagateRequestId<S> {
    /// Create a new `PropagateRequestId`.
    pub const fn new(inner: S, header_name: HeaderName) -> Self {
        Self { inner, header_name }
    }

    /// Create a new `PropagateRequestId` that uses `x-request-id` as the header name.
    pub const fn x_request_id(inner: S) -> Self {
        Self::new(inner, HeaderName::from_static(X_REQUEST_ID))
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug> fmt::Debug for PropagateRequestId<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PropagateRequestId")
            .field("inner", &self.inner)
            .field("header_name", &self.header_name)
            .finish()
    }
}

impl<S: Clone> Clone for PropagateRequestId<S> {
    fn clone(&self) -> Self {
        PropagateRequestId {
            inner: self.inner.clone(),
            header_name: self.header_name.clone(),
        }
    }
}

impl<State, S, ReqBody, ResBody> Service<State, Request<ReqBody>> for PropagateRequestId<S>
where
    State: Clone + Send + Sync + 'static,
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
        let request_id = req
            .headers()
            .get(&self.header_name)
            .cloned()
            .map(RequestId::new);

        let mut response = self.inner.serve(ctx, req).await?;

        if let Some(current_id) = response.headers().get(&self.header_name) {
            if response.extensions().get::<RequestId>().is_none() {
                let current_id = current_id.clone();
                response.extensions_mut().insert(RequestId::new(current_id));
            }
        } else if let Some(request_id) = request_id {
            response
                .headers_mut()
                .insert(self.header_name.clone(), request_id.0.clone());
            response.extensions_mut().insert(request_id);
        }

        Ok(response)
    }
}

/// A [`MakeRequestId`] that generates `UUID`s.
#[derive(Debug, Clone, Copy, Default)]
pub struct MakeRequestUuid;

impl MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&self, _request: &Request<B>) -> Option<RequestId> {
        let request_id = Uuid::new_v4().to_string().parse().unwrap();
        Some(RequestId::new(request_id))
    }
}

/// A [`MakeRequestId`] that generates `NanoID`s.
#[derive(Debug, Clone, Copy, Default)]
pub struct MakeRequestNanoid;

impl MakeRequestId for MakeRequestNanoid {
    fn make_request_id<B>(&self, _request: &Request<B>) -> Option<RequestId> {
        let request_id = nanoid!().parse().unwrap();
        Some(RequestId::new(request_id))
    }
}

#[cfg(test)]
mod tests {
    use crate::layer::set_header;
    use crate::{Body, Response};
    use rama_core::Layer;
    use rama_core::service::service_fn;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    #[allow(unused_imports)]
    use super::*;

    #[tokio::test]
    async fn basic() {
        let svc = (
            SetRequestIdLayer::x_request_id(Counter::default()),
            PropagateRequestIdLayer::x_request_id(),
        )
            .layer(service_fn(handler));

        // header on response
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.headers()["x-request-id"], "0");

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.headers()["x-request-id"], "1");

        // doesn't override if header is already there
        let req = Request::builder()
            .header("x-request-id", "foo")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.headers()["x-request-id"], "foo");

        // extension propagated
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.extensions().get::<RequestId>().unwrap().0, "2");
    }

    #[tokio::test]
    async fn other_middleware_setting_request_id_on_response() {
        let svc = (
            SetRequestIdLayer::x_request_id(Counter::default()),
            PropagateRequestIdLayer::x_request_id(),
            set_header::SetResponseHeaderLayer::overriding(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_str("foo").unwrap(),
            ),
        )
            .layer(service_fn(handler));

        let req = Request::builder()
            .header("x-request-id", "foo")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(res.headers()["x-request-id"], "foo");
        assert_eq!(res.extensions().get::<RequestId>().unwrap().0, "foo");
    }

    #[derive(Clone, Default)]
    struct Counter(Arc<AtomicU64>);

    impl MakeRequestId for Counter {
        fn make_request_id<B>(&self, _request: &Request<B>) -> Option<RequestId> {
            let id =
                HeaderValue::from_str(&self.0.fetch_add(1, Ordering::AcqRel).to_string()).unwrap();
            Some(RequestId::new(id))
        }
    }

    async fn handler(_: Request<Body>) -> Result<Response<Body>, Infallible> {
        Ok(Response::new(Body::empty()))
    }

    #[tokio::test]
    async fn uuid() {
        let svc = (
            SetRequestIdLayer::x_request_id(MakeRequestUuid),
            PropagateRequestIdLayer::x_request_id(),
        )
            .layer(service_fn(handler));

        // header on response
        let req = Request::builder().body(Body::empty()).unwrap();
        let mut res = svc.serve(Context::default(), req).await.unwrap();
        let id = res.headers_mut().remove("x-request-id").unwrap();
        id.to_str().unwrap().parse::<Uuid>().unwrap();
    }

    #[tokio::test]
    async fn nanoid() {
        let svc = (
            SetRequestIdLayer::x_request_id(MakeRequestNanoid),
            PropagateRequestIdLayer::x_request_id(),
        )
            .layer(service_fn(handler));

        // header on response
        let req = Request::builder().body(Body::empty()).unwrap();
        let mut res = svc.serve(Context::default(), req).await.unwrap();
        let id = res.headers_mut().remove("x-request-id").unwrap();
        assert_eq!(id.to_str().unwrap().chars().count(), 21);
    }
}
