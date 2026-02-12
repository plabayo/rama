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
//! use rama_core::{Service, Layer};
//! use rama_core::error::BoxError;
//! use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let handler = service_fn(async |request: Request| {
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
//! ).into_layer(handler);
//!
//! let request = Request::new(Body::empty());
//! let response = svc.serve(request).await?;
//!
//! assert_eq!(response.headers()["x-request-id"], "0");
//! #
//! # Ok(())
//! # }
//! ```

use crate::{
    Request, Response,
    header::{HeaderName, HeaderValue},
};
use rama_core::{
    Layer, Service,
    extensions::{ExtensionsMut, ExtensionsRef},
    telemetry::tracing,
};
use rama_utils::macros::define_inner_service_accessors;
use rama_utils::str::smol_str::ToSmolStr as _;

use rand::RngExt as _;
use uuid::Uuid;

/// cfr: <https://www.rfc-editor.org/rfc/rfc6648>
pub(crate) const REQUEST_ID: HeaderName = HeaderName::from_static("request-id");

pub(crate) const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

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
#[derive(Debug, Clone)]
pub struct SetRequestIdLayer<M> {
    header_name: HeaderName,
    make_request_id: M,
}

impl<M> SetRequestIdLayer<M> {
    /// Create a new `SetRequestIdLayer`.
    pub const fn new(header_name: HeaderName, make_request_id: M) -> Self
    where
        M: MakeRequestId,
    {
        Self {
            header_name,
            make_request_id,
        }
    }

    /// Create a new `SetRequestIdLayer` that uses `request-id` as the header name.
    pub const fn request_id(make_request_id: M) -> Self
    where
        M: MakeRequestId,
    {
        Self::new(REQUEST_ID, make_request_id)
    }

    /// Create a new `SetRequestIdLayer` that uses `x-request-id` as the header name.
    pub const fn x_request_id(make_request_id: M) -> Self
    where
        M: MakeRequestId,
    {
        Self::new(X_REQUEST_ID, make_request_id)
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

    fn into_layer(self, inner: S) -> Self::Service {
        SetRequestId::new(inner, self.header_name, self.make_request_id)
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
#[derive(Debug, Clone)]
pub struct SetRequestId<S, M> {
    inner: S,
    header_name: HeaderName,
    make_request_id: M,
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

    /// Create a new `SetRequestId` that uses `request-id` as the header name.
    pub const fn request_id(inner: S, make_request_id: M) -> Self
    where
        M: MakeRequestId,
    {
        Self::new(inner, REQUEST_ID, make_request_id)
    }

    /// Create a new `SetRequestId` that uses `x-request-id` as the header name.
    pub const fn x_request_id(inner: S, make_request_id: M) -> Self
    where
        M: MakeRequestId,
    {
        Self::new(inner, X_REQUEST_ID, make_request_id)
    }

    define_inner_service_accessors!();
}

impl<S, M, ReqBody, ResBody> Service<Request<ReqBody>> for SetRequestId<S, M>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    M: MakeRequestId,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
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

        self.inner.serve(req).await
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
        Self { header_name }
    }

    /// Create a new `PropagateRequestIdLayer` that uses `request-id` as the header name.
    pub const fn request_id() -> Self {
        Self::new(REQUEST_ID)
    }

    /// Create a new `PropagateRequestIdLayer` that uses `x-request-id` as the header name.
    pub const fn x_request_id() -> Self {
        Self::new(X_REQUEST_ID)
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
#[derive(Debug, Clone)]
pub struct PropagateRequestId<S> {
    inner: S,
    header_name: HeaderName,
}

impl<S> PropagateRequestId<S> {
    /// Create a new `PropagateRequestId`.
    pub const fn new(inner: S, header_name: HeaderName) -> Self {
        Self { inner, header_name }
    }

    /// Create a new `PropagateRequestId` that uses `request-id` as the header name.
    pub const fn request_id(inner: S) -> Self {
        Self::new(inner, REQUEST_ID)
    }

    /// Create a new `PropagateRequestId` that uses `x-request-id` as the header name.
    pub const fn x_request_id(inner: S) -> Self {
        Self::new(inner, X_REQUEST_ID)
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for PropagateRequestId<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let request_id = req
            .headers()
            .get(&self.header_name)
            .cloned()
            .map(RequestId::new);

        let mut response = self.inner.serve(req).await?;

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
        let request_id = Uuid::new_v4()
            .to_smolstr()
            .parse()
            .inspect_err(|err| {
                tracing::debug!("failed to parse UUID4 as RequestId: {err}");
            })
            .ok()?;
        Some(RequestId::new(request_id))
    }
}

/// A [`MakeRequestId`] that generates `NanoID`s.
#[derive(Debug, Clone, Copy, Default)]
pub struct MakeRequestNanoid;

impl MakeRequestId for MakeRequestNanoid {
    fn make_request_id<B>(&self, _request: &Request<B>) -> Option<RequestId> {
        let request_id = make_nano_id();
        Some(RequestId::new(request_id))
    }
}

fn make_nano_id() -> HeaderValue {
    const ALPHABET_LEN: usize = 64;
    const ALPHABET: [u8; ALPHABET_LEN] = [
        b'_', b'-', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c',
        b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p', b'q', b'r',
        b's', b't', b'u', b'v', b'w', b'x', b'y', b'z', b'A', b'B', b'C', b'D', b'E', b'F', b'G',
        b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V',
        b'W', b'X', b'Y', b'Z',
    ];
    const ID_LEN: usize = 21;
    const STEP: usize = 8 * ID_LEN / 5;
    const MASK: usize = (ALPHABET_LEN * 2) - 1;

    let mut id = [0u8; ID_LEN];

    let input: [u8; STEP] = rand::rng().random();

    let mut index = 0;
    loop {
        for byte in input {
            let byte = byte as usize & MASK;

            if ALPHABET_LEN > byte {
                id[index] = ALPHABET[byte];
                index += 1;
                if index == ID_LEN {
                    return unsafe { HeaderValue::from_maybe_shared_unchecked(id) };
                }
            }
        }
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
            .into_layer(service_fn(handler));

        // header on response
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.headers()["x-request-id"], "0");

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.headers()["x-request-id"], "1");

        // doesn't override if header is already there
        let req = Request::builder()
            .header("x-request-id", "foo")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.headers()["x-request-id"], "foo");

        // extension propagated
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.extensions().get::<RequestId>().unwrap().0, "2");
    }

    #[tokio::test]
    async fn basic_with_request_id() {
        let svc = (
            SetRequestIdLayer::request_id(Counter::default()),
            PropagateRequestIdLayer::request_id(),
        )
            .into_layer(service_fn(handler));

        // header on response
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.headers()["request-id"], "0");

        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.headers()["request-id"], "1");

        // doesn't override if header is already there
        let req = Request::builder()
            .header("request-id", "foo")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.headers()["request-id"], "foo");

        // extension propagated
        let req = Request::builder().body(Body::empty()).unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.extensions().get::<RequestId>().unwrap().0, "2");
    }

    #[tokio::test]
    async fn other_middleware_setting_request_id_on_response() {
        let svc = (
            SetRequestIdLayer::x_request_id(Counter::default()),
            PropagateRequestIdLayer::x_request_id(),
            set_header::SetResponseHeaderLayer::overriding(
                HeaderName::from_static("x-request-id"),
                HeaderValue::from_static("foo"),
            ),
        )
            .into_layer(service_fn(handler));

        let req = Request::builder()
            .header("x-request-id", "foo")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
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
            .into_layer(service_fn(handler));

        // header on response
        let req = Request::builder().body(Body::empty()).unwrap();
        let mut res = svc.serve(req).await.unwrap();
        let id = res.headers_mut().remove("x-request-id").unwrap();
        id.to_str().unwrap().parse::<Uuid>().unwrap();
    }

    #[tokio::test]
    async fn nanoid() {
        let svc = (
            SetRequestIdLayer::x_request_id(MakeRequestNanoid),
            PropagateRequestIdLayer::x_request_id(),
        )
            .into_layer(service_fn(handler));

        // header on response
        let req = Request::builder().body(Body::empty()).unwrap();
        let mut res = svc.serve(req).await.unwrap();
        let id = res.headers_mut().remove("x-request-id").unwrap();
        assert_eq!(id.to_str().unwrap().chars().count(), 21);
    }
}
