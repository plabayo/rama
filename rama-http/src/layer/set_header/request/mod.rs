//! Set a header on the request.
//!
//! The header value to be set may be provided as a fixed value when the
//! middleware is constructed, or determined dynamically based on the request
//! by a closure. See the [`MakeHeaderValue`] trait for details.
//!
//! # Example
//!
//! Setting a header from a fixed value provided when the middleware is constructed:
//!
//! ```
//! use rama_http::layer::set_header::SetRequestHeaderLayer;
//! use rama_http::{Body, Request, Response, header::{self, HeaderValue}};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let http_client = service_fn(async |_: Request| {
//! #     Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
//! # });
//! #
//! let mut svc = (
//!     // Layer that sets `User-Agent: my very cool proxy` on requests.
//!     //
//!     // `if_not_present` will only insert the header if it does not already
//!     // have a value.
//!     SetRequestHeaderLayer::if_not_present(
//!         header::USER_AGENT,
//!         HeaderValue::from_static("my very cool proxy"),
//!     ),
//! ).into_layer(http_client);
//!
//! let request = Request::new(Body::empty());
//!
//! let response = svc.serve(Context::default(), request).await?;
//! #
//! # Ok(())
//! # }
//! ```
//!
//! Setting a header based on a value determined dynamically from the request:
//!
//! ```
//! use rama_http::{Body, Request, Response, header::{self, HeaderValue}};
//! use rama_http::layer::set_header::SetRequestHeaderLayer;
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let http_client = service_fn(async || {
//! #     Ok::<_, std::convert::Infallible>(Response::new(Body::empty()))
//! # });
//! fn date_header_value() -> HeaderValue {
//!     // ...
//!     # HeaderValue::from_static("now")
//! }
//!
//! let mut svc = (
//!     // Layer that sets `Date` to the current date and time.
//!     //
//!     // `overriding` will insert the header and override any previous values it
//!     // may have.
//!     SetRequestHeaderLayer::overriding_fn(
//!         header::DATE,
//!         async || {
//!             Some(date_header_value())
//!         }
//!     ),
//! ).into_layer(http_client);
//!
//! let request = Request::new(Body::default());
//!
//! let response = svc.serve(Context::default(), request).await?;
//! #
//! # Ok(())
//! # }
//! ```

use crate::{HeaderValue, Request, Response, header::HeaderName, headers::HeaderEncode};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

mod header;
use header::InsertHeaderMode;

pub use header::{BoxMakeHeaderValueFn, MakeHeaderValue};

/// Layer that applies [`SetRequestHeader`] which adds a request header.
///
/// See [`SetRequestHeader`] for more details.
pub struct SetRequestHeaderLayer<M> {
    header_name: HeaderName,
    make: M,
    mode: InsertHeaderMode,
}

impl<M> fmt::Debug for SetRequestHeaderLayer<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRequestHeaderLayer")
            .field("header_name", &self.header_name)
            .field("mode", &self.mode)
            .field("make", &std::any::type_name::<M>())
            .finish()
    }
}

impl<M> SetRequestHeaderLayer<M> {
    /// Create a new [`SetRequestHeaderLayer`].
    ///
    /// If a previous value exists for the same header, it is removed and replaced with the new
    /// header value.
    pub fn overriding(header_name: HeaderName, make: M) -> Self {
        Self::new(header_name, make, InsertHeaderMode::Override)
    }

    /// Create a new [`SetRequestHeaderLayer`].
    ///
    /// The new header is always added, preserving any existing values. If previous values exist,
    /// the header will have multiple values.
    pub fn appending(header_name: HeaderName, make: M) -> Self {
        Self::new(header_name, make, InsertHeaderMode::Append)
    }

    /// Create a new [`SetRequestHeaderLayer`].
    ///
    /// If a previous value exists for the header, the new value is not inserted.
    pub fn if_not_present(header_name: HeaderName, make: M) -> Self {
        Self::new(header_name, make, InsertHeaderMode::IfNotPresent)
    }

    fn new(header_name: HeaderName, make: M, mode: InsertHeaderMode) -> Self {
        Self {
            make,
            header_name,
            mode,
        }
    }
}

impl SetRequestHeaderLayer<HeaderValue> {
    /// Create a new [`SetRequestHeaderLayer`] from a typed [`HeaderEncode`].
    ///
    /// See [`SetRequestHeaderLayer::overriding`] for more details.
    pub fn overriding_typed<H: HeaderEncode>(header: H) -> Self {
        Self::overriding(H::name().clone(), header.encode_to_value())
    }

    /// Create a new [`SetRequestHeaderLayer`] from a typed [`HeaderEncode`].
    ///
    /// See [`SetRequestHeaderLayer::appending`] for more details.
    pub fn appending_typed<H: HeaderEncode>(header: H) -> Self {
        Self::appending(H::name().clone(), header.encode_to_value())
    }

    /// Create a new [`SetRequestHeaderLayer`] from a typed [`HeaderEncode`].
    ///
    /// See [`SetRequestHeaderLayer::if_not_present`] for more details.
    pub fn if_not_present_typed<H: HeaderEncode>(header: H) -> Self {
        Self::if_not_present(H::name().clone(), header.encode_to_value())
    }
}

impl<F, A> SetRequestHeaderLayer<BoxMakeHeaderValueFn<F, A>> {
    /// Create a new [`SetRequestHeaderLayer`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetRequestHeaderLayer::overriding`] for more details.
    pub fn overriding_fn(header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            header_name,
            BoxMakeHeaderValueFn::new(make_fn),
            InsertHeaderMode::Override,
        )
    }

    /// Create a new [`SetRequestHeaderLayer`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetRequestHeaderLayer::appending`] for more details.
    pub fn appending_fn(header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            header_name,
            BoxMakeHeaderValueFn::new(make_fn),
            InsertHeaderMode::Append,
        )
    }

    /// Create a new [`SetRequestHeaderLayer`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetRequestHeaderLayer::if_not_present`] for more details.
    pub fn if_not_present_fn(header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            header_name,
            BoxMakeHeaderValueFn::new(make_fn),
            InsertHeaderMode::IfNotPresent,
        )
    }
}

impl<S, M> Layer<S> for SetRequestHeaderLayer<M>
where
    M: Clone,
{
    type Service = SetRequestHeader<S, M>;

    fn layer(&self, inner: S) -> Self::Service {
        SetRequestHeader {
            inner,
            header_name: self.header_name.clone(),
            make: self.make.clone(),
            mode: self.mode,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        SetRequestHeader {
            inner,
            header_name: self.header_name,
            make: self.make,
            mode: self.mode,
        }
    }
}

impl<M> Clone for SetRequestHeaderLayer<M>
where
    M: Clone,
{
    fn clone(&self) -> Self {
        Self {
            make: self.make.clone(),
            header_name: self.header_name.clone(),
            mode: self.mode,
        }
    }
}

/// Middleware that sets a header on the request.
#[derive(Clone)]
pub struct SetRequestHeader<S, M> {
    inner: S,
    header_name: HeaderName,
    make: M,
    mode: InsertHeaderMode,
}

impl<S, M> SetRequestHeader<S, M> {
    /// Create a new [`SetRequestHeader`].
    ///
    /// If a previous value exists for the same header, it is removed and replaced with the new
    /// header value.
    pub fn overriding(inner: S, header_name: HeaderName, make: M) -> Self {
        Self::new(inner, header_name, make, InsertHeaderMode::Override)
    }

    /// Create a new [`SetRequestHeader`].
    ///
    /// The new header is always added, preserving any existing values. If previous values exist,
    /// the header will have multiple values.
    pub fn appending(inner: S, header_name: HeaderName, make: M) -> Self {
        Self::new(inner, header_name, make, InsertHeaderMode::Append)
    }

    /// Create a new [`SetRequestHeader`].
    ///
    /// If a previous value exists for the header, the new value is not inserted.
    pub fn if_not_present(inner: S, header_name: HeaderName, make: M) -> Self {
        Self::new(inner, header_name, make, InsertHeaderMode::IfNotPresent)
    }

    fn new(inner: S, header_name: HeaderName, make: M, mode: InsertHeaderMode) -> Self {
        Self {
            inner,
            header_name,
            make,
            mode,
        }
    }

    define_inner_service_accessors!();
}

impl<S, F, A> SetRequestHeader<S, BoxMakeHeaderValueFn<F, A>> {
    /// Create a new [`SetRequestHeader`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetRequestHeader::overriding`] for more details.
    pub fn overriding_fn(inner: S, header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            inner,
            header_name,
            BoxMakeHeaderValueFn::new(make_fn),
            InsertHeaderMode::Override,
        )
    }

    /// Create a new [`SetRequestHeader`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetRequestHeader::appending`] for more details.
    pub fn appending_fn(inner: S, header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            inner,
            header_name,
            BoxMakeHeaderValueFn::new(make_fn),
            InsertHeaderMode::Append,
        )
    }

    /// Create a new [`SetRequestHeader`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetRequestHeader::if_not_present`] for more details.
    pub fn if_not_present_fn(inner: S, header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            inner,
            header_name,
            BoxMakeHeaderValueFn::new(make_fn),
            InsertHeaderMode::IfNotPresent,
        )
    }
}

impl<S, M> fmt::Debug for SetRequestHeader<S, M>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetRequestHeader")
            .field("inner", &self.inner)
            .field("header_name", &self.header_name)
            .field("mode", &self.mode)
            .field("make", &std::any::type_name::<M>())
            .finish()
    }
}

impl<ReqBody, ResBody, State, S, M> Service<State, Request<ReqBody>> for SetRequestHeader<S, M>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    State: Clone + Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    M: MakeHeaderValue<State, ReqBody>,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = self
            .mode
            .apply(&self.header_name, ctx, req, &self.make)
            .await;
        self.inner.serve(ctx, req).await
    }
}
