//! Set a header on the response.
//!
//! The header value to be set may be provided as a fixed value when the
//! middleware is constructed, or determined dynamically based on the response
//! by a closure. See the [`MakeHeaderValue`] trait for details.
//!
//! # Example
//!
//! Setting a header from a fixed value provided when the middleware is constructed:
//!
//! ```
//! use rama_http::layer::set_header::SetResponseHeaderLayer;
//! use rama_http::{Body, Request, Response, header::{self, HeaderValue}};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let render_html = service_fn(async |request: Request| {
//! #     Ok::<_, std::convert::Infallible>(Response::new(request.into_body()))
//! # });
//! #
//! let mut svc = (
//!     // Layer that sets `Content-Type: text/html` on responses.
//!     //
//!     // `if_not_present` will only insert the header if it does not already
//!     // have a value.
//!     SetResponseHeaderLayer::if_not_present(
//!         header::CONTENT_TYPE,
//!         HeaderValue::from_static("text/html"),
//!     ),
//! ).into_layer(render_html);
//!
//! let request = Request::new(Body::empty());
//!
//! let response = svc.serve(Context::default(), request).await?;
//!
//! assert_eq!(response.headers()["content-type"], "text/html");
//! #
//! # Ok(())
//! # }
//! ```
//!
//! Setting a header based on a value determined dynamically from the response:
//!
//! ```
//! use rama_core::error::BoxError;
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Layer, Service};
//! use rama_http::dep::http_body::Body as _;
//! use rama_http::layer::set_header::SetResponseHeaderLayer;
//! use rama_http::{
//!     header::{self, HeaderValue},
//!     Body, Request, Response,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), BoxError> {
//!     let render_html = service_fn(async |_request: Request| {
//!         Ok::<_, std::convert::Infallible>(Response::new(Body::from("1234567890")))
//!     });
//!
//!     let svc = (
//!         // Layer that sets `Content-Length` if the body has a known size.
//!         // Bodies with streaming responses wont have a known size.
//!         //
//!         // `overriding` will insert the header and override any previous values it
//!         // may have.
//!         SetResponseHeaderLayer::overriding_fn(
//!             header::CONTENT_LENGTH,
//!             async |response: Response| {
//!                 let value = if let Some(size) = response.body().size_hint().exact() {
//!                     // If the response body has a known size, returning `Some` will
//!                     // set the `Content-Length` header to that value.
//!                     Some(HeaderValue::try_from(size.to_string()).unwrap())
//!                 } else {
//!                     // If the response body doesn't have a known size, return `None`
//!                     // to skip setting the header on this response.
//!                     None
//!                 };
//!                 (response, value)
//!             },
//!         ),
//!     )
//!         .into_layer(render_html);
//!
//!     let request = Request::new(Body::empty());
//!
//!     let response = svc.serve(Context::default(), request).await?;
//!
//!     assert_eq!(response.headers()["content-length"], "10");
//!
//!     Ok(())
//! }
//! ```
//!
//! Setting a header based on the incoming Context and response combined.
//!
//! ```
//! use rama_core::{service::service_fn, Context, Service};
//! use rama_http::{
//!     layer::set_header::{response::BoxMakeHeaderValueFn, SetResponseHeader},
//!     Body, HeaderName, HeaderValue, Request, Response,
//!     service::web::response::IntoResponse,
//! };
//! use std::convert::Infallible;
//!
//! #[tokio::main]
//! async fn main() {
//!     #[derive(Debug, Clone)]
//!     struct RequestID(String);
//!
//!     #[derive(Debug, Clone)]
//!     struct Success;
//!
//!     let svc = SetResponseHeader::overriding_fn(
//!         service_fn(async || {
//!             let mut res = ().into_response();
//!             res.extensions_mut().insert(Success);
//!             Ok::<_, Infallible>(res)
//!         }),
//!         HeaderName::from_static("x-used-request-id"),
//!         async |ctx: Context<()>| {
//!             let factory = ctx.get::<RequestID>().cloned().map(|id| {
//!                 BoxMakeHeaderValueFn::new(async move |res: Response| {
//!                     let header_value = res.extensions().get::<Success>().map(|_| {
//!                         HeaderValue::from_str(id.0.as_str()).unwrap()
//!                     });
//!                     (res, header_value)
//!                 })
//!             });
//!             (ctx, factory)
//!         },
//!     );
//!
//!     const FAKE_USER_ID: &str = "abc123";
//!
//!     let mut ctx = Context::default();
//!     ctx.insert(RequestID(FAKE_USER_ID.to_owned()));
//!
//!     let res = svc.serve(ctx, Request::new(Body::empty())).await.unwrap();
//!
//!     let mut values = res
//!         .headers()
//!         .get_all(HeaderName::from_static("x-used-request-id"))
//!         .iter();
//!     assert_eq!(values.next().unwrap(), FAKE_USER_ID);
//!     assert_eq!(values.next(), None);
//! }
//! ```

use crate::{HeaderValue, Request, Response, header::HeaderName, headers::Header};
use rama_core::{Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

mod header;
use header::InsertHeaderMode;

pub use header::{
    BoxMakeHeaderValueFactoryFn, BoxMakeHeaderValueFn, MakeHeaderValue, MakeHeaderValueFactory,
};

/// Layer that applies [`SetResponseHeader`] which adds a response header.
///
/// See [`SetResponseHeader`] for more details.
pub struct SetResponseHeaderLayer<M> {
    header_name: HeaderName,
    make: M,
    mode: InsertHeaderMode,
}

impl<M> fmt::Debug for SetResponseHeaderLayer<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetResponseHeaderLayer")
            .field("header_name", &self.header_name)
            .field("mode", &self.mode)
            .field("make", &std::any::type_name::<M>())
            .finish()
    }
}

impl SetResponseHeaderLayer<HeaderValue> {
    /// Create a new [`SetResponseHeaderLayer`] from a typed [`Header`].
    ///
    /// See [`SetResponseHeaderLayer::overriding`] for more details.
    pub fn overriding_typed<H: Header>(header: H) -> Self {
        Self::overriding(H::name().clone(), header.encode_to_value())
    }

    /// Create a new [`SetResponseHeaderLayer`] from a typed [`Header`].
    ///
    /// See [`SetResponseHeaderLayer::appending`] for more details.
    pub fn appending_typed<H: Header>(header: H) -> Self {
        Self::appending(H::name().clone(), header.encode_to_value())
    }

    /// Create a new [`SetResponseHeaderLayer`] from a typed [`Header`].
    ///
    /// See [`SetResponseHeaderLayer::if_not_present`] for more details.
    pub fn if_not_present_typed<H: Header>(header: H) -> Self {
        Self::if_not_present(H::name().clone(), header.encode_to_value())
    }
}

impl<M> SetResponseHeaderLayer<M> {
    /// Create a new [`SetResponseHeaderLayer`].
    ///
    /// If a previous value exists for the same header, it is removed and replaced with the new
    /// header value.
    pub fn overriding(header_name: HeaderName, make: M) -> Self {
        Self::new(header_name, make, InsertHeaderMode::Override)
    }

    /// Create a new [`SetResponseHeaderLayer`].
    ///
    /// The new header is always added, preserving any existing values. If previous values exist,
    /// the header will have multiple values.
    pub fn appending(header_name: HeaderName, make: M) -> Self {
        Self::new(header_name, make, InsertHeaderMode::Append)
    }

    /// Create a new [`SetResponseHeaderLayer`].
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

impl<F, A> SetResponseHeaderLayer<BoxMakeHeaderValueFactoryFn<F, A>> {
    /// Create a new [`SetResponseHeaderLayer`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetResponseHeaderLayer::overriding`] for more details.
    pub fn overriding_fn(header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            header_name,
            BoxMakeHeaderValueFactoryFn::new(make_fn),
            InsertHeaderMode::Override,
        )
    }

    /// Create a new [`SetResponseHeaderLayer`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetResponseHeaderLayer::appending`] for more details.
    pub fn appending_fn(header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            header_name,
            BoxMakeHeaderValueFactoryFn::new(make_fn),
            InsertHeaderMode::Append,
        )
    }

    /// Create a new [`SetResponseHeaderLayer`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetResponseHeaderLayer::if_not_present`] for more details.
    pub fn if_not_present_fn(header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            header_name,
            BoxMakeHeaderValueFactoryFn::new(make_fn),
            InsertHeaderMode::IfNotPresent,
        )
    }
}

impl<S, M> Layer<S> for SetResponseHeaderLayer<M>
where
    M: Clone,
{
    type Service = SetResponseHeader<S, M>;

    fn layer(&self, inner: S) -> Self::Service {
        SetResponseHeader {
            inner,
            header_name: self.header_name.clone(),
            make: self.make.clone(),
            mode: self.mode,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        SetResponseHeader {
            inner,
            header_name: self.header_name,
            make: self.make,
            mode: self.mode,
        }
    }
}

impl<M> Clone for SetResponseHeaderLayer<M>
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

/// Middleware that sets a header on the response.
#[derive(Clone)]
pub struct SetResponseHeader<S, M> {
    inner: S,
    header_name: HeaderName,
    make: M,
    mode: InsertHeaderMode,
}

impl<S, M> SetResponseHeader<S, M> {
    /// Create a new [`SetResponseHeader`].
    ///
    /// If a previous value exists for the same header, it is removed and replaced with the new
    /// header value.
    pub fn overriding(inner: S, header_name: HeaderName, make: M) -> Self {
        Self::new(inner, header_name, make, InsertHeaderMode::Override)
    }

    /// Create a new [`SetResponseHeader`].
    ///
    /// The new header is always added, preserving any existing values. If previous values exist,
    /// the header will have multiple values.
    pub fn appending(inner: S, header_name: HeaderName, make: M) -> Self {
        Self::new(inner, header_name, make, InsertHeaderMode::Append)
    }

    /// Create a new [`SetResponseHeader`].
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

impl<S, F, A> SetResponseHeader<S, BoxMakeHeaderValueFactoryFn<F, A>> {
    /// Create a new [`SetResponseHeader`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetResponseHeader::overriding`] for more details.
    pub fn overriding_fn(inner: S, header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            inner,
            header_name,
            BoxMakeHeaderValueFactoryFn::new(make_fn),
            InsertHeaderMode::Override,
        )
    }

    /// Create a new [`SetResponseHeader`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetResponseHeader::appending`] for more details.
    pub fn appending_fn(inner: S, header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            inner,
            header_name,
            BoxMakeHeaderValueFactoryFn::new(make_fn),
            InsertHeaderMode::Append,
        )
    }

    /// Create a new [`SetResponseHeader`] from a [`super::MakeHeaderValueFn`].
    ///
    /// See [`SetResponseHeader::if_not_present`] for more details.
    pub fn if_not_present_fn(inner: S, header_name: HeaderName, make_fn: F) -> Self {
        Self::new(
            inner,
            header_name,
            BoxMakeHeaderValueFactoryFn::new(make_fn),
            InsertHeaderMode::IfNotPresent,
        )
    }
}

impl<S, M> fmt::Debug for SetResponseHeader<S, M>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetResponseHeader")
            .field("inner", &self.inner)
            .field("header_name", &self.header_name)
            .field("mode", &self.mode)
            .field("make", &std::any::type_name::<M>())
            .finish()
    }
}

impl<ReqBody, ResBody, State, S, M> Service<State, Request<ReqBody>> for SetResponseHeader<S, M>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    State: Clone + Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    M: MakeHeaderValueFactory<State, ReqBody, ResBody>,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req, header_maker) = self.make.make_header_value_maker(ctx, req).await;
        let res = self.inner.serve(ctx, req).await?;
        let res = self.mode.apply(&self.header_name, res, header_maker).await;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{Body, HeaderValue, Request, Response, header};
    use rama_core::service::service_fn;
    use std::convert::Infallible;

    #[tokio::test]
    async fn test_override_mode() {
        let svc = SetResponseHeader::overriding(
            service_fn(async || {
                let res = Response::builder()
                    .header(header::CONTENT_TYPE, "good-content")
                    .body(Body::empty())
                    .unwrap();
                Ok::<_, Infallible>(res)
            }),
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );

        let res = svc
            .serve(Context::default(), Request::new(Body::empty()))
            .await
            .unwrap();

        let mut values = res.headers().get_all(header::CONTENT_TYPE).iter();
        assert_eq!(values.next().unwrap(), "text/html");
        assert_eq!(values.next(), None);
    }

    #[tokio::test]
    async fn test_append_mode() {
        let svc = SetResponseHeader::appending(
            service_fn(async || {
                let res = Response::builder()
                    .header(header::CONTENT_TYPE, "good-content")
                    .body(Body::empty())
                    .unwrap();
                Ok::<_, Infallible>(res)
            }),
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );

        let res = svc
            .serve(Context::default(), Request::new(Body::empty()))
            .await
            .unwrap();

        let mut values = res.headers().get_all(header::CONTENT_TYPE).iter();
        assert_eq!(values.next().unwrap(), "good-content");
        assert_eq!(values.next().unwrap(), "text/html");
        assert_eq!(values.next(), None);
    }

    #[tokio::test]
    async fn test_skip_if_present_mode() {
        let svc = SetResponseHeader::if_not_present(
            service_fn(async || {
                let res = Response::builder()
                    .header(header::CONTENT_TYPE, "good-content")
                    .body(Body::empty())
                    .unwrap();
                Ok::<_, Infallible>(res)
            }),
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );

        let res = svc
            .serve(Context::default(), Request::new(Body::empty()))
            .await
            .unwrap();

        let mut values = res.headers().get_all(header::CONTENT_TYPE).iter();
        assert_eq!(values.next().unwrap(), "good-content");
        assert_eq!(values.next(), None);
    }

    #[tokio::test]
    async fn test_skip_if_present_mode_when_not_present() {
        let svc = SetResponseHeader::if_not_present(
            service_fn(async || {
                let res = Response::builder().body(Body::empty()).unwrap();
                Ok::<_, Infallible>(res)
            }),
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html"),
        );

        let res = svc
            .serve(Context::default(), Request::new(Body::empty()))
            .await
            .unwrap();

        let mut values = res.headers().get_all(header::CONTENT_TYPE).iter();
        assert_eq!(values.next().unwrap(), "text/html");
        assert_eq!(values.next(), None);
    }
}
