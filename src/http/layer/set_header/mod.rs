//! Middleware for setting headers on requests and responses.
//!
//! See [request] and [response] for more details.

use crate::{
    http::{HeaderMap, HeaderName, HeaderValue, Request, Response},
    service::Context,
};

pub mod request;
pub mod response;

#[doc(inline)]
pub use self::{
    request::{SetRequestHeader, SetRequestHeaderLayer},
    response::{SetResponseHeader, SetResponseHeaderLayer},
};

/// Trait for producing header values.
///
/// Used by [`SetRequestHeader`] and [`SetResponseHeader`].
///
/// This trait is implemented for closures with the correct type signature. Typically users will
/// not have to implement this trait for their own types.
///
/// It is also implemented directly for [`HeaderValue`]. When a fixed header value should be added
/// to all responses, it can be supplied directly to the middleware.
pub trait MakeHeaderValue<S, T>: Send + Sync + 'static {
    /// Try to create a header value from the request or response.
    fn make_header_value(&self, ctx: &Context<S>, message: &T) -> Option<HeaderValue>;
}

impl<F, S, T> MakeHeaderValue<S, T> for F
where
    F: Fn(&T) -> Option<HeaderValue> + Send + Sync + 'static,
{
    fn make_header_value(&self, _ctx: &Context<S>, message: &T) -> Option<HeaderValue> {
        self(message)
    }
}

impl<S, T> MakeHeaderValue<S, T> for HeaderValue {
    fn make_header_value(&self, _ctx: &Context<S>, _message: &T) -> Option<HeaderValue> {
        Some(self.clone())
    }
}

impl<S, T> MakeHeaderValue<S, T> for Option<HeaderValue> {
    fn make_header_value(&self, _ctx: &Context<S>, _message: &T) -> Option<HeaderValue> {
        self.clone()
    }
}

#[derive(Debug, Clone, Copy)]
enum InsertHeaderMode {
    Override,
    Append,
    IfNotPresent,
}

impl InsertHeaderMode {
    fn apply<S, T, M>(self, ctx: &Context<S>, header_name: &HeaderName, target: &mut T, make: &M)
    where
        T: Headers,
        M: MakeHeaderValue<S, T>,
    {
        match self {
            InsertHeaderMode::Override => {
                if let Some(value) = make.make_header_value(ctx, target) {
                    target.headers_mut().insert(header_name.clone(), value);
                }
            }
            InsertHeaderMode::IfNotPresent => {
                if !target.headers().contains_key(header_name) {
                    if let Some(value) = make.make_header_value(ctx, target) {
                        target.headers_mut().insert(header_name.clone(), value);
                    }
                }
            }
            InsertHeaderMode::Append => {
                if let Some(value) = make.make_header_value(ctx, target) {
                    target.headers_mut().append(header_name.clone(), value);
                }
            }
        }
    }
}

trait Headers {
    fn headers(&self) -> &HeaderMap;

    fn headers_mut(&mut self) -> &mut HeaderMap;
}

impl<B> Headers for Request<B> {
    fn headers(&self) -> &HeaderMap {
        Request::headers(self)
    }

    fn headers_mut(&mut self) -> &mut HeaderMap {
        Request::headers_mut(self)
    }
}

impl<B> Headers for Response<B> {
    fn headers(&self) -> &HeaderMap {
        Response::headers(self)
    }

    fn headers_mut(&mut self) -> &mut HeaderMap {
        Response::headers_mut(self)
    }
}
