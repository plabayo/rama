//! Middleware for setting headers on requests and responses.
//!
//! See [request] and [response] for more details.

use crate::{
    http::{HeaderMap, HeaderName, HeaderValue, Request, Response},
    service::Context,
};
use std::{
    future::{ready, Future},
    marker::PhantomData,
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
    fn make_header_value(
        &self,
        ctx: Context<S>,
        message: T,
    ) -> impl Future<Output = (Context<S>, T, Option<HeaderValue>)> + Send + '_;
}

/// Functional version of [`MakeHeaderValue`].
pub trait MakeHeaderValueFn<S, T, A>: Send + Sync + 'static {
    /// Try to create a header value from the request or response.
    fn call(
        &self,
        ctx: Context<S>,
        message: T,
    ) -> impl Future<Output = (Context<S>, T, Option<HeaderValue>)> + Send + '_;
}

impl<F, Fut, S, T> MakeHeaderValueFn<S, T, ()> for F
where
    S: Send + Sync + 'static,
    T: Send + 'static,
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<HeaderValue>> + Send + 'static,
{
    async fn call(&self, ctx: Context<S>, message: T) -> (Context<S>, T, Option<HeaderValue>) {
        let maybe_value = self().await;
        (ctx, message, maybe_value)
    }
}

impl<F, Fut, S, T> MakeHeaderValueFn<S, T, ((), T)> for F
where
    S: Send + Sync + 'static,
    T: Send + 'static,
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (T, Option<HeaderValue>)> + Send + 'static,
{
    async fn call(&self, ctx: Context<S>, message: T) -> (Context<S>, T, Option<HeaderValue>) {
        let (message, maybe_value) = self(message).await;
        (ctx, message, maybe_value)
    }
}

impl<F, Fut, S, T> MakeHeaderValueFn<S, T, (Context<S>,)> for F
where
    S: Send + Sync + 'static,
    T: Send + 'static,
    F: Fn(Context<S>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Context<S>, Option<HeaderValue>)> + Send + 'static,
{
    async fn call(&self, ctx: Context<S>, message: T) -> (Context<S>, T, Option<HeaderValue>) {
        let (ctx, maybe_value) = self(ctx).await;
        (ctx, message, maybe_value)
    }
}

impl<F, Fut, S, T> MakeHeaderValueFn<S, T, (Context<S>, T)> for F
where
    F: Fn(Context<S>, T) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Context<S>, T, Option<HeaderValue>)> + Send + 'static,
{
    fn call(
        &self,
        ctx: Context<S>,
        message: T,
    ) -> impl Future<Output = (Context<S>, T, Option<HeaderValue>)> + Send + '_ {
        self(ctx, message)
    }
}

/// The public wrapper type for [`MakeHeaderValueFn`].
pub struct BoxMakeHeaderValueFn<F, A> {
    f: F,
    _marker: PhantomData<fn(A) -> ()>,
}

impl<F, A> BoxMakeHeaderValueFn<F, A> {
    /// Create a new [`BoxMakeHeaderValueFn`].
    pub const fn new(f: F) -> Self {
        Self {
            f,
            _marker: PhantomData,
        }
    }
}

impl<F, A> Clone for BoxMakeHeaderValueFn<F, A>
where
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            f: self.f.clone(),
            _marker: PhantomData,
        }
    }
}

impl<F, A> std::fmt::Debug for BoxMakeHeaderValueFn<F, A>
where
    F: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxMakeHeaderValueFn")
            .field("f", &self.f)
            .finish()
    }
}

impl<S, B, A, F> MakeHeaderValue<S, B> for BoxMakeHeaderValueFn<F, A>
where
    A: Send + 'static,
    F: MakeHeaderValueFn<S, B, A>,
{
    fn make_header_value(
        &self,
        ctx: Context<S>,
        message: B,
    ) -> impl Future<Output = (Context<S>, B, Option<HeaderValue>)> + Send + '_ {
        self.f.call(ctx, message)
    }
}

impl<S, T> MakeHeaderValue<S, T> for HeaderValue
where
    S: Send + Sync + 'static,
    T: Send + 'static,
{
    fn make_header_value(
        &self,
        ctx: Context<S>,
        message: T,
    ) -> impl Future<Output = (Context<S>, T, Option<HeaderValue>)> + Send + '_ {
        ready((ctx, message, Some(self.clone())))
    }
}

impl<S, T> MakeHeaderValue<S, T> for Option<HeaderValue>
where
    S: Send + Sync + 'static,
    T: Send + 'static,
{
    fn make_header_value(
        &self,
        ctx: Context<S>,
        message: T,
    ) -> impl Future<Output = (Context<S>, T, Option<HeaderValue>)> + Send + '_ {
        ready((ctx, message, self.clone()))
    }
}

#[derive(Debug, Clone, Copy)]
enum InsertHeaderMode {
    Override,
    Append,
    IfNotPresent,
}

impl InsertHeaderMode {
    async fn apply<S, T, M>(
        self,
        header_name: &HeaderName,
        ctx: Context<S>,
        target: T,
        make: &M,
    ) -> (Context<S>, T)
    where
        T: Headers,
        M: MakeHeaderValue<S, T>,
    {
        match self {
            InsertHeaderMode::Override => {
                let (ctx, mut target, maybe_value) = make.make_header_value(ctx, target).await;
                if let Some(value) = maybe_value {
                    target.headers_mut().insert(header_name.clone(), value);
                }
                (ctx, target)
            }
            InsertHeaderMode::IfNotPresent => {
                if !target.headers().contains_key(header_name) {
                    let (ctx, mut target, maybe_value) = make.make_header_value(ctx, target).await;
                    if let Some(value) = maybe_value {
                        target.headers_mut().insert(header_name.clone(), value);
                    }
                    (ctx, target)
                } else {
                    (ctx, target)
                }
            }
            InsertHeaderMode::Append => {
                let (ctx, mut target, maybe_value) = make.make_header_value(ctx, target).await;
                if let Some(value) = maybe_value {
                    target.headers_mut().append(header_name.clone(), value);
                }
                (ctx, target)
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
