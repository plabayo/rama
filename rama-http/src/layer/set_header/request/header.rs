use crate::{HeaderName, HeaderValue, Request};
use rama_core::Context;
use std::{
    future::{Future, ready},
    marker::PhantomData,
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
pub trait MakeHeaderValue<B>: Send + Sync + 'static {
    /// Try to create a header value from the request or response.
    fn make_header_value(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> impl Future<Output = (Context, Request<B>, Option<HeaderValue>)> + Send + '_;
}

/// Functional version of [`MakeHeaderValue`].
pub trait MakeHeaderValueFn<B, A>: Send + Sync + 'static {
    /// Try to create a header value from the request or response.
    fn call(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> impl Future<Output = (Context, Request<B>, Option<HeaderValue>)> + Send + '_;
}

impl<F, Fut, B> MakeHeaderValueFn<B, ()> for F
where
    B: Send + 'static,
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<HeaderValue>> + Send + 'static,
{
    async fn call(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> (Context, Request<B>, Option<HeaderValue>) {
        let maybe_value = self().await;
        (ctx, req, maybe_value)
    }
}

impl<F, Fut, B> MakeHeaderValueFn<B, ((), B)> for F
where
    B: Send + 'static,
    F: Fn(Request<B>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Request<B>, Option<HeaderValue>)> + Send + 'static,
{
    async fn call(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> (Context, Request<B>, Option<HeaderValue>) {
        let (req, maybe_value) = self(req).await;
        (ctx, req, maybe_value)
    }
}

impl<F, Fut, B> MakeHeaderValueFn<B, (Context,)> for F
where
    B: Send + 'static,
    F: Fn(Context) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Context, Option<HeaderValue>)> + Send + 'static,
{
    async fn call(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> (Context, Request<B>, Option<HeaderValue>) {
        let (ctx, maybe_value) = self(ctx).await;
        (ctx, req, maybe_value)
    }
}

impl<F, Fut, B> MakeHeaderValueFn<B, (Context, B)> for F
where
    F: Fn(Context, Request<B>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Context, Request<B>, Option<HeaderValue>)> + Send + 'static,
{
    fn call(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> impl Future<Output = (Context, Request<B>, Option<HeaderValue>)> + Send + '_ {
        self(ctx, req)
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

impl<B, A, F> MakeHeaderValue<B> for BoxMakeHeaderValueFn<F, A>
where
    A: Send + 'static,
    F: MakeHeaderValueFn<B, A>,
{
    fn make_header_value(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> impl Future<Output = (Context, Request<B>, Option<HeaderValue>)> + Send + '_ {
        self.f.call(ctx, req)
    }
}

impl<B> MakeHeaderValue<B> for HeaderValue
where
    B: Send + 'static,
{
    fn make_header_value(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> impl Future<Output = (Context, Request<B>, Option<Self>)> + Send + '_ {
        ready((ctx, req, Some(self.clone())))
    }
}

impl<B> MakeHeaderValue<B> for Option<HeaderValue>
where
    B: Send + 'static,
{
    fn make_header_value(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> impl Future<Output = (Context, Request<B>, Self)> + Send + '_ {
        ready((ctx, req, self.clone()))
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum InsertHeaderMode {
    Override,
    Append,
    IfNotPresent,
}

impl InsertHeaderMode {
    pub(super) async fn apply<B, M>(
        self,
        header_name: &HeaderName,
        ctx: Context,
        req: Request<B>,
        make: &M,
    ) -> (Context, Request<B>)
    where
        B: Send + 'static,
        M: MakeHeaderValue<B>,
    {
        match self {
            Self::Override => {
                let (ctx, mut req, maybe_value) = make.make_header_value(ctx, req).await;
                if let Some(value) = maybe_value {
                    req.headers_mut().insert(header_name.clone(), value);
                }
                (ctx, req)
            }
            Self::IfNotPresent => {
                if !req.headers().contains_key(header_name) {
                    let (ctx, mut req, maybe_value) = make.make_header_value(ctx, req).await;
                    if let Some(value) = maybe_value {
                        req.headers_mut().insert(header_name.clone(), value);
                    }
                    (ctx, req)
                } else {
                    (ctx, req)
                }
            }
            Self::Append => {
                let (ctx, mut req, maybe_value) = make.make_header_value(ctx, req).await;
                if let Some(value) = maybe_value {
                    req.headers_mut().append(header_name.clone(), value);
                }
                (ctx, req)
            }
        }
    }
}
