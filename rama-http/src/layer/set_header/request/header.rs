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
pub trait MakeHeaderValue<S, B>: Send + Sync + 'static {
    /// Try to create a header value from the request or response.
    fn make_header_value(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> impl Future<Output = (Context<S>, Request<B>, Option<HeaderValue>)> + Send + '_;
}

/// Functional version of [`MakeHeaderValue`].
pub trait MakeHeaderValueFn<S, B, A>: Send + Sync + 'static {
    /// Try to create a header value from the request or response.
    fn call(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> impl Future<Output = (Context<S>, Request<B>, Option<HeaderValue>)> + Send + '_;
}

impl<F, Fut, S, B> MakeHeaderValueFn<S, B, ()> for F
where
    S: Clone + Send + Sync + 'static,
    B: Send + 'static,
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<HeaderValue>> + Send + 'static,
{
    async fn call(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> (Context<S>, Request<B>, Option<HeaderValue>) {
        let maybe_value = self().await;
        (ctx, req, maybe_value)
    }
}

impl<F, Fut, S, B> MakeHeaderValueFn<S, B, ((), B)> for F
where
    S: Clone + Send + Sync + 'static,
    B: Send + 'static,
    F: Fn(Request<B>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Request<B>, Option<HeaderValue>)> + Send + 'static,
{
    async fn call(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> (Context<S>, Request<B>, Option<HeaderValue>) {
        let (req, maybe_value) = self(req).await;
        (ctx, req, maybe_value)
    }
}

impl<F, Fut, S, B> MakeHeaderValueFn<S, B, (Context<S>,)> for F
where
    S: Clone + Send + Sync + 'static,
    B: Send + 'static,
    F: Fn(Context<S>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Context<S>, Option<HeaderValue>)> + Send + 'static,
{
    async fn call(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> (Context<S>, Request<B>, Option<HeaderValue>) {
        let (ctx, maybe_value) = self(ctx).await;
        (ctx, req, maybe_value)
    }
}

impl<F, Fut, S, B> MakeHeaderValueFn<S, B, (Context<S>, B)> for F
where
    F: Fn(Context<S>, Request<B>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Context<S>, Request<B>, Option<HeaderValue>)> + Send + 'static,
{
    fn call(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> impl Future<Output = (Context<S>, Request<B>, Option<HeaderValue>)> + Send + '_ {
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

impl<S, B, A, F> MakeHeaderValue<S, B> for BoxMakeHeaderValueFn<F, A>
where
    A: Send + 'static,
    F: MakeHeaderValueFn<S, B, A>,
{
    fn make_header_value(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> impl Future<Output = (Context<S>, Request<B>, Option<HeaderValue>)> + Send + '_ {
        self.f.call(ctx, req)
    }
}

impl<S, B> MakeHeaderValue<S, B> for HeaderValue
where
    S: Clone + Send + Sync + 'static,
    B: Send + 'static,
{
    fn make_header_value(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> impl Future<Output = (Context<S>, Request<B>, Option<Self>)> + Send + '_ {
        ready((ctx, req, Some(self.clone())))
    }
}

impl<S, B> MakeHeaderValue<S, B> for Option<HeaderValue>
where
    S: Clone + Send + Sync + 'static,
    B: Send + 'static,
{
    fn make_header_value(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> impl Future<Output = (Context<S>, Request<B>, Self)> + Send + '_ {
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
    pub(super) async fn apply<S, B, M>(
        self,
        header_name: &HeaderName,
        ctx: Context<S>,
        req: Request<B>,
        make: &M,
    ) -> (Context<S>, Request<B>)
    where
        B: Send + 'static,
        M: MakeHeaderValue<S, B>,
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
