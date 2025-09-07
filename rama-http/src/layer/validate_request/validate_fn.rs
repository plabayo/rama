use super::ValidateRequest;
use crate::{Request, Response};
use rama_core::Context;
use std::marker::PhantomData;

/// Trait for validating requests.
pub trait ValidateRequestFn<B, A>: Send + Sync + 'static {
    /// The body type used for responses to unvalidated requests.
    type ResponseBody;

    /// Validate the request.
    ///
    /// If `Ok(())` is returned then the request is allowed through, otherwise not.
    fn call(
        &self,
        ctx: Context,
        request: Request<B>,
    ) -> impl Future<Output = Result<(Context, Request<B>), Response<Self::ResponseBody>>> + Send + '_;
}

impl<B, F, Fut, ResBody> ValidateRequestFn<B, ()> for F
where
    B: Send + 'static,
    ResBody: Send + 'static,
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), Response<ResBody>>> + Send + 'static,
{
    type ResponseBody = ResBody;

    async fn call(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> Result<(Context, Request<B>), Response<Self::ResponseBody>> {
        match self().await {
            Ok(_) => Ok((ctx, req)),
            Err(res) => Err(res),
        }
    }
}

impl<B, F, Fut, ResBody> ValidateRequestFn<B, ((), Request<B>)> for F
where
    B: Send + 'static,
    ResBody: Send + 'static,
    F: Fn(Request<B>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Request<B>, Response<ResBody>>> + Send + 'static,
{
    type ResponseBody = ResBody;

    async fn call(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> Result<(Context, Request<B>), Response<Self::ResponseBody>> {
        match self(req).await {
            Ok(req) => Ok((ctx, req)),
            Err(res) => Err(res),
        }
    }
}

impl<B, F, Fut, ResBody> ValidateRequestFn<B, (Context,)> for F
where
    B: Send + 'static,
    ResBody: Send + 'static,
    F: Fn(Context) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Context, Response<ResBody>>> + Send + 'static,
{
    type ResponseBody = ResBody;

    async fn call(
        &self,
        ctx: Context,
        req: Request<B>,
    ) -> Result<(Context, Request<B>), Response<Self::ResponseBody>> {
        match self(ctx).await {
            Ok(ctx) => Ok((ctx, req)),
            Err(res) => Err(res),
        }
    }
}

impl<B, F, Fut, ResBody> ValidateRequestFn<B, (Context, Request<B>)> for F
where
    F: Fn(Context, Request<B>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(Context, Request<B>), Response<ResBody>>> + Send + 'static,
{
    type ResponseBody = ResBody;

    fn call(
        &self,
        ctx: Context,
        request: Request<B>,
    ) -> impl Future<Output = Result<(Context, Request<B>), Response<Self::ResponseBody>>> + Send + '_
    {
        self(ctx, request)
    }
}

/// The public wrapper type for [`ValidateRequestFn`].
pub struct BoxValidateRequestFn<F, A> {
    f: F,
    _marker: PhantomData<A>,
}

impl<F, A> BoxValidateRequestFn<F, A> {
    /// Create a new [`BoxValidateRequestFn`].
    pub const fn new(f: F) -> Self {
        Self {
            f,
            _marker: PhantomData,
        }
    }
}

impl<F, A> Clone for BoxValidateRequestFn<F, A>
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

impl<F, A> std::fmt::Debug for BoxValidateRequestFn<F, A>
where
    F: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxValidateRequestFn")
            .field("f", &self.f)
            .finish()
    }
}

impl<B, A, F> ValidateRequest<B> for BoxValidateRequestFn<F, A>
where
    A: Send + Sync + 'static,
    F: ValidateRequestFn<B, A>,
{
    type ResponseBody = F::ResponseBody;

    fn validate(
        &self,
        ctx: Context,
        request: Request<B>,
    ) -> impl Future<Output = Result<(Context, Request<B>), Response<Self::ResponseBody>>> + Send + '_
    {
        self.f.call(ctx, request)
    }
}
