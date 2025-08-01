use crate::{HeaderName, HeaderValue, Request, Response};
use rama_core::Context;
use std::{
    future::{Future, ready},
    marker::PhantomData,
};

/// Trait for preparing a maker ([`MakeHeaderValue`]) that will be used
/// to actually create the [`HeaderValue`] when desired.
///
/// The reason why this is split in two parts for responses is because
/// the context is consumed by the inner service producting the response
/// to which the header (maybe) will be attached to. In order to not
/// clone the entire `Context` and its `State` it is therefore better
/// to let the implementer decide what state is to be cloned and which not.
///
/// E.g. for a static Header value one might not need any state or context at all,
/// which would make it pretty wastefull if we would for such cases clone
/// these stateful datastructures anyhow.
///
/// Most users will however not have to worry about this Trait or why it is there,
/// as the trait is implemented already for functions, closures and HeaderValues.
pub trait MakeHeaderValueFactory<S, ReqBody, ResBody>: Send + Sync + 'static {
    /// Maker that _can_ be produced by this Factory.
    type Maker: MakeHeaderValue<ResBody>;

    /// Try to create a header value from the request or response.
    fn make_header_value_maker(
        &self,
        ctx: Context<S>,
        request: Request<ReqBody>,
    ) -> impl Future<Output = (Context<S>, Request<ReqBody>, Self::Maker)> + Send + '_;
}

/// Trait for producing header values, created by a `MakeHeaderValueFactory`.
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
        self,
        response: Response<B>,
    ) -> impl Future<Output = (Response<B>, Option<HeaderValue>)> + Send;
}

impl<B, M> MakeHeaderValue<B> for Option<M>
where
    M: MakeHeaderValue<B> + Clone,
    B: Send + 'static,
{
    async fn make_header_value(self, response: Response<B>) -> (Response<B>, Option<HeaderValue>) {
        match self {
            Some(m) => m.make_header_value(response).await,
            None => (response, None),
        }
    }
}

impl<B> MakeHeaderValue<B> for HeaderValue
where
    B: Send + 'static,
{
    fn make_header_value(
        self,
        response: Response<B>,
    ) -> impl Future<Output = (Response<B>, Option<Self>)> + Send {
        ready((response, Some(self)))
    }
}

impl<S, ReqBody, ResBody> MakeHeaderValueFactory<S, ReqBody, ResBody> for HeaderValue
where
    S: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Maker = Self;

    fn make_header_value_maker(
        &self,
        ctx: Context<S>,
        req: Request<ReqBody>,
    ) -> impl Future<Output = (Context<S>, Request<ReqBody>, Self::Maker)> + Send + '_ {
        ready((ctx, req, self.clone()))
    }
}

impl<S, ReqBody, ResBody> MakeHeaderValueFactory<S, ReqBody, ResBody> for Option<HeaderValue>
where
    S: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Maker = Self;

    fn make_header_value_maker(
        &self,
        ctx: Context<S>,
        req: Request<ReqBody>,
    ) -> impl Future<Output = (Context<S>, Request<ReqBody>, Self::Maker)> + Send + '_ {
        ready((ctx, req, self.clone()))
    }
}

/// Functional version of [`MakeHeaderValue`].
pub trait MakeHeaderValueFactoryFn<S, ReqBody, ResBody, A>: Send + Sync + 'static {
    type Maker: MakeHeaderValue<ResBody>;

    /// Try to create a header value from the request or response.
    fn call(
        &self,
        ctx: Context<S>,
        request: Request<ReqBody>,
    ) -> impl Future<Output = (Context<S>, Request<ReqBody>, Self::Maker)> + Send + '_;
}

impl<F, Fut, S, ReqBody, ResBody, M> MakeHeaderValueFactoryFn<S, ReqBody, ResBody, ()> for F
where
    S: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    M: MakeHeaderValue<ResBody>,
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = M> + Send + 'static,
    M: MakeHeaderValue<ResBody>,
{
    type Maker = M;

    async fn call(
        &self,
        ctx: Context<S>,
        request: Request<ReqBody>,
    ) -> (Context<S>, Request<ReqBody>, M) {
        let maker = self().await;
        (ctx, request, maker)
    }
}

impl<F, Fut, S, ReqBody, ResBody, M>
    MakeHeaderValueFactoryFn<S, ReqBody, ResBody, ((), Request<ReqBody>)> for F
where
    S: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    M: MakeHeaderValue<ResBody>,
    F: Fn(Request<ReqBody>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Request<ReqBody>, M)> + Send + 'static,
    M: MakeHeaderValue<ResBody>,
{
    type Maker = M;

    async fn call(
        &self,
        ctx: Context<S>,
        request: Request<ReqBody>,
    ) -> (Context<S>, Request<ReqBody>, M) {
        let (request, maker) = self(request).await;
        (ctx, request, maker)
    }
}

impl<F, Fut, S, ReqBody, ResBody, M> MakeHeaderValueFactoryFn<S, ReqBody, ResBody, (Context<S>,)>
    for F
where
    S: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    M: MakeHeaderValue<ResBody>,
    F: Fn(Context<S>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Context<S>, M)> + Send + 'static,
    M: MakeHeaderValue<ResBody>,
{
    type Maker = M;

    async fn call(
        &self,
        ctx: Context<S>,
        request: Request<ReqBody>,
    ) -> (Context<S>, Request<ReqBody>, M) {
        let (ctx, maker) = self(ctx).await;
        (ctx, request, maker)
    }
}

impl<F, Fut, S, ReqBody, ResBody, M> MakeHeaderValueFactoryFn<S, ReqBody, ResBody, (Context<S>, M)>
    for F
where
    S: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    M: MakeHeaderValue<ResBody>,
    F: Fn(Context<S>, Request<ReqBody>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Context<S>, Request<ReqBody>, M)> + Send + 'static,
    M: MakeHeaderValue<ResBody>,
{
    type Maker = M;

    fn call(
        &self,
        ctx: Context<S>,
        request: Request<ReqBody>,
    ) -> impl Future<Output = (Context<S>, Request<ReqBody>, M)> + Send + '_ {
        self(ctx, request)
    }
}

/// The public wrapper type for [`MakeHeaderValueFactoryFn`].
pub struct BoxMakeHeaderValueFactoryFn<F, A> {
    f: F,
    _marker: PhantomData<fn(A) -> ()>,
}

impl<F, A> BoxMakeHeaderValueFactoryFn<F, A> {
    /// Create a new [`BoxMakeHeaderValueFactoryFn`].
    pub const fn new(f: F) -> Self {
        Self {
            f,
            _marker: PhantomData,
        }
    }
}

impl<F, A> Clone for BoxMakeHeaderValueFactoryFn<F, A>
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

impl<F, A> std::fmt::Debug for BoxMakeHeaderValueFactoryFn<F, A>
where
    F: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxMakeHeaderValueFn")
            .field("f", &self.f)
            .finish()
    }
}

impl<S, ReqBody, ResBody, A, F> MakeHeaderValueFactory<S, ReqBody, ResBody>
    for BoxMakeHeaderValueFactoryFn<F, A>
where
    A: Send + 'static,
    F: MakeHeaderValueFactoryFn<S, ReqBody, ResBody, A>,
{
    type Maker = F::Maker;

    fn make_header_value_maker(
        &self,
        ctx: Context<S>,
        request: Request<ReqBody>,
    ) -> impl Future<Output = (Context<S>, Request<ReqBody>, Self::Maker)> + Send + '_ {
        self.f.call(ctx, request)
    }
}

/// Functional version of [`MakeHeaderValue`],
/// to make it easier to create a (response) header maker
/// directly from a response.
pub trait MakeHeaderValueFn<B, A>: Send + Sync + 'static {
    /// Try to create a header value from the request or response.
    fn call(
        self,
        response: Response<B>,
    ) -> impl Future<Output = (Response<B>, Option<HeaderValue>)> + Send;
}

impl<F, Fut, B> MakeHeaderValueFn<B, ()> for F
where
    B: Send + 'static,
    F: FnOnce() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<HeaderValue>> + Send + 'static,
{
    async fn call(self, response: Response<B>) -> (Response<B>, Option<HeaderValue>) {
        let maybe_value = self().await;
        (response, maybe_value)
    }
}

impl<F, Fut, B> MakeHeaderValueFn<B, Response<B>> for F
where
    B: Send + 'static,
    F: FnOnce(Response<B>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Response<B>, Option<HeaderValue>)> + Send + 'static,
{
    async fn call(self, response: Response<B>) -> (Response<B>, Option<HeaderValue>) {
        let (response, maybe_value) = self(response).await;
        (response, maybe_value)
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
        self,
        response: Response<B>,
    ) -> impl Future<Output = (Response<B>, Option<HeaderValue>)> + Send {
        self.f.call(response)
    }
}

impl<F, Fut, S, ReqBody, ResBody> MakeHeaderValueFactoryFn<S, ReqBody, ResBody, ((), (), ())> for F
where
    S: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    F: Fn() -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Option<HeaderValue>> + Send + 'static,
{
    type Maker = BoxMakeHeaderValueFn<F, ()>;

    async fn call(
        &self,
        ctx: Context<S>,
        request: Request<ReqBody>,
    ) -> (Context<S>, Request<ReqBody>, Self::Maker) {
        let maker = self.clone();
        (ctx, request, BoxMakeHeaderValueFn::new(maker))
    }
}

impl<F, Fut, S, ReqBody, ResBody>
    MakeHeaderValueFactoryFn<S, ReqBody, ResBody, ((), (), Response<ResBody>)> for F
where
    S: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    F: Fn(Response<ResBody>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = (Response<ResBody>, Option<HeaderValue>)> + Send + 'static,
{
    type Maker = BoxMakeHeaderValueFn<F, Response<ResBody>>;

    async fn call(
        &self,
        ctx: Context<S>,
        request: Request<ReqBody>,
    ) -> (Context<S>, Request<ReqBody>, Self::Maker) {
        let maker = self.clone();
        (ctx, request, BoxMakeHeaderValueFn::new(maker))
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
        response: Response<B>,
        make: M,
    ) -> Response<B>
    where
        B: Send + 'static,
        M: MakeHeaderValue<B>,
    {
        match self {
            Self::Override => {
                let (mut response, maybe_value) = make.make_header_value(response).await;
                if let Some(value) = maybe_value {
                    response.headers_mut().insert(header_name.clone(), value);
                }
                response
            }
            Self::IfNotPresent => {
                if !response.headers().contains_key(header_name) {
                    let (mut response, maybe_value) = make.make_header_value(response).await;
                    if let Some(value) = maybe_value {
                        response.headers_mut().insert(header_name.clone(), value);
                    }
                    response
                } else {
                    response
                }
            }
            Self::Append => {
                let (mut response, maybe_value) = make.make_header_value(response).await;
                if let Some(value) = maybe_value {
                    response.headers_mut().append(header_name.clone(), value);
                }
                response
            }
        }
    }
}
