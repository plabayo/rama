use crate::{HeaderName, HeaderValue, Request};
use rama_http_headers::HeaderEncode;
use std::fmt;
use std::{
    future::{Future, ready},
    marker::PhantomData,
};

/// Trait for producing header values.
///
/// Used by [`SetRequestHeader`].
///
/// This trait is implemented for closures with the correct type signature. Typically users will
/// not have to implement this trait for their own types.
///
/// It is also implemented directly for [`HeaderValue`]. When a fixed header value should be added
/// to all responses, it can be supplied directly to the middleware.
///
/// [`SetRequestHeader`]: crate::layer::set_header::SetRequestHeader
pub trait MakeHeaderValue<B>: Send + Sync + 'static {
    /// Try to create a header value from the request or response.
    fn make_header_value(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = (Request<B>, Option<HeaderValue>)> + Send + '_;
}

#[derive(Default)]
/// Marker type to allow types which are [`MakeHeaderValue`] and
/// also have a [`Default`] way to construct to let them be constructed
/// on the fly. Useful alternative for cloning or using a function.
pub struct MakeHeaderValueDefault<M>(PhantomData<fn(M)>);

impl<M> MakeHeaderValueDefault<M> {
    #[inline(always)]
    pub(super) fn new() -> Self {
        Self(PhantomData)
    }
}

impl<M> fmt::Debug for MakeHeaderValueDefault<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MakeHeaderValueDefault")
            .field(&std::any::type_name::<M>())
            .finish()
    }
}

impl<M> Clone for MakeHeaderValueDefault<M> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<M, ReqBody> MakeHeaderValue<ReqBody> for MakeHeaderValueDefault<M>
where
    M: MakeHeaderValue<ReqBody> + Default,
    ReqBody: Send + 'static,
{
    #[inline(always)]
    async fn make_header_value(
        &self,
        req: Request<ReqBody>,
    ) -> (Request<ReqBody>, Option<HeaderValue>) {
        M::default().make_header_value(req).await
    }
}

/// Wrapper used internally as part of making typed headers
/// encode header values on the spot, when needed.
#[derive(Debug, Clone, Default)]
pub struct TypedHeaderAsMaker<H>(pub(super) H);

/// Functional version of [`MakeHeaderValue`].
pub trait MakeHeaderValueFn<B, A>: Send + Sync + 'static {
    /// Try to create a header value from the request or response.
    fn call(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = (Request<B>, Option<HeaderValue>)> + Send + '_;
}

impl<F, Fut, B> MakeHeaderValueFn<B, ()> for F
where
    B: Send + 'static,
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Option<HeaderValue>> + Send + 'static,
{
    async fn call(&self, req: Request<B>) -> (Request<B>, Option<HeaderValue>) {
        let maybe_value = self().await;
        (req, maybe_value)
    }
}

impl<F, Fut, B> MakeHeaderValueFn<B, ((), B)> for F
where
    B: Send + 'static,
    F: Fn(Request<B>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = (Request<B>, Option<HeaderValue>)> + Send + 'static,
{
    async fn call(&self, req: Request<B>) -> (Request<B>, Option<HeaderValue>) {
        let (req, maybe_value) = self(req).await;
        (req, maybe_value)
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
        req: Request<B>,
    ) -> impl Future<Output = (Request<B>, Option<HeaderValue>)> + Send + '_ {
        self.f.call(req)
    }
}

impl<B, M> MakeHeaderValue<B> for Option<M>
where
    M: MakeHeaderValue<B> + Clone,
    B: Send + 'static,
{
    async fn make_header_value(&self, req: Request<B>) -> (Request<B>, Option<HeaderValue>) {
        match self {
            Some(m) => m.make_header_value(req).await,
            None => (req, None),
        }
    }
}

impl<B> MakeHeaderValue<B> for HeaderValue
where
    B: Send + 'static,
{
    fn make_header_value(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = (Request<B>, Option<Self>)> + Send + '_ {
        ready((req, Some(self.clone())))
    }
}

impl<B, H> MakeHeaderValue<B> for TypedHeaderAsMaker<H>
where
    B: Send + 'static,
    H: HeaderEncode + Send + Sync + 'static,
{
    fn make_header_value(
        &self,
        req: Request<B>,
    ) -> impl Future<Output = (Request<B>, Option<HeaderValue>)> + Send {
        let maybe_value = self.0.encode_to_value();
        ready((req, maybe_value))
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
        req: Request<B>,
        make: &M,
    ) -> Request<B>
    where
        B: Send + 'static,
        M: MakeHeaderValue<B>,
    {
        match self {
            Self::Override => {
                let (mut req, maybe_value) = make.make_header_value(req).await;
                if let Some(value) = maybe_value {
                    req.headers_mut().insert(header_name.clone(), value);
                }
                req
            }
            Self::IfNotPresent => {
                if !req.headers().contains_key(header_name) {
                    let (mut req, maybe_value) = make.make_header_value(req).await;
                    if let Some(value) = maybe_value {
                        req.headers_mut().insert(header_name.clone(), value);
                    }
                    req
                } else {
                    req
                }
            }
            Self::Append => {
                let (mut req, maybe_value) = make.make_header_value(req).await;
                if let Some(value) = maybe_value {
                    req.headers_mut().append(header_name.clone(), value);
                }
                req
            }
        }
    }
}
