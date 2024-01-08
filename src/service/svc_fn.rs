use super::{Context, Service};
use std::future::Future;
use std::marker::PhantomData;

/// Create a [`ServiceFn`] from a function.
pub fn service_fn<F, A>(f: F) -> ServiceFnBox<F, A> {
    ServiceFnBox {
        f,
        _marker: PhantomData,
    }
}

/// A [`ServiceFn`] is a [`Service`] implemented using a function.
///
/// You do not need to implement this trait yourself.
/// Instead, you need to use the [`service_fn`] function to create a [`ServiceFn`].
pub trait ServiceFn<S, Request, A>: Send + Sync + 'static {
    /// The type of response returned by the service.
    type Response: Send + 'static;

    /// The type of error returned by the service.
    type Error: Send + Sync + 'static;

    /// Serve a response or error for the given request,
    /// using the given context.
    fn call(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_;
}

impl<F, Fut, S, Request, Response, Error> ServiceFn<S, Request, ()> for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response, Error>> + Send + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    fn call(
        &self,
        _ctx: Context<S>,
        _req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        (self)()
    }
}

impl<F, Fut, S, Request, Response, Error> ServiceFn<S, Request, (Request,)> for F
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response, Error>> + Send + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    fn call(
        &self,
        _ctx: Context<S>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        (self)(req)
    }
}

impl<F, Fut, S, Request, Response, Error> ServiceFn<S, Request, (Context<S>, Request)> for F
where
    F: Fn(Context<S>, Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response, Error>> + Send + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    fn call(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        (self)(ctx, req)
    }
}

impl<F, Fut, S, Request, Response, Error> ServiceFn<S, Request, (Context<S>, (), ())> for F
where
    F: Fn(Context<S>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Response, Error>> + Send + 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    fn call(
        &self,
        ctx: Context<S>,
        _req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        (self)(ctx)
    }
}

/// The public wrapper type for [`ServiceFn`].
#[derive(Debug)]
pub struct ServiceFnBox<F, A> {
    f: F,
    _marker: PhantomData<A>,
}

impl<F, A> Clone for ServiceFnBox<F, A>
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

impl<F, S, Request, A> Service<S, Request> for ServiceFnBox<F, A>
where
    A: Send + Sync + 'static,
    F: ServiceFn<S, Request, A>,
{
    type Response = F::Response;
    type Error = F::Error;

    fn serve(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.f.call(ctx, req)
    }
}
