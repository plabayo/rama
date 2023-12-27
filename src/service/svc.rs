//! [`Service`] and [`BoxService`] traits.

use super::Context;
use std::future::Future;
use std::pin::Pin;

/// A [`Service`] that produces rama services,
/// to serve requests with, be it transport layer requests or application layer requests.
pub trait Service<S, Request>: Send + 'static {
    /// The type of response returned by the service.
    type Response: Send + 'static;

    /// The type of error returned by the service.
    type Error: Send + 'static;

    /// Serve a response or error for the given request,
    /// using the given context.
    fn serve(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_;

    /// Box this service to allow for dynamic dispatch,
    /// only possible if the service is [`Clone`].
    fn boxed(self) -> BoxService<S, Request, Self::Response, Self::Error>
    where
        Self: Clone,
    {
        BoxService {
            inner: Box::new(self),
        }
    }
}

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented acording to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
trait DynService<S, Request> {
    type Response;
    type Error;

    fn serve(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + '_>>;

    fn clone_box(
        &self,
    ) -> Box<
        dyn DynService<S, Request, Response = Self::Response, Error = Self::Error> + Send + 'static,
    >;
}

impl<S, Request, T> DynService<S, Request> for T
where
    T: Service<S, Request> + Clone,
{
    type Response = T::Response;
    type Error = T::Error;

    fn serve(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + '_>> {
        Box::pin(self.serve(ctx, req))
    }

    fn clone_box(
        &self,
    ) -> Box<
        dyn DynService<S, Request, Response = Self::Response, Error = Self::Error> + Send + 'static,
    > {
        Box::new(self.clone())
    }
}

/// A boxed [`Service`], to serve requests with,
/// for where you require dynamic dispatch.
pub struct BoxService<S, Request, Response, Error> {
    inner: Box<dyn DynService<S, Request, Response = Response, Error = Error> + Send + 'static>,
}

impl<S, Request, Response, Error> std::fmt::Debug for BoxService<S, Request, Response, Error> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxService").finish()
    }
}

impl<S, Request, Response, Error> Clone for BoxService<S, Request, Response, Error>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone_box(),
        }
    }
}
