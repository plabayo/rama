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
    type Error: Send + Sync + 'static;

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

    fn serve_box(
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

    fn serve_box(
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

impl<S, Request, Response, Error> BoxService<S, Request, Response, Error> {
    /// Create a new [`BoxService`] from the given service.
    pub fn new<T>(service: T) -> Self
    where
        T: Service<S, Request, Response = Response, Error = Error> + Clone,
    {
        Self {
            inner: Box::new(service),
        }
    }
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

impl<S, Request, Response, Error> Service<S, Request> for BoxService<S, Request, Response, Error>
where
    S: 'static,
    Request: 'static,
    Response: Send + 'static,
    Error: Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    fn serve(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.inner.serve_box(ctx, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    #[derive(Debug, Clone)]
    struct AddSvc(usize);

    impl Service<(), usize> for AddSvc {
        type Response = usize;
        type Error = Infallible;

        async fn serve(
            &self,
            _ctx: Context<()>,
            req: usize,
        ) -> Result<Self::Response, Self::Error> {
            Ok(self.0 + req)
        }
    }

    #[derive(Debug, Clone)]
    struct MulSvc(usize);

    impl Service<(), usize> for MulSvc {
        type Response = usize;
        type Error = Infallible;

        async fn serve(
            &self,
            _ctx: Context<()>,
            req: usize,
        ) -> Result<Self::Response, Self::Error> {
            Ok(self.0 * req)
        }
    }

    #[test]
    fn assert_send() {
        use crate::test_helpers::*;

        assert_send::<AddSvc>();
        assert_send::<MulSvc>();
        assert_send::<BoxService<(), (), (), ()>>();
    }

    #[tokio::test]
    async fn add_svc() {
        let svc = AddSvc(1);

        let ctx = Context::new(());

        let response = svc.serve(ctx, 1).await.unwrap();
        assert_eq!(response, 2);
    }

    #[tokio::test]
    async fn static_dispatch() {
        let services = vec![AddSvc(1), AddSvc(2), AddSvc(3)];

        let ctx = Context::new(());

        for (i, svc) in services.into_iter().enumerate() {
            let response = svc.serve(ctx.clone(), i).await.unwrap();
            assert_eq!(response, i * 2 + 1);
        }
    }

    #[tokio::test]
    async fn dynamic_dispatch() {
        let services = vec![
            AddSvc(1).boxed(),
            AddSvc(2).boxed(),
            AddSvc(3).boxed(),
            MulSvc(4).boxed(),
            MulSvc(5).boxed(),
        ];

        let ctx = Context::new(());

        for (i, svc) in services.into_iter().enumerate() {
            let response = svc.serve(ctx.clone(), i).await.unwrap();
            if i < 3 {
                assert_eq!(response, i * 2 + 1);
            } else {
                assert_eq!(response, i * (i + 1));
            }
        }
    }
}
