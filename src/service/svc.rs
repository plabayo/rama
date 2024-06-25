//! [`Service`] and [`BoxService`] traits.

use super::Context;
use crate::error::BoxError;
use std::future::Future;
use std::pin::Pin;

/// A [`Service`] that produces rama services,
/// to serve requests with, be it transport layer requests or application layer requests.
pub trait Service<S, Request>: Sized + Send + Sync + 'static {
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

    /// Box this service to allow for dynamic dispatch.
    fn boxed(self) -> BoxService<S, Request, Self::Response, Self::Error> {
        BoxService {
            inner: Box::new(self),
        }
    }
}

impl<S, State, Request> Service<State, Request> for std::sync::Arc<S>
where
    S: Service<State, Request>,
{
    type Response = S::Response;
    type Error = S::Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.as_ref().serve(ctx, req)
    }
}

impl<S, State, Request> Service<State, Request> for Box<S>
where
    S: Service<State, Request>,
{
    type Response = S::Response;
    type Error = S::Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.as_ref().serve(ctx, req)
    }
}

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
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
}

impl<S, Request, T> DynService<S, Request> for T
where
    T: Service<S, Request>,
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
}

/// A boxed [`Service`], to serve requests with,
/// for where you require dynamic dispatch.
pub struct BoxService<S, Request, Response, Error> {
    inner:
        Box<dyn DynService<S, Request, Response = Response, Error = Error> + Send + Sync + 'static>,
}

impl<S, Request, Response, Error> BoxService<S, Request, Response, Error> {
    /// Create a new [`BoxService`] from the given service.
    pub fn new<T>(service: T) -> Self
    where
        T: Service<S, Request, Response = Response, Error = Error>,
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

macro_rules! impl_service_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, State, Request, Response> Service<State, Request> for crate::utils::combinators::$id<$($param),+>
        where
            $(
                $param: Service<State, Request, Response = Response>,
                $param::Error: Into<BoxError>,
            )+
            Request: Send + 'static,
            State: Send + Sync + 'static,
            Response: Send + 'static,
        {
            type Response = Response;
            type Error = BoxError;

            async fn serve(&self, ctx: Context<State>, req: Request) -> Result<Self::Response, Self::Error> {
                match self {
                    $(
                        crate::utils::combinators::$id::$param(s) => s.serve(ctx, req).await.map_err(Into::into),
                    )+
                }
            }
        }
    };
}

crate::utils::combinators::impl_either!(impl_service_either);

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    #[derive(Debug)]
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

    #[derive(Debug)]
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
        use crate::utils::test_helpers::*;

        assert_send::<AddSvc>();
        assert_send::<MulSvc>();
        assert_send::<BoxService<(), (), (), ()>>();
    }

    #[test]
    fn assert_sync() {
        use crate::utils::test_helpers::*;

        assert_sync::<AddSvc>();
        assert_sync::<MulSvc>();
        assert_sync::<BoxService<(), (), (), ()>>();
    }

    #[tokio::test]
    async fn add_svc() {
        let svc = AddSvc(1);

        let ctx = Context::default();

        let response = svc.serve(ctx, 1).await.unwrap();
        assert_eq!(response, 2);
    }

    #[tokio::test]
    async fn static_dispatch() {
        let services = vec![AddSvc(1), AddSvc(2), AddSvc(3)];

        let ctx = Context::default();

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

        let ctx = Context::default();

        for (i, svc) in services.into_iter().enumerate() {
            let response = svc.serve(ctx.clone(), i).await.unwrap();
            if i < 3 {
                assert_eq!(response, i * 2 + 1);
            } else {
                assert_eq!(response, i * (i + 1));
            }
        }
    }

    #[tokio::test]
    async fn service_arc() {
        let svc = std::sync::Arc::new(AddSvc(1));

        let ctx = Context::default();

        let response = svc.serve(ctx, 1).await.unwrap();
        assert_eq!(response, 2);
    }

    #[tokio::test]
    async fn box_service_arc() {
        let svc = std::sync::Arc::new(AddSvc(1)).boxed();

        let ctx = Context::default();

        let response = svc.serve(ctx, 1).await.unwrap();
        assert_eq!(response, 2);
    }
}
