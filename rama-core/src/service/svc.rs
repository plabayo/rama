//! [`Service`] and [`BoxService`] traits.

use crate::Context;
use crate::error::BoxError;
use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

/// A [`Service`] that produces rama services,
/// to serve requests with, be it transport layer requests or application layer requests.
pub trait Service<S, Request>: Sized + Send + Sync + 'static {
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

    /// Box this service to allow for dynamic dispatch.
    fn boxed(self) -> BoxService<S, Request, Self::Response, Self::Error> {
        BoxService::new(self)
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

impl<S, State, Request> Service<State, Request> for &'static S
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
        (**self).serve(ctx, req)
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

    #[allow(clippy::type_complexity)]
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
        Arc<dyn DynService<S, Request, Response = Response, Error = Error> + Send + Sync + 'static>,
}

impl<S, Request, Response, Error> Clone for BoxService<S, Request, Response, Error> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S, Request, Response, Error> BoxService<S, Request, Response, Error> {
    /// Create a new [`BoxService`] from the given service.
    #[inline]
    pub fn new<T>(service: T) -> Self
    where
        T: Service<S, Request, Response = Response, Error = Error>,
    {
        Self {
            inner: Arc::new(service),
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
    Error: Send + 'static,
{
    type Response = Response;
    type Error = Error;

    #[inline]
    fn serve(
        &self,
        ctx: Context<S>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        self.inner.serve_box(ctx, req)
    }

    #[inline]
    fn boxed(self) -> Self {
        self
    }
}

macro_rules! impl_service_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, State, Request, Response> Service<State, Request> for crate::combinators::$id<$($param),+>
        where
            $(
                $param: Service<State, Request, Response = Response, Error: Into<BoxError>>,
            )+
            Request: Send + 'static,
            State: Clone + Send + Sync + 'static,
            Response: Send + 'static,
        {
            type Response = Response;
            type Error = BoxError;

            async fn serve(&self, ctx: Context<State>, req: Request) -> Result<Self::Response, Self::Error> {
                match self {
                    $(
                        crate::combinators::$id::$param(s) => s.serve(ctx, req).await.map_err(Into::into),
                    )+
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_service_either);

rama_utils::macros::error::static_str_error! {
    #[doc = "request rejected"]
    pub struct RejectError;
}

/// A [`Service`]] which always rejects with an error.
pub struct RejectService<R = (), E = RejectError> {
    error: E,
    _phantom: PhantomData<fn() -> R>,
}

impl Default for RejectService {
    fn default() -> Self {
        Self {
            error: RejectError,
            _phantom: PhantomData,
        }
    }
}

impl<R, E: Clone + Send + Sync + 'static> RejectService<R, E> {
    /// Create a new [`RejectService`].
    pub fn new(error: E) -> Self {
        Self {
            error,
            _phantom: PhantomData,
        }
    }
}

impl<R, E: Clone> Clone for RejectService<R, E> {
    fn clone(&self) -> Self {
        Self {
            error: self.error.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<R, E: fmt::Debug> fmt::Debug for RejectService<R, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectService")
            .field("error", &self.error)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn() -> R>()),
            )
            .finish()
    }
}

impl<S, Request, Response, Error> Service<S, Request> for RejectService<Response, Error>
where
    S: 'static,
    Request: 'static,
    Response: Send + 'static,
    Error: Clone + Send + Sync + 'static,
{
    type Response = Response;
    type Error = Error;

    #[inline]
    fn serve(
        &self,
        _ctx: Context<S>,
        _req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let error = self.error.clone();
        std::future::ready(Err(error))
    }
}

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
        use rama_utils::test_helpers::*;

        assert_send::<AddSvc>();
        assert_send::<MulSvc>();
        assert_send::<BoxService<(), (), (), ()>>();
        assert_send::<RejectService>();
    }

    #[test]
    fn assert_sync() {
        use rama_utils::test_helpers::*;

        assert_sync::<AddSvc>();
        assert_sync::<MulSvc>();
        assert_sync::<BoxService<(), (), (), ()>>();
        assert_sync::<RejectService>();
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

    #[tokio::test]
    async fn reject_svc() {
        let svc = RejectService::default();

        let ctx = Context::default();

        let err = svc.serve(ctx, 1).await.unwrap_err();
        assert_eq!(err.to_string(), RejectError::new().to_string());
    }
}
