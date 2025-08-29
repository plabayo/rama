//! `async fn(...)` as [`crate`].

use std::marker::PhantomData;

use crate::{Context, Service};

/// Create a [`ServiceFn`] from a function.
pub fn service_fn<F, T, R, O, E>(f: F) -> ServiceFn<F, T, R, O, E>
where
    F: Factory<T, R, O, E>,
    R: Future<Output = Result<O, E>>,
{
    ServiceFn::new(f)
}

/// Async handler converter factory
pub trait Factory<T, R, O, E>: Send + Sync + 'static
where
    R: Future<Output = Result<O, E>>,
{
    /// Call the handler function with the given parameter.
    fn call(&self, param: T) -> R;
}

impl<F, R, O, E> Factory<(), R, O, E> for F
where
    F: Fn() -> R + Send + Sync + 'static,
    R: Future<Output = Result<O, E>>,
{
    fn call(&self, _: ()) -> R {
        (self)()
    }
}

impl<Request, F, R, O, E> Factory<(Context, Request), R, O, E> for F
where
    F: Fn(Context, Request) -> R + Send + Sync + 'static,
    R: Future<Output = Result<O, E>>,
{
    fn call(&self, (ctx, req): (Context, Request)) -> R {
        (self)(ctx, req)
    }
}

impl<Request, F, R, O, E> Factory<((), Request), R, O, E> for F
where
    F: Fn(Request) -> R + Send + Sync + 'static,
    R: Future<Output = Result<O, E>>,
{
    fn call(&self, ((), req): ((), Request)) -> R {
        (self)(req)
    }
}

/// A [`ServiceFn`] is a [`Service`] implemented using a function.
///
/// You do not need to implement this trait yourself.
/// Instead, you need to use the [`service_fn`] function to create a [`ServiceFn`].
///
/// [`Service`]: crate
pub struct ServiceFn<F, T, R, O, E>
where
    F: Factory<T, R, O, E>,
    R: Future<Output = Result<O, E>>,
{
    hnd: F,
    _t: PhantomData<fn(T, R, O) -> ()>,
}

impl<F, T, R, O, E> std::fmt::Debug for ServiceFn<F, T, R, O, E>
where
    F: Factory<T, R, O, E>,
    R: Future<Output = Result<O, E>>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceFn").finish()
    }
}

impl<F, T, R, O, E> ServiceFn<F, T, R, O, E>
where
    F: Factory<T, R, O, E>,
    R: Future<Output = Result<O, E>>,
{
    pub(crate) fn new(hnd: F) -> Self {
        Self {
            hnd,
            _t: PhantomData,
        }
    }
}

impl<F, T, R, O, E> Clone for ServiceFn<F, T, R, O, E>
where
    F: Factory<T, R, O, E> + Clone,
    R: Future<Output = Result<O, E>>,
{
    fn clone(&self) -> Self {
        Self {
            hnd: self.hnd.clone(),
            _t: PhantomData,
        }
    }
}

impl<Request, F, T, R, O, E> Service<Request> for ServiceFn<F, T, R, O, E>
where
    F: Factory<T, R, O, E>,
    R: Future<Output = Result<O, E>> + Send + 'static,
    T: FromContextRequest<Request>,
    O: Send + 'static,
    E: Send + Sync + 'static,
{
    type Response = O;
    type Error = E;

    fn serve(
        &self,
        ctx: Context,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let param = T::from_context_request(ctx, req);
        self.hnd.call(param)
    }
}

/// Convert a context+request into a parameter for the [`ServiceFn`] handler function.
pub trait FromContextRequest<Request>: Send + 'static {
    /// Convert a context+request into a parameter for the [`ServiceFn`] handler function.
    fn from_context_request(ctx: Context, req: Request) -> Self;
}

impl<Request> FromContextRequest<Request> for () {
    fn from_context_request(_ctx: Context, _req: Request) -> Self {}
}

impl<Request> FromContextRequest<Request> for ((), Request)
where
    Request: Send + 'static,
{
    fn from_context_request(_ctx: Context, req: Request) -> Self {
        ((), req)
    }
}

impl<Request> FromContextRequest<Request> for (Context, Request)
where
    Request: Send + 'static,
{
    fn from_context_request(ctx: Context, req: Request) -> Self {
        (ctx, req)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use crate::Context;

    #[tokio::test]
    async fn test_service_fn() {
        let services = vec![
            service_fn(async || Ok(())).boxed(),
            service_fn(async |req: String| {
                assert_eq!(req, "hello");
                Ok(())
            })
            .boxed(),
            service_fn(async |_ctx: Context, req: String| {
                assert_eq!(req, "hello");
                Ok(())
            })
            .boxed(),
        ];

        for service in services {
            let ctx = Context::default();
            let req = "hello".to_owned();
            let res: Result<(), Infallible> = service.serve(ctx, req).await;
            assert!(res.is_ok());
        }
    }

    fn assert_send_sync<T: Send + Sync + 'static>(_t: T) {}

    #[test]
    fn test_service_fn_without_usage() {
        assert_send_sync(service_fn(async || Ok::<_, Infallible>(())));
        assert_send_sync(service_fn(async |_req: String| Ok::<_, Infallible>(())));
        assert_send_sync(service_fn(async |_ctx: Context, _req: String| {
            Ok::<_, Infallible>(())
        }));
    }
}
