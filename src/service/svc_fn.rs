use super::{Context, Service};
use std::fmt;
use std::future::Future;

/// Returns a new [`ServiceFn`] with the given closure.
///
/// This lets you build a [`Service`] from an async function that returns a [`Result`].
pub fn service_fn<T>(f: T) -> ServiceFn<T> {
    ServiceFn { f }
}

/// A [`Service`] implemented by a closure.
///
/// See [`service_fn`] for more details.
#[derive(Copy, Clone)]
pub struct ServiceFn<T> {
    f: T,
}

impl<T> fmt::Debug for ServiceFn<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceFn")
            .field("f", &format_args!("{}", std::any::type_name::<T>()))
            .finish()
    }
}

impl<T, F, State, Request, R, E> Service<State, Request> for ServiceFn<T>
where
    T: Fn(Context<State>, Request) -> F + Send + 'static,
    F: Future<Output = Result<R, E>> + Send + 'static,
    R: Send + 'static,
    E: Send + Sync + 'static,
{
    type Response = R;
    type Error = E;

    fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        (self.f)(ctx, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_service_fn() {
        let svc = service_fn(|_, req| async move { Ok::<_, ()>(req) });
        let res = svc.serve(Context::default(), "hello").await;
        assert_eq!(res, Ok("hello"));
    }

    #[tokio::test]
    async fn test_service_fn_adder() {
        let svc = service_fn(|_, (a, b)| async move { Ok::<_, ()>(a + b) });
        let res = svc.serve(Context::default(), (1, 2)).await;
        assert_eq!(res, Ok(3));
    }
}