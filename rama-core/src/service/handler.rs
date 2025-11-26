//! `async fn(...)` as [`crate`].

use std::marker::PhantomData;

use crate::Service;

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

impl<Input, F, R, O, E> Factory<(Input,), R, O, E> for F
where
    F: Fn(Input) -> R + Send + Sync + 'static,
    R: Future<Output = Result<O, E>>,
{
    fn call(&self, (req,): (Input,)) -> R {
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

impl<Input, F, T, R, O, E> Service<Input> for ServiceFn<F, T, R, O, E>
where
    F: Factory<T, R, O, E>,
    R: Future<Output = Result<O, E>> + Send + 'static,
    T: sealed::FromInput<Input>,
    O: Send + 'static,
    E: Send + Sync + 'static,
{
    type Output = O;
    type Error = E;

    fn serve(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        let param = T::from_input(input);
        self.hnd.call(param)
    }
}

mod sealed {
    /// Convert an Input into a parameter for the [`ServiceFn`] handler function.
    pub trait FromInput<Input>: Send + 'static {
        /// Convert an Input into a parameter for the [`ServiceFn`] handler function.
        fn from_input(input: Input) -> Self;
    }

    impl<Input> FromInput<Input> for () {
        fn from_input(_input: Input) -> Self {}
    }

    impl<Input> FromInput<Input> for (Input,)
    where
        Input: Send + 'static,
    {
        fn from_input(input: Input) -> Self {
            (input,)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;

    #[tokio::test]
    async fn test_service_fn() {
        let services = vec![
            service_fn(async || Ok(())).boxed(),
            service_fn(async |req: String| {
                assert_eq!(req, "hello");
                Ok(())
            })
            .boxed(),
        ];

        for service in services {
            let req = "hello".to_owned();
            let res: Result<(), Infallible> = service.serve(req).await;
            assert!(res.is_ok());
        }
    }

    fn assert_send_sync<T: Send + Sync + 'static>(_t: T) {}

    #[test]
    fn test_service_fn_without_usage() {
        assert_send_sync(service_fn(async || Ok::<_, Infallible>(())));
        assert_send_sync(service_fn(async |_req: String| Ok::<_, Infallible>(())));
    }
}
