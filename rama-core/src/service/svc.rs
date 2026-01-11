//! [`Service`] and [`BoxService`] traits.

use std::convert::Infallible;
use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;

/// A [`Service`] that produces rama services,
/// to serve given an input, be it transport layer Inputs or application layer http requests,
/// or something else entirely.
pub trait Service<Input>: Sized + Send + Sync + 'static {
    /// The type of the output returned by the service.
    type Output: Send + 'static;

    /// The type of error returned by the service.
    type Error: Send + 'static;

    /// Serve an output or an error for the given input
    fn serve(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_;

    /// Box this service to allow for dynamic dispatch.
    fn boxed(self) -> BoxService<Input, Self::Output, Self::Error> {
        BoxService::new(self)
    }
}

impl<Input> Service<Input> for ()
where
    Input: Send + 'static,
{
    type Output = Input;
    type Error = Infallible;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        Ok(input)
    }
}

impl<S, Input> Service<Input> for std::sync::Arc<S>
where
    S: Service<Input>,
{
    type Output = S::Output;
    type Error = S::Error;

    #[inline]
    fn serve(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.as_ref().serve(input)
    }
}

impl<S, Input> Service<Input> for &'static S
where
    S: Service<Input>,
{
    type Output = S::Output;
    type Error = S::Error;

    #[inline(always)]
    fn serve(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        (**self).serve(input)
    }
}

impl<S, Input> Service<Input> for Box<S>
where
    S: Service<Input>,
{
    type Output = S::Output;
    type Error = S::Error;

    #[inline]
    fn serve(
        &self,

        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.as_ref().serve(input)
    }
}

/// Internal trait for dynamic dispatch of Async Traits,
/// implemented according to the pioneers of this Design Pattern
/// found at <https://rust-lang.github.io/async-fundamentals-initiative/evaluation/case-studies/builder-provider-api.html#dynamic-dispatch-behind-the-api>
/// and widely published at <https://blog.rust-lang.org/inside-rust/2023/05/03/stabilizing-async-fn-in-trait.html>.
trait DynService<Input> {
    type Output;
    type Error;

    #[allow(clippy::type_complexity)]
    fn serve_box(
        &self,

        input: Input,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + '_>>;
}

impl<Input, T> DynService<Input> for T
where
    T: Service<Input>,
{
    type Output = T::Output;
    type Error = T::Error;

    fn serve_box(
        &self,

        input: Input,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + '_>> {
        Box::pin(self.serve(input))
    }
}

/// A boxed [`Service`], to serve Inputs with,
/// for where you inputuire dynamic dispatch.
pub struct BoxService<Input, Output, Error> {
    inner: Arc<dyn DynService<Input, Output = Output, Error = Error> + Send + Sync + 'static>,
}

impl<Input, Output, Error> Clone for BoxService<Input, Output, Error> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<Input, Output, Error> BoxService<Input, Output, Error> {
    /// Create a new [`BoxService`] from the given service.
    #[inline]
    pub fn new<T>(service: T) -> Self
    where
        T: Service<Input, Output = Output, Error = Error>,
    {
        Self {
            inner: Arc::new(service),
        }
    }
}

impl<Input, Output, Error> std::fmt::Debug for BoxService<Input, Output, Error> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoxService").finish()
    }
}

impl<Input, Output, Error> Service<Input> for BoxService<Input, Output, Error>
where
    Input: 'static,
    Output: Send + 'static,
    Error: Send + 'static,
{
    type Output = Output;
    type Error = Error;

    #[inline]
    fn serve(
        &self,

        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        self.inner.serve_box(input)
    }

    #[inline]
    fn boxed(self) -> Self {
        self
    }
}

macro_rules! impl_service_either {
    ($id:ident, $first:ident $(, $param:ident)* $(,)?) => {
        impl<$first, $($param,)* Input, Output> Service<Input> for crate::combinators::$id<$first $(,$param)*>
        where
            $first: Service<Input, Output = Output>,
            $(
                $param: Service<Input, Output = Output, Error: Into<$first::Error>>,
            )*
            Input: Send + 'static,
            Output: Send + 'static,
        {
            type Output = Output;
            type Error = $first::Error;

            async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
                match self {
                    crate::combinators::$id::$first(s) => s.serve(input).await,
                    $(
                        crate::combinators::$id::$param(s) => s.serve(input).await.map_err(Into::into),
                    )*
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_service_either);

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default)]
/// A [`Service`] which will simply return the given input as Ok(_),
/// with an [`Infallible`] error.
pub struct MirrorService;

impl MirrorService {
    /// Create a new [`MirrorService`].
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<Input> Service<Input> for MirrorService
where
    Input: Send + 'static,
{
    type Output = Input;
    type Error = Infallible;

    #[inline]
    fn serve(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        std::future::ready(Ok(input))
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "Input rejected"]
    pub struct RejectError;
}

/// A [`Service`] which always rejects with an error.
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

impl<Input, Output, Error> Service<Input> for RejectService<Output, Error>
where
    Input: 'static,
    Output: Send + 'static,
    Error: Clone + Send + Sync + 'static,
{
    type Output = Output;
    type Error = Error;

    #[inline]
    fn serve(
        &self,

        _input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
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

    impl Service<usize> for AddSvc {
        type Output = usize;
        type Error = Infallible;

        async fn serve(&self, input: usize) -> Result<Self::Output, Self::Error> {
            Ok(self.0 + input)
        }
    }

    #[derive(Debug)]
    struct MulSvc(usize);

    impl Service<usize> for MulSvc {
        type Output = usize;
        type Error = Infallible;

        async fn serve(&self, input: usize) -> Result<Self::Output, Self::Error> {
            Ok(self.0 * input)
        }
    }

    #[test]
    fn assert_send() {
        use rama_utils::test_helpers::*;

        assert_send::<AddSvc>();
        assert_send::<MulSvc>();
        assert_send::<BoxService<(), (), ()>>();
        assert_send::<RejectService>();
    }

    #[test]
    fn assert_sync() {
        use rama_utils::test_helpers::*;

        assert_sync::<AddSvc>();
        assert_sync::<MulSvc>();
        assert_sync::<BoxService<(), (), ()>>();
        assert_sync::<RejectService>();
    }

    #[tokio::test]
    async fn add_svc() {
        let svc = AddSvc(1);

        let output = svc.serve(1).await.unwrap();
        assert_eq!(output, 2);
    }

    #[tokio::test]
    async fn static_dispatch() {
        let services = vec![AddSvc(1), AddSvc(2), AddSvc(3)];

        for (i, svc) in services.into_iter().enumerate() {
            let output = svc.serve(i).await.unwrap();
            assert_eq!(output, i * 2 + 1);
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

        for (i, svc) in services.into_iter().enumerate() {
            let output = svc.serve(i).await.unwrap();
            if i < 3 {
                assert_eq!(output, i * 2 + 1);
            } else {
                assert_eq!(output, i * (i + 1));
            }
        }
    }

    #[tokio::test]
    async fn service_arc() {
        let svc = std::sync::Arc::new(AddSvc(1));

        let output = svc.serve(1).await.unwrap();
        assert_eq!(output, 2);
    }

    #[tokio::test]
    async fn box_service_arc() {
        let svc = std::sync::Arc::new(AddSvc(1)).boxed();

        let output = svc.serve(1).await.unwrap();
        assert_eq!(output, 2);
    }

    #[tokio::test]
    async fn reject_svc() {
        let svc = RejectService::default();

        let err = svc.serve(1).await.unwrap_err();
        assert_eq!(err.to_string(), RejectError::new().to_string());
    }
}
