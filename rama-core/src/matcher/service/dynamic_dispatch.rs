use std::{fmt, pin::Pin, sync::Arc};

use super::{ServiceMatch, ServiceMatcher};

/// Dynamic-dispatch interface for [`ServiceMatcher`].
///
/// This is mainly useful behind [`BoxServiceMatcher`], but is public so
/// crates building their own matcher containers can reuse the same pattern.
pub trait DynServiceMatcher<Input>: Send + Sync + 'static {
    /// The value returned when a match succeeds.
    type Service: Send + 'static;
    /// The error that can happen while evaluating the matcher.
    type Error: Send + 'static;

    /// Attempt to select a service for `input`.
    #[allow(clippy::type_complexity)]
    fn match_service_box(
        &self,
        input: Input,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ServiceMatch<Input, Self::Service>, Self::Error>>
                + Send
                + '_,
        >,
    >;
}

impl<Input, T> DynServiceMatcher<Input> for T
where
    T: ServiceMatcher<Input>,
{
    type Service = T::Service;
    type Error = T::Error;

    fn match_service_box(
        &self,
        input: Input,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ServiceMatch<Input, Self::Service>, Self::Error>>
                + Send
                + '_,
        >,
    > {
        Box::pin(self.match_service(input))
    }
}

/// A boxed [`ServiceMatcher`].
///
/// This gives dynamic dispatch without constraining the selected value.
pub struct BoxServiceMatcher<Input, SelectedService, Error> {
    inner: Arc<dyn DynServiceMatcher<Input, Service = SelectedService, Error = Error> + Send + Sync + 'static>,
}

impl<Input, SelectedService, Error> Clone
    for BoxServiceMatcher<Input, SelectedService, Error>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<Input, SelectedService, Error> BoxServiceMatcher<Input, SelectedService, Error>
{
    /// Create a boxed matcher from a concrete matcher implementation.
    #[inline]
    pub fn new<T>(matcher: T) -> Self
    where
        T: ServiceMatcher<Input, Service = SelectedService, Error = Error>,
    {
        Self {
            inner: Arc::new(matcher),
        }
    }
}

impl<Input, SelectedService, Error> fmt::Debug for BoxServiceMatcher<Input, SelectedService, Error>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxServiceMatcher").finish()
    }
}

impl<Input, SelectedService, Error> ServiceMatcher<Input>
    for BoxServiceMatcher<Input, SelectedService, Error>
where
    Input: 'static,
    SelectedService: Send + 'static,
    Error: Send + 'static,
{
    type Service = SelectedService;
    type Error = Error;

    #[inline]
    fn match_service(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<ServiceMatch<Input, Self::Service>, Self::Error>> + Send + '_
    {
        self.inner.match_service_box(input)
    }

    fn into_match_service(
        self,
        input: Input,
    ) -> impl Future<Output = Result<ServiceMatch<Input, Self::Service>, Self::Error>> + Send
    where
        Self: Sized,
        Input: Send,
    {
        async move { self.inner.match_service_box(input).await }
    }

    #[inline]
    fn boxed(self) -> Self {
        self
    }
}
