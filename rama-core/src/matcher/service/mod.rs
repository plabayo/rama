use std::sync::Arc;

mod dynamic_dispatch;
mod match_service_pair;
mod tuples;

pub use self::{
    dynamic_dispatch::{BoxServiceMatcher, DynServiceMatcher},
    match_service_pair::MatcherServicePair,
};

/// The result of attempting to select a service for an input.
///
/// The original input is always returned so that matcher-added extensions
/// can continue through the pipeline even when no service matched.
#[derive(Debug, Clone)]
pub struct ServiceMatch<Input, Service> {
    /// The input after matcher evaluation.
    pub input: Input,
    /// The selected service, if any matcher accepted the input.
    pub service: Option<Service>,
}

/// Selects a concrete service for an input.
///
/// This is useful when the service decision itself depends on runtime input,
/// while still preserving the selected value for later processing.
pub trait ServiceMatcher<Input>: Send + Sync + 'static {
    /// The value returned when a match succeeds.
    type Service: Send + 'static;
    /// The error that can happen while evaluating the matcher.
    type Error: Send + 'static;

    type ModifiedInput: Send + 'static;

    /// Attempt to select a service for `input`.
    fn match_service(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error>>
    + Send
    + '_;

    /// Attempt to select a service for `input`, consuming the matcher.
    ///
    /// Override this when the matcher stores services by value and can return
    /// them without cloning.
    fn into_match_service(
        self,
        input: Input,
    ) -> impl Future<Output = Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error>> + Send
    where
        Self: Sized,
        Input: Send,
    {
        async move { self.match_service(input).await }
    }

    /// Box this matcher for dynamic dispatch.
    fn boxed(self) -> BoxServiceMatcher<Input, Self::Service, Self::Error, Self::ModifiedInput>
    where
        Self: Sized,
    {
        BoxServiceMatcher::new(self)
    }
}

impl<Input, M> ServiceMatcher<Input> for Arc<M>
where
    M: ServiceMatcher<Input>,
{
    type Service = M::Service;
    type Error = M::Error;
    type ModifiedInput = M::ModifiedInput;

    fn match_service(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error>>
    + Send
    + '_ {
        (**self).match_service(input)
    }

    async fn into_match_service(
        self,
        input: Input,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error>
    where
        Self: Sized,
        Input: Send,
    {
        (*self).match_service(input).await
    }
}
