use std::marker::PhantomData;

use rama_core::{Layer, Service};

use crate::server::NamedService;

/// A layered service to propagate [`NamedService`] implementation.
#[derive(Debug, Clone)]
pub struct Layered<S, T> {
    inner: S,
    _ty: PhantomData<T>,
}

impl<S, T: NamedService> NamedService for Layered<S, T> {
    const NAME: &'static str = T::NAME;
}

impl<Req, S, T> Service<Req> for Layered<S, T>
where
    S: Service<Req>,
    Req: Send + 'static,
    T: Send + Sync + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, request: Req) -> Result<Self::Output, Self::Error> {
        self.inner.serve(request).await
    }
}

/// Extension trait which adds utility methods to types which implement [`Layer`].
pub trait LayerExt<L>: sealed::Sealed {
    /// Applies the layer to a service and wraps it in [`Layered`].
    fn named_layer<S>(&self, service: S) -> Layered<L::Service, S>
    where
        L: Layer<S>;
}

impl<L> LayerExt<L> for L {
    fn named_layer<S>(&self, service: S) -> Layered<<L>::Service, S>
    where
        L: Layer<S>,
    {
        Layered {
            inner: self.layer(service),
            _ty: PhantomData,
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl<T> Sealed for T {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct TestService {}

    const TEST_SERVICE_NAME: &str = "test-service-name";

    impl NamedService for TestService {
        const NAME: &'static str = TEST_SERVICE_NAME;
    }

    // Checks if the argument implements `NamedService` and returns the implemented `NAME`.
    fn get_name_of_named_service<S: NamedService>(_s: &S) -> &'static str {
        S::NAME
    }

    #[test]
    fn named_service_is_propagated_to_layered() {
        use rama_core::layer::timeout::TimeoutLayer;
        use std::time::Duration;

        let layered = TimeoutLayer::new(Duration::from_secs(5)).named_layer(TestService::default());
        assert_eq!(get_name_of_named_service(&layered), TEST_SERVICE_NAME);
    }
}
