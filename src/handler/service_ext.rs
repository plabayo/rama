use super::IntoMakeService;
use tower_service::Service;

/// Extension trait that adds additional methods to any [`Service`].
pub trait ServiceExt<R>: Service<R> + Sized {
    /// Convert this service into a [`MakeService`], that is a [`Service`] whose
    /// response is another service.
    ///
    /// [`MakeService`]: tower::make::MakeService
    fn into_make_service(self) -> IntoMakeService<Self>;
}

impl<S, R> ServiceExt<R> for S
where
    S: Service<R> + Sized,
{
    fn into_make_service(self) -> IntoMakeService<Self> {
        IntoMakeService::new(self)
    }
}
