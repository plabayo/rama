use std::convert::Infallible;

pub use tower_async::Service;

pub trait ServiceFactory<Request> {
    type Error;
    type Service: Service<Request>;

    async fn new_service(&mut self) -> Result<Self::Service, Self::Error>;

    async fn handle_setup_error(&mut self, err: std::io::Error) -> Result<(), Self::Error> {
        tracing::error!("setup error: {}", err);
        Ok(())
    }

    async fn handle_service_error(
        &mut self,
        _: Self::Service,
        _: <Self::Service as Service<Request>>::Error,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<S, Request> ServiceFactory<Request> for S
where
    S: Service<Request> + Clone,
{
    type Error = Infallible;
    type Service = S;

    async fn new_service(&mut self) -> Result<Self::Service, Self::Error> {
        Ok(self.clone())
    }
}
