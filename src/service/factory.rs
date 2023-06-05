use super::Service;

pub trait ServiceFactory<Input> {
    type Error;
    type Service: Service<Input>;

    async fn new_service(&mut self) -> Result<Self::Service, Self::Error>;

    async fn handle_setup_error(&mut self, err: std::io::Error) -> Result<(), Self::Error> {
        tracing::error!("setup error: {}", err);
        Ok(())
    }

    async fn handle_service_error(
        &mut self,
        _: Self::Service,
        _: <Self::Service as Service<Input>>::Error,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<S, Input> ServiceFactory<Input> for S
where
    S: Service<Input> + Clone,
{
    type Error = <S as Service<Input>>::Error;
    type Service = S;

    async fn new_service(&mut self) -> Result<Self::Service, Self::Error> {
        Ok(self.clone())
    }
}
