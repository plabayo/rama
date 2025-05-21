use super::TlsConnectorDataBuilder;
use rama_core::{Layer, Service, error::BoxError};
use rama_ua::profile::TlsProfile;

pub struct EmulateTlsService<S> {
    inner: S,
}

impl<S> EmulateTlsService<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, State, Request> Service<State, Request> for EmulateTlsService<S>
where
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
    S: Service<State, Request, Error: Into<BoxError>>,
{
    type Response = S::Response;

    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: rama_core::Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let tls_profile = ctx.get::<TlsProfile>().cloned();

        if let Some(profile) = tls_profile {
            let builder =
                ctx.get_or_insert_with::<TlsConnectorDataBuilder>(TlsConnectorDataBuilder::new);

            // TODO dont always create this once we have moved away from ClientConfig
            // We can do that using something like `Arc::as_ptr` or adding something like a hash key to `TlsProfile`, or ...
            let emulate_base = TlsConnectorDataBuilder::try_from(&profile.client_config)
                .map_err(Into::<BoxError>::into)?;

            builder.push_base_config(emulate_base.into());
        }

        self.inner.serve(ctx, req).await.map_err(Into::into)
    }
}

#[non_exhaustive]
pub struct EmulateTlsLayer;

impl EmulateTlsLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for EmulateTlsLayer {
    type Service = EmulateTlsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EmulateTlsService::new(inner)
    }
}
