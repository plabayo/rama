use super::TlsConnectorDataBuilder;
use rama_core::{Layer, Service, error::BoxError};
use rama_ua::profile::TlsProfile;
use rama_utils::macros::generate_set_and_with;
use std::sync::Arc;

pub struct EmulateTlsProfileService<S> {
    inner: S,
    builder_overwrites: Option<Arc<TlsConnectorDataBuilder>>,
}

impl<S> EmulateTlsProfileService<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            builder_overwrites: None,
        }
    }

    generate_set_and_with!(
        /// Set overwrites that will always be applied when a Tls Profile is applied
        ///
        /// It does this by setting this builder chain: Base -> TlsProfile -> Overwrites, instead
        /// of just setting Base -> TlsProfile
        pub fn builder_overwrites(mut self, builder: Option<Arc<TlsConnectorDataBuilder>>) -> Self {
            self.builder_overwrites = builder;
            self
        }
    );
}

impl<S, State, Request> Service<State, Request> for EmulateTlsProfileService<S>
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

        // Right now this is very simple, but it will get a lot more complex, which is why it is separated from the connector itself
        if let Some(profile) = tls_profile {
            // TODO dont always create this once we have moved away from ClientConfig
            // We can do that using something like `Arc::as_ptr` or adding something like a hash key to `TlsProfile`, or ...
            let emulate_builder = TlsConnectorDataBuilder::try_from(&profile.client_config)
                .map_err(Into::<BoxError>::into)?
                .into_shared_builder();

            let builder = ctx.get_or_insert_default::<TlsConnectorDataBuilder>();
            builder.push_base_config(emulate_builder);
            if let Some(overwrites) = self.builder_overwrites.clone() {
                builder.push_base_config(overwrites);
            }
        }

        self.inner.serve(ctx, req).await.map_err(Into::into)
    }
}

#[non_exhaustive]
#[derive(Default, Clone)]
pub struct EmulateTlsProfileLayer {
    builder_overwrites: Option<Arc<TlsConnectorDataBuilder>>,
}

impl EmulateTlsProfileLayer {
    pub fn new() -> Self {
        Self {
            builder_overwrites: None,
        }
    }

    generate_set_and_with!(
        /// Set overwrites that will always be applied when a Tls Profile is applied
        ///
        /// It does this by setting this builder chain: Base -> TlsProfile -> Overwrites, instead
        /// of just setting Base -> TlsProfile
        pub fn builder_overwrites(mut self, builder: Option<Arc<TlsConnectorDataBuilder>>) -> Self {
            self.builder_overwrites = builder;
            self
        }
    );
}

impl<S> Layer<S> for EmulateTlsProfileLayer {
    type Service = EmulateTlsProfileService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EmulateTlsProfileService {
            builder_overwrites: self.builder_overwrites.clone(),
            inner,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        EmulateTlsProfileService {
            builder_overwrites: self.builder_overwrites,
            inner,
        }
    }
}
