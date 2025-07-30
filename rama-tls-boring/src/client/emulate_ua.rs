use super::TlsConnectorDataBuilder;
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    telemetry::tracing,
};
use rama_net::{
    address::Host, tls::client::ClientHelloExtension, transport::TryRefIntoTransportContext,
};
use rama_ua::profile::TlsProfile;
use rama_utils::macros::generate_set_and_with;
use std::{borrow::Cow, sync::Arc};

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
    Request: TryRefIntoTransportContext<State, Error: Into<BoxError>> + Send + 'static,
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
            let mut domain_overwrite = None;
            let mut emulate_config = Cow::Borrowed(profile.client_config.as_ref());

            let transport_ctx = ctx
                .get_or_try_insert_with_ctx(|ctx| req.try_ref_into_transport_ctx(ctx))
                .map_err(|err| {
                    OpaqueError::from_boxed(err.into())
                        .context("UA TLS Emulator: compute transport context to get authority")
                })?;

            if profile
                .client_config
                .extensions
                .iter()
                .flatten()
                .any(|e| matches!(e, ClientHelloExtension::ServerName(_)))
            {
                match transport_ctx.authority.host() {
                    Host::Name(domain) => {
                        tracing::trace!(
                            "ua tls emulator: ensure we append domain {domain} (SNI) overwriter"
                        );
                        domain_overwrite = Some(Arc::new(
                            TlsConnectorDataBuilder::new().with_server_name(domain.clone()),
                        ));
                    }
                    Host::Address(ip) => {
                        tracing::trace!("ua tls emulator: drop SNI as target is IP: {ip}");
                        let cfg = emulate_config.to_mut();
                        let extensions: Vec<_> = cfg
                            .extensions
                            .take()
                            .into_iter()
                            .flatten()
                            .filter(|ext| !matches!(ext, ClientHelloExtension::ServerName(_)))
                            .collect();
                        if !extensions.is_empty() {
                            cfg.extensions = Some(extensions);
                        }
                    }
                }
            } else {
                tracing::trace!("ua tls emulator: no SNI defined, so neither do we");
            }

            // TODO dont always create this once we have moved away from ClientConfig
            // We can do that using something like `Arc::as_ptr` or adding something like a hash key to `TlsProfile`, or ...
            let emulate_builder = TlsConnectorDataBuilder::try_from(&profile.client_config)
                .map_err(Into::<BoxError>::into)?
                .into_shared_builder();

            let mut ws_overwrite = None;
            if transport_ctx
                .app_protocol
                .as_ref()
                .map(|p| p.is_ws())
                .unwrap_or_default()
                && let Some(overwrites) = profile.ws_client_config_overwrites
                && let Some(alpn) = overwrites.alpn
            {
                ws_overwrite = Some(Arc::new(
                    TlsConnectorDataBuilder::new()
                        .try_with_rama_alpn_protos(alpn.as_slice())
                        .context("set rama ALPNs")?,
                ));
            }

            let builder = ctx.get_or_insert_default::<TlsConnectorDataBuilder>();
            builder.push_base_config(emulate_builder);
            if let Some(overwrites) = self.builder_overwrites.clone() {
                builder.push_base_config(overwrites);
            }

            if let Some(overwrite) = domain_overwrite.take() {
                builder.push_base_config(overwrite);
            }

            if let Some(overwrite) = ws_overwrite.take() {
                builder.push_base_config(overwrite);
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
    #[must_use]
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
