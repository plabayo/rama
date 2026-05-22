use super::TlsConnectorDataBuilder;
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_net::{tls::client::ClientHelloExtension, transport::TryRefIntoTransportContext};
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

impl<S, Input> Service<Input> for EmulateTlsProfileService<S>
where
    Input: TryRefIntoTransportContext<Error: Into<BoxError>> + Send + ExtensionsRef + 'static,
    S: Service<Input, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let tls_profile = input.extensions().get_ref::<TlsProfile>().cloned();

        // Right now this is very simple, but it will get a lot more complex, which is why it is separated from the connector itself
        if let Some(profile) = tls_profile {
            let mut domain_overwrite = None;
            let mut emulate_config = Cow::Borrowed(profile.client_config.as_ref());

            let transport_ctx = input
                .try_ref_into_transport_ctx()
                .context("UA TLS Emulator: compute transport context to get authority")?;

            if profile
                .client_config
                .extensions
                .iter()
                .flatten()
                .any(|e| matches!(e, ClientHelloExtension::ServerName(_)))
            {
                let host = &transport_ctx.authority.host;
                // SNI is a DNS name. IP-first: pct-encoded IP literals
                // (`%31%32%37.0.0.1`) can promote to BOTH Domain and
                // IpAddr — emitting them as SNI would be wrong per
                // RFC 6066 §3 ("Literal IPv4 and IPv6 addresses are
                // not permitted in [SNI]"). Drop SNI for any IP-shaped
                // host. Otherwise, bridge `Uninterpreted` to Domain
                // via `try_as_domain`.
                let host_is_ip = host.try_as_ip().is_ok();
                let domain_opt = if host_is_ip {
                    None
                } else {
                    host.try_as_domain().ok()
                };
                if let Some(domain) = domain_opt {
                    tracing::trace!(
                        "ua tls emulator: ensure we append domain {domain} (SNI) overwriter"
                    );
                    domain_overwrite = Some(Arc::new(
                        TlsConnectorDataBuilder::new().with_server_name(domain.into_owned()),
                    ));
                } else {
                    tracing::trace!("ua tls emulator: drop SNI as target is not a domain: {host}");
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
            } else {
                tracing::trace!("ua tls emulator: no SNI defined, so neither do we");
            }

            // TODO dont always create this once we have moved away from ClientConfig
            // We can do that using something like `Arc::as_ptr` or adding something like a hash key to `TlsProfile`, or ...
            let emulate_builder =
                TlsConnectorDataBuilder::try_from(&profile.client_config)?.into_shared_builder();

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

            let mut builder = input
                .extensions()
                .get_ref::<TlsConnectorDataBuilder>()
                .cloned()
                .unwrap_or_default();

            tracing::trace!("push emulate TLS builder as base config");
            builder.push_base_config(emulate_builder);
            if let Some(overwrites) = self.builder_overwrites.clone() {
                tracing::trace!("push TLS builder static overwrites as base config");
                builder.push_base_config(overwrites);
            }

            if let Some(overwrite) = domain_overwrite.take() {
                tracing::trace!("push TLS builder domain overwrites as base config");
                builder.push_base_config(overwrite);
            }

            if let Some(overwrite) = ws_overwrite.take() {
                tracing::trace!("push TLS builder ws overwrites as base config");
                builder.push_base_config(overwrite);
            }

            input.extensions().insert(builder);
        }

        self.inner.serve(input).await.into_box_error()
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
