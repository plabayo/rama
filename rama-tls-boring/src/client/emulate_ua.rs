use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_net::tls::client::TlsClientConfig;
use rama_net::transport::TryRefIntoTransportContext;
use rama_ua::profile::TlsProfile;
use rama_utils::macros::generate_set_and_with;

use crate::client::BoringClientConfigExt;

pub struct EmulateTlsProfileService<S> {
    inner: S,
    config_overwrites: Option<TlsClientConfig>,
}

impl<S> EmulateTlsProfileService<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            config_overwrites: None,
        }
    }

    generate_set_and_with!(
        /// Set config pieces that are always layered on top of the emulated
        /// profile (they override the profile, newest-wins).
        pub fn config_overwrites(mut self, config: Option<TlsClientConfig>) -> Self {
            self.config_overwrites = config;
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
        if let Some(profile) = input.extensions().get_arc::<TlsProfile>() {
            // Create a config for for the provided client_hello
            // TODO we could cache this in the future
            let mut cfg = TlsClientConfig::new_from_client_hello(&profile.client_hello);

            // Apply overwrites to config
            if let Some(overwrites) = &self.config_overwrites {
                tracing::trace!("ua tls emulator: layer static config overwrites");
                overwrites.write_to(cfg.as_extensions());
            }

            // WebSocket ALPN override (highest priority).
            let transport_ctx = input
                .try_ref_into_transport_ctx()
                .context("UA TLS Emulator: compute transport context")?;
            if transport_ctx
                .app_protocol
                .as_ref()
                .map(|p| p.is_ws())
                .unwrap_or_default()
                && let Some(overwrites) = &profile.ws_client_config_overwrites
                && let Some(alpn) = overwrites.alpn.clone()
            {
                tracing::trace!(?alpn, "ua tls emulator: layer websocket ALPN overwrite");
                cfg.set_alpn(alpn.into());
            }

            // Apply config to our input
            cfg.write_to(input.extensions());
        }

        self.inner.serve(input).await.into_box_error()
    }
}

#[non_exhaustive]
#[derive(Default, Clone)]
pub struct EmulateTlsProfileLayer {
    config_overwrites: Option<TlsClientConfig>,
}

impl EmulateTlsProfileLayer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            config_overwrites: None,
        }
    }

    generate_set_and_with!(
        /// Set config pieces that are always layered on top of the emulated
        /// profile (they override the profile).
        pub fn config_overwrites(mut self, config: Option<TlsClientConfig>) -> Self {
            self.config_overwrites = config;
            self
        }
    );
}

impl<S> Layer<S> for EmulateTlsProfileLayer {
    type Service = EmulateTlsProfileService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        EmulateTlsProfileService {
            config_overwrites: self.config_overwrites.clone(),
            inner,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        EmulateTlsProfileService {
            config_overwrites: self.config_overwrites,
            inner,
        }
    }
}
