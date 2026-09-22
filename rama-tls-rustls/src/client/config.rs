use crate::dep::rustls::ClientConfig;
use crate::dep::rustls::client::danger::ServerCertVerifier;
use rama_core::error::BoxError;
use rama_core::extensions::{Extension, FromExtensions};
use rama_net::tls::TlsAlpn;
use rama_tls::client::{
    TlsClientAuth, TlsClientConfig, TlsServerCertPins, TlsServerName, TlsServerTrust,
    TlsServerVerify, TlsStoreServerCertChain,
};
use rama_tls::{TlsKeyLog, TlsSupportedVersions};
use rama_utils::macros::generate_set_and_with;
use std::sync::Arc;

/// Gather all the TLS extensions supported by rustls
#[derive(FromExtensions)]
pub struct RustlsTlsConnectorConfig<'a> {
    pub alpn: Option<&'a TlsAlpn>,
    pub versions: Option<&'a TlsSupportedVersions>,
    pub verify: Option<&'a TlsServerVerify>,
    pub keylog: Option<&'a TlsKeyLog>,
    pub server_name: Option<&'a TlsServerName>,
    pub store_chain: Option<&'a TlsStoreServerCertChain>,
    pub client_auth: Option<&'a TlsClientAuth>,
    pub server_cert_pins: Option<&'a TlsServerCertPins>,
    pub server_trust: Option<&'a TlsServerTrust>,
    pub verifier: Option<&'a RustlsServerCertVerifier>,
    pub modify: Option<&'a ModifyRustlsClientConfig>,
}

impl RustlsTlsConnectorConfig<'_> {
    /// Whether no request-level TLS configuration is present.
    ///
    /// A connection pool dedicated to a fixed connector policy can reuse its
    /// connections only when request extensions do not override that policy.
    /// Inspect the request extensions before layering connector defaults.
    pub fn is_empty(&self) -> bool {
        // Name every field so additions require an explicit pooling decision.
        let Self {
            alpn,
            versions,
            verify,
            keylog,
            server_name,
            store_chain,
            client_auth,
            server_cert_pins,
            server_trust,
            verifier,
            modify,
        } = self;

        alpn.is_none()
            && versions.is_none()
            && verify.is_none()
            && keylog.is_none()
            && server_name.is_none()
            && store_chain.is_none()
            && client_auth.is_none()
            && server_cert_pins.is_none()
            && server_trust.is_none()
            && verifier.is_none()
            && modify.is_none()
    }

    /// Whether a successful handshake establishes the configured server identity.
    pub fn authenticates_server(&self) -> bool {
        // New fields must also be reviewed for their effect on authentication.
        let Self {
            alpn: _,
            versions: _,
            verify,
            keylog: _,
            server_name: _,
            store_chain: _,
            client_auth: _,
            server_cert_pins: _,
            server_trust: _,
            verifier,
            modify,
        } = self;

        verifier.is_none()
            && modify.is_none()
            && verify.is_none_or(|verify| verify.0 != rama_tls::client::ServerVerifyMode::Disable)
    }

    /// Build a native TLS client configuration using the supplied cryptographic provider.
    ///
    /// This does not read or install the process-wide default provider. Certificate
    /// verification uses the same provider. The modify hook runs last and may replace
    /// the configuration, including its provider.
    pub fn try_into_client_config_with_provider(
        self,
        provider: Arc<crate::dep::rustls::crypto::CryptoProvider>,
    ) -> Result<ClientConfig, BoxError> {
        super::connector_data::build_client_config(&self, Some(provider))
    }
}

/// Rustls specific setters for [`TlsClientConfig`].
pub trait RustlsClientConfigExt: Sized {
    generate_set_and_with! {
        /// Set a custom server certificate verifier
        ///
        /// Ignored with [`ServerVerifyMode::Disable`]; takes precedence over
        /// common server trust policy. With server certificate pins
        /// configured, it verifies certificates that pass the pin check.
        ///
        /// [`ServerVerifyMode::Disable`]: rama_tls::client::ServerVerifyMode::Disable
        fn cert_verifier(self, verifier: Arc<dyn ServerCertVerifier>) -> Self;
    }

    generate_set_and_with! {
        /// Take over the final rustls [`ClientConfig`] build: see [`ModifyRustlsClientConfig`].
        fn modify_rustls_config(
            self,
            modify: impl Fn(ClientConfig) -> Result<ClientConfig, BoxError> + Send + Sync + 'static,
        ) -> Self;
    }
}

impl RustlsClientConfigExt for TlsClientConfig {
    generate_set_and_with! {
        fn cert_verifier(mut self, verifier: Arc<dyn ServerCertVerifier>) -> Self {
            self.insert(RustlsServerCertVerifier(verifier));
            self
        }
    }

    generate_set_and_with! {
        fn modify_rustls_config(
            mut self,
            modify: impl Fn(ClientConfig) -> Result<ClientConfig, BoxError> + Send + Sync + 'static,
        ) -> Self {
            self.insert(ModifyRustlsClientConfig::new(modify));
            self
        }
    }
}

#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
/// A custom rustls server certificate verifier
pub struct RustlsServerCertVerifier(pub Arc<dyn ServerCertVerifier>);

#[derive(Extension)]
#[extension(tags(tls))]
/// Escape hatch: take over the final rustls [`ClientConfig`] build.
///
/// Rama builds the config from the common [`TlsClientConfig`] pieces and as the
/// last step of building, hands it to this function. Either tweak the input
/// and return it, or ignore it and build a fresh one through the full rustls
/// builder for anything the common pieces can't express.
pub struct ModifyRustlsClientConfig(pub Box<ModifyFn>);

type ModifyFn = dyn Fn(ClientConfig) -> Result<ClientConfig, BoxError> + Send + Sync + 'static;

impl ModifyRustlsClientConfig {
    pub fn new<F>(modify: F) -> Self
    where
        F: Fn(ClientConfig) -> Result<ClientConfig, BoxError> + Send + Sync + 'static,
    {
        Self(Box::new(modify))
    }

    pub(crate) fn apply(&self, config: ClientConfig) -> Result<ClientConfig, BoxError> {
        (self.0)(config)
    }
}

impl std::fmt::Debug for ModifyRustlsClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyRustlsClientConfig")
            .finish_non_exhaustive()
    }
}
