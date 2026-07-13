use crate::dep::rustls::ClientConfig;
use crate::dep::rustls::client::danger::ServerCertVerifier;
use rama_core::error::BoxError;
use rama_core::extensions::{Extension, FromExtensions};
use rama_tls::client::{
    TlsClientAuth, TlsClientConfig, TlsServerCertPins, TlsServerName, TlsServerVerify,
    TlsStoreServerCertChain,
};
use rama_tls::{TlsAlpn, TlsKeyLog, TlsSupportedVersions};
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
    pub verifier: Option<&'a RustlsServerCertVerifier>,
    pub modify: Option<&'a ModifyRustlsClientConfig>,
}

/// Rustls specific setters for [`TlsClientConfig`].
pub trait RustlsClientConfigExt: Sized {
    rama_utils::macros::generate_set_and_with! {
        /// Set a custom server certificate verifier
        fn cert_verifier(self, verifier: Arc<dyn ServerCertVerifier>) -> Self;
    }

    rama_utils::macros::generate_set_and_with! {
        /// Take over the final rustls [`ClientConfig`] build: see [`ModifyRustlsClientConfig`].
        fn modify_rustls_config(
            self,
            modify: impl Fn(ClientConfig) -> Result<ClientConfig, BoxError> + Send + Sync + 'static,
        ) -> Self;
    }
}

impl RustlsClientConfigExt for TlsClientConfig {
    rama_utils::macros::generate_set_and_with! {
        fn cert_verifier(mut self, verifier: Arc<dyn ServerCertVerifier>) -> Self {
            self.insert(RustlsServerCertVerifier(verifier));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
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
