use super::acceptor_data::{DynDynamicConfigProvider, DynamicConfigProvider};
use crate::dep::rustls::ServerConfig;
use rama_core::error::BoxError;
use rama_core::extensions::{Extension, FromExtensions};
use rama_net::tls::server::{TlsClientVerify, TlsServerAuth, TlsStoreClientCertChain};
use rama_net::tls::{TlsAlpn, TlsKeyLog, TlsSupportedVersions};
use std::sync::Arc;

/// Gather all config pieces support by rustls
#[derive(FromExtensions)]
pub struct RustlsTlsAcceptorConfig<'a> {
    pub server_auth: Option<&'a TlsServerAuth>,
    pub alpn: Option<&'a TlsAlpn>,
    pub versions: Option<&'a TlsSupportedVersions>,
    pub keylog: Option<&'a TlsKeyLog>,
    pub client_verify: Option<&'a TlsClientVerify>,
    pub store_client_chain: Option<&'a TlsStoreClientCertChain>,
    pub modify: Option<&'a ModifyRustlsServerConfig>,
    pub dynamic: Option<&'a RustlsDynamicConfig>,
}

/// Rustls-specific setters.
pub trait RustlsServerConfigExt: Sized {
    rama_utils::macros::generate_set_and_with! {
        /// Take over the final rustls [`ServerConfig`] build: see [`ModifyRustlsServerConfig`].
        fn modify_rustls_config(
            self,
            modify: impl Fn(ServerConfig) -> Result<ServerConfig, BoxError> + Send + Sync + 'static,
        ) -> Self;
    }

    rama_utils::macros::generate_set_and_with! {
        /// Resolve a full [`rustls::ServerConfig`] per ClientHello via a [`DynamicConfigProvider`]
        ///
        /// When set, the common static pieces are ignored.
        ///
        /// [`rustls::ServerConfig`]: ServerConfig
        #[must_use]
        fn dynamic_config(self, provider: Arc<impl DynamicConfigProvider>) -> Self;
    }
}

impl RustlsServerConfigExt for rama_net::tls::server::TlsServerConfig {
    rama_utils::macros::generate_set_and_with! {
        fn modify_rustls_config(
            mut self,
            modify: impl Fn(ServerConfig) -> Result<ServerConfig, BoxError> + Send + Sync + 'static,
        ) -> Self {
            self.insert(ModifyRustlsServerConfig::new(modify));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        fn dynamic_config(mut self, provider: Arc<impl DynamicConfigProvider>) -> Self {
            self.insert(RustlsDynamicConfig(provider));
            self
        }
    }
}

/// A [`DynamicConfigProvider`] piece: resolves a full rustls config per
/// ClientHello
#[derive(Extension)]
#[extension(tags(tls))]
pub struct RustlsDynamicConfig(pub(crate) Arc<dyn DynDynamicConfigProvider + Send + Sync>);

impl std::fmt::Debug for RustlsDynamicConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsDynamicConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Extension)]
#[extension(tags(tls))]
/// Escape hatch: take over the final rustls [`ServerConfig`] build.
///
/// Rama builds the config from the common [`TlsServerConfig`] pieces and as the
/// last step hands it to this function. Either tweak the input and return it,
/// or ignore it and build a fresh one through the full rustls builder for
/// anything the common pieces can't express (e.g. a custom
/// [`ResolvesServerCert`]).
///
/// If no server auth piece is set, the base config handed to this hook is
/// backed by a freshly generated self-signed certificate, so the hook can
/// install its own cert source (such as a resolver) without first configuring
/// one through the common pieces.
///
/// [`TlsServerConfig`]: rama_net::tls::server::TlsServerConfig
/// [`ResolvesServerCert`]: ServerConfig
pub struct ModifyRustlsServerConfig(pub Box<ModifyFn>);

type ModifyFn = dyn Fn(ServerConfig) -> Result<ServerConfig, BoxError> + Send + Sync + 'static;

impl ModifyRustlsServerConfig {
    pub fn new<F>(modify: F) -> Self
    where
        F: Fn(ServerConfig) -> Result<ServerConfig, BoxError> + Send + Sync + 'static,
    {
        Self(Box::new(modify))
    }

    pub(crate) fn apply(&self, config: ServerConfig) -> Result<ServerConfig, BoxError> {
        (self.0)(config)
    }
}

impl std::fmt::Debug for ModifyRustlsServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyRustlsServerConfig")
            .finish_non_exhaustive()
    }
}
