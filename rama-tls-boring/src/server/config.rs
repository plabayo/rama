use crate::server::ServerCertIssuerData;

use rama_core::extensions::{Extension, FromExtensions};
use rama_tls::server::{TlsClientVerify, TlsServerAuth, TlsServerConfig, TlsStoreClientCertChain};
use rama_tls::{TlsAlpn, TlsKeyLog, TlsSupportedVersions};

/// Gather all the TLS extensions supported by boring
#[derive(FromExtensions)]
pub struct BoringTlsAcceptorConfig<'a> {
    pub alpn: Option<&'a TlsAlpn>,
    pub versions: Option<&'a TlsSupportedVersions>,
    pub keylog: Option<&'a TlsKeyLog>,
    pub client_verify: Option<&'a TlsClientVerify>,
    pub store_client_chain: Option<&'a TlsStoreClientCertChain>,
    pub auth: Option<BoringTlsAuth<'a>>,
}

#[derive(FromExtensions)]
/// Auth used by boring acceptor
pub enum BoringTlsAuth<'a> {
    ServerAuth(&'a TlsServerAuth),
    CertIssuer(&'a BoringServerCertIssuer),
}

/// Boring specific tls setters.
pub trait BoringServerConfigExt: Sized {
    rama_utils::macros::generate_set_and_with! {
        /// Issue server certs on the fly (from a CA or a custom [`DynamicCertIssuer`]),
        /// with optional in-memory caching.
        fn cert_issuer(self, data: ServerCertIssuerData) -> Self;
    }
}

impl BoringServerConfigExt for TlsServerConfig {
    rama_utils::macros::generate_set_and_with! {
        fn cert_issuer(mut self, data: ServerCertIssuerData) -> Self {
            self.insert(BoringServerCertIssuer(data));
            self
        }
    }
}

/// Issue server certs on the fly. See [`BoringServerConfigExt::with_cert_issuer`].
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringServerCertIssuer(pub ServerCertIssuerData);
