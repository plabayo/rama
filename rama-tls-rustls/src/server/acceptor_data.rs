use crate::RamaTlsRustlsCrateMarker;
use crate::dep::rustls::{self, ALL_VERSIONS};
use crate::key_log::RamaKeyLog;
use rama_core::conversion::{RamaTryFrom, RamaTryInto};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext};
use rama_core::extensions::Extension;
use rama_core::telemetry::tracing;
use rama_net::tls::keylog::open_intent_sink;
use rama_net::tls::server::{ClientVerifyMode, SelfSignedData, ServerAuthData};
use std::pin::Pin;
use std::sync::Arc;

#[derive(Clone, Debug, Extension)]
#[extension(tags(tls))]
/// Internal data used as configuration/input for the [`super::TlsAcceptorService`].
///
/// Built from a [`TlsServerConfig`] by gathering its common pieces.
///
/// [`TlsServerConfig`]: rama_net::tls::server::TlsServerConfig
pub struct TlsAcceptorData {
    pub(super) server_config: ServerConfig,
}

#[derive(Clone)]
/// [`ServerConfig`] used to configure rustls
///
/// This can either be a directly stored [`rustls::ServerConfig`], or a [`rustls::ServerConfig`]
/// returned by a [`DynamicConfigProvider`] based on the received client hello
pub(super) enum ServerConfig {
    Stored(Arc<rustls::ServerConfig>),
    Async(Arc<dyn DynDynamicConfigProvider + Send + Sync>),
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stored(arg0) => f.debug_tuple("Stored").field(arg0).finish(),
            Self::Async(_) => f
                .debug_tuple("Async")
                .field(&"dynamic config provider")
                .finish(),
        }
    }
}

impl TryFrom<&rama_net::tls::server::TlsServerConfig> for TlsAcceptorData {
    type Error = BoxError;

    fn try_from(value: &rama_net::tls::server::TlsServerConfig) -> Result<Self, Self::Error> {
        Self::try_from(super::config::RustlsTlsAcceptorConfig::from_extensions(
            value.as_extensions(),
        ))
    }
}

impl TryFrom<super::config::RustlsTlsAcceptorConfig<'_>> for TlsAcceptorData {
    type Error = BoxError;

    fn try_from(value: super::config::RustlsTlsAcceptorConfig<'_>) -> Result<Self, Self::Error> {
        crate::ensure_default_crypto_provider();

        // Dynamic escape hatch: resolve a full config per ClientHello, ignoring
        // the static pieces.
        if let Some(dynamic) = value.dynamic {
            Ok(Self {
                server_config: ServerConfig::Async(dynamic.0.clone()),
            })
        } else {
            let config = rustls::ServerConfig::try_from(value)?;
            Ok(Self {
                server_config: ServerConfig::Stored(Arc::new(config)),
            })
        }
    }
}

impl RamaTryFrom<rama_net::tls::server::TlsServerConfig, RamaTlsRustlsCrateMarker>
    for rustls::ServerConfig
{
    type Error = BoxError;

    fn rama_try_from(value: rama_net::tls::server::TlsServerConfig) -> Result<Self, Self::Error> {
        Self::try_from(super::config::RustlsTlsAcceptorConfig::from_extensions(
            value.as_extensions(),
        ))
    }
}

impl RamaTryFrom<&rama_net::tls::server::TlsServerConfig, RamaTlsRustlsCrateMarker>
    for rustls::ServerConfig
{
    type Error = BoxError;

    fn rama_try_from(value: &rama_net::tls::server::TlsServerConfig) -> Result<Self, Self::Error> {
        Self::try_from(super::config::RustlsTlsAcceptorConfig::from_extensions(
            value.as_extensions(),
        ))
    }
}

impl TryFrom<super::config::RustlsTlsAcceptorConfig<'_>> for rustls::ServerConfig {
    type Error = BoxError;
    fn try_from(value: super::config::RustlsTlsAcceptorConfig<'_>) -> Result<Self, Self::Error> {
        crate::ensure_default_crypto_provider();
        if value.dynamic.is_some() {
            tracing::debug!(
                "ignoring dynamic field when converting RustlsTlsAcceptorConfig into rustls::ServerConfig directly",
            )
        }

        // Versions: rustls only models TLS 1.2/1.3; anything else (incl. GREASE)
        // is dropped. Empty = all supported versions.
        let versions: Vec<&'static rustls::SupportedProtocolVersion> = value
            .versions
            .map(|v| {
                v.0.iter()
                    .filter_map(|pv| (*pv).rama_try_into().ok())
                    .collect()
            })
            .unwrap_or_default();
        let builder = if versions.is_empty() {
            Self::builder_with_protocol_versions(ALL_VERSIONS)
        } else {
            Self::builder_with_protocol_versions(&versions)
        };

        let builder = match value.client_verify.map(|v| &v.0) {
            None | Some(ClientVerifyMode::Auto | ClientVerifyMode::Disable) => {
                builder.with_no_client_auth()
            }
            Some(ClientVerifyMode::ClientAuth(certs)) => {
                let mut roots = rustls::RootCertStore::empty();
                for cert in certs {
                    roots
                        .add(cert.to_owned())
                        .context("rustls server: add client CA cert to root store")?;
                }
                let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .context("rustls server: build client cert verifier")?;
                builder.with_client_cert_verifier(verifier)
            }
        };

        let (cert_chain, key, ocsp) = match value.server_auth.map(|a| a.0.clone()) {
            Some(ServerAuthData {
                cert_chain,
                ocsp,
                private_key,
            }) => (cert_chain, private_key, ocsp),
            // No server identity configured. If a modify hook is present, build a
            // self-signed scaffold so the hook can install its own cert source.
            // Without a modify hook there is nothing to serve, so this is an error.
            None if value.modify.is_some() => {
                let (chain, key) =
                    rama_crypto::cert::self_signed_server_auth(SelfSignedData::default())?;
                (chain, key, None)
            }
            None => {
                return Err(BoxError::from_static_str(
                    "rustls server: no server auth configured (set TlsServerConfig::with_server_auth)",
                ));
            }
        };

        let mut server_config = match ocsp {
            Some(ocsp) => builder
                .with_single_cert_with_ocsp(cert_chain, key, ocsp)
                .context("rustls server: set single cert with ocsp")?,
            None => builder
                .with_single_cert(cert_chain, key)
                .context("rustls server: set single cert")?,
        };

        if let Some(alpn) = value.alpn {
            server_config.alpn_protocols = alpn.0.iter().map(|p| p.as_bytes().to_vec()).collect();
        }

        if let Some(keylog) = value.keylog
            && let Some(sink) = open_intent_sink(&keylog.0)?
        {
            server_config.key_log = Arc::new(RamaKeyLog::new(sink));
        }

        if let Some(modify) = value.modify {
            server_config = modify.apply(server_config)?;
        }

        Ok(server_config)
    }
}

impl From<rustls::ServerConfig> for TlsAcceptorData {
    #[inline]
    fn from(value: rustls::ServerConfig) -> Self {
        Arc::new(value).into()
    }
}

impl From<Arc<rustls::ServerConfig>> for TlsAcceptorData {
    fn from(value: Arc<rustls::ServerConfig>) -> Self {
        Self {
            server_config: ServerConfig::Stored(value),
        }
    }
}

impl<D: DynamicConfigProvider> From<D> for TlsAcceptorData {
    fn from(value: D) -> Self {
        Arc::new(value).into()
    }
}

impl<D: DynamicConfigProvider> From<Arc<D>> for TlsAcceptorData {
    fn from(value: Arc<D>) -> Self {
        Self {
            server_config: ServerConfig::Async(value),
        }
    }
}

pub trait DynamicConfigProvider: Send + Sync + 'static {
    fn get_config(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> impl Future<Output = Result<Arc<rustls::ServerConfig>, BoxError>> + Send;
}

/// Internal trait to support dynamic dispatch of trait with async fn.
/// See trait [`rama_core::service::svc::DynService`] for more info about this pattern.
pub(crate) trait DynDynamicConfigProvider {
    fn get_config<'a, 'b: 'a>(
        &'a self,
        client_hello: rustls::server::ClientHello<'b>,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<rustls::ServerConfig>, BoxError>> + Send + 'a>>;
}

impl<T> DynDynamicConfigProvider for T
where
    T: DynamicConfigProvider,
{
    fn get_config<'a, 'b: 'a>(
        &'a self,
        client_hello: rustls::server::ClientHello<'b>,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<rustls::ServerConfig>, BoxError>> + Send + 'a>>
    {
        Box::pin(self.get_config(client_hello))
    }
}

#[cfg(all(test, any(feature = "aws-lc", feature = "ring")))]
mod server_pieces_tests {
    use super::*;
    use rama_net::tls::server::{SelfSignedData, TlsServerConfig};

    fn stored(data: &TlsAcceptorData) -> Option<&Arc<rustls::ServerConfig>> {
        match &data.server_config {
            ServerConfig::Stored(cfg) => Some(cfg),
            ServerConfig::Async(_) => None,
        }
    }

    #[test]
    fn build_from_pieces_self_signed_with_alpn() {
        crate::ensure_default_crypto_provider();
        let cfg = TlsServerConfig::new()
            .try_with_self_signed(SelfSignedData::default())
            .unwrap()
            .with_alpn_http_auto();
        let data = TlsAcceptorData::try_from(&cfg).unwrap();
        assert_eq!(
            stored(&data).unwrap().alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        );
    }

    #[test]
    fn modify_rustls_config_runs_last() {
        use super::super::config::RustlsServerConfigExt;
        crate::ensure_default_crypto_provider();
        let cfg = TlsServerConfig::new()
            .try_with_self_signed(SelfSignedData::default())
            .unwrap()
            .with_alpn_http_auto()
            .with_modify_rustls_config(|mut c| {
                c.alpn_protocols = vec![b"my-proto".to_vec()];
                Ok(c)
            });
        let data = TlsAcceptorData::try_from(&cfg).unwrap();
        assert_eq!(
            stored(&data).unwrap().alpn_protocols,
            vec![b"my-proto".to_vec()]
        );
    }

    #[test]
    fn missing_server_auth_errors() {
        crate::ensure_default_crypto_provider();
        let cfg = TlsServerConfig::new().with_alpn_http_auto();
        TlsAcceptorData::try_from(&cfg).unwrap_err();
    }
}
