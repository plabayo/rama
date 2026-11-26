//! Prepared ECH keys shared by the TCP and QUIC server backends.

mod input;

use std::{
    fmt,
    sync::{Arc, Weak},
};

use arc_swap::ArcSwap;
use rama_boring::{
    hpke::HpkeKey,
    ssl::{SslContext, SslContextRef, SslEchKeys, SslMethod},
};
use rama_core::error::{BoxError, BoxErrorExt as _};

/// One ECHConfig and its separately generated X25519 private key.
///
/// The config is a single encoded ECHConfig, without the ECHConfigList prefix.
/// Borrowed private bytes are parsed on load and are never retained by Rama.
/// The caller remains responsible for clearing its input buffer.
#[non_exhaustive]
pub struct EchServerKey<'a> {
    /// The encoded ECHConfig.
    pub config: &'a [u8],
    /// The private key of `config`.
    pub private_key: &'a [u8],
    /// Advertise this config after authenticated rejection. Retiring keys can
    /// remain decryptable without being advertised to new clients.
    pub retry: bool,
}

impl<'a> EchServerKey<'a> {
    /// A single encoded X25519 ECHConfig, its private key and retry policy.
    #[must_use]
    pub const fn new(config: &'a [u8], private_key: &'a [u8], retry: bool) -> Self {
        Self {
            config,
            private_key,
            retry,
        }
    }
}

impl fmt::Debug for EchServerKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchServerKey")
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

/// An immutable, validated generation of accepted keys and retry configs.
///
/// Construction checks key/config correspondence in BoringSSL. At least one
/// retry config is required. Clone the `Arc`, never the private key material.
#[non_exhaustive]
pub struct EchServerKeys {
    native: SslEchKeys,
    retry_configs: Box<[u8]>,
}

impl fmt::Debug for EchServerKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchServerKeys").finish_non_exhaustive()
    }
}

impl EchServerKeys {
    /// Prepare a fixed single key or an ordered rotation set before serving it.
    pub fn new<'a>(
        keys: impl IntoIterator<Item = EchServerKey<'a>>,
    ) -> Result<Arc<Self>, BoxError> {
        let mut native = SslEchKeys::builder()?;
        let mut retry_configs = vec![0, 0];
        let mut ids = [false; 256];
        let mut count = 0;
        for key in keys {
            // BoringSSL validates the complete encoding and public/private key
            // correspondence below; the config ID is at offset four.
            let id = *key
                .config
                .get(4)
                .ok_or_else(|| BoxError::from_static_str("truncated ECHConfig"))?;
            if std::mem::replace(&mut ids[usize::from(id)], true) {
                return Err(BoxError::from_static_str("duplicate ECH config ID"));
            }
            native.add_key(
                key.retry,
                key.config,
                HpkeKey::dhkem_x25519_sha256(key.private_key)?,
            )?;
            if key.retry {
                let length = retry_configs
                    .len()
                    .checked_add(key.config.len())
                    .filter(|length| *length <= usize::from(u16::MAX) + 2)
                    .ok_or_else(|| {
                        BoxError::from_static_str("ECH retry list exceeds wire limit")
                    })?;
                retry_configs.reserve(length - retry_configs.len());
                retry_configs.extend_from_slice(key.config);
            }
            count += 1;
        }
        if count == 0 || retry_configs.len() == 2 {
            return Err(BoxError::from_static_str(
                "ECH keys require at least one retry config",
            ));
        }
        let length = u16::try_from(retry_configs.len() - 2)?;
        retry_configs[..2].copy_from_slice(&length.to_be_bytes());
        let native = native.build();
        // Installation validates backend constraints now, before publication.
        let context = SslContext::builder(SslMethod::tls_server())?;
        context.set_ech_keys(&native)?;
        Ok(Arc::new(Self {
            native,
            retry_configs: retry_configs.into(),
        }))
    }

    /// Public ECHConfigList suitable for the HTTPS `ech` SvcParam.
    pub fn retry_configs(&self) -> &[u8] {
        &self.retry_configs
    }

    /// Install a complete generation. BoringSSL snapshots it when processing
    /// the first ClientHello and retains it through HRR and retry advertisement.
    pub fn install(&self, context: &SslContextRef) -> Result<(), BoxError> {
        context.set_ech_keys(&self.native)?;
        Ok(())
    }
}

/// Prepared ECH configuration with optional live context updates.
///
/// Contexts subscribe once at construction. Updates must push complete validated
/// generations; no provider work or key parsing runs on the handshake path.
/// BoringSSL takes its stable snapshot at the first ClientHello, not TCP accept.
pub trait EchServerKeysProvider: Send + Sync + 'static {
    /// The current generation of keys.
    fn snapshot(&self) -> Arc<EchServerKeys>;

    /// Install the current generation and register a context for future updates.
    /// Registration and replacement must be serialized to avoid stale installs.
    fn bind_context(&self, context: SslContext) -> Result<Arc<SslContext>, BoxError>;
}

impl EchServerKeysProvider for Arc<EchServerKeys> {
    fn snapshot(&self) -> Arc<EchServerKeys> {
        self.clone()
    }

    fn bind_context(&self, context: SslContext) -> Result<Arc<SslContext>, BoxError> {
        self.install(&context)?;
        Ok(Arc::new(context))
    }
}

struct LiveKeys {
    keys: ArcSwap<EchServerKeys>,
    contexts: parking_lot::Mutex<Vec<Weak<SslContext>>>,
}

/// Shared atomic key snapshots and serialized updates of live native contexts.
///
/// Replacement preserves TLS contexts and their session tickets. Atomicity is
/// per native context; install overlapping A+B on all endpoints before publishing
/// B in DNS. Existing handshakes retain the generation they already observed.
#[derive(Clone)]
#[non_exhaustive]
pub struct ReloadableEchServerKeys(Arc<LiveKeys>);

impl fmt::Debug for ReloadableEchServerKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReloadableEchServerKeys")
            .finish_non_exhaustive()
    }
}

impl ReloadableEchServerKeys {
    /// Start from the generation `keys`.
    pub fn new(keys: Arc<EchServerKeys>) -> Self {
        Self(Arc::new(LiveKeys {
            keys: ArcSwap::from(keys),
            contexts: parking_lot::Mutex::new(Vec::new()),
        }))
    }

    /// Publish an already validated generation without rebuilding TLS contexts.
    /// Failed parsing happens before this call and leaves the last set intact.
    pub fn replace(&self, keys: Arc<EchServerKeys>) -> Result<(), BoxError> {
        let mut contexts = self.0.contexts.lock();
        contexts.retain(|context| context.strong_count() != 0);
        // Installation of a validated immutable set only takes a native reference;
        // native validation has already succeeded in EchServerKeys::new.
        let previous = self.snapshot();
        let active: Vec<_> = contexts.iter().filter_map(Weak::upgrade).collect();
        for context in &active {
            if let Err(error) = keys.install(context) {
                for context in &active {
                    previous.install(context)?;
                }
                return Err(error);
            }
        }
        self.0.keys.store(keys);
        Ok(())
    }
}

impl EchServerKeysProvider for ReloadableEchServerKeys {
    fn snapshot(&self) -> Arc<EchServerKeys> {
        self.0.keys.load_full()
    }

    fn bind_context(&self, context: SslContext) -> Result<Arc<SslContext>, BoxError> {
        let mut contexts = self.0.contexts.lock();
        self.snapshot().install(&context)?;
        let context = Arc::new(context);
        contexts.retain(|context| context.strong_count() != 0);
        contexts.push(Arc::downgrade(&context));
        Ok(context)
    }
}

#[cfg(test)]
#[path = "../../../tests/support/ech_keys.rs"]
mod fixtures;

#[cfg(test)]
pub(crate) mod tests {
    use super::super::{BoringServerConfigExt as _, TlsAcceptorService};
    pub(crate) use super::fixtures::{SERVER_ECH_CONFIG, SERVER_ECH_KEY};
    use super::*;
    use rama_boring::{
        ssl::{Ssl, SslContentType, SslVerifyMode, is_ech_rejected},
        x509::{X509, verify::X509VerifyFlags},
    };
    use rama_core::{Service, ServiceInput, extensions::ExtensionsRef, service::service_fn};
    use rama_net::address::Domain;
    use rama_tls::{
        SecureTransport,
        client::{ClientHelloExtension, ECHClientHello, parse_client_hello},
        server::{
            GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData, ServerEchAccepted,
            TlsServerConfig,
        },
    };
    use rama_utils::octets::kib;

    fn key(config: &[u8], retry: bool) -> EchServerKey<'_> {
        EchServerKey {
            config,
            private_key: SERVER_ECH_KEY,
            retry,
        }
    }

    #[test]
    fn rotation_keeps_snapshots_and_only_advertises_active_keys() {
        let mut b = SERVER_ECH_CONFIG.to_vec();
        b[4] = 2;
        let a = EchServerKeys::new([key(SERVER_ECH_CONFIG, true)]).unwrap();
        let provider = ReloadableEchServerKeys::new(a.clone());
        let held = provider.snapshot();
        let both = EchServerKeys::new([key(SERVER_ECH_CONFIG, false), key(&b, true)]).unwrap();
        assert_eq!(&both.retry_configs()[2..], &b);
        provider.replace(both.clone()).unwrap();
        assert!(Arc::ptr_eq(&provider.snapshot(), &both));
        assert!(Arc::ptr_eq(&held, &a));
        let b = EchServerKeys::new([key(&b, true)]).unwrap();
        provider.replace(b.clone()).unwrap();
        assert!(Arc::ptr_eq(&provider.snapshot(), &b));
        assert_eq!(&held.retry_configs()[2..], SERVER_ECH_CONFIG);
    }

    #[test]
    fn invalid_updates_preserve_last_valid_generation() {
        let a = EchServerKeys::new([key(SERVER_ECH_CONFIG, true)]).unwrap();
        let provider = ReloadableEchServerKeys::new(a.clone());
        let wrong_key = [0; 32];
        for keys in [
            vec![],
            vec![key(SERVER_ECH_CONFIG, false)],
            vec![key(SERVER_ECH_CONFIG, true), key(SERVER_ECH_CONFIG, false)],
            vec![key(&[0; 5], true)],
            vec![EchServerKey {
                config: SERVER_ECH_CONFIG,
                private_key: &wrong_key,
                retry: true,
            }],
        ] {
            let next = EchServerKeys::new(keys);
            next.unwrap_err();
            assert!(Arc::ptr_eq(&provider.snapshot(), &a));
        }
    }

    #[test]
    fn debug_does_not_disclose_key_material() {
        assert_eq!(
            format!("{:?}", key(SERVER_ECH_CONFIG, true)),
            "EchServerKey { retry: true, .. }"
        );
        let keys = EchServerKeys::new([key(SERVER_ECH_CONFIG, true)]).unwrap();
        assert_eq!(format!("{keys:?}"), "EchServerKeys { .. }");
        assert_eq!(
            format!("{:?}", ReloadableEchServerKeys::new(keys)),
            "ReloadableEchServerKeys { .. }"
        );
    }

    #[tokio::test]
    async fn tcp_acceptance_and_effective_hello_follow_rotation() {
        let a = EchServerKeys::new([key(SERVER_ECH_CONFIG, true)]).unwrap();
        let provider = ReloadableEchServerKeys::new(a.clone());
        let service = TlsAcceptorService::new(
            TlsServerConfig::generated_http_auto()
                .unwrap()
                .with_ech_keys(provider.clone()),
            service_fn(
                |stream: crate::TlsStream<ServiceInput<tokio::io::DuplexStream>>| async move {
                    let accepted = stream
                        .extensions()
                        .get_ref::<ServerEchAccepted>()
                        .unwrap()
                        .0;
                    let hello = stream
                        .extensions()
                        .get_ref::<SecureTransport>()
                        .unwrap()
                        .client_hello()
                        .unwrap()
                        .clone();
                    Ok::<_, BoxError>((accepted, hello))
                },
            ),
            true,
        );
        let mut b_config = SERVER_ECH_CONFIG.to_vec();
        b_config[4] = 2;
        let b = EchServerKeys::new([key(&b_config, true)]).unwrap();
        let both =
            EchServerKeys::new([key(SERVER_ECH_CONFIG, false), key(&b_config, true)]).unwrap();
        for (generation, client_keys) in [
            (a.clone(), a.clone()),
            (both.clone(), a.clone()),
            (both, b.clone()),
            (b.clone(), b),
        ] {
            provider.replace(generation).unwrap();
            for (real, grease) in [(true, false), (false, false), (false, true)] {
                let mut context = SslContext::builder(SslMethod::tls_client()).unwrap();
                context.set_verify(SslVerifyMode::NONE);
                let mut ssl = Ssl::new(&context.build()).unwrap();
                ssl.set_hostname("localhost").unwrap();
                ssl.set_alpn_protos(b"\x02h2").unwrap();
                ssl.set_enable_ech_grease(grease);
                let wire = Arc::new(parking_lot::Mutex::new(None));
                let captured = wire.clone();
                ssl.set_msg_callback(move |_, message| {
                    if message.is_written()
                        && message.content_type() == SslContentType::HANDSHAKE
                        && message.handshake_type() == Some(1)
                    {
                        *captured.lock() = Some(parse_client_hello(&message.bytes()[4..]).unwrap());
                    }
                });
                if real {
                    ssl.set_ech_config_list(client_keys.retry_configs())
                        .unwrap();
                }
                let (client, server) = tokio::io::duplex(kib(64));
                let (client, server) = tokio::join!(
                    rama_boring_tokio::SslStreamBuilder::new(ssl, client).connect(),
                    service.serve(ServiceInput::new(server)),
                );
                assert_eq!(client.unwrap().ssl().ech_accepted(), real);
                let (accepted, hello) = server.unwrap();
                assert_eq!(accepted, real);
                assert_eq!(hello.ext_server_domain().unwrap().as_str(), "localhost");
                if !real {
                    assert_eq!(
                        serde_json::to_value(wire.lock().as_ref().unwrap()).unwrap(),
                        serde_json::to_value(&hello).unwrap()
                    );
                } else {
                    assert_eq!(
                        wire.lock()
                            .as_ref()
                            .unwrap()
                            .ext_server_domain()
                            .unwrap()
                            .as_str(),
                        "ech.com"
                    );
                }
                assert_eq!(
                    hello.extensions().iter().any(|extension| matches!(
                        extension,
                        ClientHelloExtension::EncryptedClientHello(ECHClientHello::Inner)
                    )),
                    real
                );
            }
        }
    }

    #[tokio::test]
    async fn retired_key_rejection_advertises_exact_current_configs() {
        let leaf = LeafCertRequest {
            identities: ["localhost", "ech.com"]
                .map(|name| Domain::try_from(name).unwrap().into())
                .to_vec(),
            ..Default::default()
        };
        let auth =
            ServerAuthData::new_generated(GeneratedServerAuthConfig::SelfSignedLeaf(leaf)).unwrap();
        let mut context = SslContext::builder(SslMethod::tls_client()).unwrap();
        context.set_verify(SslVerifyMode::PEER);
        context
            .cert_store_mut()
            .set_flags(X509VerifyFlags::PARTIAL_CHAIN);
        context
            .cert_store_mut()
            .add_cert(X509::from_der(auth.cert_chain.last().unwrap()).unwrap())
            .unwrap();
        let context = context.build();
        let old = EchServerKeys::new([key(SERVER_ECH_CONFIG, true)]).unwrap();
        let provider = ReloadableEchServerKeys::new(old.clone());
        let service = TlsAcceptorService::new(
            TlsServerConfig::new()
                .with_server_auth(auth)
                .with_ech_keys(provider.clone()),
            service_fn(
                |stream: crate::TlsStream<ServiceInput<tokio::io::DuplexStream>>| async move {
                    Ok::<_, BoxError>(
                        stream
                            .extensions()
                            .get_ref::<ServerEchAccepted>()
                            .unwrap()
                            .0,
                    )
                },
            ),
            true,
        );
        let mut new_config = SERVER_ECH_CONFIG.to_vec();
        new_config[4] = 2;
        let current = EchServerKeys::new([key(&new_config, true)]).unwrap();
        provider.replace(current.clone()).unwrap();
        let mut ssl = Ssl::new(&context).unwrap();
        ssl.set_hostname("localhost").unwrap();
        ssl.param_mut().set_host("localhost").unwrap();
        ssl.set_ech_config_list(old.retry_configs()).unwrap();
        let (client, server) = tokio::io::duplex(kib(64));
        let (client, server) = tokio::join!(
            rama_boring_tokio::SslStreamBuilder::new(ssl, client).connect(),
            service.serve(ServiceInput::new(server)),
        );
        let error = client.unwrap_err();
        assert!(
            error
                .as_ssl_error_stack()
                .unwrap()
                .iter()
                .any(|error| { is_ech_rejected(error.library_code(), error.reason_code()) }),
            "{error:?}"
        );
        let ssl = error.ssl().unwrap();
        assert!(!ssl.ech_accepted());
        assert_eq!(ssl.get_ech_retry_configs(), Some(current.retry_configs()));
        assert!(!server.unwrap());
    }
}
