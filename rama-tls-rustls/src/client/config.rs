use crate::dep::rustls::ClientConfig;
use crate::dep::rustls::client::danger::ServerCertVerifier;
use rama_core::error::BoxError;
use rama_core::extensions::{Extension, Extensions, FromExtensions};
use rama_net::tls::TlsAlpn;
#[cfg(test)]
use rama_tls::KeyLogIntent;
use rama_tls::client::{
    TlsClientAuth, TlsClientConfig, TlsClientConfigProvider, TlsComponentIdentity,
    TlsPoolComponent, TlsPoolId, TlsServerCertPins, TlsServerName, TlsServerTrust, TlsServerVerify,
    TlsStoreServerCertChain,
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
    pub verifier: Option<Arc<RustlsServerCertVerifier>>,
    pub modify: Option<Arc<ModifyRustlsClientConfig>>,
}

impl RustlsTlsConnectorConfig<'_> {
    /// Whether any supported request-level TLS override is present.
    /// Inspect request extensions before layering connector defaults.
    pub fn has_overrides(&self) -> bool {
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

        alpn.is_some()
            || versions.is_some()
            || verify.is_some()
            || keylog.is_some()
            || server_name.is_some()
            || store_chain.is_some()
            || client_auth.is_some()
            || server_cert_pins.is_some()
            || server_trust.is_some()
            || verifier.is_some()
            || modify.is_some()
    }

    /// Compact identity of request-level overrides, or `None` for the baseline.
    ///
    /// Explicit defaults remain distinct from absence. Equivalent settings compare
    /// independently of the TLS implementation. Shared hooks, verifiers and log
    /// sinks reuse connections while retaining their original instance identity.
    /// Connector defaults are fixed for the lifetime of the pool and must not
    /// be layered onto this request-only view.
    pub fn pool_id(&self) -> Option<TlsPoolId> {
        if !self.has_overrides() {
            return None;
        }
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
        let mut builder = TlsPoolId::builder()
            .maybe_with_alpn(*alpn)
            .maybe_with_versions(*versions)
            .maybe_with_verify(*verify)
            .maybe_with_keylog(*keylog)
            .maybe_with_server_name(*server_name)
            .maybe_with_store_chain(*store_chain)
            .maybe_with_client_auth(*client_auth)
            .maybe_with_server_cert_pins(*server_cert_pins)
            .maybe_with_server_trust(*server_trust);
        if let Some(verifier) = verifier {
            builder.set_component(verifier.as_ref());
        }
        if let Some(modify) = modify {
            builder.set_shared_instance(modify);
        }
        builder.build()
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

impl TlsPoolComponent for RustlsServerCertVerifier {
    type Identity = TlsComponentIdentity<dyn ServerCertVerifier>;

    fn pool_component_identity(&self) -> Self::Identity {
        TlsComponentIdentity::shared(&self.0)
    }
}

#[derive(Extension)]
#[extension(tags(tls))]
/// Escape hatch: take over the final rustls [`ClientConfig`] build.
///
/// Rama builds the config from the common [`TlsClientConfig`] pieces and as the
/// last step of building, hands it to this function. Either tweak the input
/// and return it, or ignore it and build a fresh one through the full rustls
/// builder for anything the common pieces can't express.
///
/// For request overrides, pool reuse follows the shared extension owner. Share
/// its `Arc` across requests to retain the same hook identity. Its TLS policy
/// must remain fixed while connections or cached configurations can be reused;
/// replace the extension owner when captured mutable state changes that policy.
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

/// Classification of request overrides understood by Rustls.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustlsTlsClientConfigProvider;

impl TlsClientConfigProvider for RustlsTlsClientConfigProvider {
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
        RustlsTlsConnectorConfig::from_extensions(extensions).pool_id()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        RustlsTlsConnectorConfig::from_extensions(extensions).authenticates_server()
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;
    use crate::verify::NoServerCertVerifier;
    use rama_core::extensions::Extensions;
    use rama_tls::ProtocolVersion;
    use rama_tls::client::{ClientAuth, ServerVerifyMode, TlsServerCertPin, TlsServerTrustAnchors};
    use rama_tls::keylog::NoopKeyLogSink;

    #[test]
    fn every_comparable_override_preserves_presence_and_value() {
        type Insert = fn(&Extensions, u8);
        let cases: &[(&str, Insert)] = &[
            ("empty_alpn", |ext, value| {
                ext.insert(if value == 0 {
                    TlsAlpn::empty()
                } else {
                    TlsAlpn::http_2()
                });
            }),
            ("keylog_environment_disabled", |ext, value| {
                ext.insert(TlsKeyLog(if value == 0 {
                    KeyLogIntent::Environment
                } else {
                    KeyLogIntent::Disabled
                }));
            }),
            ("alpn", |ext, value| {
                ext.insert(if value == 0 {
                    TlsAlpn::http_1()
                } else {
                    TlsAlpn::http_2()
                });
            }),
            ("versions", |ext, value| {
                ext.insert(TlsSupportedVersions(vec![if value == 0 {
                    ProtocolVersion::TLSv1_2
                } else {
                    ProtocolVersion::TLSv1_3
                }]));
            }),
            ("verify", |ext, value| {
                ext.insert(TlsServerVerify(if value == 0 {
                    ServerVerifyMode::Auto
                } else {
                    ServerVerifyMode::Disable
                }));
            }),
            ("keylog", |ext, value| {
                ext.insert(TlsKeyLog(KeyLogIntent::File(format!("pool-test-{value}"))));
            }),
            ("server_name", |ext, value| {
                ext.insert(TlsServerName(
                    if value == 0 {
                        "one.example"
                    } else {
                        "two.example"
                    }
                    .parse()
                    .unwrap(),
                ));
            }),
            ("store_chain", |ext, value| {
                ext.insert(TlsStoreServerCertChain(value != 0));
            }),
            ("pins", |ext, value| {
                ext.insert(TlsServerCertPins::new(TlsServerCertPin::SpkiSha256(
                    [value; 32],
                )));
            }),
            ("trust", |ext, value| {
                ext.insert(TlsServerTrust::custom(
                    TlsServerTrustAnchors::try_new([vec![value; 4096].into()]).unwrap(),
                ));
            }),
        ];
        for (name, insert) in cases {
            let first = Extensions::new();
            let empty = RustlsTlsConnectorConfig::from_extensions(&first);
            assert!(!empty.has_overrides(), "{name}");
            assert_eq!(empty.pool_id(), None, "{name}");
            insert(&first, 0);
            let view = RustlsTlsConnectorConfig::from_extensions(&first);
            assert!(view.has_overrides(), "{name}");
            let id = view.pool_id().unwrap();
            assert!(id.is_reusable(), "{name}");
            let equal = Extensions::new();
            insert(&equal, 0);
            assert_eq!(
                Some(id.clone()),
                RustlsTlsConnectorConfig::from_extensions(&equal).pool_id(),
                "{name}"
            );
            let changed = Extensions::new();
            insert(&changed, 1);
            assert_ne!(
                Some(id),
                RustlsTlsConnectorConfig::from_extensions(&changed).pool_id(),
                "{name}"
            );
            // Newest request settings replace older values of the same type.
            insert(&first, 1);
            assert_eq!(
                RustlsTlsConnectorConfig::from_extensions(&first).pool_id(),
                RustlsTlsConnectorConfig::from_extensions(&changed).pool_id(),
                "{name}"
            );
        }
    }

    #[test]
    fn custom_overrides_reuse_their_shared_policy() {
        let cases: &[fn(&Extensions)] = &[
            |ext| {
                ext.insert(TlsClientAuth(ClientAuth::SelfSigned));
            },
            |ext| {
                ext.insert(TlsKeyLog(KeyLogIntent::Custom(Arc::new(NoopKeyLogSink))));
            },
            |ext| {
                ext.insert(ModifyRustlsClientConfig::new(Ok));
            },
            |ext| {
                ext.insert(RustlsServerCertVerifier(Arc::new(
                    NoServerCertVerifier::new(),
                )));
            },
        ];
        for insert in cases {
            let extensions = Extensions::new();
            insert(&extensions);
            let view = RustlsTlsConnectorConfig::from_extensions(&extensions);
            assert!(view.has_overrides());
            let id = view.pool_id().unwrap();
            assert!(id.is_reusable());
            assert_eq!(Some(id), view.pool_id());
        }
    }

    #[test]
    fn cloned_native_components_match_but_replacements_do_not() {
        let verifier = RustlsServerCertVerifier(Arc::new(NoServerCertVerifier::new()));
        let modify = Arc::new(ModifyRustlsClientConfig::new(Ok));
        let first = Extensions::new();
        first.insert(verifier.clone());
        first.insert_arc(modify.clone());
        let same = Extensions::new();
        same.insert_arc(modify);
        same.insert(verifier);
        let identity = RustlsTlsClientConfigProvider.pool_id(&first);
        assert_eq!(identity, RustlsTlsClientConfigProvider.pool_id(&same));
        same.insert(ModifyRustlsClientConfig::new(Ok));
        assert_ne!(identity, RustlsTlsClientConfigProvider.pool_id(&same));
        let same = first.fork();
        same.insert(RustlsServerCertVerifier(Arc::new(
            NoServerCertVerifier::new(),
        )));
        assert_ne!(identity, RustlsTlsClientConfigProvider.pool_id(&same));
    }

    #[test]
    fn hook_pool_identity_keeps_the_extension_owner_alive() {
        let hook = Arc::new(ModifyRustlsClientConfig::new(Ok));
        let weak = Arc::downgrade(&hook);
        let extensions = Extensions::new();
        extensions.insert_arc(hook.clone());
        let identity = RustlsTlsClientConfigProvider.pool_id(&extensions).unwrap();

        drop((hook, extensions));
        assert!(weak.upgrade().is_some());
        drop(identity);
        assert!(weak.upgrade().is_none());
    }
}
