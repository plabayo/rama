use crate::certificate_compression::{
    NativeCertificateCompression, SUPPORTED_CERTIFICATE_COMPRESSION, add_certificate_compressors,
    native_certificate_compression,
};
use crate::client::config::BoringTlsConnectorConfig;
use crate::client::server_answer::ServerAnswerRecorder;
use crate::client::session::{
    self, SessionStore, TlsClientSession, TlsClientSessionKey, TlsClientSessionStore,
};
use crate::type_conversion::native_unique;
use ahash::{HashSet, HashSetExt as _};
use moka::sync::Cache;
use rama_boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    sha::sha256,
    ssl::{
        ClientHelloShape, ConnectConfiguration, GreaseLists, SslConnector, SslConnectorBuilder,
        SslCredential, SslCurve, SslMethod, SslOptions, SslRef, SslSessionCacheMode,
        SslSignatureAlgorithm, SslVerifyMode, SslVersion,
    },
    x509::{
        X509,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        store::{X509Store, X509StoreBuilder},
        verify::X509VerifyFlags,
    },
};
use rama_core::bytes::Bytes;
use rama_core::error::BoxErrorExt as _;
use rama_core::telemetry::tracing::{debug, trace};
use rama_core::{
    conversion::RamaTryInto,
    error::{BoxError, ErrorContext, ErrorExt},
};
use rama_crypto::dep::x509_parser::nom::AsBytes;
use rama_net::{address::Host, tls::ApplicationProtocol};
use rama_tls::client::ClientAuth;
use rama_tls::client::TlsClientConfig;
use rama_tls::client::{ServerTrustRoots, ServerVerifyMode};
use rama_tls::client::{TlsPoolId, TlsServerCertPins};
use rama_tls::client::{TlsServerTrust, TlsServerTrustAnchors};
use rama_tls::{ExtensionId, KeyLogIntent};
use rama_utils::macros::generate_set_and_with;
use std::{
    fmt,
    sync::{Arc, LazyLock},
};

use rama_tls::keylog::{KeyLogSink, open_intent_sink};

/// The resolved native BoringSSL config consumed by [`super::TlsConnector`].
pub struct TlsConnectorData {
    pub config: ConnectConfiguration,
    pub store_server_certificate_chain: bool,
    /// Record the ServerHello for the connection's negotiated parameters.
    pub store_server_hello: bool,
    pub server_name: Option<Host>,
    pub server_verify_mode: ServerVerifyMode,
    pub server_cert_pins: Option<TlsServerCertPins>,
    remembers_sessions: bool,
    session_store: Option<SessionStore>,
}

/// Shared client configuration, including native context callbacks and session state.
#[derive(Clone, Debug)]
pub struct TlsConnectorContext {
    connector: SslConnector,
    options: ConnectorOptions,
}

/// Configures a reusable client TLS context before it is shared.
pub struct TlsConnectorContextBuilder {
    pub config: SslConnectorBuilder,
    options: ConnectorOptions,
}

impl fmt::Debug for TlsConnectorContextBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnectorContextBuilder")
            .field("server_name", &self.options.server_name)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
struct ConnectorOptions {
    store_server_certificate_chain: bool,
    store_server_hello: bool,
    server_name: Option<Host>,
    server_verify_mode: ServerVerifyMode,
    server_cert_pins: Option<TlsServerCertPins>,
    wire: WirePlan,
    remembers_sessions: bool,
    session_store: Option<SessionStore>,
}

/// Every ClientHello setting, applied per connection: a native context carries only the
/// security policy, so one context serves every wire variant of that policy.
#[derive(Clone, Debug)]
struct WirePlan {
    cipher_list: Option<Vec<u16>>,
    alpn_protos: Option<Bytes>,
    curves: Option<Vec<SslCurve>>,
    key_shares: Option<Vec<SslCurve>>,
    verify_algorithm_prefs: Option<Vec<SslSignatureAlgorithm>>,
    min_version: Option<SslVersion>,
    max_version: Option<SslVersion>,
    extension_order: Option<Vec<u16>>,
    permute_extensions: bool,
    requested_trust_anchors: Option<Vec<u8>>,
    grease: GreaseLists,
    ocsp_stapling: bool,
    signed_cert_timestamps: bool,
    session_tickets: bool,
    certificate_compression: Vec<NativeCertificateCompression>,
    alps: Option<(Vec<ApplicationProtocol>, bool)>,
    record_size_limit: Option<u16>,
    delegated_credential_schemes: Option<Vec<SslSignatureAlgorithm>>,
    encrypted_client_hello: bool,
}

impl WirePlan {
    fn apply(&self, cfg: &mut ConnectConfiguration) -> Result<(), BoxError> {
        if !self.grease.is_empty() {
            cfg.set_client_hello_shape(&ClientHelloShape::new().with_grease_lists(self.grease))
                .context("set GREASE lists")?;
        }
        if self.permute_extensions {
            cfg.set_permute_extensions(true);
        } else if let Some(order) = &self.extension_order {
            cfg.set_extension_order(order)
                .context("set extension order")?;
        }
        if let Some(ids) = &self.requested_trust_anchors {
            cfg.set_requested_trust_anchors(ids)
                .context("set requested trust anchors")?;
        }
        if let Some(list) = &self.cipher_list {
            cfg.set_raw_cipher_list(list).context("set cipher list")?;
        }
        if let Some(protos) = &self.alpn_protos {
            cfg.set_alpn_protos(protos).context("set alpn protos")?;
        }
        if let Some(curves) = &self.curves {
            cfg.set_curves(curves).context("set curves")?;
        }
        if let Some(curves) = &self.key_shares {
            cfg.set_client_key_shares(curves)
                .context("set client key shares")?;
        }
        if self.min_version.is_some() {
            cfg.set_min_proto_version(self.min_version)
                .context("set min proto version")?;
        }
        if self.max_version.is_some() {
            cfg.set_max_proto_version(self.max_version)
                .context("set max proto version")?;
        }
        if let Some(prefs) = &self.verify_algorithm_prefs {
            cfg.set_verify_algorithm_prefs(prefs)
                .context("set signature schemes (verify algorithm prefs)")?;
        }
        if self.ocsp_stapling {
            cfg.enable_ocsp_stapling();
        }
        if self.signed_cert_timestamps {
            cfg.enable_signed_cert_timestamps();
        }
        if !self.session_tickets {
            cfg.set_options(SslOptions::NO_TICKET);
        }
        // The context registers every algorithm; a connection offers only its own.
        cfg.set_certificate_compression_algorithms(&self.certificate_compression)
            .context("set certificate compression algorithms")?;
        if let Some((alps_list, new_codepoint)) = &self.alps {
            cfg.set_alps_use_new_codepoint(*new_codepoint);
            for app_proto in alps_list {
                cfg.add_application_settings(app_proto.as_bytes())
                    .context("set alps application settings")?;
            }
        }
        if let Some(limit) = self.record_size_limit {
            cfg.set_record_size_limit(limit)
                .context("set record size limit")?;
        }
        if let Some(schemes) = &self.delegated_credential_schemes {
            cfg.set_delegated_credential_schemes(schemes)
                .context("set delegated credential schemes")?;
        }
        if self.encrypted_client_hello {
            cfg.set_enable_ech_grease(true);
        }
        Ok(())
    }
}

impl TlsConnectorContextBuilder {
    generate_set_and_with!(
        /// Pass each established client session to `remember`. Resumption requires
        /// the same server, security policy and session domain.
        pub fn new_session_callback(
            mut self,
            remember: impl Fn(&mut SslRef, TlsClientSession) + Send + Sync + 'static,
        ) -> Self {
            self.options.remembers_sessions = true;
            self.config
                .set_session_cache_mode(SslSessionCacheMode::CLIENT);
            self.config.set_new_session_callback(move |ssl, session| {
                if let Some(session) = TlsClientSession::established(ssl, session) {
                    remember(ssl, session);
                }
            });
            self
        }
    );

    generate_set_and_with!(
        /// Keep the sessions this context establishes in `store`, and offer them on
        /// its later connections to the same server identity.
        pub fn session_store(mut self, store: Arc<dyn TlsClientSessionStore>) -> Self {
            let sink = store.clone();
            self.set_new_session_callback(move |_, session| sink.put(session));
            self.options.session_store = Some(SessionStore(store));
            self
        }
    );

    /// The highest version a connection offers, if configured.
    #[must_use]
    pub fn max_proto_version(&self) -> Option<SslVersion> {
        self.options.wire.max_version
    }

    pub fn build(self) -> TlsConnectorContext {
        TlsConnectorContext {
            connector: self.config.build(),
            options: self.options,
        }
    }
}

impl TlsConnectorContext {
    /// Expected key for sessions established with `server` by this context.
    /// Security policy and domain are captured when the native context is built.
    pub fn session_key(&self, server: &Host) -> Option<TlsClientSessionKey> {
        session::context_key(
            self.connector.context(),
            self.options.server_name.as_ref().unwrap_or(server),
        )
    }

    /// Configure a connection with `config`'s wire settings and identity on this context,
    /// which carries `config`'s security policy; session settings stay this context's.
    pub(super) fn configure_variant(
        &self,
        config: &BoringTlsConnectorConfig<'_>,
    ) -> Result<TlsConnectorData, BoxError> {
        let mut options = ConnectorOptions::try_from(config)?;
        options.remembers_sessions = self.options.remembers_sessions;
        options.session_store = self.options.session_store.clone();
        Self {
            connector: self.connector.clone(),
            options,
        }
        .configure()
    }

    /// Create independent connection state while retaining the shared native context.
    pub fn configure(&self) -> Result<TlsConnectorData, BoxError> {
        let mut cfg = self
            .connector
            .configure()
            .context("create ssl connector configuration")?;
        self.options.wire.apply(&mut cfg)?;
        Ok(TlsConnectorData {
            config: cfg,
            store_server_certificate_chain: self.options.store_server_certificate_chain,
            store_server_hello: self.options.store_server_hello,
            server_name: self.options.server_name.clone(),
            server_verify_mode: self.options.server_verify_mode,
            server_cert_pins: self.options.server_cert_pins.clone(),
            remembers_sessions: self.options.remembers_sessions,
            session_store: self.options.session_store.clone(),
        })
    }
}

impl TlsConnectorData {
    /// Prepare one TLS session, including peer identity verification and certificate pins.
    /// The caller selects its transport and starts the handshake.
    pub fn into_ssl(mut self) -> Result<rama_boring::ssl::Ssl, BoxError> {
        if self.server_verify_mode == ServerVerifyMode::Auto && self.server_name.is_none() {
            return Err(BoxError::from_static_str(
                "server identity required when server verification is enabled",
            ));
        }
        super::connector::configure_server_cert_pins(
            &mut self.config,
            self.server_verify_mode,
            self.server_cert_pins,
            self.server_name.as_ref(),
        );
        let identity = self
            .server_name
            .as_ref()
            .map(super::connector::server_identity_for)
            .transpose()?;
        let mut ssl = self
            .config
            .into_ssl(identity.as_deref())
            .context("prepare boring client TLS session")?;
        if self.store_server_hello {
            ServerAnswerRecorder::of(&mut ssl)?;
        }
        if self.remembers_sessions
            && let Some(server) = &self.server_name
            && let Some(key) = session::bind_session_key(&mut ssl, server)?
            && let Some(SessionStore(store)) = &self.session_store
            && let Some(session) = store.take(&key)
        {
            // TLS 1.2 sessions remain available to concurrent and later connections.
            if !session.is_single_use() {
                store.put(session.clone());
            }
            if let Err(error) = session.resume_on(&mut ssl) {
                debug!(%error, "boring connector: stored session not offered");
            }
        }
        Ok(ssl)
    }

    /// Whether [`Self::into_ssl`] offers a stored session for resumption.
    #[must_use]
    pub fn resumes_sessions(&self) -> bool {
        self.session_store.is_some()
    }
}

impl std::fmt::Debug for TlsConnectorData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnectorData")
            .field(
                "store_server_certificate_chain",
                &self.store_server_certificate_chain,
            )
            .field("server_name", &self.server_name)
            .field("server_verify_mode", &self.server_verify_mode)
            .field("has_server_cert_pins", &self.server_cert_pins.is_some())
            .field("resumes_sessions", &self.resumes_sessions())
            .finish()
    }
}

impl TryFrom<&TlsClientConfig> for TlsConnectorData {
    type Error = BoxError;

    /// Build [`TlsConnectorData`] from a [`TlsClientConfig`] by gathering its
    /// pieces (the same path the connector uses internally).
    fn try_from(value: &TlsClientConfig) -> Result<Self, Self::Error> {
        Self::try_from(BoringTlsConnectorConfig::from_extensions(
            value.as_extensions(),
        ))
    }
}

impl TryFrom<BoringTlsConnectorConfig<'_>> for TlsConnectorData {
    type Error = BoxError;

    fn try_from(value: BoringTlsConnectorConfig<'_>) -> Result<Self, Self::Error> {
        TlsConnectorContext {
            connector: shared_security_context(&value)?,
            options: ConnectorOptions::try_from(&value)?,
        }
        .configure()
    }
}

/// The native context for `value`'s security policy, shared by every connection without a
/// session store: it holds no per-connection or session state.
fn shared_security_context(value: &BoringTlsConnectorConfig<'_>) -> Result<SslConnector, BoxError> {
    const MAX_SHARED_CONTEXTS: u64 = 64;
    static CONTEXTS: LazyLock<Cache<TlsPoolId, SslConnector>> =
        LazyLock::new(|| Cache::new(MAX_SHARED_CONTEXTS));
    let Some(scope) = value.context_scope().filter(TlsPoolId::is_reusable) else {
        return Ok(security_context(value)?.build());
    };
    if let Some(connector) = CONTEXTS.get(&scope) {
        return Ok(connector);
    }
    let connector = security_context(value)?.build();
    Ok(CONTEXTS.entry(scope).or_insert(connector).into_value())
}

impl TryFrom<&TlsClientConfig> for TlsConnectorContextBuilder {
    type Error = BoxError;

    fn try_from(value: &TlsClientConfig) -> Result<Self, Self::Error> {
        Self::try_from(BoringTlsConnectorConfig::from_extensions(
            value.as_extensions(),
        ))
    }
}

impl TryFrom<BoringTlsConnectorConfig<'_>> for TlsConnectorContextBuilder {
    type Error = BoxError;

    fn try_from(value: BoringTlsConnectorConfig<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            config: security_context(&value)?,
            options: ConnectorOptions::try_from(&value)?,
        })
    }
}

impl TryFrom<&BoringTlsConnectorConfig<'_>> for ConnectorOptions {
    type Error = BoxError;

    fn try_from(value: &BoringTlsConnectorConfig<'_>) -> Result<Self, Self::Error> {
        let grease_enabled = value.grease.map(|p| p.0).unwrap_or_default();

        let alpn_protos = value
            .alpn
            .map(|a| {
                ApplicationProtocol::encode_alpns(&a.0)
                    .context("build (boring) ssl connector: encode alpns")
            })
            .transpose()?;

        // A set list is exact: with GREASE on, one naming no GREASE slot gets the native ones.
        let cipher_list: Option<Vec<u16>> = value.cipher_suites.map(|p| {
            let list = p.0.iter().map(|c| (*c).into()).collect();
            if grease_enabled {
                with_native_grease_slots(list, NativeGrease::First)
            } else {
                list
            }
        });
        // An empty order keeps the native layout, GREASE extensions included.
        let extension_order: Option<Vec<u16>> =
            value.extension_order.filter(|p| !p.0.is_empty()).map(|p| {
                let order = p.0.iter().map(|e| u16::from(*e)).collect();
                if grease_enabled {
                    with_native_grease_slots(order, NativeGrease::FirstAndLast)
                } else {
                    order
                }
            });

        // BoringSSL rejects any duplicate group or signature scheme, adjacent or not.
        let curves: Option<Vec<SslCurve>> = value
            .supported_groups
            .map(|p| native_unique(p.0.iter().filter_map(|g| (*g).rama_try_into().ok())));
        // An empty native list means BoringSSL's defaults, which a configuration naming
        // only groups it cannot use never asked for.
        if curves.as_ref().is_some_and(Vec::is_empty) {
            return Err(BoxError::from_static_str(
                "build (boring) ssl connector: no supported group",
            ));
        }
        let verify_algorithm_prefs: Option<Vec<SslSignatureAlgorithm>> = value
            .signature_schemes
            .map(|p| native_unique(p.0.iter().filter_map(|s| (*s).rama_try_into().ok())));
        // BoringSSL only accepts key shares for an ordered subset of the offered groups.
        let key_shares: Option<Vec<SslCurve>> = value.key_shares.map(|p| {
            let shares = p.0.iter().filter_map(|g| (*g).rama_try_into().ok());
            match &curves {
                Some(curves) => ordered_subset(shares, curves),
                None => native_unique(shares),
            }
        });
        let delegated_credential_schemes: Option<Vec<SslSignatureAlgorithm>> =
            value.delegated_credentials.map(|p| {
                p.0.iter()
                    .filter_map(|s| (*s).rama_try_into().ok())
                    .collect()
            });

        // Versions: min/max derived from the offered list, explicit overrides win.
        // (The max override also doubles as the mitm egress safety clamp.)
        let mut min_version: Option<SslVersion> = None;
        let mut max_version: Option<SslVersion> = None;
        if let Some(versions) = value.versions {
            if let Some(min) = versions.0.iter().filter(|v| !v.is_grease()).min() {
                min_version = Some((*min).rama_try_into().map_err(|v| {
                    BoxError::from_static_str("boring connector: cast min proto version")
                        .context_field("protocol_version", v)
                })?);
            }
            if let Some(max) = versions.0.iter().filter(|v| !v.is_grease()).max() {
                max_version = Some((*max).rama_try_into().map_err(|v| {
                    BoxError::from_static_str("boring connector: cast max proto version")
                        .context_field("protocol_version", v)
                })?);
            }
        }
        if let Some(p) = value.min_version {
            min_version = Some((p.0).rama_try_into().map_err(|v| {
                BoxError::from_static_str("boring connector: cast min proto version override")
                    .context_field("protocol_version", v)
            })?);
        }
        if let Some(p) = value.max_version {
            max_version = Some((p.0).rama_try_into().map_err(|v| {
                BoxError::from_static_str("boring connector: cast max proto version override")
                    .context_field("protocol_version", v)
            })?);
        }

        // A TLS 1.3-only `supported_versions` offer derives min == max == TLS 1.3
        // from the list. If an egress max-version clamp (mitm safety, see
        // `BoringMaxVersion` / `TlsClientConfig::rama_from(&ClientHello)`) then lowered
        // max to TLS 1.2, min would exceed max, which boring rejects. TLS 1.3 is
        // the only version above TLS 1.2, so lower exactly that floor to keep the
        // connector internally consistent (a lower legitimate floor is untouched).
        if min_version == Some(SslVersion::TLS1_3) && max_version == Some(SslVersion::TLS1_2) {
            min_version = Some(SslVersion::TLS1_2);
        }

        let requested_trust_anchors = value
            .requested_trust_anchors
            .map(|anchors| anchors.identifier_list())
            .transpose()
            .context("build (boring) ssl connector: validate requested trust anchors")?
            .flatten()
            .map(<[u8]>::to_vec);

        // An explicit order replaces native permutation, so only apply it without.
        let permute_extensions = value.permute_extensions.is_some_and(|p| p.0);

        let mut grease = GreaseLists::empty();
        if grease_enabled {
            grease |= GreaseLists::CIPHERS
                | GreaseLists::GROUPS
                | GreaseLists::KEY_SHARES
                | GreaseLists::VERSIONS
                | GreaseLists::EXTENSIONS;
        }
        if value.grease_signature_schemes.is_some_and(|p| p.0) {
            grease |= GreaseLists::SIGNATURE_ALGORITHMS;
        }

        let wire = WirePlan {
            cipher_list,
            alpn_protos,
            curves,
            key_shares,
            verify_algorithm_prefs,
            min_version,
            max_version,
            extension_order,
            permute_extensions,
            requested_trust_anchors,
            grease,
            ocsp_stapling: value.ocsp_stapling.map(|p| p.0).unwrap_or_default(),
            signed_cert_timestamps: value
                .signed_cert_timestamps
                .map(|p| p.0)
                .unwrap_or_default(),
            session_tickets: value.tls12_session_tickets.is_none_or(|p| p.0),
            certificate_compression: value
                .cert_compression
                .map(|p| native_certificate_compression(&p.0))
                .unwrap_or_default(),
            alps: value.alps.map(|p| (p.protocols.clone(), p.new_codepoint)),
            record_size_limit: value.record_size_limit.map(|p| p.0),
            delegated_credential_schemes,
            encrypted_client_hello: value
                .encrypted_client_hello
                .map(|p| p.0)
                .unwrap_or_default(),
        };

        Ok(Self {
            store_server_certificate_chain: value.store_chain.map(|p| p.0).unwrap_or_default(),
            store_server_hello: value.store_server_hello.map(|p| p.0).unwrap_or_default(),
            server_name: value.server_name.map(|s| s.0.clone()),
            server_verify_mode: value.verify.map(|v| v.0).unwrap_or_default(),
            server_cert_pins: value.server_cert_pins.cloned(),
            wire,
            remembers_sessions: false,
            session_store: None,
        })
    }
}

/// The native context for `value`'s security policy: trust, verification, client
/// credential, keylog and session identity. Wire settings are per connection.
fn security_context(value: &BoringTlsConnectorConfig<'_>) -> Result<SslConnectorBuilder, BoxError> {
    let session_policy = value.session_scope();
    let session_domain = value.session_domain.copied();
    let server_verify_mode = value.verify.map(|v| v.0).unwrap_or_default();
    let keylog_intent = value
        .keylog
        .map(|k| k.0.clone())
        .unwrap_or(KeyLogIntent::Environment);
    let server_verify_cert_store = value.verify_cert_store.as_ref().map(|p| p.0.clone());
    if server_verify_mode == ServerVerifyMode::Disable {
        if value.server_trust.is_some() {
            debug!(
                "boring connector: server trust policy ignored: server verification is disabled"
            );
        }
        if server_verify_cert_store.is_some() {
            debug!(
                "boring connector: custom certificate store ignored: server verification is disabled"
            );
        }
    }
    let server_trust_store = match (server_verify_mode, value.server_trust) {
        (ServerVerifyMode::Auto, Some(trust)) => {
            if server_verify_cert_store.is_some() {
                debug!(
                    "boring connector: server trust policy ignored: custom certificate store takes precedence"
                );
                None
            } else {
                Some(resolve_server_trust_store(trust)?)
            }
        }
        (ServerVerifyMode::Auto, None) => Some(ResolvedServerTrustStore::Default),
        _ => None,
    };
    let client_auth = value
        .client_auth
        .map(|c| ConnectorConfigClientAuth::try_from(c.0.clone()))
        .transpose()?;

    // `no_default_verify_builder` skips boring's per-call
    // `set_default_verify_paths`, which would otherwise parse the entire OS
    // trust store into a throwaway per-connector store on every build. We
    // install exactly the store we need below instead.
    let mut cfg_builder = SslConnector::no_default_verify_builder(SslMethod::tls_client())
        .context("create (boring) ssl connector builder")?;

    if let Some(store) = &server_verify_cert_store {
        trace!("boring connector: set provided cert store to verify as server");
        cfg_builder.set_cert_store_ref(store);
    } else {
        match (server_verify_mode, server_trust_store) {
            (ServerVerifyMode::Disable, _) => {
                // Verification is disabled (a NONE verify callback is
                // installed below), so the trust store is never consulted:
                // leave the empty store from `no_default_verify_builder`
                // and don't parse the OS bundle at all.
                trace!(
                    "boring connector: server verification disabled; no verify cert store loaded"
                );
            }
            (ServerVerifyMode::Auto, Some(ResolvedServerTrustStore::Default) | None) => {
                // Install a process-wide, parse-once shared OS default store
                // so every connector references one copy instead of
                // re-parsing the bundle on every build.
                trace!("boring connector: using shared default verify cert store");
                cfg_builder.set_cert_store_ref(shared_default_verify_store()?);
            }
            (ServerVerifyMode::Auto, Some(ResolvedServerTrustStore::WebPki)) => {
                trace!("boring connector: using shared WebPKI verify cert store");
                cfg_builder.set_cert_store_ref(shared_webpki_verify_store()?);
            }
            (ServerVerifyMode::Auto, Some(ResolvedServerTrustStore::Derived(store))) => {
                trace!("boring connector: using shared derived server verify cert store");
                cfg_builder.set_cert_store_ref(store.as_ref());
            }
        }
    }

    if let Some(sink) = open_intent_sink(&keylog_intent)? {
        cfg_builder.set_keylog_callback(move |_, line| {
            let mut buf = String::with_capacity(line.len() + 1);
            buf.push_str(line);
            buf.push('\n');
            sink.write_line(&buf);
        });
    }

    // Each connection selects its own algorithms from these.
    add_certificate_compressors(&mut cfg_builder, SUPPORTED_CERTIFICATE_COMPRESSION)
        .context("build (boring) ssl connector: certificate compression")?;

    match server_verify_mode {
        ServerVerifyMode::Auto => {
            trace!("boring connector: server verify mode: auto (default verifier)");
        }
        ServerVerifyMode::Disable => {
            trace!("boring connector: server verify mode: disable");
            cfg_builder.set_custom_verify_callback(SslVerifyMode::NONE, |_| Ok(()));
        }
    }

    if let Some(auth) = &client_auth {
        trace!("boring connector: client mTls: set private key");
        cfg_builder
            .set_private_key(auth.private_key.as_ref())
            .context("build (boring) ssl connector: set private key")?;
        if auth.cert_chain.is_empty() {
            return Err(BoxError::from_static_str(
                "build (boring) ssl connector: cert chain is empty",
            ));
        }
        trace!("boring connector: client mTls: set cert chain root");
        cfg_builder
            .set_certificate(
                auth.cert_chain
                    .first()
                    .context("build (boring) ssl connector: get primary client cert")?,
            )
            .context("build (boring) ssl connector: add primary client cert")?;
        for cert in &auth.cert_chain[1..] {
            trace!("boring connector: client mTls: set extra cert chain");
            cfg_builder
                .add_extra_chain_cert(cert.clone())
                .context("build (boring) ssl connector: set client cert")?;
        }
    }

    session::identify_context(
        &mut cfg_builder,
        session_domain,
        session_policy,
        client_credential_scope(client_auth.as_ref())?,
    )?;
    Ok(cfg_builder)
}

// SelfSigned resolves to a new certificate when a native context is built. Keep
// that actual credential separate even when the symbolic input policy is equal.
fn client_credential_scope(
    auth: Option<&ConnectorConfigClientAuth>,
) -> Result<Option<[u8; 32]>, BoxError> {
    let Some(cert) = auth.and_then(|auth| auth.cert_chain.first()) else {
        return Ok(None);
    };
    let encoded = cert
        .to_der()
        .context("encode TLS client credential identity")?;
    Ok(Some(sha256(&encoded)))
}

/// Where BoringSSL's native lists carry GREASE: first, and for extensions also last.
#[derive(Clone, Copy)]
enum NativeGrease {
    First,
    FirstAndLast,
}

/// `list` as set, or with GREASE slots where the native list has them when it names none.
fn with_native_grease_slots(mut list: Vec<u16>, slots: NativeGrease) -> Vec<u16> {
    if list.iter().any(|id| ExtensionId::from(*id).is_grease()) {
        return list;
    }
    // Two distinct codepoints: a repeated one would name the same slot twice.
    list.insert(0, 0x0a0a);
    if matches!(slots, NativeGrease::FirstAndLast) {
        list.push(0x1a1a);
    }
    list
}

fn ordered_subset<T: PartialEq>(values: impl Iterator<Item = T>, superset: &[T]) -> Vec<T> {
    let mut next = 0;
    values
        .filter(
            |value| match superset[next..].iter().position(|item| item == value) {
                Some(offset) => {
                    next += offset + 1;
                    true
                }
                None => false,
            },
        )
        .collect()
}

enum ResolvedServerTrustStore {
    Default,
    WebPki,
    Derived(Arc<X509Store>),
}

fn resolve_server_trust_store(
    trust: &TlsServerTrust,
) -> Result<ResolvedServerTrustStore, BoxError> {
    match (trust.roots(), trust.additional_anchors()) {
        (ServerTrustRoots::Default, None) => Ok(ResolvedServerTrustStore::Default),
        (ServerTrustRoots::WebPki, None) => Ok(ResolvedServerTrustStore::WebPki),
        _ => cached_server_verify_store(trust).map(ResolvedServerTrustStore::Derived),
    }
}

fn cached_server_verify_store(trust: &TlsServerTrust) -> Result<Arc<X509Store>, BoxError> {
    const MAX_CACHED_TRUST_POLICIES: u64 = 64;
    static STORES: LazyLock<Cache<TlsServerTrust, Arc<X509Store>>> = LazyLock::new(|| {
        Cache::builder()
            .max_capacity(MAX_CACHED_TRUST_POLICIES)
            .build()
    });

    STORES
        .entry(trust.clone())
        .or_try_insert_with(|| build_server_verify_store(trust).map(Arc::new))
        .map(|entry| entry.into_value())
        .map_err(|err| {
            err.to_string()
                .context("build cached derived server trust store")
                .into_box_error()
        })
}

fn build_server_verify_store(trust: &TlsServerTrust) -> Result<X509Store, BoxError> {
    let mut builder = X509StoreBuilder::new().context("create server trust store")?;
    // Custom roots intentionally include intermediate or end-entity trust
    // anchors, which require partial-chain verification in BoringSSL.
    builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN);
    let mut added = HashSet::new();

    match trust.roots() {
        ServerTrustRoots::Default => add_builtin_trust_anchors(
            &mut builder,
            &mut added,
            &rama_crypto::native_certs::shared_native_trust_anchors(),
            "native",
        ),
        ServerTrustRoots::WebPki => add_builtin_trust_anchors(
            &mut builder,
            &mut added,
            rama_crypto::native_certs::bundled_root_certs(),
            "WebPKI",
        ),
        ServerTrustRoots::Custom(anchors) => {
            add_configured_trust_anchors(&mut builder, &mut added, anchors)?;
        }
    }
    if let Some(anchors) = trust.additional_anchors() {
        add_configured_trust_anchors(&mut builder, &mut added, anchors)?;
    }

    if added.is_empty() {
        return Err(BoxError::from_static_str(
            "no server trust anchors could be added to the boring x509 verify store",
        ));
    }
    Ok(builder.build())
}

fn add_configured_trust_anchors(
    builder: &mut X509StoreBuilder,
    added: &mut HashSet<[u8; 32]>,
    anchors: &TlsServerTrustAnchors,
) -> Result<(), BoxError> {
    for der in anchors.certificates() {
        let digest = rama_boring::sha::sha256(der.as_ref());
        if added.contains(&digest) {
            continue;
        }
        let certificate =
            X509::from_der(der.as_ref()).context("parse configured server trust anchor")?;
        builder
            .add_cert(&certificate)
            .context("add configured server trust anchor to boring x509 store")?;
        added.insert(digest);
    }
    Ok(())
}

fn add_builtin_trust_anchors(
    builder: &mut X509StoreBuilder,
    added: &mut HashSet<[u8; 32]>,
    anchors: &[rama_crypto::pki_types::CertificateDer<'static>],
    kind: &'static str,
) {
    for der in anchors {
        let digest = rama_boring::sha::sha256(der.as_ref());
        if added.contains(&digest) {
            continue;
        }
        match X509::from_der(der.as_ref()) {
            Ok(cert) => match builder.add_cert(&cert) {
                Ok(()) => {
                    added.insert(digest);
                }
                Err(err) => {
                    debug!(%err, trust_anchor_kind = kind, "boring connector: failed to add built-in trust anchor");
                }
            },
            Err(err) => {
                debug!(%err, trust_anchor_kind = kind, "boring connector: failed to parse built-in trust anchor");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectorConfigClientAuth {
    pub cert_chain: Vec<X509>,
    pub private_key: PKey<Private>,
}

impl TryFrom<ConnectorConfigClientAuth> for SslCredential {
    type Error = BoxError;

    fn try_from(auth: ConnectorConfigClientAuth) -> Result<Self, Self::Error> {
        let mut credential = Self::builder()?;
        credential.set_certificate_chain(&auth.cert_chain)?;
        credential.set_private_key(&auth.private_key)?;
        Ok(credential.build())
    }
}

/// Process-wide trust store, built once and shared by every connector that
/// needs server verification.
///
/// The store is populated from the platform's native trust anchors (the system
/// root certificates), loaded once via
/// [`rama_crypto::native_certs::shared_native_trust_anchors`] and shared across
/// both the `rustls` and `boring` backends. Every connector references this one
/// store via `set_cert_store_ref` instead of re-parsing a bundle per build.
fn shared_default_verify_store() -> Result<&'static X509Store, BoxError> {
    static STORE: LazyLock<Result<X509Store, BoxError>> =
        LazyLock::new(build_os_default_verify_store);
    match &*STORE {
        Ok(store) => Ok(store),
        Err(err) => Err(err
            .to_string()
            .context("shared default verify store")
            .into_box_error()),
    }
}

/// Process-wide store containing Rama's bundled Mozilla (CCADB) roots.
fn shared_webpki_verify_store() -> Result<&'static X509Store, BoxError> {
    static STORE: LazyLock<Result<X509Store, BoxError>> = LazyLock::new(build_webpki_verify_store);
    match &*STORE {
        Ok(store) => Ok(store),
        Err(err) => Err(err
            .to_string()
            .context("shared WebPKI verify store")
            .into_box_error()),
    }
}

/// Build a boring [`X509Store`] from the shared, process-wide native trust
/// anchors (the system root certificates).
///
/// The anchors are loaded once in a tls-implementation agnostic way by
/// [`rama_crypto::native_certs::shared_native_trust_anchors`] (which itself
/// warns and falls back to the bundled webpki roots if the platform store is
/// empty), so this is identical to the trust used by the `rustls` backend.
fn build_os_default_verify_store() -> Result<X509Store, BoxError> {
    let anchors = rama_crypto::native_certs::shared_native_trust_anchors();
    trace!(
        anchor_count = anchors.len(),
        "boring connector: building shared verify store from native trust anchors"
    );
    build_builtin_verify_store(&anchors, "native")
}

fn build_webpki_verify_store() -> Result<X509Store, BoxError> {
    let anchors = rama_crypto::native_certs::bundled_root_certs();
    trace!(
        anchor_count = anchors.len(),
        "boring connector: building shared verify store from bundled WebPKI roots"
    );
    build_builtin_verify_store(anchors, "WebPKI")
}

fn build_builtin_verify_store(
    anchors: &[rama_crypto::pki_types::CertificateDer<'static>],
    kind: &'static str,
) -> Result<X509Store, BoxError> {
    let mut builder =
        X509StoreBuilder::new().context("create x509 store builder for built-in trust anchors")?;
    // Native trust stores can deliberately contain non-self-signed trust
    // anchors. WebPKI roots are self-signed, so the flag is inert there.
    builder.set_flags(X509VerifyFlags::PARTIAL_CHAIN);
    let mut added = HashSet::new();
    add_builtin_trust_anchors(&mut builder, &mut added, anchors, kind);

    trace!(
        added = added.len(),
        trust_anchor_kind = kind,
        "boring connector: shared verify store built"
    );

    if added.is_empty() {
        return Err(BoxError::from_static_str(
            "no built-in trust anchors could be added to the boring x509 verify store",
        ));
    }

    Ok(builder.build())
}

impl TryFrom<ClientAuth> for ConnectorConfigClientAuth {
    type Error = BoxError;

    fn try_from(auth: ClientAuth) -> Result<Self, Self::Error> {
        match auth {
            ClientAuth::SelfSigned => {
                let (cert_chain, private_key) =
                    self_signed_client_auth().context("boring/TlsConnectorData")?;
                Ok(Self {
                    cert_chain,
                    private_key,
                })
            }
            ClientAuth::Single(data) => {
                // server TLS Certs
                let cert_chain = data
                    .cert_chain
                    .into_iter()
                    .map(|cert| {
                        X509::from_der(cert.as_bytes()).context(
                            "boring/TlsConnectorData: parse x509 client cert from DER content",
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                // server TLS key
                let private_key = PKey::private_key_from_der(data.private_key.secret_der())
                    .context("boring/TlsConnectorData: parse private key from DER content")?;

                Ok(Self {
                    cert_chain,
                    private_key,
                })
            }
        }
    }
}

fn self_signed_client_auth() -> Result<(Vec<X509>, PKey<Private>), BoxError> {
    let rsa = Rsa::generate(4096).context("generate 4096 RSA key")?;
    let privkey = PKey::from_rsa(rsa).context("create private key from 4096 RSA key")?;

    let mut cert_builder = X509::builder().context("create x509 (cert) builder")?;
    cert_builder
        .set_version(2)
        .context("x509 cert builder: set version = 2")?;
    let serial_number = {
        let mut serial = BigNum::new().context("x509 cert builder: create big num (serial")?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .context("x509 cert builder: randomise serial number (big num)")?;
        serial
            .to_asn1_integer()
            .context("x509 cert builder: convert serial to ASN1 integer")?
    };
    cert_builder
        .set_serial_number(&serial_number)
        .context("x509 cert builder: set serial number")?;
    cert_builder
        .set_pubkey(&privkey)
        .context("x509 cert builder: set public key using private key (ref)")?;
    let not_before =
        Asn1Time::days_from_now(0).context("x509 cert builder: create ASN1Time for today")?;
    cert_builder
        .set_not_before(&not_before)
        .context("x509 cert builder: set not before to today")?;
    let not_after = Asn1Time::days_from_now(90)
        .context("x509 cert builder: create ASN1Time for 90 days in future")?;
    cert_builder
        .set_not_after(&not_after)
        .context("x509 cert builder: set not after to 90 days in future")?;

    cert_builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .context("x509 cert builder: build basic constraints")?
                .as_ref(),
        )
        .context("x509 cert builder: add basic constraints as x509 extension")?;
    cert_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .context("x509 cert builder: create key usage")?
                .as_ref(),
        )
        .context("x509 cert builder: add key usage x509 extension")?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(None, None))
        .context("x509 cert builder: build subject key id")?;
    cert_builder
        .append_extension(subject_key_identifier.as_ref())
        .context("x509 cert builder: add subject key id x509 extension")?;

    cert_builder
        .sign(&privkey, MessageDigest::sha256())
        .context("x509 cert builder: sign cert")?;
    let cert = cert_builder.build();

    Ok((vec![cert], privkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{BoringMaxVersion, BoringSignatureSchemes};
    use rama_core::extensions::Extensions;
    use rama_crypto::pki_types::CertificateDer;
    use rama_net::tls::TlsAlpn;
    use rama_tls::client::{
        ClientHello, ClientHelloExtension, TlsServerCertPins, TlsServerTrust,
        TlsServerTrustAnchors, TlsServerVerify, TlsStoreServerCertChain,
    };
    use rama_tls::{CipherSuite, ProtocolVersion, SignatureScheme};

    #[test]
    fn shared_context_keeps_connection_configuration_independent() {
        let config = TlsClientConfig::new().with_server_name(Host::from_static("one.example"));
        let mut builder = TlsConnectorContextBuilder::try_from(&config).unwrap();
        builder
            .config
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .unwrap();
        let context = builder.build();
        let shared = context.clone();
        let mut first = context.configure().unwrap();
        first
            .config
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .unwrap();
        first.server_name = Some(Host::from_static("two.example"));
        let second = shared.configure().unwrap();
        assert!(std::ptr::eq(
            first.config.ssl_context(),
            second.config.ssl_context()
        ));
        assert_eq!(second.config.max_proto_version(), Some(SslVersion::TLS1_3));
        assert_eq!(second.server_verify_mode, ServerVerifyMode::Auto);
        let first = first.into_ssl().unwrap();
        let second = second.into_ssl().unwrap();
        assert_eq!(
            first.servername(rama_boring::ssl::NameType::HOST_NAME),
            Some("two.example")
        );
        assert_eq!(
            second.servername(rama_boring::ssl::NameType::HOST_NAME),
            Some("one.example")
        );
    }

    #[test]
    fn shared_context_still_requires_each_verified_connection_identity() {
        let context = TlsConnectorContextBuilder::try_from(&TlsClientConfig::new())
            .unwrap()
            .build();
        context.configure().unwrap().into_ssl().unwrap_err();
        let mut named = context.configure().unwrap();
        named.server_name = Some(Host::from_static("example.com"));
        named.into_ssl().unwrap();
        context.configure().unwrap().into_ssl().unwrap_err();
    }

    #[test]
    fn build_from_common_pieces() {
        let ext = Extensions::new();
        ext.insert(TlsAlpn::http_auto());
        ext.insert(TlsServerVerify(ServerVerifyMode::Disable));
        ext.insert(TlsStoreServerCertChain(true));

        let config = BoringTlsConnectorConfig::from_extensions(&ext);
        let data = TlsConnectorData::try_from(config).unwrap();

        assert!(data.store_server_certificate_chain);
    }

    #[test]
    fn build_dedups_duplicate_signature_schemes() {
        let ext = Extensions::new();
        ext.insert(BoringSignatureSchemes(vec![
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
        ]));

        let config = BoringTlsConnectorConfig::from_extensions(&ext);
        // This would crash if we didn't dedup properly
        TlsConnectorData::try_from(config).expect("build with duplicate signature schemes");
    }

    #[test]
    fn build_applies_max_version_clamp() {
        let ext = Extensions::new();
        ext.insert(BoringMaxVersion(ProtocolVersion::TLSv1_2));

        let config = BoringTlsConnectorConfig::from_extensions(&ext);
        let data = TlsConnectorData::try_from(config).unwrap();

        assert_eq!(data.config.max_proto_version(), Some(SslVersion::TLS1_2));
    }

    #[test]
    fn pins_can_be_the_only_certificate_check() {
        let ext = Extensions::new();
        ext.insert(TlsServerVerify(ServerVerifyMode::Disable));
        ext.insert(TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3])));

        let config = BoringTlsConnectorConfig::from_extensions(&ext);
        TlsConnectorData::try_from(config).unwrap();
    }

    #[test]
    fn custom_server_trust_anchors_build_default_verifier() {
        use rama_crypto::cert::{GeneratedServerAuthConfig, generate_server_auth};

        let (chain, _) = generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
        let config = TlsClientConfig::new()
            .try_with_server_trust_anchors([chain[1].clone()])
            .unwrap();

        TlsConnectorData::try_from(&config).unwrap();
    }

    #[test]
    fn exact_builtin_trust_policies_use_shared_stores() {
        assert!(matches!(
            resolve_server_trust_store(&TlsServerTrust::default_roots()).unwrap(),
            ResolvedServerTrustStore::Default
        ));
        assert!(matches!(
            resolve_server_trust_store(&TlsServerTrust::webpki_roots()).unwrap(),
            ResolvedServerTrustStore::WebPki
        ));

        shared_default_verify_store().unwrap();
        shared_webpki_verify_store().unwrap();

        let anchors = rama_crypto::native_certs::bundled_root_certs();
        let mut store = X509StoreBuilder::new().unwrap();
        let mut added = HashSet::new();
        add_builtin_trust_anchors(&mut store, &mut added, anchors, "WebPKI");
        assert_eq!(added.len(), anchors.len());
    }

    #[test]
    fn additional_trust_anchors_extend_default_and_webpki_roots() {
        use rama_crypto::cert::{GeneratedServerAuthConfig, generate_server_auth};

        let (chain, _) = generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
        let anchor = chain[1].clone();

        for trust in [
            TlsServerTrust::default_roots()
                .try_with_additional_anchors([anchor.clone()])
                .unwrap(),
            TlsServerTrust::webpki_roots()
                .try_with_additional_anchors([anchor])
                .unwrap(),
        ] {
            let ResolvedServerTrustStore::Derived(first) =
                resolve_server_trust_store(&trust).unwrap()
            else {
                panic!("expected derived trust store");
            };
            let ResolvedServerTrustStore::Derived(second) =
                resolve_server_trust_store(&trust).unwrap()
            else {
                panic!("expected derived trust store");
            };
            assert!(Arc::ptr_eq(&first, &second));
            TlsConnectorData::try_from(&TlsClientConfig::new().with_server_trust(trust)).unwrap();
        }
    }

    #[test]
    fn invalid_server_trust_anchor_is_rejected() {
        let config = TlsClientConfig::new()
            .try_with_server_trust_anchors([CertificateDer::from(vec![1, 2, 3])])
            .unwrap();

        TlsConnectorData::try_from(&config).unwrap_err();
    }

    #[test]
    fn invalid_additional_server_trust_anchor_is_rejected() {
        let trust = TlsServerTrust::webpki_roots()
            .try_with_additional_anchors([CertificateDer::from(vec![1, 2, 3])])
            .unwrap();
        let config = TlsClientConfig::new().with_server_trust(trust);

        TlsConnectorData::try_from(&config).unwrap_err();
    }

    #[test]
    fn custom_cert_store_takes_precedence_over_trust_anchors() {
        use crate::client::BoringClientConfigExt as _;

        let store = X509StoreBuilder::new().unwrap().build();
        // the unparsable anchor proves the anchors are ignored
        let config = TlsClientConfig::new()
            .try_with_server_trust_anchors([CertificateDer::from(vec![1, 2, 3])])
            .unwrap()
            .with_server_verify_cert_store(std::sync::Arc::new(store));

        TlsConnectorData::try_from(&config).unwrap();
    }

    #[test]
    fn disabled_verification_ignores_invalid_trust_policy() {
        let invalid =
            TlsServerTrustAnchors::try_new([CertificateDer::from(vec![1, 2, 3])]).unwrap();
        let config = TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Disable)
            .with_server_trust(TlsServerTrust::custom(invalid));

        TlsConnectorData::try_from(&config).unwrap();
    }

    /// A minimal hello: TLS 1.2 legacy version, carrying the given
    /// supported_versions and cipher suites plus any extra extensions
    /// (cipher suites / sig algs control TLS 1.3 viability).
    fn hello_from(
        versions: Vec<ProtocolVersion>,
        cipher_suites: Vec<CipherSuite>,
        exts_extra: Vec<ClientHelloExtension>,
    ) -> ClientHello {
        let mut exts = vec![ClientHelloExtension::SupportedVersions(versions)];
        exts.extend(exts_extra);
        ClientHello::new(ProtocolVersion::TLSv1_2, cipher_suites, Vec::new(), exts)
    }

    /// Build connector data straight from a captured ClientHello, through the
    /// full pieces pipeline (clamp decision in `config.rs` + min/max derivation
    /// here), so these tests exercise the real `tls13` egress safeguard.
    fn connector_data_from_hello(hello: &ClientHello) -> TlsConnectorData {
        use crate::client::BoringClientConfigExt as _;
        let config = TlsClientConfig::new_from_client_hello(hello);
        TlsConnectorData::try_from(&config).expect("build connector data from client hello")
    }

    #[test]
    fn tls13_only_but_not_viable_clamps_and_keeps_min_le_max() {
        // TLS 1.3 advertised, but no TLS 1.3 cipher suites: not viable.
        let hello = hello_from(vec![ProtocolVersion::TLSv1_3], Vec::new(), Vec::new());
        let mut data = connector_data_from_hello(&hello);
        // Regression guard for the min>max inversion: both ends pinned to TLS 1.2.
        assert_eq!(data.config.max_proto_version(), Some(SslVersion::TLS1_2));
        assert_eq!(data.config.min_proto_version(), Some(SslVersion::TLS1_2));
    }

    #[test]
    fn valid_tls13_hello_is_not_clamped() {
        let hello = hello_from(
            vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            vec![ClientHelloExtension::SignatureAlgorithms(vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
            ])],
        );
        let mut data = connector_data_from_hello(&hello);
        // A coherent TLS 1.3 hello must NOT be clamped down to TLS 1.2.
        assert_eq!(data.config.max_proto_version(), Some(SslVersion::TLS1_3));
        assert_eq!(data.config.min_proto_version(), Some(SslVersion::TLS1_2));
    }

    #[test]
    fn tls13_viability_clamp_truth_table_never_inverts_min_max() {
        // Drive the whole pipeline for every TLS 1.3 viability combination: the
        // connector must always be internally consistent (boring never sees
        // min > max), and the clamp must fire exactly when TLS 1.3 is offered
        // without being coherently viable.
        for supported in [false, true] {
            for ciphers in [false, true] {
                for sigalgs in [false, true] {
                    let mut versions = vec![ProtocolVersion::TLSv1_2];
                    if supported {
                        versions.push(ProtocolVersion::TLSv1_3);
                    }
                    let cipher_suites = if ciphers {
                        vec![CipherSuite::TLS13_AES_128_GCM_SHA256]
                    } else {
                        Vec::new()
                    };
                    let exts = if sigalgs {
                        vec![ClientHelloExtension::SignatureAlgorithms(vec![
                            SignatureScheme::ECDSA_NISTP256_SHA256,
                        ])]
                    } else {
                        Vec::new()
                    };

                    let hello = hello_from(versions, cipher_suites, exts);
                    let mut data = connector_data_from_hello(&hello);
                    let min = data.config.min_proto_version();
                    let max = data.config.max_proto_version();

                    // The only inversion the clamp could introduce is min=1.3, max=1.2.
                    assert!(
                        !(min == Some(SslVersion::TLS1_3) && max == Some(SslVersion::TLS1_2)),
                        "inverted min>max (supported={supported} ciphers={ciphers} sigalgs={sigalgs}): min={min:?} max={max:?}"
                    );

                    // Clamp fires iff TLS 1.3 is offered but not viable.
                    if supported && (!ciphers || !sigalgs) {
                        assert_eq!(
                            max,
                            Some(SslVersion::TLS1_2),
                            "expected TLS 1.2 clamp (supported={supported} ciphers={ciphers} sigalgs={sigalgs})"
                        );
                    }
                }
            }
        }
    }
}
