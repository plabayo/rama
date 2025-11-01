use itertools::Itertools;
use rama_boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{ConnectConfiguration, SslCurve, SslSignatureAlgorithm, SslVerifyMode, SslVersion},
    x509::{
        X509,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        store::X509Store,
    },
};
use rama_core::telemetry::tracing::{debug, trace};
use rama_core::{
    bytes::Bytes,
    conversion::RamaTryInto,
    error::{ErrorContext, ErrorExt, OpaqueError},
};
use rama_net::tls::{
    ApplicationProtocol, CertificateCompressionAlgorithm, ExtensionId, KeyLogIntent,
    client::ClientHello,
};
use rama_net::tls::{
    DataEncoding,
    client::{ClientAuth, ClientHelloExtension},
};
use rama_net::{address::Domain, tls::client::ServerVerifyMode};
use rama_utils::macros::generate_set_and_with;
use std::{borrow::Cow, fmt, sync::Arc};

#[cfg(feature = "compression")]
use super::compress_certificate::{
    BrotliCertificateCompressor, ZlibCertificateCompressor, ZstdCertificateCompressor,
};

use crate::keylog::new_key_log_file_handle;

/// [`TlsConnectorData`] that will be used by the connector
///
/// In almost all circumstances you should never create this.
/// Instead you should use [`TlsConnectorDataBuilder`] and pass
/// that around, [`TlsConnector`] will then build the final config.
///
/// [`TlsConnector`]: super::TlsConnector
pub struct TlsConnectorData {
    pub config: ConnectConfiguration,
    pub store_server_certificate_chain: bool,
    pub server_name: Option<Domain>,
}

impl std::fmt::Debug for TlsConnectorData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnectorData")
            .field(
                "store_server_certificate_chain",
                &self.store_server_certificate_chain,
            )
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl TlsConnectorData {
    #[must_use]
    pub fn builder() -> TlsConnectorDataBuilder {
        TlsConnectorDataBuilder::new()
    }
}

#[derive(Clone, Default)]
/// Use [`TlsConnectorDataBuilder`] to build a [`TlsConnectorData`] in an ergonomic way
///
/// This builder is very powerful and is capable of stacking other builders. Using it
/// this way gives each layer the option to modify what is needed in an efficient way.
pub struct TlsConnectorDataBuilder {
    base_builders: Vec<Arc<TlsConnectorDataBuilder>>,
    server_verify_mode: Option<ServerVerifyMode>,
    keylog_intent: Option<KeyLogIntent>,
    cipher_list: Option<Vec<u16>>,
    server_verify_cert_store: Option<Arc<X509Store>>,
    store_server_certificate_chain: Option<bool>,
    alpn_protos: Option<Bytes>,
    min_ssl_version: Option<SslVersion>,
    max_ssl_version: Option<SslVersion>,
    record_size_limit: Option<u16>,
    encrypted_client_hello: Option<bool>,
    grease_enabled: Option<bool>,
    ocsp_stapling_enabled: Option<bool>,
    signed_cert_timestamps_enabled: Option<bool>,
    extension_order: Option<Vec<u16>>,

    curves: Option<Vec<SslCurve>>,
    verify_algorithm_prefs: Option<Vec<SslSignatureAlgorithm>>,
    client_auth: Option<ConnectorConfigClientAuth>,
    certificate_compression_algorithms: Option<Vec<CertificateCompressionAlgorithm>>,
    delegated_credential_schemes: Option<Vec<SslSignatureAlgorithm>>,
    server_name: Option<Domain>,
}

macro_rules! implement_copy_getters {
    ($($name:ident: Option<$type:ty>),* $(,)?) => {
        $(
            /// Get Copy of this field.
            ///
            /// Will return Some(value) if it is set on this builder.
            /// If not set on this builder `base_builders` will be checked
            /// starting from the end to see if one of them contains a value.
            /// The first match is returned.
            pub fn $name(&self) -> Option<$type> {
                self.$name.or_else(|| {
                    self.base_builders
                        .iter()
                        .rev()
                        .find_map(|builder| builder.$name())
                })
            }
        )*
    };
}

macro_rules! implement_reference_getters {
    ($($name:ident: Option<$type:ty>),* $(,)?) => {
        $(
            /// Get reference to this field.
            ///
            /// Will return Some(&value) if it is set on this builder.
            /// If not set on this builder `base_builders` will be checked
            /// starting from the end to see if one of them contains a value.
            /// The first match is returned.
            pub fn $name(&self) -> Option<&$type> {
                self.$name.as_ref().or_else(|| {
                    self.base_builders
                        .iter()
                        .rev()
                        .find_map(|builder| builder.$name())
                })
            }
        )*
    };
}

#[derive(Debug, Clone)]
pub struct ConnectorConfigClientAuth {
    pub cert_chain: Vec<X509>,
    pub private_key: PKey<Private>,
}

impl TlsConnectorDataBuilder {
    implement_copy_getters!(
        server_verify_mode: Option<ServerVerifyMode>,
        min_ssl_version: Option<SslVersion>,
        max_ssl_version: Option<SslVersion>,
        record_size_limit: Option<u16>,
        encrypted_client_hello: Option<bool>,
        store_server_certificate_chain: Option<bool>,
        grease_enabled: Option<bool>,
        ocsp_stapling_enabled: Option<bool>,
        signed_cert_timestamps_enabled: Option<bool>,
    );

    /// Get reference to this field.
    ///
    /// Will return Some(&value) if it is set on this builder.
    /// If not set on this builder `base_builders` will be checked
    /// starting from the end to see if one of them contains a value.
    /// The first match is returned.
    pub fn server_verify_cert_store(&self) -> Option<&X509Store> {
        self.server_verify_cert_store.as_deref().or_else(|| {
            self.base_builders
                .iter()
                .rev()
                .find_map(|builder| builder.server_verify_cert_store())
        })
    }

    implement_reference_getters!(
        cipher_list: Option<Vec<u16>>,
        extension_order: Option<Vec<u16>>,
        alpn_protos: Option<Bytes>,
        curves: Option<Vec<SslCurve>>,
        verify_algorithm_prefs: Option<Vec<SslSignatureAlgorithm>>,
        client_auth: Option<ConnectorConfigClientAuth>,
        certificate_compression_algorithms: Option<Vec<CertificateCompressionAlgorithm>>,
        delegated_credential_schemes: Option<Vec<SslSignatureAlgorithm>>,
        server_name: Option<Domain>,
    );

    /// Return the SSL keylog file path if one exists.
    pub fn keylog_filepath(&self) -> Option<Cow<'_, str>> {
        if let Some(intent) = self.keylog_intent_inner() {
            return intent.file_path();
        }
        KeyLogIntent::env_file_path().map(Into::into)
    }

    fn keylog_intent_inner(&self) -> Option<&KeyLogIntent> {
        self.keylog_intent.as_ref().or_else(|| {
            self.base_builders
                .iter()
                .rev()
                .find_map(|builder| builder.keylog_intent_inner())
        })
    }

    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn new_http_auto() -> Self {
        Self::new()
            .try_with_rama_alpn_protos(&[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11])
            .expect("with http2 and http1")
    }

    #[must_use]
    pub fn new_http_1() -> Self {
        Self::new()
            .try_with_rama_alpn_protos(&[ApplicationProtocol::HTTP_11])
            .expect("with http1")
    }

    #[must_use]
    pub fn new_http_2() -> Self {
        Self::new()
            .try_with_rama_alpn_protos(&[ApplicationProtocol::HTTP_2])
            .expect("with http 2")
    }

    /// Add [`ConfigBuilder`] to the end of our base builder
    ///
    /// When evaluating builders we start from this builder (the last one) and
    /// work our way back until we find a value.
    pub fn push_base_config(&mut self, config: Arc<Self>) -> &mut Self {
        self.base_builders.push(config);
        self
    }

    /// Add [`ConfigBuilder`] to the start of our base builders
    ///
    /// Builder in the start is evaluated as the last one when iterating over builders
    pub fn prepend_base_config(&mut self, config: Arc<Self>) -> &mut Self {
        self.base_builders.insert(0, config);
        self
    }

    /// Same as [`TlsConnectorDataBuilder::push_base_config`] but consuming self
    #[must_use]
    pub fn with_base_config(mut self, config: Arc<Self>) -> Self {
        self.push_base_config(config);
        self
    }

    generate_set_and_with!(
        /// Set the [`ServerVerifyMode`] that will be used by the tls client to verify the server
        pub fn server_verify_mode(mut self, server_verify_mode: Option<ServerVerifyMode>) -> Self {
            self.server_verify_mode = server_verify_mode;
            self
        }
    );

    generate_set_and_with!(
        /// Set the [`X509Store`] that will be used by the tls client to verify the server certs
        ///
        /// (unless the mode is [`ServerVerifyMode::Disable`])
        pub fn server_verify_cert_store(
            mut self,
            server_verify_cert_store: Option<Arc<X509Store>>,
        ) -> Self {
            self.server_verify_cert_store = server_verify_cert_store;
            self
        }
    );

    generate_set_and_with!(
        /// Set [`KeyLogIntent`] that will be used
        pub fn keylog_intent(mut self, intent: Option<KeyLogIntent>) -> Self {
            self.keylog_intent = intent;
            self
        }
    );

    generate_set_and_with!(
        /// Set the cipher list for this config
        pub fn cipher_list(mut self, list: Option<Vec<u16>>) -> Self {
            self.cipher_list = list;
            self
        }
    );

    generate_set_and_with!(
        /// Store server certificate chain if enabled in [`NegotiatedTlsParameters`] extension
        ///
        /// This will always clone the entire chain, so only enable this if needed.
        pub fn store_server_certificate_chain(
            mut self,
            store_server_certificate_chain: Option<bool>,
        ) -> Self {
            self.store_server_certificate_chain = store_server_certificate_chain;
            self
        }
    );

    generate_set_and_with!(
        /// Set alpn protos that this client will send to server
        ///
        /// Order of protocols here is important. When server supports
        /// multiple protocols it will choose the first one it supports
        /// from this list.
        pub fn alpn_protos(mut self, protos: Option<Bytes>) -> Self {
            self.alpn_protos = protos;
            self
        }
    );

    generate_set_and_with!(
        /// Set [`ApplicationProtocol`] that this client will send to server
        ///
        /// Order of protocols here is important. When server supports
        /// multiple protocols it will choose the first one it supports
        /// from this list.
        pub fn rama_alpn_protos(
            mut self,
            protos: Option<&[ApplicationProtocol]>,
        ) -> Result<Self, OpaqueError> {
            self.alpn_protos = protos
                .map(|protos| {
                    ApplicationProtocol::encode_alpns(protos)
                        .context("build (boring) ssl connector: encode alpns")
                })
                .transpose()?;
            Ok(self)
        }
    );

    generate_set_and_with!(
        /// Set the minimum ssl version that this connector will accept
        pub fn min_ssl_version(mut self, version: Option<SslVersion>) -> Self {
            self.min_ssl_version = version;
            self
        }
    );

    generate_set_and_with!(
        /// Set the maxium ssl version that this connector will accept
        pub fn max_ssl_version(mut self, version: Option<SslVersion>) -> Self {
            self.max_ssl_version = version;
            self
        }
    );

    generate_set_and_with!(
        /// Set the record size limit that will be set on this connector
        pub fn record_size_limit(mut self, limit: Option<u16>) -> Self {
            self.record_size_limit = limit;
            self
        }
    );

    generate_set_and_with!(
        /// Set if encrypted client hello should be enabled
        pub fn encrypted_client_hello(mut self, value: Option<bool>) -> Self {
            self.encrypted_client_hello = value;
            self
        }
    );

    generate_set_and_with!(
        /// Set if grease should be enable
        pub fn grease_enabled(mut self, value: Option<bool>) -> Self {
            self.grease_enabled = value;
            self
        }
    );

    generate_set_and_with!(
        /// Set if ocsp stapling should be needed
        pub fn ocsp_stapling_enabled(mut self, value: Option<bool>) -> Self {
            self.ocsp_stapling_enabled = value;
            self
        }
    );

    generate_set_and_with!(
        /// Set if signed certificate timestamps should be enabled
        pub fn signed_cert_timestamps_enabled(mut self, value: Option<bool>) -> Self {
            self.signed_cert_timestamps_enabled = value;
            self
        }
    );

    generate_set_and_with!(
        /// Set the order of client hello extensions
        pub fn extension_order(mut self, order: Option<Vec<u16>>) -> Self {
            self.extension_order = order;
            self
        }
    );

    generate_set_and_with!(
        /// Set the eliptic curves supported by this client
        pub fn curves(mut self, curves: Option<Vec<SslCurve>>) -> Self {
            self.curves = curves;
            self
        }
    );

    generate_set_and_with!(
        /// Set [`SslSignatureAlgorithm`]s for verifying
        pub fn verify_algorithm_prefs(mut self, prefs: Option<Vec<SslSignatureAlgorithm>>) -> Self {
            self.verify_algorithm_prefs = prefs;
            self
        }
    );

    generate_set_and_with!(
        /// Set client auth that will be used by this connector
        pub fn client_auth(mut self, auth: Option<ConnectorConfigClientAuth>) -> Self {
            self.client_auth = auth;
            self
        }
    );

    generate_set_and_with!(
        /// Set certificate compression algorithms
        pub fn certificate_compression_algorithms(
            mut self,
            algorithms: Option<Vec<CertificateCompressionAlgorithm>>,
        ) -> Self {
            self.certificate_compression_algorithms = algorithms;
            self
        }
    );

    generate_set_and_with!(
        /// Set delegated credential schemes
        pub fn delegated_credential_schemes(
            mut self,
            schemes: Option<Vec<SslSignatureAlgorithm>>,
        ) -> Self {
            self.delegated_credential_schemes = schemes;
            self
        }
    );

    generate_set_and_with!(
        /// Set server name used for SNI extension
        pub fn server_name(mut self, name: Option<Domain>) -> Self {
            self.server_name = name;
            self
        }
    );

    pub fn into_shared_builder(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Build the [`TlsConnectorData`] used by the [`TlsConnector`]
    ///
    /// NOTE: this method should in almost all circumstances never by called
    /// directly. The [`TlsConnector`] will call build only when needed and
    /// as late as possible. The only place where you manually need to build
    /// the [`TlsConnectorData`] is if you use [`tls_connect`] directly.
    ///
    /// [`TlsConnector`]: super::TlsConnector
    /// [`tls_connect`]: super::tls_connect
    pub fn build(&self) -> Result<TlsConnectorData, OpaqueError> {
        let mut cfg_builder =
            rama_boring::ssl::SslConnector::builder(rama_boring::ssl::SslMethod::tls_client())
                .context("create (boring) ssl connector builder")?;

        if let Some(store) = self.server_verify_cert_store() {
            trace!("boring connector: set provided cert store to verify as server");
            cfg_builder.set_cert_store_ref(store)
        } else {
            #[cfg(target_os = "windows")]
            {
                // on windows it seems to have no root CA by default when using boringssl
                // this code path is there to set it anyway
                static WINDOWS_ROOT_CA: std::sync::LazyLock<Result<X509Store, OpaqueError>> =
                    std::sync::LazyLock::new(|| {
                        trace!("boring connector: windows: load root certs for current user");

                        // Trusted Root Certification Authorities
                        let user_root = schannel::cert_store::CertStore::open_current_user("ROOT")
                            .context("open (root) cert store for current user")?;

                        let mut builder = rama_boring::x509::store::X509StoreBuilder::new()
                            .context("build x509 store builder")?;

                        for cert in user_root.certs() {
                            // Convert the Windows cert to DER, then to BoringSSL X509
                            if let Ok(x509) = X509::from_der(cert.to_der()) {
                                let _ = builder.add_cert(x509);
                            }
                        }

                        Ok(builder.build())
                    });

                let store_ref = WINDOWS_ROOT_CA.as_ref().context("create windows root CA")?;
                cfg_builder.set_cert_store_ref(store_ref);
            }
            #[cfg(not(target_os = "windows"))]
            trace!("boring connector: do not set (root) ca file"); // on non-windows we assume that the default is fine
        }

        if let Some(keylog_filename) = self.keylog_filepath().as_deref() {
            let handle = new_key_log_file_handle(keylog_filename)?;
            cfg_builder.set_keylog_callback(move |_, line| {
                let line = format!("{line}\n");
                handle.write_log_line(line);
            });
        }

        if let Some(order) = self.extension_order() {
            trace!("boring connector: set extension order: {order:?}");
            cfg_builder
                .set_extension_order(order)
                .context("build (boring) ssl connector: set extension order")?;
        }

        if let Some(list) = self.cipher_list() {
            trace!("boring connector: set raw cipher list: {list:?}");
            cfg_builder
                .set_raw_cipher_list(list)
                .context("build (boring) ssl connector: set cipher list")?;
        }

        if let Some(b) = self.alpn_protos() {
            trace!("boring connector: set ALPN protos: {b:?}",);
            cfg_builder
                .set_alpn_protos(b)
                .context("build (boring) ssl connector: set alpn protos")?;
        }

        if let Some(c) = self.curves() {
            trace!("boring connector: set {} SSL curve(s)", c.len());
            cfg_builder
                .set_curves(c)
                .context("build (boring) ssl connector: set curves")?;
        }

        let min_ssl_version = self.min_ssl_version();
        trace!(
            "boring connector: set SSL version: min: {:?}",
            min_ssl_version
        );
        cfg_builder
            .set_min_proto_version(min_ssl_version)
            .context("build (boring) ssl connector: set min proto version")?;

        let max_ssl_version = self.max_ssl_version();
        trace!(
            "boring connector: set SSL version: max: {:?}",
            max_ssl_version
        );
        cfg_builder
            .set_max_proto_version(max_ssl_version)
            .context("build (boring) ssl connector: set max proto version")?;

        if let Some(s) = self.verify_algorithm_prefs() {
            cfg_builder.set_verify_algorithm_prefs(s).context(
                "build (boring) ssl connector: set signature schemes (verify algorithm prefs)",
            )?;
        }

        let grease_enabled = self.grease_enabled().unwrap_or_default();
        cfg_builder.set_grease_enabled(grease_enabled);

        if self.ocsp_stapling_enabled().unwrap_or_default() {
            cfg_builder.enable_ocsp_stapling();
        }

        if self.signed_cert_timestamps_enabled().unwrap_or_default() {
            cfg_builder.enable_signed_cert_timestamps();
        }

        if let Some(compression_algorithms) = self.certificate_compression_algorithms() {
            for compressor in compression_algorithms.iter() {
                #[cfg(feature = "compression")]
                match compressor {
                    CertificateCompressionAlgorithm::Zlib => {
                        cfg_builder.add_certificate_compression_algorithm(ZlibCertificateCompressor::default()).context("build (boring) ssl connector: add certificate compression algorithm: zlib")?;
                    }
                    CertificateCompressionAlgorithm::Brotli => {
                        cfg_builder.add_certificate_compression_algorithm(
                            BrotliCertificateCompressor::default(),
                        )
                        .context("build (boring) ssl connector: add certificate compression algorithm: brotli")?;
                    }
                    CertificateCompressionAlgorithm::Zstd => {
                        cfg_builder.add_certificate_compression_algorithm(
                            ZstdCertificateCompressor::default(),
                        )
                        .context("build (boring) ssl connector: add certificate compression algorithm: zstd")?;
                    }
                    CertificateCompressionAlgorithm::Unknown(_) => {
                        debug!(
                            "boring connector: certificate compression algorithm: unknown: ignore"
                        );
                    }
                }
                #[cfg(not(feature = "compression"))]
                {
                    debug!(
                        "boring connector: certificate compression algorithm: {compressor}: not supported (feature compression not enabled)"
                    );
                }
            }
        }

        match self.server_verify_mode().unwrap_or_default() {
            ServerVerifyMode::Auto => {
                trace!("boring connector: server verify mode: auto (default verifier)");
            } // nothing explicit to do
            ServerVerifyMode::Disable => {
                trace!("boring connector: server verify mode: disable");
                cfg_builder.set_custom_verify_callback(SslVerifyMode::NONE, |_| Ok(()));
            }
        }

        if let Some(auth) = self.client_auth() {
            trace!("boring connector: client mTls: set private key");
            cfg_builder
                .set_private_key(auth.private_key.as_ref())
                .context("build (boring) ssl connector: set private key")?;
            if auth.cert_chain.is_empty() {
                return Err(OpaqueError::from_display(
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

        trace!("boring connector: build SSL connector config");
        let mut cfg = cfg_builder
            .build()
            .configure()
            .context("create ssl connector configuration")?;

        if let Some(limit) = self.record_size_limit() {
            trace!("boring connector: setting record size limit");
            cfg.set_record_size_limit(limit).unwrap();
        }

        if let Some(schemes) = self.delegated_credential_schemes() {
            trace!("boring connector: setting delegated credential schemes");
            cfg.set_delegated_credential_schemes(schemes).unwrap();
        }

        if self.encrypted_client_hello().unwrap_or_default() {
            trace!("boring connector: enabling ech grease");
            cfg.set_enable_ech_grease(true);
        }

        trace!(
            "boring connector: return SSL connector config for server: {:?}",
            self.server_name()
        );

        Ok(TlsConnectorData {
            config: cfg,
            store_server_certificate_chain: self
                .store_server_certificate_chain()
                .unwrap_or_default(),
            server_name: self.server_name().cloned(),
        })
    }
}

impl std::fmt::Debug for TlsConnectorDataBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug implementation of this struct will print each field, but also the getter of
        // each field. E.g server_verify_mode will show the value set on this exact builder and
        // server_verify_mode() will print the output of the getter, this will also go over
        // the entire chain of base_builders and will show the final value that will be used during build.
        f.debug_struct("TlsConnectorDataBuilder")
            .field("server_verify_mode", &self.server_verify_mode)
            .field("server_verify_mode()", &self.server_verify_mode())
            .field("keylog_intent", &self.keylog_intent)
            .field("keylog_intent()", &self.keylog_intent_inner())
            .field("cipher_list", &self.cipher_list)
            .field("cipher_list()", &self.cipher_list())
            .field(
                "store_server_certificate_chain",
                &self.store_server_certificate_chain,
            )
            .field(
                "store_server_certificate_chain()",
                &self.store_server_certificate_chain(),
            )
            .field("alpn_protos", &self.alpn_protos)
            .field("alpn_protos()", &self.alpn_protos())
            .field("min_ssl_version", &self.min_ssl_version)
            .field("min_ssl_version()", &self.min_ssl_version())
            .field("max_ssl_version", &self.max_ssl_version)
            .field("max_ssl_version()", &self.max_ssl_version())
            .field("record_size_limit", &self.record_size_limit)
            .field("record_size_limit()", &self.record_size_limit())
            .field("encrypted_client_hello", &self.encrypted_client_hello)
            .field("encrypted_client_hello()", &self.encrypted_client_hello())
            .field("grease_enabled", &self.grease_enabled)
            .field("grease_enabled()", &self.grease_enabled())
            .field("ocsp_stapling_enabled", &self.ocsp_stapling_enabled)
            .field("ocsp_stapling_enabled()", &self.ocsp_stapling_enabled())
            .field(
                "signed_cert_timestamps_enabled",
                &self.signed_cert_timestamps_enabled,
            )
            .field(
                "signed_cert_timestamps_enabled()",
                &self.signed_cert_timestamps_enabled(),
            )
            .field("extension_order", &self.extension_order)
            .field("extension_order()", &self.extension_order())
            .field("curves", &self.curves)
            .field("curves()", &self.curves())
            .field("verify_algorithm_prefs", &self.verify_algorithm_prefs)
            .field("verify_algorithm_prefs()", &self.verify_algorithm_prefs())
            .field("client_auth", &self.client_auth)
            .field("client_auth()", &self.client_auth())
            .field(
                "certificate_compression_algorithms",
                &self.certificate_compression_algorithms,
            )
            .field(
                "certificate_compression_algorithms()",
                &self.certificate_compression_algorithms(),
            )
            .field(
                "delegated_credential_schemes",
                &self.delegated_credential_schemes,
            )
            .field(
                "delegated_credential_schemes()",
                &self.delegated_credential_schemes(),
            )
            .field("server_name", &self.server_name)
            .field("server_name()", &self.server_name())
            .field("base_builders", &self.base_builders)
            .finish()
    }
}

// TODO in the future ClientConfig will be removed and instead we will create
// this builder from a client_hello (or something else) directly, but until we do that we also
// support creating this builder from a ClientConfig chain.
impl TlsConnectorDataBuilder {
    pub fn try_from_multiple_client_configs<'a>(
        cfg_it: impl Iterator<Item = &'a rama_net::tls::client::ClientConfig>,
    ) -> Result<Self, OpaqueError> {
        let mut keylog_intent = None;
        let mut extension_order = None;
        let mut cipher_suites = None;
        let mut server_name = None;
        let mut alpn_protos = None;
        let mut curves = None;
        let mut min_ssl_version = None;
        let mut max_ssl_version = None;
        let mut verify_algorithm_prefs = None;
        let mut server_verify_mode = None;
        let mut store_server_certificate_chain = false;
        let mut client_auth = None;
        let mut grease_enabled = false;
        let mut ocsp_stapling_enabled = false;
        let mut signed_cert_timestamps_enabled = false;
        let mut certificate_compression_algorithms = None;
        let mut record_size_limit = None;
        let mut delegated_credential_schemes = None;
        let mut encrypted_client_hello = None;

        for cfg in cfg_it {
            cipher_suites = cfg.cipher_suites.as_ref().or(cipher_suites);
            keylog_intent = cfg.key_logger.as_ref().or(keylog_intent);
            client_auth = cfg.client_auth.as_ref().or(client_auth);
            server_verify_mode = cfg.server_verify_mode.or(server_verify_mode);
            store_server_certificate_chain =
                store_server_certificate_chain || cfg.store_server_certificate_chain;

            extension_order = {
                let v: Vec<_> = extension_order
                    .into_iter()
                    .flatten()
                    .chain(
                        cfg.extensions
                            .iter()
                            .flatten()
                            .map(|ext| u16::from(ext.id())),
                    )
                    .dedup()
                    .collect();
                (!v.is_empty()).then_some(v)
            };

            // use the extensions that we can use for the builder
            for extension in cfg.extensions.iter().flatten() {
                match extension {
                    ClientHelloExtension::ServerName(maybe_domain) => {
                        server_name = if maybe_domain.is_some() {
                            trace!(
                                "TlsConnectorData: builder: from std client config: set server (domain) name from host: {:?}",
                                maybe_domain
                            );
                            maybe_domain.clone()
                        } else {
                            trace!(
                                "TlsConnectorData: builder: from std client config: ignore server null value"
                            );
                            None
                        };
                    }
                    ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn_list) => {
                        trace!(
                            "TlsConnectorData: builder: from std client config: alpn: {:?}",
                            alpn_list
                        );
                        let alpns = ApplicationProtocol::encode_alpns(alpn_list)
                            .context("build (boring) ssl connector: encode alpns")?;
                        alpn_protos = Some(alpns);
                    }
                    ClientHelloExtension::SupportedGroups(groups) => {
                        trace!(
                            "TlsConnectorData: builder: from std client config: supported groups: {:?}",
                            groups
                        );
                        curves = Some(groups.iter().filter_map(|c| {
                            if c.is_grease() {
                                grease_enabled = true;
                                trace!("ignore grease support group (curve) {c}");
                                return None;
                            }

                            match (*c).rama_try_into() {
                                Ok(v) => Some(v),
                                Err(c) => {
                                trace!("ignore unsupported support group (curve) {c} (file issue if you require it");
                                None
                                }
                                }
                        }).dedup().collect());
                    }
                    ClientHelloExtension::SupportedVersions(versions) => {
                        trace!(
                            "TlsConnectorData: builder: from std client config: supported versions: {:?}",
                            versions
                        );

                        if let Some(min_ver) = versions
                            .iter()
                            .filter(|v| {
                                if v.is_grease() {
                                    grease_enabled = true;
                                    trace!("ignore grease support version {v}");
                                    return false;
                                }
                                true
                            })
                            .min()
                        {
                            trace!(
                                "TlsConnectorData: builder: from std client config: min version: {:?}",
                                min_ver
                            );
                            min_ssl_version = Some((*min_ver).rama_try_into().map_err(|v| {
                                OpaqueError::from_display(format!("protocol version {v}"))
                                    .context("build boring ssl connector: min proto version")
                            })?);
                        }

                        if let Some(max_ver) = versions
                            .iter()
                            .filter(|v| {
                                if v.is_grease() {
                                    grease_enabled = true;
                                    trace!("ignore grease support version {v}");
                                    return false;
                                }
                                true
                            })
                            .max()
                        {
                            trace!(
                                "TlsConnectorData: builder: from std client config: max version: {:?}",
                                max_ver
                            );
                            max_ssl_version = Some((*max_ver).rama_try_into().map_err(|v| {
                                OpaqueError::from_display(format!("protocol version {v}"))
                                    .context("build boring ssl connector: max proto version")
                            })?);
                        }
                    }
                    ClientHelloExtension::SignatureAlgorithms(schemes) => {
                        trace!(
                            "TlsConnectorData: builder: from std client config: signature algorithms: {:?}",
                            schemes
                        );
                        verify_algorithm_prefs = Some(schemes.iter().filter_map(|s| {
                            if s.is_grease() {
                                grease_enabled = true;
                                trace!("ignore grease signatured schemes {s}");
                                return None;
                            }

                            match (*s).rama_try_into() {
                                Ok(v) => Some(v),
                                Err(s) => {
                                    trace!("ignore unsupported signatured schemes {s} (file issue if you require it");
                                    None
                                }
                            }
                        }).dedup().collect());
                    }
                    ClientHelloExtension::CertificateCompression(algorithms) => {
                        trace!(
                            "TlsConnectorData: builder: from std client config: certificate compression algorithms: {:?}",
                            algorithms
                        );
                        certificate_compression_algorithms = Some(algorithms.clone());
                    }
                    ClientHelloExtension::DelegatedCredentials(schemes) => {
                        trace!(
                            "TlsConnectorData: builder: from std client config: delegated credentials signature algorithms: {:?}",
                            schemes
                        );
                        delegated_credential_schemes = Some(
                            schemes
                                .iter()
                                .filter_map(|s| {
                                    match (*s).rama_try_into() {
                                        Ok(v) => Some(v),
                                        Err(s) => {
                                            trace!("ignore unsupported signatured scheme for delegated creds {s} (file issue if you require it");
                                            None
                                        }
                                    }
                                })
                                .collect(),
                        );
                    }
                    ClientHelloExtension::RecordSizeLimit(limit) => {
                        trace!(
                            "TlsConnectorData: builder: from std client config: record size limit: {:?}",
                            limit
                        );
                        record_size_limit = Some(*limit);
                    }
                    ClientHelloExtension::EncryptedClientHello(_) => {
                        trace!(
                            "TlsConnectorData: builder: from std client config: encrypted client hello enabled",
                        );
                        encrypted_client_hello = Some(true);
                    }
                    other => match other.id() {
                        ExtensionId::STATUS_REQUEST | ExtensionId::STATUS_REQUEST_V2 => {
                            trace!(
                                "TlsConnectorData: builder: from std client config: enable ocsp stapling (ext = {other:?})"
                            );
                            ocsp_stapling_enabled = true;
                        }
                        ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP => {
                            trace!(
                                "TlsConnectorData: builder: from std client config: enable signed cert timestamps (ext = {other:?})"
                            );
                            signed_cert_timestamps_enabled = true;
                        }
                        _ => {
                            trace!(
                                "TlsConnectorData: builder: from std client config: ignore client hello ext (ext = {other:?})"
                            );
                        }
                    },
                }
            }
        }

        let cipher_list: Option<Vec<u16>> = cipher_suites
            .as_ref()
            .map(|v| v.iter().copied().map(Into::into).collect());
        trace!(
            "TlsConnectorData: builder: from std client config: cipher list: {:?}; supported groups: {:?}",
            cipher_list, curves,
        );

        let client_auth = client_auth
            .map(|auth| auth.clone().try_into())
            .transpose()?;

        Ok(Self {
            base_builders: vec![],
            keylog_intent: keylog_intent.cloned(),
            extension_order,
            cipher_list,
            alpn_protos,
            curves,
            min_ssl_version,
            max_ssl_version,
            verify_algorithm_prefs,
            server_verify_mode,
            server_verify_cert_store: None,
            client_auth,
            store_server_certificate_chain: Some(store_server_certificate_chain),
            grease_enabled: Some(grease_enabled),
            ocsp_stapling_enabled: Some(ocsp_stapling_enabled),
            signed_cert_timestamps_enabled: Some(signed_cert_timestamps_enabled),
            certificate_compression_algorithms,
            delegated_credential_schemes,
            record_size_limit,
            encrypted_client_hello,
            server_name,
        })
    }
}

impl TryFrom<&rama_net::tls::client::ClientConfig> for TlsConnectorDataBuilder {
    type Error = OpaqueError;

    fn try_from(value: &rama_net::tls::client::ClientConfig) -> Result<Self, Self::Error> {
        Self::try_from_multiple_client_configs(std::iter::once(value))
    }
}

impl TryFrom<&Arc<rama_net::tls::client::ClientConfig>> for TlsConnectorDataBuilder {
    type Error = OpaqueError;

    fn try_from(value: &Arc<rama_net::tls::client::ClientConfig>) -> Result<Self, Self::Error> {
        Self::try_from_multiple_client_configs(std::iter::once(value.as_ref()))
    }
}

impl TryFrom<ClientHello> for TlsConnectorDataBuilder {
    type Error = OpaqueError;

    fn try_from(value: ClientHello) -> Result<Self, Self::Error> {
        let client_config = rama_net::tls::client::ClientConfig::from(value);
        Self::try_from(&client_config)
    }
}

impl TryFrom<ClientAuth> for ConnectorConfigClientAuth {
    type Error = OpaqueError;

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
                let cert_chain = match data.cert_chain {
                    DataEncoding::Der(raw_data) => vec![X509::from_der(&raw_data[..]).context(
                        "boring/TlsConnectorData: parse x509 client cert from DER content",
                    )?],
                    DataEncoding::DerStack(raw_data_list) => raw_data_list
                        .into_iter()
                        .map(|raw_data| {
                            X509::from_der(&raw_data[..]).context(
                                "boring/TlsConnectorData: parse x509 client cert from DER content",
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    DataEncoding::Pem(raw_data) => X509::stack_from_pem(raw_data.as_bytes())
                        .context(
                        "boring/TlsConnectorData: parse x509 client cert chain from PEM content",
                    )?,
                };

                // server TLS key
                let private_key = match data.private_key {
                    DataEncoding::Der(raw_data) => PKey::private_key_from_der(&raw_data[..])
                        .context("boring/TlsConnectorData: parse private key from DER content")?,
                    DataEncoding::DerStack(raw_data_list) => {
                        PKey::private_key_from_der(
                            &raw_data_list.first().context(
                                "boring/TlsConnectorData: get first private key raw data",
                            )?[..],
                        )
                        .context("boring/TlsConnectorData: parse private key from DER content")?
                    }
                    DataEncoding::Pem(raw_data) => PKey::private_key_from_pem(raw_data.as_bytes())
                        .context("boring/TlsConnectorData: parse private key from PEM content")?,
                };

                Ok(Self {
                    cert_chain,
                    private_key,
                })
            }
        }
    }
}

fn self_signed_client_auth() -> Result<(Vec<X509>, PKey<Private>), OpaqueError> {
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

    #[test]
    fn test_chaining() {
        let base_builder =
            TlsConnectorDataBuilder::new_http_1().with_store_server_certificate_chain(true);

        let builder =
            TlsConnectorDataBuilder::new().with_base_config(base_builder.into_shared_builder());

        assert_eq!(builder.store_server_certificate_chain(), Some(true));
    }
}
