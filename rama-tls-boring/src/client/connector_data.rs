use crate::RamaTryInto;
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
    },
};
use rama_core::error::{ErrorContext, ErrorExt, OpaqueError};
use rama_net::tls::CipherSuite;
use rama_net::tls::{
    ApplicationProtocol, CertificateCompressionAlgorithm, ExtensionId, KeyLogIntent,
};
use rama_net::tls::{
    DataEncoding,
    client::{ClientAuth, ClientHelloExtension},
};
use rama_net::{address::Host, tls::client::ServerVerifyMode};
use rama_utils::macros::generate_set_and_with;
use std::{fmt, sync::Arc};
use tracing::{debug, trace};

#[cfg(feature = "compression")]
use super::compress_certificate::{BrotliCertificateCompressor, ZlibCertificateCompressor};

use crate::keylog::new_key_log_file_handle;

#[non_exhaustive]
/// [`TlsConnectorData`] that will be used by the connector
pub struct TlsConnectorData {
    pub config: ConnectConfiguration,
    pub store_server_certificate_chain: bool,
    pub server_name: Option<Host>,
}

impl std::fmt::Debug for TlsConnectorData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConnectorData")
            .field("config", &"debug not implemented")
            .field(
                "store_server_certificate_chain",
                &self.store_server_certificate_chain,
            )
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl TlsConnectorData {
    pub fn builder() -> TlsConnectorDataBuilder {
        TlsConnectorDataBuilder::new()
    }
}

/// Create [`TlsConnectorDataBuilder`] struct
///
/// This also adds a getter for each field. If this field
/// is None it will try to get a value from `base_builder`
/// if it exists.
macro_rules! generate_tls_connector_data_builder {
    (
        $($name:ident: Option<$type:ty>),* $(,)?
        =>
        $($copy_name:ident: Option<$copy_type:ty>),* $(,)?
    ) => {
        #[derive(Clone, Default, Debug)]
        /// Use [`TlsConnectorDataBuilder`] to build a [`TlsConnectorData`] in an ergonomic way
        ///
        /// This builder is very powerful and is capable of stacking other builders. Using it
        /// this way gives each layer the option to modify what is needed in a very efficient way.
        pub struct TlsConnectorDataBuilder {
            base_builders: Vec<Arc<TlsConnectorDataBuilder>>,
            $(
                $name: Option<$type>,
            )*
            $(
                $copy_name: Option<$copy_type>,
            )*
        }

        impl TlsConnectorDataBuilder {
            $(
                pub fn $name(&self) -> Option<&$type> {
                    if let Some(value) = &self.$name {
                        return Some(value);
                    }
                    for builder in self.base_builders.iter().rev() {
                        if let Some(value) = builder.$name() {
                            return Some(value);
                        }
                    }
                    None
                }
            )*

            $(
                pub fn $copy_name(&self) -> Option<$copy_type> {
                    if let Some(value) = self.$copy_name {
                        return Some(value);
                    }
                    for builder in self.base_builders.iter().rev() {
                        if let Some(value) = builder.$copy_name() {
                            return Some(value);
                        }
                    }
                    None
                }
            )*
        }
    };
}

generate_tls_connector_data_builder!(
    keylog_intent: Option<KeyLogIntent>,
    cipher_list: Option<Vec<u16>>,
    extension_order: Option<Vec<u16>>,
    alpn_protos: Option<Vec<u8>>,
    curves: Option<Vec<SslCurve>>,
    verify_algorithm_prefs: Option<Vec<SslSignatureAlgorithm>>,
    client_auth: Option<ConnectorConfigClientAuth>,
    certificate_compression_algorithms: Option<Vec<CertificateCompressionAlgorithm>>,
    delegated_credential_schemes: Option<Vec<SslSignatureAlgorithm>>,
    server_name: Option<Host>,
    => // These types implement copy
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

#[derive(Debug, Clone)]
pub struct ConnectorConfigClientAuth {
    pub(super) cert_chain: Vec<X509>,
    pub(super) private_key: PKey<Private>,
}

impl TlsConnectorDataBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_http_auto() -> Self {
        Self::new()
            .with_alpn_protos(&[ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11])
            .expect("with http 2 and http 1")
    }

    pub fn new_http_1() -> Self {
        Self::new()
            .with_alpn_protos(&[ApplicationProtocol::HTTP_11])
            .expect("with http1")
    }

    pub fn new_http_2() -> Self {
        Self::new()
            .with_alpn_protos(&[ApplicationProtocol::HTTP_2])
            .expect("with http 2")
    }

    /// Add [`ConfigBuilder`] to the end of base config builder
    ///
    /// When evaluating builders we start from this builder and
    /// work our way back until we find a value.
    pub fn push_base_config(&mut self, config: Arc<TlsConnectorDataBuilder>) -> &mut Self {
        self.base_builders.push(config);
        self
    }

    pub fn prepend_base_config(&mut self, config: Arc<TlsConnectorDataBuilder>) -> &mut Self {
        self.base_builders.insert(0, config);
        self
    }

    /// Will push base config to end
    pub fn with_base_config(mut self, config: Arc<TlsConnectorDataBuilder>) -> Self {
        self.push_base_config(config);
        self
    }

    generate_set_and_with!(
        /// Set [`KeyLogIntent`] that will be used
        pub fn keylog_intent(mut self, intent: Option<KeyLogIntent>) -> Self {
            self.keylog_intent = intent;
            self
        }
    );

    generate_set_and_with!(
        /// TODO
        pub fn cipher_list(mut self, cipher_suites: Option<&Vec<CipherSuite>>) -> Self {
            self.cipher_list = cipher_suites.map(|v| v.iter().copied().map(Into::into).collect());
            self
        }
    );

    generate_set_and_with!(
        /// TODO
        pub fn store_server_certificate_chain(
            mut self,
            store_server_certificate_chain: Option<bool>,
        ) -> Self {
            self.store_server_certificate_chain = store_server_certificate_chain;
            self
        }
    );

    generate_set_and_with!(
        /// TODO
        pub fn server_verify_mode(mut self, server_verify_mode: Option<ServerVerifyMode>) -> Self {
            self.server_verify_mode = server_verify_mode;
            self
        }
    );

    generate_set_and_with!(
        /// TODO
        pub fn alpn_protos(
            mut self,
            protos: Option<&[ApplicationProtocol]>,
        ) -> Result<Self, OpaqueError> {
            self.alpn_protos = if let Some(protos) = protos {
                let mut alpn_protos: Vec<u8> = vec![];
                for alpn in protos {
                    alpn.encode_wire_format(&mut alpn_protos)
                        .context("build (boring) ssl connector: encode alpn")?;
                }
                Some(alpn_protos)
            } else {
                None
            };

            Ok(self)
        }
    );

    pub fn build_shared_builder(self) -> Arc<Self> {
        Arc::new(self)
    }

    pub(super) fn build(&self) -> Result<TlsConnectorData, OpaqueError> {
        let mut cfg_builder =
            rama_boring::ssl::SslConnector::builder(rama_boring::ssl::SslMethod::tls_client())
                .context("create (boring) ssl connector builder")?;

        if let Some(keylog_filename) = self
            .keylog_intent()
            .as_ref()
            .and_then(|intent| intent.file_path())
        {
            let handle = new_key_log_file_handle(keylog_filename)?;
            cfg_builder.set_keylog_callback(move |_, line| {
                let line = format!("{}\n", line);
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
                        // TODO fork boring and implement zstd compression
                        debug!(
                            "boring connector: certificate compression algorithm: zstd: not (yet) supported: ignore"
                        );
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
        println!(
            "builder with: {}",
            self.store_server_certificate_chain().unwrap_or_default()
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

// TODO in the future ClientConfig will be removed and instead we will create
// this builder from a client_hello directly, but until we do that we keep this indirection
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
                    ClientHelloExtension::ServerName(maybe_host) => {
                        server_name = match maybe_host {
                            Some(Host::Name(_)) => {
                                trace!(
                                    "TlsConnectorData: builder: from std client config: set server (domain) name from host: {:?}",
                                    maybe_host
                                );
                                maybe_host.clone()
                            }
                            Some(Host::Address(_)) => {
                                trace!(
                                    "TlsConnectorData: builder: from std client config: set server (ip) name from host: {:?}",
                                    maybe_host
                                );
                                maybe_host.clone()
                            }
                            None => {
                                trace!(
                                    "TlsConnectorData: builder: from std client config: ignore server null value"
                                );
                                None
                            }
                        };
                    }
                    ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn_list) => {
                        trace!(
                            "TlsConnectorData: builder: from std client config: alpn: {:?}",
                            alpn_list
                        );
                        let mut buf = vec![];
                        for alpn in alpn_list {
                            alpn.encode_wire_format(&mut buf)
                                .context("build (boring) ssl connector: encode alpn")?;
                        }
                        alpn_protos = Some(buf);
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
                            trace!(ext = ?other, "TlsConnectorData: builder: from std client config: enable ocsp stapling");
                            ocsp_stapling_enabled = true;
                        }
                        ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP => {
                            trace!(ext = ?other, "TlsConnectorData: builder: from std client config: enable signed cert timestamps");
                            signed_cert_timestamps_enabled = true;
                        }
                        _ => {
                            trace!(ext = ?other, "TlsConnectorData: builder: from std client config: ignore client hello ext");
                        }
                    },
                }
            }
        }

        let cipher_list: Option<Vec<u16>> = cipher_suites
            .as_ref()
            .map(|v| v.iter().copied().map(Into::into).collect());
        trace!(
            "TlsConnectorData: builder: from std client config: cipher list: {:?}",
            cipher_list
        );

        let client_auth = match client_auth.cloned() {
            None => None,
            Some(ClientAuth::SelfSigned) => {
                let (cert_chain, private_key) =
                    self_signed_client_auth().context("boring/TlsConnectorData")?;
                Some(ConnectorConfigClientAuth {
                    cert_chain,
                    private_key,
                })
            }
            Some(ClientAuth::Single(data)) => {
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

                Some(ConnectorConfigClientAuth {
                    cert_chain,
                    private_key,
                })
            }
        };

        println!("builder with servername: {:?}", server_name);
        Ok(TlsConnectorDataBuilder {
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
        TlsConnectorDataBuilder::try_from_multiple_client_configs(std::iter::once(value))
    }
}

impl TryFrom<&Arc<rama_net::tls::client::ClientConfig>> for TlsConnectorDataBuilder {
    type Error = OpaqueError;

    fn try_from(value: &Arc<rama_net::tls::client::ClientConfig>) -> Result<Self, Self::Error> {
        TlsConnectorDataBuilder::try_from_multiple_client_configs(std::iter::once(value.as_ref()))
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
                .context("x509 cert builder: build basic constraints")?,
        )
        .context("x509 cert builder: add basic constraints as x509 extension")?;
    cert_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .context("x509 cert builder: create key usage")?,
        )
        .context("x509 cert builder: add key usage x509 extension")?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(None, None))
        .context("x509 cert builder: build subject key id")?;
    cert_builder
        .append_extension(subject_key_identifier)
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
            TlsConnectorDataBuilder::new().with_base_config(base_builder.build_shared_builder());

        assert_eq!(builder.store_server_certificate_chain(), Some(true));
    }

    // TODO test more advanced combinations
}
