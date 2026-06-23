use crate::client::config::BoringTlsConnectorConfig;
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
        store::{X509Store, X509StoreBuilder},
    },
};
use rama_core::error::BoxErrorExt as _;
use rama_core::telemetry::tracing::{debug, trace};
use rama_core::{
    conversion::RamaTryInto,
    error::{BoxError, ErrorContext, ErrorExt},
};
use rama_crypto::dep::x509_parser::nom::AsBytes;
use rama_net::tls::client::ClientAuth;
use rama_net::tls::client::TlsClientConfig;
use rama_net::tls::{ApplicationProtocol, KeyLogIntent};
use rama_net::{address::Domain, tls::client::ServerVerifyMode};
use std::fmt;

#[cfg(feature = "compression")]
use super::compress_certificate::{
    BrotliCertificateCompressor, ZlibCertificateCompressor, ZstdCertificateCompressor,
};
#[cfg(feature = "compression")]
use rama_net::tls::CertificateCompressionAlgorithm;

use rama_net::tls::keylog::{KeyLogSink, open_intent_sink};

/// /// The resolved native boringssl config consumed by [`super::TlsConnector`].
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
        let server_verify_mode = value.verify.map(|v| v.0).unwrap_or_default();
        let store_server_certificate_chain = value.store_chain.map(|p| p.0).unwrap_or_default();
        let server_name = value
            .server_name
            .and_then(|s| s.0.clone().try_into_domain().ok());

        let keylog_intent = value
            .keylog
            .map(|k| k.0.clone())
            .unwrap_or(KeyLogIntent::Environment);
        let grease_enabled = value.grease.map(|p| p.0).unwrap_or_default();
        let ocsp_stapling_enabled = value.ocsp_stapling.map(|p| p.0).unwrap_or_default();
        let signed_cert_timestamps_enabled = value
            .signed_cert_timestamps
            .map(|p| p.0)
            .unwrap_or_default();
        let encrypted_client_hello = value
            .encrypted_client_hello
            .map(|p| p.0)
            .unwrap_or_default();
        let record_size_limit = value.record_size_limit.map(|p| p.0);
        let server_verify_cert_store = value.verify_cert_store.map(|p| p.0.clone());
        let alps = value.alps.map(|p| (p.protocols.clone(), p.new_codepoint));

        let alpn_protos = value
            .alpn
            .map(|a| {
                ApplicationProtocol::encode_alpns(&a.0)
                    .context("build (boring) ssl connector: encode alpns")
            })
            .transpose()?;

        let cipher_list: Option<Vec<u16>> = value
            .cipher_suites
            .map(|p| p.0.iter().map(|c| (*c).into()).collect());
        let extension_order: Option<Vec<u16>> = value
            .extension_order
            .map(|p| p.0.iter().map(|e| u16::from(*e)).collect());
        let certificate_compression_algorithms = value.cert_compression.map(|p| p.0.clone());

        let curves = value.supported_groups.map(|p| {
            // Distinct rama groups can map to the same boring `SslCurve`: drop the
            // resulting consecutive duplicates (boring rejects a duplicate curve).
            let mut curves: Vec<SslCurve> =
                p.0.iter()
                    .filter_map(|g| (*g).rama_try_into().ok())
                    .collect();
            curves.dedup();
            curves
        });
        let verify_algorithm_prefs = value.signature_schemes.map(|p| {
            // Distinct rama schemes can map to the same boring `SslSignatureAlgorithm`;
            // drop the resulting consecutive duplicates (boring errors on
            // DUPLICATE_SIGNATURE_ALGORITHM otherwise).
            let mut prefs: Vec<SslSignatureAlgorithm> =
                p.0.iter()
                    .filter_map(|s| (*s).rama_try_into().ok())
                    .collect();
            prefs.dedup();
            prefs
        });
        let delegated_credential_schemes: Option<Vec<SslSignatureAlgorithm>> =
            value.delegated_credentials.map(|p| {
                p.0.iter()
                    .filter_map(|s| (*s).rama_try_into().ok())
                    .collect()
            });

        let client_auth = value
            .client_auth
            .map(|c| ConnectorConfigClientAuth::try_from(c.0.clone()))
            .transpose()?;

        // Versions: min/max derived from the offered list, explicit overrides win.
        // (The max override also doubles as the mitm egress safety clamp.)
        let mut min_ssl_version: Option<SslVersion> = None;
        let mut max_ssl_version: Option<SslVersion> = None;
        if let Some(versions) = value.versions {
            if let Some(min) = versions.0.iter().filter(|v| !v.is_grease()).min() {
                min_ssl_version = Some((*min).rama_try_into().map_err(|v| {
                    BoxError::from_static_str("boring connector: cast min proto version")
                        .context_field("protocol_version", v)
                })?);
            }
            if let Some(max) = versions.0.iter().filter(|v| !v.is_grease()).max() {
                max_ssl_version = Some((*max).rama_try_into().map_err(|v| {
                    BoxError::from_static_str("boring connector: cast max proto version")
                        .context_field("protocol_version", v)
                })?);
            }
        }
        if let Some(p) = value.min_version {
            min_ssl_version = Some((p.0).rama_try_into().map_err(|v| {
                BoxError::from_static_str("boring connector: cast min proto version override")
                    .context_field("protocol_version", v)
            })?);
        }
        if let Some(p) = value.max_version {
            max_ssl_version = Some((p.0).rama_try_into().map_err(|v| {
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
        if min_ssl_version == Some(SslVersion::TLS1_3)
            && max_ssl_version == Some(SslVersion::TLS1_2)
        {
            min_ssl_version = Some(SslVersion::TLS1_2);
        }

        // `no_default_verify_builder` skips boring's per-call
        // `set_default_verify_paths`, which would otherwise parse the entire OS
        // trust store into a throwaway per-connector store on every build. We
        // install exactly the store we need below instead.
        let mut cfg_builder = rama_boring::ssl::SslConnector::no_default_verify_builder(
            rama_boring::ssl::SslMethod::tls_client(),
        )
        .context("create (boring) ssl connector builder")?;

        if let Some(store) = &server_verify_cert_store {
            trace!("boring connector: set provided cert store to verify as server");
            cfg_builder.set_cert_store_ref(store);
        } else {
            match server_verify_mode {
                ServerVerifyMode::Disable => {
                    // Verification is disabled (a NONE verify callback is
                    // installed below), so the trust store is never consulted:
                    // leave the empty store from `no_default_verify_builder`
                    // and don't parse the OS bundle at all.
                    trace!(
                        "boring connector: server verification disabled; no verify cert store loaded"
                    );
                }
                ServerVerifyMode::Auto => {
                    // Install a process-wide, parse-once shared OS default store
                    // so every connector references one copy instead of
                    // re-parsing the bundle on every build.
                    trace!("boring connector: using shared default verify cert store");
                    cfg_builder.set_cert_store_ref(shared_default_verify_store()?);
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

        if let Some(order) = &extension_order {
            trace!(?order, "boring connector: set extension order");
            cfg_builder
                .set_extension_order(order)
                .context("build (boring) ssl connector: set extension order")?;
        }

        if let Some(list) = &cipher_list {
            trace!(?list, "boring connector: set raw cipher list");
            cfg_builder
                .set_raw_cipher_list(list)
                .context("build (boring) ssl connector: set cipher list")?;
        }

        if let Some(alpn_protos) = &alpn_protos {
            trace!(?alpn_protos, "boring connector: set ALPN protos");
            cfg_builder
                .set_alpn_protos(alpn_protos)
                .context("build (boring) ssl connector: set alpn protos")?;
        }

        if let Some(curves) = &curves {
            trace!(curves = curves.len(), "boring connector: set SSL curve(s)");
            cfg_builder
                .set_curves(curves)
                .context("build (boring) ssl connector: set curves")?;
        }

        trace!(?min_ssl_version, "boring connector: set min SSL version");
        cfg_builder
            .set_min_proto_version(min_ssl_version)
            .context("build (boring) ssl connector: set min proto version")?;

        trace!(?max_ssl_version, "boring connector: set max SSL version");
        cfg_builder
            .set_max_proto_version(max_ssl_version)
            .context("build (boring) ssl connector: set max proto version")?;

        if let Some(s) = &verify_algorithm_prefs {
            cfg_builder.set_verify_algorithm_prefs(s).context(
                "build (boring) ssl connector: set signature schemes (verify algorithm prefs)",
            )?;
        }

        cfg_builder.set_grease_enabled(grease_enabled);

        if ocsp_stapling_enabled {
            cfg_builder.enable_ocsp_stapling();
        }

        if signed_cert_timestamps_enabled {
            cfg_builder.enable_signed_cert_timestamps();
        }

        if let Some(compression_algorithms) = &certificate_compression_algorithms {
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

        match server_verify_mode {
            ServerVerifyMode::Auto => {
                trace!("boring connector: server verify mode: auto (default verifier)");
            } // nothing explicit to do
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

        trace!("boring connector: build SSL connector config");
        let mut cfg = cfg_builder
            .build()
            .configure()
            .context("create ssl connector configuration")?;

        if let Some((alps_list, new_codepoint)) = &alps {
            trace!("boring connector: set ALPS config");
            cfg.set_alps_use_new_codepoint(*new_codepoint);
            for app_proto in alps_list {
                cfg.add_application_settings(app_proto.as_bytes())
                    .context("set alps application settings")?;
            }
        }

        if let Some(limit) = record_size_limit {
            trace!("boring connector: setting record size limit");
            cfg.set_record_size_limit(limit)
                .context("set record size limit")?;
        }

        if let Some(schemes) = &delegated_credential_schemes {
            trace!("boring connector: setting delegated credential schemes");
            cfg.set_delegated_credential_schemes(schemes)
                .context("set delegated credential schemas")?;
        }

        if encrypted_client_hello {
            trace!("boring connector: enabling ech grease");
            cfg.set_enable_ech_grease(true);
        }

        trace!(
            ?server_name,
            "boring connector: return SSL connector config for server"
        );

        Ok(Self {
            config: cfg,
            store_server_certificate_chain,
            server_name,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ConnectorConfigClientAuth {
    pub cert_chain: Vec<X509>,
    pub private_key: PKey<Private>,
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
    static STORE: std::sync::LazyLock<Result<X509Store, BoxError>> =
        std::sync::LazyLock::new(build_os_default_verify_store);
    match &*STORE {
        Ok(store) => Ok(store),
        Err(err) => Err(err
            .to_string()
            .context("shared default verify store")
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

    let mut builder =
        X509StoreBuilder::new().context("create x509 store builder for native trust anchors")?;

    let mut added = 0_usize;
    let mut failed = 0_usize;
    for der in anchors.iter() {
        match X509::from_der(der.as_ref()) {
            Ok(cert) => match builder.add_cert(cert) {
                Ok(()) => added += 1,
                Err(err) => {
                    failed += 1;
                    debug!(%err, "boring connector: failed to add native trust anchor to store");
                }
            },
            Err(err) => {
                failed += 1;
                debug!(%err, "boring connector: failed to parse native trust anchor as x509");
            }
        }
    }

    trace!(added, failed, "boring connector: shared verify store built");

    if added == 0 {
        return Err(BoxError::from_static_str(
            "no native trust anchors could be added to the boring x509 verify store",
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
    use rama_net::tls::client::{
        ClientHello, ClientHelloExtension, TlsServerVerify, TlsStoreServerCertChain,
    };
    use rama_net::tls::{CipherSuite, ProtocolVersion, SignatureScheme, TlsAlpn};

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
