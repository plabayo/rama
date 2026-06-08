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
use rama_core::telemetry::tracing::{debug, trace};
use rama_core::{
    conversion::RamaTryInto,
    error::{BoxError, ErrorContext, ErrorExt},
};
use rama_net::tls::client::TlsClientConfig;
use rama_net::tls::{ApplicationProtocol, KeyLogIntent};
use rama_net::tls::{DataEncoding, client::ClientAuth};
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
                    BoxError::from("boring connector: cast min proto version")
                        .context_field("protocol_version", v)
                })?);
            }
            if let Some(max) = versions.0.iter().filter(|v| !v.is_grease()).max() {
                max_ssl_version = Some((*max).rama_try_into().map_err(|v| {
                    BoxError::from("boring connector: cast max proto version")
                        .context_field("protocol_version", v)
                })?);
            }
        }
        if let Some(p) = value.min_version {
            min_ssl_version = Some((p.0).rama_try_into().map_err(|v| {
                BoxError::from("boring connector: cast min proto version override")
                    .context_field("protocol_version", v)
            })?);
        }
        if let Some(p) = value.max_version {
            max_ssl_version = Some((p.0).rama_try_into().map_err(|v| {
                BoxError::from("boring connector: cast max proto version override")
                    .context_field("protocol_version", v)
            })?);
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
                return Err(BoxError::from(
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

/// Process-wide OS default trust store, parsed once and shared by every
/// connector that needs server verification.
///
/// `SslConnector::builder` calls `set_default_verify_paths` internally,
/// which parses the entire system CA bundle into a *fresh* store on every
/// call; left as-is that keeps a full copy of the bundle resident for the
/// lifetime of each in-flight connection. Swapping in this single shared
/// store via `set_cert_store_ref` collapses that to one parsed copy. (The
/// redundant parse inside `builder` still happens per call — eliminating it
/// would require a no-default-verify builder in `rama-boring`.)
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

#[cfg(not(target_os = "windows"))]
fn build_os_default_verify_store() -> Result<X509Store, BoxError> {
    trace!("boring connector: loading OS default verify paths into shared store");
    let mut builder =
        X509StoreBuilder::new().context("create x509 store builder for default verify paths")?;
    builder
        .set_default_paths()
        .context("load OS default verify paths into shared x509 store")?;
    Ok(builder.build())
}

#[cfg(target_os = "windows")]
fn build_os_default_verify_store() -> Result<X509Store, BoxError> {
    // on windows it seems to have no root CA by default when using boringssl
    // this code path is there to set it anyway
    trace!("boring connector: windows: load system certs");

    let mut builder = X509StoreBuilder::new().context("build x509 store builder")?;

    let mut total_cert_count = 0;
    let mut total_added_cert_count = 0;

    const PKIX_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
    const WINDOWS_STORE_NAMES: &[&str] = &["ROOT", "CA"];

    type CertStoreOpenFn =
        for<'a> fn(&'a str) -> Result<schannel::cert_store::CertStore, std::io::Error>;
    const CERTIFICATE_OPENERS: &[(CertStoreOpenFn, &str)] = &[
        (
            schannel::cert_store::CertStore::open_current_user,
            "open_current_user",
        ),
        (
            schannel::cert_store::CertStore::open_local_machine,
            "open_local_machine",
        ),
    ];

    for (open_fn, open_fn_name) in CERTIFICATE_OPENERS {
        for windows_store_name in WINDOWS_STORE_NAMES {
            match open_fn(windows_store_name) {
                Ok(cstore) => {
                    let mut current_cert_count = 0;
                    let mut current_invalid_cert_count = 0;
                    let mut current_added_cert_count = 0;

                    for cert in cstore.certs() {
                        current_cert_count += 1;
                        total_cert_count += 1;

                        if !cert.is_time_valid().unwrap_or_default()
                            || !cert
                                .valid_uses()
                                .map(|use_case| match use_case {
                                    schannel::cert_context::ValidUses::All => true,
                                    schannel::cert_context::ValidUses::Oids(strs) => {
                                        strs.iter().any(|x| x == PKIX_SERVER_AUTH)
                                    }
                                })
                                .unwrap_or_default()
                        {
                            current_invalid_cert_count += 1;
                            continue;
                        }

                        // Convert the Windows cert to DER, then to BoringSSL X509
                        match X509::from_der(cert.to_der()) {
                            Ok(x509) => {
                                if let Err(err) = builder.add_cert(x509) {
                                    debug!("failed to add x509 cert to windows: {err}");
                                } else {
                                    current_added_cert_count += 1;
                                    total_added_cert_count += 1;
                                }
                            }
                            Err(err) => {
                                debug!("failed to convert DER cert to x509: {err}");
                            }
                        }
                    }
                    trace!(
                        "boring connector: windows: {open_fn_name}::{windows_store_name}: added {current_added_cert_count} certs of {current_cert_count} certs (invalid schannel certs: {current_invalid_cert_count})"
                    );
                }
                Err(err) => {
                    debug!(
                        "failed to open {windows_store_name} cert store using schannel::cert_store::CertStore::{open_fn_name}; err = {err:?}",
                    );
                }
            }
        }
    }

    trace!(
        "boring connector: windows: final result: added {total_added_cert_count} certs of {total_cert_count} certs"
    );

    if total_added_cert_count == 0 {
        return Err(BoxError::from(
            "failed to add windows certs from system (user/machine x Root/CA)",
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

    #[test]
    fn build_from_common_pieces() {
        use rama_core::extensions::Extensions;
        use rama_net::tls::client::{TlsAlpn, TlsServerVerify, TlsStoreServerCertChain};

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
        use crate::client::BoringSignatureSchemes;
        use rama_core::extensions::Extensions;
        use rama_net::tls::SignatureScheme;

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
        use crate::client::BoringMaxVersion;
        use rama_core::extensions::Extensions;
        use rama_net::tls::ProtocolVersion;

        let ext = Extensions::new();
        ext.insert(BoringMaxVersion(ProtocolVersion::TLSv1_2));

        let config = BoringTlsConnectorConfig::from_extensions(&ext);
        let data = TlsConnectorData::try_from(config).unwrap();

        assert_eq!(data.config.max_proto_version(), Some(SslVersion::TLS1_2));
    }
}
