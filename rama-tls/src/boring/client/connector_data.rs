use boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{ConnectConfiguration, SslCurve, SslSignatureAlgorithm, SslVerifyMode, SslVersion},
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509,
    },
};
use rama_core::error::{ErrorContext, ErrorExt, OpaqueError};
use rama_net::tls::{
    client::{ClientAuth, ClientHelloExtension},
    DataEncoding,
};
use rama_net::tls::{openssl_cipher_list_str_from_cipher_list, ApplicationProtocol, KeyLogIntent};
use rama_net::{address::Host, tls::client::ServerVerifyMode};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::trace;

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::HttpsConnector`].
///
/// Created by trying to turn the _rama_ opiniated [`rama_net::tls::client::ClientConfig`] into it.
pub struct TlsConnectorData {
    pub(super) connect_config_input: Arc<ConnectConfigurationInput>,
    pub(super) server_name: Option<Host>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct ConnectConfigurationInput {
    pub(super) keylog_filename: Option<PathBuf>,
    pub(super) cipher_list: Option<String>,
    pub(super) alpn_protos: Option<Vec<u8>>,
    pub(super) curves: Option<Vec<SslCurve>>,
    pub(super) min_ssl_version: Option<SslVersion>,
    pub(super) max_ssl_version: Option<SslVersion>,
    pub(super) verify_algorithm_prefs: Option<Vec<SslSignatureAlgorithm>>,
    pub(super) server_verify_mode: ServerVerifyMode,
    pub(super) client_auth: Option<ConnectorConfigClientAuth>,
}

#[derive(Debug, Clone)]
pub(super) struct ConnectorConfigClientAuth {
    pub(super) cert_chain: Vec<X509>,
    pub(super) private_key: PKey<Private>,
}

impl ConnectConfigurationInput {
    pub(super) fn try_to_build_config(&self) -> Result<ConnectConfiguration, OpaqueError> {
        let mut cfg_builder =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls_client())
                .context("create (boring) ssl connector builder")?;

        if let Some(keylog_filename) = self.keylog_filename.as_deref() {
            // open file in append mode and write keylog to it with callback
            let file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(keylog_filename)
                .context("build (boring) ssl connector: set keylog: open file")?;
            cfg_builder.set_keylog_callback(move |_, line| {
                use std::io::Write;
                let line = format!("{}\n", line);
                let mut file = &file;
                let _ = file.write_all(line.as_bytes());
            });
        }

        if let Some(s) = self.cipher_list.as_deref() {
            cfg_builder
                .set_cipher_list(s)
                .context("build (boring) ssl connector: set cipher list")?;
        }

        if let Some(b) = self.alpn_protos.as_deref() {
            cfg_builder
                .set_alpn_protos(b)
                .context("build (boring) ssl connector: set alpn protos")?;
        }

        if let Some(c) = self.curves.as_deref() {
            cfg_builder
                .set_curves(c)
                .context("build (boring) ssl connector: set curves")?;
        }

        cfg_builder
            .set_min_proto_version(self.min_ssl_version)
            .context("build (boring) ssl connector: set min proto version")?;
        cfg_builder
            .set_max_proto_version(self.max_ssl_version)
            .context("build (boring) ssl connector: set max proto version")?;

        if let Some(s) = self.verify_algorithm_prefs.as_deref() {
            cfg_builder.set_verify_algorithm_prefs(s).context(
                "build (boring) ssl connector: set signature schemes (verify algorithm prefs)",
            )?;
        }

        match self.server_verify_mode {
            ServerVerifyMode::Auto => (), // nothing explicit to do
            ServerVerifyMode::Disable => {
                cfg_builder.set_custom_verify_callback(SslVerifyMode::NONE, |_| Ok(()));
                cfg_builder.set_verify(SslVerifyMode::NONE);
            }
        }

        if let Some(auth) = self.client_auth.as_ref() {
            cfg_builder
                .set_private_key(auth.private_key.as_ref())
                .context("build (boring) ssl connector: set private key")?;
            for cert in &auth.cert_chain {
                cfg_builder
                    .add_client_ca(cert)
                    .context("build (boring) ssl connector: set client cert")?;
            }
        }

        let mut cfg = cfg_builder
            .build()
            .configure()
            .context("create ssl connector configuration")?;

        match self.server_verify_mode {
            ServerVerifyMode::Auto => (), // nothing explicit to do
            ServerVerifyMode::Disable => {
                cfg.set_verify_hostname(false);
            }
        }

        Ok(cfg)
    }
}

impl TlsConnectorData {
    /// Create a default [`TlsConnectorData`].
    ///
    /// This constructor is best fit for tunnel purposes,
    /// for https purposes and other application protocols
    /// you may want to use another constructor instead.
    pub fn new() -> Result<TlsConnectorData, OpaqueError> {
        Ok(TlsConnectorData {
            connect_config_input: Arc::new(ConnectConfigurationInput::default()),
            server_name: None,
        })
    }

    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing auto http connections, meaning supporting
    /// the http connections which `rama` supports out of the box.
    pub fn new_http_auto() -> Result<TlsConnectorData, OpaqueError> {
        let mut alpn_protos = vec![];
        for alpn in [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11] {
            alpn.encode_wire_format(&mut alpn_protos)
                .context("build (boring) ssl connector: encode alpn")?;
        }
        Ok(TlsConnectorData {
            connect_config_input: Arc::new(ConnectConfigurationInput {
                alpn_protos: Some(alpn_protos),
                ..Default::default()
            }),
            server_name: None,
        })
    }

    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing http/1.1 connections.
    pub fn new_http_1() -> Result<TlsConnectorData, OpaqueError> {
        let mut alpn_protos = vec![];
        ApplicationProtocol::HTTP_11
            .encode_wire_format(&mut alpn_protos)
            .context("build (boring) ssl connector: encode alpn")?;
        Ok(TlsConnectorData {
            connect_config_input: Arc::new(ConnectConfigurationInput {
                alpn_protos: Some(alpn_protos),
                ..Default::default()
            }),
            server_name: None,
        })
    }

    /// Create a default [`TlsConnectorData`] that is focussed
    /// on providing h2 connections.
    pub fn new_http_2() -> Result<TlsConnectorData, OpaqueError> {
        let mut alpn_protos = vec![];
        ApplicationProtocol::HTTP_2
            .encode_wire_format(&mut alpn_protos)
            .context("build (boring) ssl connector: encode alpn")?;
        Ok(TlsConnectorData {
            connect_config_input: Arc::new(ConnectConfigurationInput {
                alpn_protos: Some(alpn_protos),
                ..Default::default()
            }),
            server_name: None,
        })
    }
}

impl TlsConnectorData {
    /// Return a reference to the exposed client cert chain,
    /// should these exist and be exposed.
    pub fn client_auth_cert_chain(&self) -> Option<&[X509]> {
        self.connect_config_input
            .client_auth
            .as_ref()
            .map(|a| &a.cert_chain[..])
    }

    /// Take (consume) the exposed client cert chain,
    /// should these exist and be exposed.
    pub fn take_client_auth_cert_chain(&mut self) -> Option<Vec<X509>> {
        self.connect_config_input
            .client_auth
            .as_ref()
            .map(|a| a.cert_chain.clone())
    }

    /// Return a reference the desired (SNI) in case it exists
    pub fn server_name(&self) -> Option<&Host> {
        self.server_name.as_ref()
    }
}

impl TryFrom<rama_net::tls::client::ClientConfig> for TlsConnectorData {
    type Error = OpaqueError;

    fn try_from(value: rama_net::tls::client::ClientConfig) -> Result<Self, Self::Error> {
        let keylog_filename = match value.key_logger {
            KeyLogIntent::Disabled => None,
            KeyLogIntent::Environment => std::env::var("SSLKEYLOGFILE").ok().map(Into::into),
            KeyLogIntent::File(keylog_filename) => Some(keylog_filename.clone()),
        };

        let cipher_list = value
            .cipher_suites
            .as_deref()
            .and_then(openssl_cipher_list_str_from_cipher_list);

        let mut server_name = None;
        let mut alpn_protos = None;
        let mut curves = None;
        let mut min_ssl_version = None;
        let mut max_ssl_version = None;
        let mut verify_algorithm_prefs = None;

        // use the extensions that we can use for the builder
        for extension in value.extensions.iter().flatten() {
            match extension {
                ClientHelloExtension::ServerName(maybe_host) => {
                    server_name = maybe_host.clone();
                }
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn_list) => {
                    let mut buf = vec![];
                    for alpn in alpn_list {
                        alpn.encode_wire_format(&mut buf)
                            .context("build (boring) ssl connector: encode alpn")?;
                    }
                    alpn_protos = Some(buf);
                }
                ClientHelloExtension::SupportedGroups(groups) => {
                    curves = Some(groups.iter().filter_map(|c| match (*c).try_into() {
                        Ok(v) => Some(v),
                        Err(c) => {
                            trace!("ignore unsupported support group (curve) {c} (file issue if you require it");
                            None
                        }
                    }).collect());
                }
                ClientHelloExtension::SupportedVersions(versions) => {
                    if let Some(min_ver) = versions.iter().min() {
                        min_ssl_version = Some((*min_ver).try_into().map_err(|v| {
                            OpaqueError::from_display(format!("protocol version {v}"))
                                .context("build boring ssl connector: min proto version")
                        })?);
                    }

                    if let Some(max_ver) = versions.iter().max() {
                        max_ssl_version = Some((*max_ver).try_into().map_err(|v| {
                            OpaqueError::from_display(format!("protocol version {v}"))
                                .context("build boring ssl connector: max proto version")
                        })?);
                    }
                }
                ClientHelloExtension::SignatureAlgorithms(schemes) => {
                    verify_algorithm_prefs = Some(schemes.iter().filter_map(|s| match (*s).try_into() {
                        Ok(v) => Some(v),
                        Err(s) => {
                            trace!("ignore unsupported signatured schemes {s} (file issue if you require it");
                            None
                        }
                    }).collect());
                }
                other => {
                    trace!(ext = ?other, "build (boring) ssl connector: ignore client hello ext");
                }
            }
        }

        let client_auth = match value.client_auth {
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

        Ok(TlsConnectorData {
            connect_config_input: Arc::new(ConnectConfigurationInput {
                keylog_filename,
                cipher_list,
                alpn_protos,
                curves,
                min_ssl_version,
                max_ssl_version,
                verify_algorithm_prefs,
                server_verify_mode: value.server_verify_mode,
                client_auth,
            }),
            server_name,
        })
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
