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
use std::{fmt, sync::Arc};
use tracing::trace;

use crate::keylog::new_key_log_file_handle;

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
    pub(super) keylog_intent: Option<KeyLogIntent>,
    pub(super) cipher_list: Option<String>,
    pub(super) alpn_protos: Option<Vec<u8>>,
    pub(super) curves: Option<Vec<SslCurve>>,
    pub(super) min_ssl_version: Option<SslVersion>,
    pub(super) max_ssl_version: Option<SslVersion>,
    pub(super) verify_algorithm_prefs: Option<Vec<SslSignatureAlgorithm>>,
    pub(super) server_verify_mode: Option<ServerVerifyMode>,
    pub(super) client_auth: Option<ConnectorConfigClientAuth>,
}

#[derive(Debug, Clone)]
pub(super) struct ConnectorConfigClientAuth {
    pub(super) cert_chain: Vec<X509>,
    pub(super) private_key: PKey<Private>,
}

pub(super) struct ConnectConfigData {
    pub(super) config: ConnectConfiguration,
    pub(super) server_name: Option<Host>,
}

impl fmt::Debug for ConnectConfigData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectConfigData")
            .field("config", &"boring::ConnectConfiguration<Opaque>")
            .field("server_name", &self.server_name)
            .finish()
    }
}

impl TlsConnectorData {
    pub(super) fn try_to_build_config(&self) -> Result<ConnectConfigData, OpaqueError> {
        let mut cfg_builder =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls_client())
                .context("create (boring) ssl connector builder")?;

        if let Some(keylog_filename) = self
            .connect_config_input
            .keylog_intent
            .clone()
            .unwrap_or_default()
            .file_path()
        {
            let handle = new_key_log_file_handle(keylog_filename)?;
            cfg_builder.set_keylog_callback(move |_, line| {
                let line = format!("{}\n", line);
                handle.write_log_line(line);
            });
        }

        if let Some(s) = self.connect_config_input.cipher_list.as_deref() {
            trace!("boring connector: set cipher list: {s}");
            cfg_builder
                .set_cipher_list(s)
                .context("build (boring) ssl connector: set cipher list")?;
        }

        if let Some(b) = self.connect_config_input.alpn_protos.as_deref() {
            trace!("boring connector: set ALPN protos: {b:?}",);
            cfg_builder
                .set_alpn_protos(b)
                .context("build (boring) ssl connector: set alpn protos")?;
        }

        if let Some(c) = self.connect_config_input.curves.as_deref() {
            trace!("boring connector: set {} SSL curve(s)", c.len());
            cfg_builder
                .set_curves(c)
                .context("build (boring) ssl connector: set curves")?;
        }

        trace!(
            "boring connector: set SSL version: min: {:?}",
            self.connect_config_input.min_ssl_version
        );
        cfg_builder
            .set_min_proto_version(self.connect_config_input.min_ssl_version)
            .context("build (boring) ssl connector: set min proto version")?;
        trace!(
            "boring connector: set SSL version: max: {:?}",
            self.connect_config_input.max_ssl_version
        );
        cfg_builder
            .set_max_proto_version(self.connect_config_input.max_ssl_version)
            .context("build (boring) ssl connector: set max proto version")?;

        if let Some(s) = self.connect_config_input.verify_algorithm_prefs.as_deref() {
            cfg_builder.set_verify_algorithm_prefs(s).context(
                "build (boring) ssl connector: set signature schemes (verify algorithm prefs)",
            )?;
        }

        // TODO: support grease, need to first detect it from config / client hello
        // cfg_builder.set_grease_enabled(true);

        match self
            .connect_config_input
            .server_verify_mode
            .unwrap_or_default()
        {
            ServerVerifyMode::Auto => {
                trace!("boring connector: server verify mode: auto (default verifier)");
            } // nothing explicit to do
            ServerVerifyMode::Disable => {
                trace!("boring connector: server verify mode: disable");
                cfg_builder.set_custom_verify_callback(SslVerifyMode::NONE, |_| Ok(()));
            }
        }

        if let Some(auth) = self.connect_config_input.client_auth.as_ref() {
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
        let cfg = cfg_builder
            .build()
            .configure()
            .context("create ssl connector configuration")?;

        trace!(
            "boring connector: return SSL connector config for server: {:?}",
            self.server_name
        );
        Ok(ConnectConfigData {
            config: cfg,
            server_name: self.server_name.clone(),
        })
    }

    /// Merge `self` together with the `other`, resulting in
    /// a new [`TlsConnectorData`], where any defined properties of `other`
    /// take priority over conflicting ones in `self`.
    pub fn merge(&self, other: &TlsConnectorData) -> TlsConnectorData {
        TlsConnectorData {
            connect_config_input: Arc::new(ConnectConfigurationInput {
                keylog_intent: other
                    .connect_config_input
                    .keylog_intent
                    .clone()
                    .or_else(|| self.connect_config_input.keylog_intent.clone()),
                cipher_list: other
                    .connect_config_input
                    .cipher_list
                    .clone()
                    .or_else(|| self.connect_config_input.cipher_list.clone()),
                alpn_protos: other
                    .connect_config_input
                    .alpn_protos
                    .clone()
                    .or_else(|| self.connect_config_input.alpn_protos.clone()),
                curves: other
                    .connect_config_input
                    .curves
                    .clone()
                    .or_else(|| self.connect_config_input.curves.clone()),
                min_ssl_version: other
                    .connect_config_input
                    .min_ssl_version
                    .or(self.connect_config_input.min_ssl_version),
                max_ssl_version: other
                    .connect_config_input
                    .max_ssl_version
                    .or(self.connect_config_input.max_ssl_version),
                verify_algorithm_prefs: other
                    .connect_config_input
                    .verify_algorithm_prefs
                    .clone()
                    .or_else(|| self.connect_config_input.verify_algorithm_prefs.clone()),
                server_verify_mode: other
                    .connect_config_input
                    .server_verify_mode
                    .or_else(|| self.connect_config_input.server_verify_mode),
                client_auth: other
                    .connect_config_input
                    .client_auth
                    .clone()
                    .or_else(|| self.connect_config_input.client_auth.clone()),
            }),
            server_name: other
                .server_name
                .clone()
                .or_else(|| self.server_name.clone()),
        }
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

    /// Return a reference the desired (SNI) in case it exists
    pub fn server_name(&self) -> Option<&Host> {
        self.server_name.as_ref()
    }
}

impl TryFrom<rama_net::tls::client::ClientConfig> for TlsConnectorData {
    type Error = OpaqueError;

    fn try_from(value: rama_net::tls::client::ClientConfig) -> Result<Self, Self::Error> {
        let cipher_list = value
            .cipher_suites
            .as_deref()
            .and_then(openssl_cipher_list_str_from_cipher_list);
        trace!(
            "TlsConnectorData: builder: from std client config: cipher list: {:?}",
            cipher_list
        );

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
                    server_name = match maybe_host {
                        Some(Host::Name(_)) => {
                            trace!("TlsConnectorData: builder: from std client config: set server (domain) name from host: {:?}", maybe_host);
                            maybe_host.clone()
                        }
                        Some(Host::Address(_)) => {
                            trace!("TlsConnectorData: builder: from std client config: set server (ip) name from host: {:?}", maybe_host);
                            maybe_host.clone()
                        }
                        None => {
                            trace!("TlsConnectorData: builder: from std client config: ignore server null value");
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
                    curves = Some(groups.iter().filter_map(|c| match (*c).try_into() {
                        Ok(v) => Some(v),
                        Err(c) => {
                            trace!("ignore unsupported support group (curve) {c} (file issue if you require it");
                            None
                        }
                    }).collect());
                }
                ClientHelloExtension::SupportedVersions(versions) => {
                    trace!("TlsConnectorData: builder: from std client config: supported versions: {:?}", versions);

                    if let Some(min_ver) = versions.iter().min() {
                        trace!(
                            "TlsConnectorData: builder: from std client config: min version: {:?}",
                            min_ver
                        );
                        min_ssl_version = Some((*min_ver).try_into().map_err(|v| {
                            OpaqueError::from_display(format!("protocol version {v}"))
                                .context("build boring ssl connector: min proto version")
                        })?);
                    }

                    if let Some(max_ver) = versions.iter().max() {
                        trace!(
                            "TlsConnectorData: builder: from std client config: max version: {:?}",
                            max_ver
                        );
                        max_ssl_version = Some((*max_ver).try_into().map_err(|v| {
                            OpaqueError::from_display(format!("protocol version {v}"))
                                .context("build boring ssl connector: max proto version")
                        })?);
                    }
                }
                ClientHelloExtension::SignatureAlgorithms(schemes) => {
                    trace!("TlsConnectorData: builder: from std client config: signature algorithms: {:?}", schemes);
                    verify_algorithm_prefs = Some(schemes.iter().filter_map(|s| match (*s).try_into() {
                        Ok(v) => Some(v),
                        Err(s) => {
                            trace!("ignore unsupported signatured schemes {s} (file issue if you require it");
                            None
                        }
                    }).collect());
                }
                other => {
                    trace!(ext = ?other, "TlsConnectorData: builder: from std client config: ignore client hello ext");
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
                keylog_intent: value.key_logger,
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
