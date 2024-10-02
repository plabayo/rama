use crate::boring::dep::boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509NameBuilder, X509,
    },
};
use rama_core::error::{ErrorContext, OpaqueError};
use rama_net::tls::{
    server::{ClientVerifyMode, SelfSignedData, ServerAuth},
    ApplicationProtocol, DataEncoding, KeyLogIntent, ProtocolVersion,
};
use std::sync::Arc;

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::TlsAcceptorService`].
///
/// Created by trying to turn the _rama_ opiniated [`rama_net::tls::server::ServerConfig`] into it.
pub struct TlsAcceptorData {
    pub(super) config: Arc<TlsConfig>,
}

#[derive(Debug, Clone)]
pub(super) struct TlsConfig {
    /// Private Key of the server
    pub(super) private_key: PKey<Private>,
    /// Cert Chain of the server
    pub(super) cert_chain: Vec<X509>,
    /// Optionally set the ALPN protocols supported by the service's inner application service.
    pub(super) alpn_protocols: Option<Vec<ApplicationProtocol>>,
    /// Optionally write logging information to facilitate tls interception.
    pub(super) keylog_intent: KeyLogIntent,
    /// optionally define protocol versions to support
    pub(super) protocol_versions: Option<Vec<ProtocolVersion>>,
    /// optionally define client certificates in case client auth is enabled
    pub(super) client_cert_chain: Option<Vec<X509>>,
}

impl TryFrom<rama_net::tls::server::ServerConfig> for TlsAcceptorData {
    type Error = OpaqueError;

    fn try_from(value: rama_net::tls::server::ServerConfig) -> Result<Self, Self::Error> {
        let client_cert_chain = match value.client_verify_mode {
            // no client auth
            ClientVerifyMode::Auto | ClientVerifyMode::Disable => None,
            // client auth enabled
            ClientVerifyMode::ClientAuth(DataEncoding::Der(bytes)) => Some(vec![X509::from_der(
                &bytes[..],
            )
            .context("boring/TlsAcceptorData: parse x509 client cert from DER content")?]),
            ClientVerifyMode::ClientAuth(DataEncoding::DerStack(bytes_list)) => Some(
                bytes_list
                    .into_iter()
                    .map(|b| {
                        X509::from_der(&b[..]).context(
                            "boring/TlsAcceptorData: parse x509 client cert from DER content",
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            ClientVerifyMode::ClientAuth(DataEncoding::Pem(raw_data)) => Some(
                X509::stack_from_pem(raw_data.as_bytes())
                    .context("boring/TlsAcceptorData: parse x509 client cert from PEM content")?,
            ),
        };

        let (cert_chain, private_key) = match value.server_auth {
            ServerAuth::SelfSigned(data) => {
                self_signed_server_auth(data).context("boring/TlsAcceptorData")?
            }
            ServerAuth::Single(data) => {
                // server TLS Certs
                let cert_chain = match data.cert_chain {
                    DataEncoding::Der(raw_data) => vec![X509::from_der(&raw_data[..]).context(
                        "boring/TlsAcceptorData: parse x509 server cert from DER content",
                    )?],
                    DataEncoding::DerStack(raw_data_list) => raw_data_list
                        .into_iter()
                        .map(|raw_data| {
                            X509::from_der(&raw_data[..]).context(
                                "boring/TlsAcceptorData: parse x509 server cert from DER content",
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    DataEncoding::Pem(raw_data) => X509::stack_from_pem(raw_data.as_bytes())
                        .context(
                            "boring/TlsAcceptorData: parse x509 server cert chain from PEM content",
                        )?,
                };

                // server TLS key
                let private_key = match data.private_key {
                    DataEncoding::Der(raw_data) => PKey::private_key_from_der(&raw_data[..])
                        .context("boring/TlsAcceptorData: parse private key from DER content")?,
                    DataEncoding::DerStack(raw_data_list) => PKey::private_key_from_der(
                        &raw_data_list
                            .first()
                            .context("boring/TlsAcceptorData: get first private key raw data")?[..],
                    )
                    .context("boring/TlsAcceptorData: parse private key from DER content")?,
                    DataEncoding::Pem(raw_data) => PKey::private_key_from_pem(raw_data.as_bytes())
                        .context("boring/TlsAcceptorData: parse private key from PEM content")?,
                };

                (cert_chain, private_key)
            }
        };

        // return the created server config, all good if you reach here
        Ok(TlsAcceptorData {
            config: Arc::new(TlsConfig {
                private_key,
                cert_chain,
                alpn_protocols: value.application_layer_protocol_negotiation.clone(),
                keylog_intent: value.key_logger,
                protocol_versions: value.protocol_versions.clone(),
                client_cert_chain,
            }),
        })
    }
}

fn self_signed_server_auth(
    data: SelfSignedData,
) -> Result<(Vec<X509>, PKey<Private>), OpaqueError> {
    let rsa = Rsa::generate(4096).context("generate 4096 RSA key")?;
    let privkey = PKey::from_rsa(rsa).context("create private key from 4096 RSA key")?;

    let mut x509_name = X509NameBuilder::new().context("create x509 name builder")?;
    x509_name
        .append_entry_by_nid(
            Nid::ORGANIZATIONNAME,
            data.organisation_name.as_deref().unwrap_or("Anonymous"),
        )
        .context("append organisation name to x509 name builder")?;
    for subject_alt_name in data.subject_alternative_names.iter().flatten() {
        x509_name
            .append_entry_by_nid(Nid::SUBJECT_ALT_NAME, subject_alt_name.as_ref())
            .context("append subject alt name to x509 name builder")?;
    }
    x509_name
        .append_entry_by_nid(
            Nid::COMMONNAME,
            data.common_name.as_deref().unwrap_or("localhost"),
        )
        .context("append common name to x509 name builder")?;
    let x509_name = x509_name.build();

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
        .set_subject_name(&x509_name)
        .context("x509 cert builder: set subject name")?;
    cert_builder
        .set_issuer_name(&x509_name)
        .context("x509 cert builder: set issuer (self-signed")?;
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
