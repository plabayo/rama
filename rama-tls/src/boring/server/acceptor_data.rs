use crate::boring::dep::boring::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    },
};
use boring::{
    ssl::{ClientHello, NameType, SelectCertError, SslAcceptorBuilder, SslRef},
    x509::extension::{AuthorityKeyIdentifier, SubjectAlternativeName},
};
use moka::sync::Cache;
use parking_lot::Mutex;
use rama_core::error::{ErrorContext, OpaqueError};
use rama_net::{
    address::{Domain, Host},
    tls::{
        ApplicationProtocol, DataEncoding, KeyLogIntent, ProtocolVersion,
        client::ClientHello as RamaClientHello,
        server::{
            CacheKind, ClientVerifyMode, DynamicIssuer, SelfSignedData, ServerAuth, ServerAuthData,
            ServerCertIssuerKind,
        },
    },
};
use std::{sync::Arc, time::Duration};
use tokio_boring::{AsyncSelectCertError, BoxSelectCertFinish};

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::TlsAcceptorService`].
///
/// Created by trying to turn the _rama_ opiniated [`rama_net::tls::server::ServerConfig`] into it.
pub struct TlsAcceptorData {
    pub(super) config: Arc<TlsConfig>,
}

#[derive(Debug, Clone)]
pub(super) struct TlsConfig {
    /// source for certs
    pub(super) cert_source: TlsCertSource,
    /// Optionally set the ALPN protocols supported by the service's inner application service.
    pub(super) alpn_protocols: Option<Vec<ApplicationProtocol>>,
    /// Optionally write logging information to facilitate tls interception.
    pub(super) keylog_intent: KeyLogIntent,
    /// optionally define protocol versions to support
    pub(super) protocol_versions: Option<Vec<ProtocolVersion>>,
    /// optionally define client certificates in case client auth is enabled
    pub(super) client_cert_chain: Option<Vec<X509>>,
    /// store client certificate chain if true and client provided this
    pub store_client_certificate_chain: bool,
}

#[derive(Debug, Clone)]
pub(super) struct TlsCertSource {
    kind: TlsCertSourceKind,
}

#[derive(Debug, Clone)]
enum TlsCertSourceKind {
    InMemory(IssuedCert),
    InMemoryIssuer {
        /// Cache for certs already issued
        cert_cache: Option<Cache<Host, IssuedCert>>,
        /// Private Key for issueing
        ca_key: PKey<Private>,
        /// CA Cert to be used for issueing
        ca_cert: X509,
    },
    DynamicIssuer {
        issuer: DynamicIssuer,
        /// Cache for certs already issued
        cert_cache: Option<Cache<Host, IssuedCert>>,
    },
}

#[derive(Debug, Clone)]
struct IssuedCert {
    cert_chain: Vec<X509>,
    key: PKey<Private>,
}

impl TlsCertSource {
    pub(super) async fn issue_certs(
        self,
        mut builder: SslAcceptorBuilder,
        server_name: Option<Host>,
        maybe_client_hello: &Option<Arc<Mutex<Option<RamaClientHello>>>>,
    ) -> Result<SslAcceptorBuilder, OpaqueError> {
        match self.kind {
            TlsCertSourceKind::InMemory(issued_cert) => {
                for (i, ca_cert) in issued_cert.cert_chain.iter().enumerate() {
                    if i == 0 {
                        builder
                            .set_certificate(ca_cert.as_ref())
                            .context("build boring ssl acceptor: set Leaf CA certificate (x509)")?;
                    } else {
                        builder.add_extra_chain_cert(ca_cert.clone()).context(
                            "build boring ssl acceptor: add extra chain certificate (x509)",
                        )?;
                    }
                }
                builder
                    .set_private_key(issued_cert.key.as_ref())
                    .context("build boring ssl acceptor: set private key")?;
                builder
                    .check_private_key()
                    .context("build boring ssl acceptor: check private key")?;

                if let Some(maybe_client_hello) = maybe_client_hello {
                    let cb_maybe_client_hello = maybe_client_hello.clone();
                    builder.set_select_certificate_callback(move |boring_client_hello| {
                        let maybe_client_hello = match RamaClientHello::try_from(boring_client_hello) {
                            Ok(ch) => Some(ch),
                            Err(err) => {
                                tracing::warn!(err = %err, "failed to extract boringssl client hello");
                                None
                            }
                        };
                        *cb_maybe_client_hello.lock() = maybe_client_hello;
                        Ok(())
                    });
                }
            }
            TlsCertSourceKind::InMemoryIssuer {
                cert_cache,
                ca_key,
                ca_cert,
            } => {
                let cb_maybe_client_hello = maybe_client_hello.clone();
                builder.set_select_certificate_callback(move |client_hello| {
                    if let Some(cb_maybe_client_hello) = &cb_maybe_client_hello {
                        let maybe_client_hello = match RamaClientHello::try_from(&client_hello) {
                            Ok(ch) => Some(ch),
                            Err(err) => {
                                tracing::warn!(err = %err, "failed to extract boringssl client hello");
                                None
                            }
                        };
                        *cb_maybe_client_hello.lock() = maybe_client_hello;
                    }

                    let mut client_hello = client_hello;
                    let ssl_ref = client_hello.ssl_mut();

                    let host = to_host(ssl_ref, &server_name).map_err(|err| {
                        tracing::error!(error = %err, "boring: failed getting host");
                        SelectCertError::ERROR
                    })?;

                    tracing::trace!(%host, "try to use cached issued cert or generate new one");
                    let issued_cert = match &cert_cache {
                        None => issue_cert_for_ca(host.clone(), &ca_cert, &ca_key).context("fresh issue of cert").map_err(|err| {
                            tracing::error!(error = %err, "boring: select certificate callback: issue failed");
                            SelectCertError::ERROR
                        })?,
                        Some(cert_cache) => cert_cache
                        .try_get_with(host.clone(), || {
                            issue_cert_for_ca(host.clone(), &ca_cert, &ca_key)
                        })
                        .context("fresh issue of cert + insert").map_err(|err| {
                            tracing::error!(error = %err, "boring: select certificate callback: issue failed");
                            SelectCertError::ERROR
                        })?,
                    };

                    add_issued_cert_to_ssl_ref(
                        host,
                        issued_cert,
                        ssl_ref,
                    ).map_err(|err| {
                        tracing::error!(error = %err, "boring: select certificate callback: add certs to ssl ref");
                        SelectCertError::ERROR
                    })?;

                    Ok(())
                });
            }
            TlsCertSourceKind::DynamicIssuer { issuer, cert_cache } => {
                let cb_maybe_client_hello = maybe_client_hello.clone();
                let cert_cache = cert_cache.clone();

                builder.set_async_select_certificate_callback(move |client_hello| {
                    let rama_client_hello =
                        RamaClientHello::try_from(&*client_hello).map_err(|err| {
                            tracing::error!(error = %err, "boring: failed converting to rama client hello");
                            AsyncSelectCertError{}
                        })?;

                    if let Some(cb_maybe_client_hello) = &cb_maybe_client_hello {
                        *cb_maybe_client_hello.lock() = Some(rama_client_hello.clone());
                    }

                    let ssl_ref = client_hello.ssl_mut();
                    let host = to_host(ssl_ref, &server_name).map_err(|err| {
                        tracing::error!(error = %err, "boring: failed getting host");
                        AsyncSelectCertError{}
                    })?;


                    let issuer = issuer.clone();
                    let cert_cache = cert_cache.clone();
                    let server_name = server_name.clone();

                    Ok(Box::pin(async move {
                        let issued_cert = if let Some(cached_cert) = cert_cache.as_ref().and_then(|cert_cache| cert_cache.get(&host)) {
                            cached_cert
                        } else {
                            let auth_data = issuer.issue_cert(rama_client_hello, server_name).await.map_err(|err| {
                                tracing::error!(error = %err, "boring: dynamic cert issuer failed");
                                AsyncSelectCertError{}
                            })?;
                            server_auth_data_to_private_key_and_ca_chain(&auth_data).map_err(|err| {
                                tracing::error!(error = %err, "boring: server_auth_data to key and ca chain failed");
                                AsyncSelectCertError{}
                            })?
                        };

                        if let Some(cert_cache) = cert_cache {
                            cert_cache.insert(host.clone(), issued_cert.clone());
                        }

                        let apply_cert = Box::new(move |client_hello: ClientHello<'_>| {
                            let mut client_hello = client_hello;
                            let ssl_ref = client_hello.ssl_mut();

                            add_issued_cert_to_ssl_ref(
                                host,
                                issued_cert,
                                ssl_ref,
                            ).map_err(|err| {
                                tracing::error!(error = %err, "boring: async select certificate callback: add certs to ssl ref");
                                AsyncSelectCertError{}
                            })?;
                            Ok(())
                        }) as BoxSelectCertFinish;

                        Ok(apply_cert)
                    }))
                });
            }
        }

        Ok(builder)
    }
}

impl TryFrom<rama_net::tls::server::ServerConfig> for TlsAcceptorData {
    type Error = OpaqueError;

    fn try_from(value: rama_net::tls::server::ServerConfig) -> Result<Self, Self::Error> {
        let client_cert_chain = match value.client_verify_mode {
            // no client auth
            ClientVerifyMode::Auto | ClientVerifyMode::Disable => None,
            // client auth enabled
            ClientVerifyMode::ClientAuth(DataEncoding::Der(bytes)) => {
                Some(vec![X509::from_der(&bytes[..]).context(
                    "boring/TlsAcceptorData: parse x509 client cert from DER content",
                )?])
            }
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

        let cert_source_kind = match value.server_auth {
            ServerAuth::SelfSigned(data) => {
                let issued_cert =
                    self_signed_server_auth(data).context("boring/TlsAcceptorData")?;
                TlsCertSourceKind::InMemory(issued_cert)
            }
            ServerAuth::Single(data) => {
                // server TLS Certs
                let issued_cert = server_auth_data_to_private_key_and_ca_chain(&data)?;

                TlsCertSourceKind::InMemory(issued_cert)
            }

            ServerAuth::CertIssuer(data) => {
                let cert_cache = match data.cache_kind {
                    CacheKind::Disabled => None,
                    CacheKind::MemCache { max_size } => Some(
                        Cache::builder()
                            .time_to_live(Duration::from_secs(60 * 60 * 24 * 89))
                            .max_capacity(max_size.into())
                            .build(),
                    ),
                };

                match data.kind {
                    ServerCertIssuerKind::SelfSigned(data) => {
                        let (ca_cert, ca_key) = self_signed_server_ca(data)
                            .context("boring/TlsAcceptorData: CA: self-signed ca")?;
                        TlsCertSourceKind::InMemoryIssuer {
                            cert_cache,
                            ca_key,
                            ca_cert,
                        }
                    }
                    ServerCertIssuerKind::Single(data) => {
                        let mut issued_cert = server_auth_data_to_private_key_and_ca_chain(&data)?;
                        let ca_cert = issued_cert
                            .cert_chain
                            .pop()
                            .context("pop CA Cert (last) from stack")?;

                        TlsCertSourceKind::InMemoryIssuer {
                            cert_cache,
                            ca_key: issued_cert.key,
                            ca_cert,
                        }
                    }
                    ServerCertIssuerKind::Dynamic(issuer) => {
                        TlsCertSourceKind::DynamicIssuer { issuer, cert_cache }
                    }
                }
            }
        };

        // return the created server config, all good if you reach here
        Ok(TlsAcceptorData {
            config: Arc::new(TlsConfig {
                cert_source: TlsCertSource {
                    kind: cert_source_kind,
                },
                alpn_protocols: value.application_layer_protocol_negotiation.clone(),
                keylog_intent: value.key_logger,
                protocol_versions: value.protocol_versions.clone(),
                client_cert_chain,
                store_client_certificate_chain: value.store_client_certificate_chain,
            }),
        })
    }
}

fn to_host(ssl_ref: &SslRef, server_name: &Option<Host>) -> Result<Host, OpaqueError> {
    let host = match (ssl_ref.servername(NameType::HOST_NAME), &server_name) {
        (Some(sni), _) => {
            tracing::trace!(host = %sni, "boring: server_name to host: use client SNI");
            sni.parse().map_err(|err| {
                tracing::warn!(error = %err, "boring: invalid servername received in callback");
                OpaqueError::from_display("sni parse failed")
            })? // from client (e.g. only possibility for SNI proxy)
        }
        (_, Some(host)) => {
            tracing::trace!(%host, "boring: server_name not in sni: using context");
            host.clone() // from context (lower prio)
        }
        // We aren't sure if we actually want this logic here or if this should be an error path
        // We will come back to this once we have some more data about this.
        (None, None) => {
            tracing::warn!(
                "boring: no host found in server_name or ctx: defaulting to 'localhost'"
            );
            Host::Name(Domain::from_static("localhost")) // fallback
        }
    };
    Ok(host)
}

fn server_auth_data_to_private_key_and_ca_chain(
    data: &ServerAuthData,
) -> Result<IssuedCert, OpaqueError> {
    // server TLS key
    let private_key = match &data.private_key {
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

    let cert_chain = match &data.cert_chain {
        DataEncoding::Der(raw_data) => vec![
            X509::from_der(&raw_data[..])
                .context("boring/TlsAcceptorData: parse x509 server cert from DER content")?,
        ],
        DataEncoding::DerStack(raw_data_list) => raw_data_list
            .iter()
            .map(|raw_data| {
                X509::from_der(&raw_data[..])
                    .context("boring/TlsAcceptorData: parse x509 server cert from DER content")
            })
            .collect::<Result<Vec<_>, _>>()?,
        DataEncoding::Pem(raw_data) => X509::stack_from_pem(raw_data.as_bytes())
            .context("boring/TlsAcceptorData: parse x509 server cert chain from PEM content")?,
    };

    Ok(IssuedCert {
        cert_chain,
        key: private_key,
    })
}

fn issue_cert_for_ca(
    host: Host,
    ca_cert: &X509,
    ca_key: &PKey<Private>,
) -> Result<IssuedCert, OpaqueError> {
    tracing::trace!(
        %host,
        "generate certs for host using in-memory ca cert"
    );
    let (cert, key) = self_signed_server_auth_gen_cert(
        &SelfSignedData {
            organisation_name: Some(
                ca_cert
                    .subject_name()
                    .entries_by_nid(Nid::ORGANIZATIONNAME)
                    .next()
                    .and_then(|entry| entry.data().as_utf8().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Anonymous".to_owned()),
            ),
            common_name: Some(host.clone()),
            subject_alternative_names: None,
        },
        ca_cert,
        ca_key,
    )
    .with_context(|| format!("issue certs in memory for: {host:?}"))?;

    Ok(IssuedCert {
        cert_chain: vec![cert, ca_cert.clone()],
        key,
    })
}

fn add_issued_cert_to_ssl_ref(
    host: Host,
    issued_cert: IssuedCert,
    builder: &mut SslRef,
) -> Result<(), OpaqueError> {
    tracing::trace!(
        %host,
        "add issued cert for host to (boring) SslAcceptorBuilder"
    );

    for (i, ca_cert) in issued_cert.cert_chain.iter().enumerate() {
        if i == 0 {
            builder
                .set_certificate(ca_cert.as_ref())
                .context("boring add issue cert to ssl ref: set certificate")?;
        } else {
            builder
                .add_chain_cert(ca_cert)
                .context("boring add issue cert to ssl ref: add chain certificate")?;
        }
    }

    builder
        .set_private_key(issued_cert.key.as_ref())
        .context("boring add issue cert to ssl ref: set private key")?;
    // builder
    //     .check()
    //     .context("build boring ssl acceptor: issued in-mem: check private key")?;

    Ok(())
}

fn self_signed_server_auth(data: SelfSignedData) -> Result<IssuedCert, OpaqueError> {
    let (ca_cert, ca_privkey) = self_signed_server_auth_gen_ca(&data).context("self-signed CA")?;
    let (cert, privkey) = self_signed_server_auth_gen_cert(&data, &ca_cert, &ca_privkey)
        .context("self-signed cert using self-signed CA")?;
    Ok(IssuedCert {
        cert_chain: vec![cert, ca_cert],
        key: privkey,
    })
}

#[inline]
fn self_signed_server_ca(data: SelfSignedData) -> Result<(X509, PKey<Private>), OpaqueError> {
    self_signed_server_auth_gen_ca(&data)
}

fn self_signed_server_auth_gen_cert(
    data: &SelfSignedData,
    ca_cert: &X509,
    ca_privkey: &PKey<Private>,
) -> Result<(X509, PKey<Private>), OpaqueError> {
    let rsa = Rsa::generate(4096).context("generate 4096 RSA key")?;
    let privkey = PKey::from_rsa(rsa).context("create private key from 4096 RSA key")?;

    let common_name = data
        .common_name
        .clone()
        .unwrap_or(Host::Name(Domain::from_static("localhost")));

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
        .append_entry_by_nid(Nid::COMMONNAME, common_name.to_string().as_str())
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
        .set_issuer_name(ca_cert.subject_name())
        .context("x509 cert builder: set issuer name")?;
    cert_builder
        .set_pubkey(&privkey)
        .context("x509 cert builder: set pub key")?;
    cert_builder
        .set_subject_name(&x509_name)
        .context("x509 cert builder: set subject name")?;
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
                .build()
                .context("x509 cert builder: build basic constraints")?,
        )
        .context("x509 cert builder: add basic constraints as x509 extension")?;
    cert_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()
                .context("x509 cert builder: create key usage")?,
        )
        .context("x509 cert builder: add key usage x509 extension")?;

    let mut subject_alt_name = SubjectAlternativeName::new();
    match common_name {
        Host::Name(domain) => {
            subject_alt_name.dns(domain.as_str());
        }
        Host::Address(addr) => {
            subject_alt_name.ip(addr.to_string().as_str());
        }
    }
    let subject_alt_name = subject_alt_name
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("x509 cert builder: build subject alt name")?;

    cert_builder
        .append_extension(subject_alt_name)
        .context("x509 cert builder: add subject alt name")?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("x509 cert builder: build subject key id")?;
    cert_builder
        .append_extension(subject_key_identifier)
        .context("x509 cert builder: add subject key id x509 extension")?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("x509 cert builder: build auth key id")?;
    cert_builder
        .append_extension(auth_key_identifier)
        .context("x509 cert builder: set auth key id extension")?;

    cert_builder
        .sign(ca_privkey, MessageDigest::sha256())
        .context("x509 cert builder: sign cert")?;

    let cert = cert_builder.build();

    Ok((cert, privkey))
}

fn self_signed_server_auth_gen_ca(
    data: &SelfSignedData,
) -> Result<(X509, PKey<Private>), OpaqueError> {
    let rsa = Rsa::generate(4096).context("generate 4096 RSA key")?;
    let privkey = PKey::from_rsa(rsa).context("create private key from 4096 RSA key")?;

    let common_name = data
        .common_name
        .clone()
        .unwrap_or(Host::Name(Domain::from_static("localhost")));

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
        .append_entry_by_nid(Nid::COMMONNAME, common_name.to_string().as_str())
        .context("append common name to x509 name builder")?;
    let x509_name = x509_name.build();

    let mut ca_cert_builder = X509::builder().context("create x509 (cert) builder")?;
    ca_cert_builder
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
    ca_cert_builder
        .set_serial_number(&serial_number)
        .context("x509 cert builder: set serial number")?;
    ca_cert_builder
        .set_subject_name(&x509_name)
        .context("x509 cert builder: set subject name")?;
    ca_cert_builder
        .set_issuer_name(&x509_name)
        .context("x509 cert builder: set issuer (self-signed")?;
    ca_cert_builder
        .set_pubkey(&privkey)
        .context("x509 cert builder: set public key using private key (ref)")?;
    let not_before =
        Asn1Time::days_from_now(0).context("x509 cert builder: create ASN1Time for today")?;
    ca_cert_builder
        .set_not_before(&not_before)
        .context("x509 cert builder: set not before to today")?;
    let not_after = Asn1Time::days_from_now(90)
        .context("x509 cert builder: create ASN1Time for 90 days in future")?;
    ca_cert_builder
        .set_not_after(&not_after)
        .context("x509 cert builder: set not after to 90 days in future")?;

    ca_cert_builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .context("x509 cert builder: build basic constraints")?,
        )
        .context("x509 cert builder: add basic constraints as x509 extension")?;
    ca_cert_builder
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
        .build(&ca_cert_builder.x509v3_context(None, None))
        .context("x509 cert builder: build subject key id")?;
    ca_cert_builder
        .append_extension(subject_key_identifier)
        .context("x509 cert builder: add subject key id x509 extension")?;

    ca_cert_builder
        .sign(&privkey, MessageDigest::sha256())
        .context("x509 cert builder: sign cert")?;

    let cert = ca_cert_builder.build();

    Ok((cert, privkey))
}
