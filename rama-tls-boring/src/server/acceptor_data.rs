use crate::core::{
    nid::Nid,
    pkey::{PKey, Private},
    x509::X509,
};
use moka::sync::Cache;
use parking_lot::Mutex;
use rama_boring::ssl::{ClientHello, NameType, SelectCertError, SslAcceptorBuilder, SslRef};
use rama_boring_tokio::{AsyncSelectCertError, BoxSelectCertFinish};
use rama_core::conversion::RamaTryFrom;
use rama_core::error::{BoxError, ErrorContext, ErrorExt as _};
use rama_core::telemetry::tracing;
use rama_net::{
    address::Domain,
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
        cert_cache: Option<Cache<Domain, IssuedCert>>,
        /// Private Key for issueing
        ca_key: PKey<Private>,
        /// CA Cert to be used for issueing
        ca_cert: X509,
    },
    DynamicIssuer {
        issuer: DynamicIssuer,
        /// Cache for certs already issued
        cert_cache: Option<Cache<Domain, IssuedCert>>,
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
        server_name: Option<Domain>,
        maybe_client_hello: Option<&Arc<Mutex<Option<RamaClientHello>>>>,
    ) -> Result<SslAcceptorBuilder, BoxError> {
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
                        let maybe_client_hello =
                            match RamaClientHello::rama_try_from(boring_client_hello) {
                                Ok(ch) => Some(ch),
                                Err(err) => {
                                    tracing::warn!(
                                        "failed to extract boringssl client hello: {err:?}"
                                    );
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
                let cb_maybe_client_hello = maybe_client_hello.cloned();
                builder.set_select_certificate_callback(move |client_hello| {
                    if let Some(cb_maybe_client_hello) = &cb_maybe_client_hello {
                        let maybe_client_hello = match RamaClientHello::rama_try_from(&client_hello)
                        {
                            Ok(ch) => Some(ch),
                            Err(err) => {
                                tracing::warn!("failed to extract boringssl client hello: {err:?}");
                                None
                            }
                        };
                        *cb_maybe_client_hello.lock() = maybe_client_hello;
                    }

                    let mut client_hello = client_hello;
                    let ssl_ref = client_hello.ssl_mut();

                    let domain = to_domain(ssl_ref, server_name.as_ref()).map_err(|err| {
                        tracing::error!("boring: failed getting host: {err:?}");
                        SelectCertError::ERROR
                    })?;

                    tracing::trace!(%domain, "try to use cached issued cert or generate new one");
                    let issued_cert = match &cert_cache {
                        None => issue_cert_for_ca(&domain, &ca_cert, &ca_key)
                            .context("fresh issue of cert")
                            .map_err(|err| {
                                tracing::error!(
                                    "boring: select certificate callback: issue failed: {err:?}"
                                );
                                SelectCertError::ERROR
                            })?,
                        Some(cert_cache) => cert_cache
                            .try_get_with(domain.clone(), || {
                                issue_cert_for_ca(&domain, &ca_cert, &ca_key)
                            })
                            .map_err(|err| {
                                tracing::error!(
                                    "boring: select certificate callback: issue failed: {err:?}"
                                );
                                SelectCertError::ERROR
                            })?,
                    };

                    add_issued_cert_to_ssl_ref(&domain, &issued_cert, ssl_ref).map_err(|err| {
                        tracing::error!(
                            "boring: select certificate callback: add certs to ssl ref: {err:?}"
                        );
                        SelectCertError::ERROR
                    })?;

                    Ok(())
                });
            }
            TlsCertSourceKind::DynamicIssuer { issuer, cert_cache } => {
                let cb_maybe_client_hello = maybe_client_hello.cloned();
                let cert_cache = cert_cache;

                builder.set_async_select_certificate_callback(move |client_hello| {
                    let rama_client_hello =
                        RamaClientHello::rama_try_from(&*client_hello).map_err(|err| {
                            tracing::error!("boring: failed converting to rama client hello: {err:?}");
                            AsyncSelectCertError{}
                        })?;

                    if let Some(cb_maybe_client_hello) = &cb_maybe_client_hello {
                        *cb_maybe_client_hello.lock() = Some(rama_client_hello.clone());
                    }

                    let ssl_ref = client_hello.ssl_mut();
                    let host = to_domain(ssl_ref, server_name.as_ref()).map_err(|err| {
                        tracing::error!("boring: failed getting host: {err:?}");
                        AsyncSelectCertError{}
                    })?;


                    let issuer = issuer.clone();
                    let cert_cache = cert_cache.clone();
                    let server_name = server_name.clone();

                    Ok(Box::pin(async move {
                        let cache_key = issuer.norm_cn(&host).unwrap_or(&host);

                        let issued_cert = if let Some(cached_cert) = cert_cache.as_ref().and_then(|cert_cache| cert_cache.get(cache_key)) {
                            cached_cert
                        } else {
                            let auth_data = issuer.issue_cert(rama_client_hello, server_name).await.map_err(|err| {
                                tracing::error!("boring: dynamic cert issuer failed: {err:?}");
                                AsyncSelectCertError{}
                            })?;
                            server_auth_data_to_private_key_and_ca_chain(&auth_data).map_err(|err| {
                                tracing::error!("boring: server_auth_data to key and ca chain failed: {err:?}");
                                AsyncSelectCertError{}
                            })?
                        };

                        if let Some(cert_cache) = cert_cache {
                            cert_cache.insert(cache_key.clone(), issued_cert.clone());
                        }

                        let apply_cert = Box::new(move |client_hello: ClientHello<'_>| {
                            let mut client_hello = client_hello;
                            let ssl_ref = client_hello.ssl_mut();

                            add_issued_cert_to_ssl_ref(
                                &host,
                                &issued_cert,
                                ssl_ref,
                            ).map_err(|err| {
                                tracing::error!("boring: async select certificate callback: add certs to ssl ref: {err:?}");
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
    type Error = BoxError;

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
                    self_signed_server_auth(&data).context("boring/TlsAcceptorData")?;
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
                    CacheKind::MemCache { max_size, ttl } => Some(
                        Cache::builder()
                            .time_to_live(match ttl {
                                None | Some(Duration::ZERO) => {
                                    Duration::from_hours(24 * 89) // 89 days
                                }
                                Some(custom) => custom,
                            })
                            .max_capacity(max_size.into())
                            .build(),
                    ),
                };

                match data.kind {
                    ServerCertIssuerKind::SelfSigned(data) => {
                        let (ca_cert, ca_key) = super::utils::self_signed_server_auth_gen_ca(&data)
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
        Ok(Self {
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

fn to_domain(ssl_ref: &SslRef, server_name: Option<&Domain>) -> Result<Domain, BoxError> {
    let host = match (ssl_ref.servername(NameType::HOST_NAME), server_name) {
        (Some(sni), _) => {
            tracing::trace!("boring: server_name to host: use client SNI: {sni}");
            sni.parse().map_err(|err: BoxError| {
                tracing::warn!("boring: invalid servername received in callback: {err:?}");
                err.context("sni parse failed")
            })? // from client (e.g. only possibility for SNI proxy)
        }
        (_, Some(host)) => {
            tracing::trace!("boring: server_name {host} not in sni: using context");
            host.clone() // from context (lower prio)
        }
        // We aren't sure if we actually want this logic here or if this should be an error path
        // We will come back to this once we have some more data about this.
        (None, None) => {
            tracing::warn!(
                "boring: no host found in server_name or ctx: defaulting to 'localhost'"
            );
            Domain::from_static("localhost") // fallback
        }
    };
    Ok(host)
}

fn server_auth_data_to_private_key_and_ca_chain(
    data: &ServerAuthData,
) -> Result<IssuedCert, BoxError> {
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
    domain: &Domain,
    ca_cert: &X509,
    ca_key: &PKey<Private>,
) -> Result<IssuedCert, BoxError> {
    tracing::trace!("generate certs for host {domain} using in-memory ca cert");
    let (cert, key) = super::utils::self_signed_server_auth_gen_cert(
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
            common_name: Some(domain.clone()),
            subject_alternative_names: None,
        },
        ca_cert,
        ca_key,
    )
    .context("issue certs in memory")
    .context_field("domain", domain.clone())?;

    Ok(IssuedCert {
        cert_chain: vec![cert, ca_cert.clone()],
        key,
    })
}

fn add_issued_cert_to_ssl_ref(
    domain: &Domain,
    issued_cert: &IssuedCert,
    builder: &mut SslRef,
) -> Result<(), BoxError> {
    tracing::trace!("add issued cert for host {domain} to (boring) SslAcceptorBuilder");

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

fn self_signed_server_auth(data: &SelfSignedData) -> Result<IssuedCert, BoxError> {
    let (ca_cert, ca_privkey) =
        super::utils::self_signed_server_auth_gen_ca(data).context("self-signed CA")?;
    let (cert, privkey) =
        super::utils::self_signed_server_auth_gen_cert(data, &ca_cert, &ca_privkey)
            .context("self-signed cert using self-signed CA")?;
    Ok(IssuedCert {
        cert_chain: vec![cert, ca_cert],
        key: privkey,
    })
}
