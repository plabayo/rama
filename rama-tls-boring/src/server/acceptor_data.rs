use super::cert_issuer::{CacheKind, DynamicIssuer, ServerCertIssuerKind};
use super::config::BoringTlsAuth;
use crate::core::{
    asn1::Asn1Time,
    pkey::{PKey, Private},
    x509::X509,
};
use moka::sync::Cache;
use parking_lot::Mutex;
use rama_boring::ssl::{ClientHello, NameType, SelectCertError, SslAcceptorBuilder, SslRef};
use rama_boring_tokio::{AsyncSelectCertError, BoxSelectCertFinish};
use rama_core::conversion::RamaTryFrom;
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext, ErrorExt as _};
use rama_core::telemetry::tracing;
use rama_crypto::dep::x509_parser::nom::AsBytes;
use rama_net::address::Domain;
use rama_tls::{
    ApplicationProtocol, KeyLogIntent, ProtocolVersion,
    client::ClientHello as RamaClientHello,
    server::{
        CertificateAuthorityData, CertificateIdentity, CertificateIssuanceContext,
        ClientVerifyMode, LeafCertConfig, LeafCertRequest, ServerAuthData,
    },
};
use std::{sync::Arc, time::Duration};

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::TlsAcceptorService`].
pub struct TlsAcceptorData {
    pub(super) config: TlsConfig,
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
        cert_cache: Option<Cache<CertificateIdentity, IssuedCert>>,
        /// Private Key for issueing
        ca_key: PKey<Private>,
        /// Issuing CA first, followed by any parent certificates.
        ca_chain: Vec<X509>,
        leaf_config: LeafCertConfig,
        fallback_identity: Option<CertificateIdentity>,
    },
    DynamicIssuer {
        issuer: DynamicIssuer,
        /// Cache for certs already issued
        cert_cache: Option<Cache<CertificateIdentity, IssuedCert>>,
        fallback_identity: Option<CertificateIdentity>,
    },
}

#[derive(Debug, Clone)]
struct IssuedCert {
    cert_chain: Vec<X509>,
    key: PKey<Private>,
}

impl IssuedCert {
    fn is_valid(&self) -> bool {
        let Ok(now) = Asn1Time::days_from_now(0) else {
            return false;
        };
        self.cert_chain.first().is_some_and(|leaf| {
            leaf.not_before() <= now.as_ref() && now.as_ref() < leaf.not_after()
        })
    }
}

impl TlsCertSource {
    pub(super) async fn issue_certs(
        self,
        mut builder: SslAcceptorBuilder,
        target_identity: Option<CertificateIdentity>,
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
                ca_chain,
                leaf_config,
                fallback_identity,
            } => {
                let cb_maybe_client_hello = maybe_client_hello.cloned();
                let fallback_identity = target_identity.or(fallback_identity);
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

                    let identity = to_opt_identity(ssl_ref, fallback_identity.as_ref())
                        .map_err(|err| {
                            tracing::error!("boring: failed getting host: {err:?}");
                            SelectCertError::ERROR
                        })?
                        .ok_or_else(|| {
                            tracing::error!(
                                "boring: no DNS SNI or target identity for leaf issuance"
                            );
                            SelectCertError::ERROR
                        })?;

                    tracing::trace!(
                        ?identity,
                        "try to use cached issued cert or generate new one"
                    );
                    let issued_cert = match &cert_cache {
                        None => issue_cert_for_ca(&identity, &leaf_config, &ca_chain, &ca_key)
                            .context("fresh issue of cert")
                            .map_err(|err| {
                                tracing::error!(
                                    "boring: select certificate callback: issue failed: {err:?}"
                                );
                                SelectCertError::ERROR
                            })?,
                        Some(cert_cache) => match cert_cache.get(&identity) {
                            Some(cached) if cached.is_valid() => cached,
                            _ => {
                                cert_cache.invalidate(&identity);
                                let issued = issue_cert_for_ca(
                                    &identity,
                                    &leaf_config,
                                    &ca_chain,
                                    &ca_key,
                                )
                                .map_err(|err| {
                                    tracing::error!(
                                        "boring: select certificate callback: issue failed: {err:?}"
                                    );
                                    SelectCertError::ERROR
                                })?;
                                cert_cache.insert(identity.clone(), issued.clone());
                                issued
                            }
                        },
                    };

                    add_issued_cert_to_ssl_ref(Some(&identity), &issued_cert, ssl_ref).map_err(
                        |err| {
                            tracing::error!(
                                "boring: select certificate callback: add certs to ssl ref: {err:?}"
                            );
                            SelectCertError::ERROR
                        },
                    )?;

                    Ok(())
                });
            }
            TlsCertSourceKind::DynamicIssuer {
                issuer,
                cert_cache,
                fallback_identity,
            } => {
                let cb_maybe_client_hello = maybe_client_hello.cloned();
                let cert_cache = cert_cache;
                let fallback_identity = target_identity.or(fallback_identity);

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
                    let server_identity = to_opt_identity(ssl_ref, fallback_identity.as_ref()).map_err(|err| {
                        tracing::error!("boring: failed getting host: {err:?}");
                        AsyncSelectCertError{}
                    })?;


                    let issuer = issuer.clone();
                    let cert_cache = cert_cache.clone();

                    Ok(Box::pin(async move {
                        let maybe_cache_key = server_identity.as_ref().map(|identity| {
                            issuer
                                .normalize_identity(identity)
                                .unwrap_or_else(|| identity.clone())
                        });

                        let issued_cert = if let Some(cache_key) = maybe_cache_key.as_ref()
                            && let Some(cached_cert) = cert_cache.as_ref().and_then(|cert_cache| cert_cache.get(cache_key))
                            && cached_cert.is_valid()
                        {
                            cached_cert
                        } else {
                            if let Some(cache_key) = maybe_cache_key.as_ref()
                                && let Some(cert_cache) = cert_cache.as_ref()
                            {
                                cert_cache.invalidate(cache_key);
                            }
                            let auth_data = issuer.issue_cert(CertificateIssuanceContext {
                                client_hello: rama_client_hello,
                                server_identity: server_identity.clone(),
                            }).await.map_err(|err| {
                                tracing::error!("boring: dynamic cert issuer failed: {err:?}");
                                AsyncSelectCertError{}
                            })?;
                            server_auth_data_to_private_key_and_ca_chain(&auth_data).map_err(|err| {
                                tracing::error!("boring: server_auth_data to key and ca chain failed: {err:?}");
                                AsyncSelectCertError{}
                            })?
                        };

                        if let Some(cache_key) = maybe_cache_key && let Some(cert_cache) = cert_cache {
                            cert_cache.insert(cache_key, issued_cert.clone());
                        }

                        let apply_cert = Box::new(move |client_hello: ClientHello<'_>| {
                            let mut client_hello = client_hello;
                            let ssl_ref = client_hello.ssl_mut();

                            add_issued_cert_to_ssl_ref(
                                server_identity.as_ref(),
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

impl TryFrom<&rama_tls::server::TlsServerConfig> for TlsAcceptorData {
    type Error = BoxError;

    fn try_from(value: &rama_tls::server::TlsServerConfig) -> Result<Self, Self::Error> {
        Self::try_from(super::config::BoringTlsAcceptorConfig::from_extensions(
            value.as_extensions(),
        ))
    }
}

impl TryFrom<super::config::BoringTlsAcceptorConfig<'_>> for TlsAcceptorData {
    type Error = BoxError;

    /// Build [`TlsAcceptorData`] from the gathered common pieces.
    fn try_from(value: super::config::BoringTlsAcceptorConfig<'_>) -> Result<Self, Self::Error> {
        Ok(Self {
            config: TlsConfig::try_from(value)?,
        })
    }
}

impl TryFrom<super::config::BoringTlsAcceptorConfig<'_>> for TlsConfig {
    type Error = BoxError;

    /// Build [`TlsConfig`] from the gathered common pieces.
    fn try_from(value: super::config::BoringTlsAcceptorConfig<'_>) -> Result<Self, Self::Error> {
        let client_cert_chain = match value.client_verify.map(|c| &c.0) {
            // no client auth
            None | Some(ClientVerifyMode::Auto | ClientVerifyMode::Disable) => None,
            // client auth enabled
            Some(ClientVerifyMode::ClientAuth(certs)) => Some(
                certs
                    .iter()
                    .map(|cert| {
                        X509::from_der(cert.as_bytes()).context(
                            "boring/TlsAcceptorData: parse x509 client cert from DER content",
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        };

        let cert_source_kind = match value.auth {
            Some(BoringTlsAuth::CertIssuer(cert_issuer)) => {
                let issuer_data = cert_issuer.0.clone();
                let cert_cache = match issuer_data.cache_kind {
                    CacheKind::Disabled => None,
                    CacheKind::MemCache { max_size, ttl } => {
                        let builder = Cache::builder().max_capacity(max_size.into());
                        let builder = match ttl {
                            Some(ttl) if ttl != Duration::ZERO => builder.time_to_live(ttl),
                            _ => builder,
                        };
                        Some(builder.build())
                    }
                };
                let fallback_identity = issuer_data.fallback_identity;

                match issuer_data.kind {
                    ServerCertIssuerKind::GeneratedCa { ca, leaf } => {
                        let (ca_cert, ca_key) =
                            rama_crypto::cert::boring::generate_certificate_authority_x509(&ca)
                                .context("boring/TlsAcceptorData: CA: self-signed ca")?;
                        TlsCertSourceKind::InMemoryIssuer {
                            cert_cache,
                            ca_key,
                            ca_chain: vec![ca_cert],
                            leaf_config: leaf,
                            fallback_identity,
                        }
                    }
                    ServerCertIssuerKind::ProvidedCa { ca, leaf } => {
                        let (ca_chain, ca_key) = certificate_authority_data_to_chain_and_key(&ca)?;
                        TlsCertSourceKind::InMemoryIssuer {
                            cert_cache,
                            ca_key,
                            ca_chain,
                            leaf_config: leaf,
                            fallback_identity,
                        }
                    }
                    ServerCertIssuerKind::Dynamic(issuer) => TlsCertSourceKind::DynamicIssuer {
                        issuer,
                        cert_cache,
                        fallback_identity,
                    },
                }
            }

            other => {
                let server_auth = match other {
                    Some(BoringTlsAuth::ServerAuth(server_auth)) => &server_auth.0,
                    _ => {
                        return Err(BoxError::from_static_str(
                            "boring/TlsAcceptorData: no server auth configured: provide a certificate \
                             (e.g. via TlsServerConfig::single_cert or generated_server_auth)",
                        ));
                    }
                };
                let issued_cert = server_auth_data_to_private_key_and_ca_chain(server_auth)?;
                TlsCertSourceKind::InMemory(issued_cert)
            }
        };

        Ok(Self {
            cert_source: TlsCertSource {
                kind: cert_source_kind,
            },
            alpn_protocols: value.alpn.map(|a| a.0.to_vec()),
            keylog_intent: value.keylog.map(|k| k.0.clone()).unwrap_or_default(),
            protocol_versions: value.versions.map(|v| v.0.clone()),
            client_cert_chain,
            store_client_certificate_chain: value
                .store_client_chain
                .map(|s| s.0)
                .unwrap_or_default(),
        })
    }
}

fn to_opt_identity(
    ssl_ref: &SslRef,
    fallback: Option<&CertificateIdentity>,
) -> Result<Option<CertificateIdentity>, BoxError> {
    let identity = match (ssl_ref.servername(NameType::HOST_NAME), fallback) {
        (Some(sni), _) => {
            tracing::trace!("boring: use client DNS SNI as certificate identity: {sni}");
            Some(CertificateIdentity::from(sni.parse::<Domain>().map_err(
                |err| {
                    tracing::warn!("boring: invalid servername received in callback: {err:?}");
                    err.into_box_error().context("sni parse failed")
                },
            )?))
        }
        (_, Some(identity)) => {
            tracing::trace!(?identity, "boring: no SNI; use target certificate identity");
            Some(identity.clone())
        }
        (None, None) => {
            tracing::debug!("boring: no certificate identity found in SNI or context");
            None
        }
    };
    Ok(identity)
}

fn server_auth_data_to_private_key_and_ca_chain(
    data: &ServerAuthData,
) -> Result<IssuedCert, BoxError> {
    let private_key = PKey::private_key_from_der(data.private_key.secret_der())
        .context("boring/TlsAcceptorData: parse private key from DER content")?;

    let cert_chain = data
        .cert_chain
        .iter()
        .map(|raw_data| {
            X509::from_der(&raw_data[..])
                .context("boring/TlsAcceptorData: parse x509 server cert from DER content")
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(IssuedCert {
        cert_chain,
        key: private_key,
    })
}

fn certificate_authority_data_to_chain_and_key(
    data: &CertificateAuthorityData,
) -> Result<(Vec<X509>, PKey<Private>), BoxError> {
    let key = PKey::private_key_from_der(data.private_key().secret_der())
        .context("boring/TlsAcceptorData: parse CA private key")?;
    let chain = data
        .certificate_chain()
        .iter()
        .map(|raw| X509::from_der(raw.as_ref()).context("parse CA certificate chain"))
        .collect::<Result<Vec<_>, _>>()?;
    let issuer = chain
        .first()
        .ok_or_else(|| BoxError::from_static_str("certificate authority chain cannot be empty"))?;
    let public_key = issuer.public_key().context("read issuing CA public key")?;
    if !key.public_eq(&public_key) {
        return Err(BoxError::from_static_str(
            "certificate authority private key does not match its certificate",
        ));
    }
    Ok((chain, key))
}

fn issue_cert_for_ca(
    identity: &CertificateIdentity,
    leaf_config: &LeafCertConfig,
    ca_chain: &[X509],
    ca_key: &PKey<Private>,
) -> Result<IssuedCert, BoxError> {
    tracing::trace!(?identity, "generate certificate using in-memory CA");
    let ca_cert = ca_chain
        .first()
        .ok_or_else(|| BoxError::from_static_str("certificate authority chain cannot be empty"))?;
    let (cert, key) = rama_crypto::cert::boring::issue_leaf_certificate(
        &LeafCertRequest {
            config: leaf_config.clone(),
            identities: vec![identity.clone()],
        },
        ca_cert,
        ca_key,
    )
    .context("issue certs in memory")
    .with_context_debug_field("identity", || identity.clone())?;

    let mut cert_chain = Vec::with_capacity(ca_chain.len() + 1);
    cert_chain.push(cert);
    cert_chain.extend(ca_chain.iter().cloned());
    Ok(IssuedCert { cert_chain, key })
}

fn add_issued_cert_to_ssl_ref(
    identity: Option<&CertificateIdentity>,
    issued_cert: &IssuedCert,
    builder: &mut SslRef,
) -> Result<(), BoxError> {
    tracing::trace!(?identity, "add issued cert to BoringSSL acceptor");

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

    Ok(())
}
