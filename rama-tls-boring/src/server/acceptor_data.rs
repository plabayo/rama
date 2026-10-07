use std::sync::Arc;

use moka::future::Cache;
use parking_lot::Mutex;
use rama_boring::ssl::{
    AlpnError, ClientHello, NameType, SslAcceptorBuilder, SslCurve, SslOptions, SslRef,
    SslSignatureAlgorithm,
};
use rama_boring_tokio::{AsyncSelectCertError, BoxSelectCertFinish};
use rama_core::{
    conversion::{RamaTryFrom, RamaTryInto},
    error::{ArcError, BoxError, BoxErrorExt as _, ErrorContext, ErrorExt as _},
    telemetry::tracing,
};
use rama_crypto::dep::x509_parser::nom::AsBytes;
use rama_net::{address::Domain, tls::ApplicationProtocol};
use rama_tls::{
    CertificateCompressionAlgorithm, KeyLogIntent, ProtocolVersion,
    client::ClientHello as RamaClientHello,
    server::{
        CertificateAuthorityData, CertificateIdentity, CertificateIssuanceContext,
        ClientVerifyMode, LeafCertConfig, LeafCertRequest, ServerAuthData,
    },
};

use super::{
    cert_issuer::{
        CaMaterial, DynamicIssuer, IssuedCert, ServerCertIssuerData, ServerCertIssuerKind,
    },
    config::BoringTlsAuth,
};
use crate::certificate_compression::add_certificate_compressors;
use crate::core::{
    pkey::{PKey, Private},
    x509::X509,
};
use crate::type_conversion::{native_unique, openssl_cipher_list_str_from_cipher_list};

pub(super) async fn prepare_server_cert_issuer(
    issuer_data: ServerCertIssuerData,
) -> Result<(), BoxError> {
    if issuer_data.ca_material_is_initialized()
        || matches!(issuer_data.kind(), ServerCertIssuerKind::Dynamic(_))
    {
        return Ok(());
    }

    let kind = issuer_data.kind().clone();
    tokio::task::spawn_blocking(move || match kind {
        ServerCertIssuerKind::GeneratedCa { ca, .. } => issuer_data
            .ca_material(|| {
                let (cert, key) =
                    rama_crypto::cert::boring::generate_certificate_authority_x509(&ca)
                        .context("boring/TlsAcceptorData: CA: self-signed ca")?;
                Ok(CaMaterial {
                    key,
                    chain: vec![cert],
                })
            })
            .map(|_| ()),
        ServerCertIssuerKind::ProvidedCa { ca, .. } => issuer_data
            .ca_material(|| {
                let (chain, key) = certificate_authority_data_to_chain_and_key(&ca)?;
                Ok(CaMaterial { key, chain })
            })
            .map(|_| ()),
        ServerCertIssuerKind::Dynamic(_) => Ok(()),
    })
    .await
    .context("join certificate authority initialization task")?
}

/// Leaf issuance is CPU work (key generation + signing) that must not run on a
/// runtime worker: the callback is driven from inside the handshake poll.
async fn issue_blocking(
    issue: impl FnOnce() -> Result<IssuedCert, BoxError> + Send + 'static,
) -> Result<IssuedCert, BoxError> {
    tokio::task::spawn_blocking(issue)
        .await
        .context("join certificate issuance task")?
}

/// Concurrent misses for one identity share a single issuance.
async fn get_or_issue_cached(
    cert_cache: &Cache<CertificateIdentity, IssuedCert>,
    identity: &CertificateIdentity,
    issue: impl Future<Output = Result<IssuedCert, BoxError>>,
) -> Result<IssuedCert, BoxError> {
    if let Some(cached) = cert_cache.get(identity).await {
        if cached.is_valid() {
            return Ok(cached);
        }
        cert_cache.invalidate(identity).await;
    }

    cert_cache
        .try_get_with_by_ref(identity, async {
            issue.await.map_err(ArcError::from_box_error)
        })
        .await
        .map_err(|err: Arc<ArcError>| -> BoxError { ArcError::clone(&err).into() })
}

/// The cached certificate for `identity`, unless it expired, which issuance replaces.
async fn valid_cached(
    cert_cache: &Cache<CertificateIdentity, IssuedCert>,
    identity: &CertificateIdentity,
) -> Option<IssuedCert> {
    cert_cache.get(identity).await.filter(IssuedCert::is_valid)
}

#[derive(Debug, Clone)]
/// Internal data used as configuration/input for the [`super::TlsAcceptorService`].
pub struct TlsAcceptorData {
    pub(super) config: TlsConfig,
}

impl TlsAcceptorData {
    /// Whether certificates are issued per handshake, which needs its ClientHello first.
    #[must_use]
    pub fn issues_certificates(&self) -> bool {
        self.config.cert_source.issues_per_identity()
    }

    /// Issue the certificate `client_hello` asks for, or reuse it from the issuer's cache.
    ///
    /// The identity is the ClientHello's server name, else the issuer's fallback identity.
    /// For TLS stacks that cannot wait on issuance in the middle of a handshake, such as
    /// QUIC's: install the result on the session before it starts, over a context from
    /// [`Self::acceptor_builder_without_identity`]. A fixed identity is returned as is.
    pub async fn issue_certificate(
        &self,
        client_hello: &RamaClientHello,
    ) -> Result<IssuedCertificate, BoxError> {
        let source = self.config.cert_source.clone();
        let identity = source.identity_for(client_hello);
        let signing_prefs = source.signing_prefs.clone();
        let cert = source
            .issue_for(identity.clone(), Some(client_hello.clone()))
            .await?;
        Ok(IssuedCertificate {
            identity,
            cert,
            signing_prefs,
        })
    }

    /// The certificate [`Self::issue_certificate`] hands out for `client_hello` without
    /// issuing one: the fixed identity, or a valid one the issuer's cache holds.
    ///
    /// The result holds the certificate itself, so a later eviction cannot change it.
    pub async fn reusable_certificate(
        &self,
        client_hello: &RamaClientHello,
    ) -> Option<IssuedCertificate> {
        let source = &self.config.cert_source;
        let identity = source.identity_for(client_hello);
        let cert = source.reusable_for(identity.as_ref()).await?;
        Some(IssuedCertificate {
            identity,
            cert,
            signing_prefs: source.signing_prefs.clone(),
        })
    }

    /// A server context builder with every setting of this configuration but its identity,
    /// which is installed per session instead; see [`Self::issue_certificate`].
    pub fn acceptor_builder_without_identity(&self) -> Result<SslAcceptorBuilder, BoxError> {
        self.config.acceptor_builder()
    }

    /// Prepare a server context with a fixed identity, without starting a transport.
    /// Certificate issuers require the asynchronous acceptor path and are rejected here;
    /// see [`Self::issue_certificate`].
    pub fn into_static_acceptor_builder(self) -> Result<SslAcceptorBuilder, BoxError> {
        let mut builder = self.config.acceptor_builder()?;
        let source = self.config.cert_source;
        let TlsCertSourceKind::InMemory(cert) = &source.kind else {
            return Err(BoxError::from_static_str(
                "static TLS context requires a fixed server identity",
            ));
        };
        install_identity(&mut builder, cert, source.signing_prefs.as_deref())?;
        Ok(builder)
    }
}

/// A certificate issued for one handshake, with its private key.
#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    identity: Option<CertificateIdentity>,
    cert: IssuedCert,
    signing_prefs: Option<Arc<[SslSignatureAlgorithm]>>,
}

impl IssuedCertificate {
    /// The identity it was issued for, if the handshake named one.
    #[must_use]
    pub fn identity(&self) -> Option<&CertificateIdentity> {
        self.identity.as_ref()
    }

    /// Present this certificate on `ssl`, before its handshake starts.
    pub fn install(&self, ssl: &mut SslRef) -> Result<(), BoxError> {
        add_issued_cert_to_ssl_ref(
            self.identity.as_ref(),
            &self.cert,
            self.signing_prefs.as_deref(),
            ssl,
        )
    }
}

fn install_identity(
    builder: &mut SslAcceptorBuilder,
    cert: &IssuedCert,
    signing_prefs: Option<&[SslSignatureAlgorithm]>,
) -> Result<(), BoxError> {
    let credential = cert.credential(signing_prefs)?;
    builder
        .add_credential(&credential)
        .context("boring acceptor: add server credential")
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
    /// OpenSSL cipher string for TLS 1.2 and below, in preference order.
    pub(super) cipher_list: Option<String>,
    /// Key exchange groups, in preference order.
    pub(super) curves: Option<Vec<SslCurve>>,
    /// Algorithms the server can compress its certificate with.
    pub(super) cert_compression: Option<Vec<CertificateCompressionAlgorithm>>,
}

impl TlsConfig {
    pub(super) fn acceptor_builder(&self) -> Result<SslAcceptorBuilder, BoxError> {
        use rama_boring::{
            ssl::{SslAcceptor, SslMethod, SslVerifyMode},
            x509::{store::X509StoreBuilder, verify::X509VerifyFlags},
        };
        use rama_tls::keylog::{KeyLogSink, open_intent_sink};
        let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        builder.set_grease_enabled(true);
        for (version, minimum) in [
            (self.protocol_versions.iter().flatten().min(), true),
            (self.protocol_versions.iter().flatten().max(), false),
        ] {
            if let Some(version) = version {
                let version = (*version).rama_try_into().map_err(|v| {
                    BoxError::from_static_str("invalid TLS protocol version")
                        .context_field("version", v)
                })?;
                if minimum {
                    builder.set_min_proto_version(Some(version))?;
                } else {
                    builder.set_max_proto_version(Some(version))?;
                }
            }
        }
        if let Some(certs) = &self.client_cert_chain {
            let mut store = X509StoreBuilder::new()?;
            store.try_set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
            for cert in certs {
                builder.add_client_ca(cert)?;
                store.add_cert(cert.clone())?;
            }
            builder.set_cert_store(store.build());
            builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        }
        if let Some(protocols) = self.alpn_protocols.clone() {
            builder.set_alpn_select_callback(move |_, offered| {
                select_alpn_by_server_preference(&protocols, offered)
            });
        }
        if let Some(sink) = open_intent_sink(&self.keylog_intent)? {
            builder.set_keylog_callback(move |_, line| {
                let mut output = String::with_capacity(line.len() + 1);
                output.push_str(line);
                output.push('\n');
                sink.write_line(&output);
            });
        }
        if let Some(cipher_list) = &self.cipher_list {
            builder
                .set_cipher_list(cipher_list)
                .context("boring acceptor: set cipher list")?;
        }
        if let Some(curves) = &self.curves {
            builder
                .set_curves(curves)
                .context("boring acceptor: set curves")?;
        }
        // Configured lists are preference orders, as for ALPN.
        if self.cipher_list.is_some() || self.curves.is_some() {
            builder.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
        }
        if let Some(algorithms) = &self.cert_compression {
            add_certificate_compressors(&mut builder, algorithms)
                .context("boring acceptor: certificate compression")?;
        }
        Ok(builder)
    }
}

#[derive(Debug, Clone)]
pub(super) struct TlsCertSource {
    kind: TlsCertSourceKind,
    /// Signing preferences of every installed credential.
    signing_prefs: Option<Arc<[SslSignatureAlgorithm]>>,
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

impl TlsCertSource {
    fn issues_per_identity(&self) -> bool {
        !matches!(self.kind, TlsCertSourceKind::InMemory(_))
    }

    fn fallback_identity(&self) -> Option<&CertificateIdentity> {
        match &self.kind {
            TlsCertSourceKind::InMemory(_) => None,
            TlsCertSourceKind::InMemoryIssuer {
                fallback_identity, ..
            }
            | TlsCertSourceKind::DynamicIssuer {
                fallback_identity, ..
            } => fallback_identity.as_ref(),
        }
    }

    /// The identity a handshake asks a certificate for: its server name, else the fallback.
    fn identity_for(&self, client_hello: &RamaClientHello) -> Option<CertificateIdentity> {
        match client_hello.ext_server_name() {
            Some(name) => Some(CertificateIdentity::from(name.clone())),
            None => self.fallback_identity().cloned(),
        }
    }

    /// The certificate [`Self::issue_for`] returns for `identity` without issuing one.
    async fn reusable_for(&self, identity: Option<&CertificateIdentity>) -> Option<IssuedCert> {
        match &self.kind {
            TlsCertSourceKind::InMemory(cert) => Some(cert.clone()),
            TlsCertSourceKind::InMemoryIssuer { cert_cache, .. } => {
                valid_cached(cert_cache.as_ref()?, identity?).await
            }
            TlsCertSourceKind::DynamicIssuer {
                issuer, cert_cache, ..
            } => {
                let identity = identity?;
                let normalized = issuer.normalize_identity(identity);
                valid_cached(
                    cert_cache.as_ref()?,
                    normalized.as_ref().unwrap_or(identity),
                )
                .await
            }
        }
    }

    /// The certificate for `identity`, issued now or reused from the cache.
    ///
    /// A dynamic issuer decides from the ClientHello and may accept no identity at all;
    /// leaves issued by an in-memory CA need one.
    async fn issue_for(
        self,
        identity: Option<CertificateIdentity>,
        client_hello: Option<RamaClientHello>,
    ) -> Result<IssuedCert, BoxError> {
        match self.kind {
            TlsCertSourceKind::InMemory(issued_cert) => Ok(issued_cert),
            TlsCertSourceKind::InMemoryIssuer {
                cert_cache,
                ca_key,
                ca_chain,
                leaf_config,
                ..
            } => {
                let identity = identity.ok_or_else(|| {
                    BoxError::from_static_str("no DNS SNI or target identity for leaf issuance")
                })?;
                tracing::trace!(
                    ?identity,
                    "try to use cached issued cert or generate new one"
                );
                let issue = {
                    let identity = identity.clone();
                    issue_blocking(move || {
                        issue_cert_for_ca(&identity, &leaf_config, &ca_chain, &ca_key)
                    })
                };
                match &cert_cache {
                    None => issue.await.context("fresh issue of cert"),
                    Some(cert_cache) => get_or_issue_cached(cert_cache, &identity, issue).await,
                }
            }
            TlsCertSourceKind::DynamicIssuer {
                issuer, cert_cache, ..
            } => {
                let client_hello = client_hello.ok_or_else(|| {
                    BoxError::from_static_str("dynamic cert issuer requires the client hello")
                })?;
                let cache_key = identity.as_ref().map(|identity| {
                    issuer
                        .normalize_identity(identity)
                        .unwrap_or_else(|| identity.clone())
                });
                let issue = async move {
                    let auth_data = issuer
                        .issue_cert(CertificateIssuanceContext {
                            client_hello,
                            server_identity: identity,
                        })
                        .await
                        .context("dynamic cert issuer")?;
                    // DER parsing of the returned material is cheap; only the
                    // issuer's own work (remote or local signing) is async here.
                    server_auth_data_to_private_key_and_ca_chain(&auth_data)
                        .context("server_auth_data to key and ca chain")
                };
                match (cache_key.as_ref(), cert_cache.as_ref()) {
                    (Some(cache_key), Some(cert_cache)) => {
                        get_or_issue_cached(cert_cache, cache_key, issue).await
                    }
                    _ => issue.await,
                }
            }
        }
    }

    pub(super) async fn issue_certs(
        self,
        mut builder: SslAcceptorBuilder,
        target_identity: Option<CertificateIdentity>,
        maybe_client_hello: Option<&Arc<Mutex<Option<RamaClientHello>>>>,
    ) -> Result<SslAcceptorBuilder, BoxError> {
        if let TlsCertSourceKind::InMemory(issued_cert) = &self.kind {
            install_identity(&mut builder, issued_cert, self.signing_prefs.as_deref())?;

            if let Some(maybe_client_hello) = maybe_client_hello {
                let cb_maybe_client_hello = maybe_client_hello.clone();
                builder.set_select_certificate_callback(move |boring_client_hello| {
                    let maybe_client_hello =
                        match RamaClientHello::rama_try_from(boring_client_hello) {
                            Ok(ch) => Some(ch),
                            Err(err) => {
                                tracing::warn!("failed to extract boringssl client hello: {err:?}");
                                None
                            }
                        };
                    *cb_maybe_client_hello.lock() = maybe_client_hello;
                    Ok(())
                });
            }
            return Ok(builder);
        }

        let cb_maybe_client_hello = maybe_client_hello.cloned();
        let fallback_identity = target_identity.or_else(|| self.fallback_identity().cloned());
        builder.set_async_select_certificate_callback(move |client_hello| {
            let rama_client_hello = match RamaClientHello::rama_try_from(&*client_hello) {
                Ok(ch) => Some(ch),
                Err(err) => {
                    tracing::warn!("failed to extract boringssl client hello: {err:?}");
                    None
                }
            };
            if let Some(cb_maybe_client_hello) = &cb_maybe_client_hello {
                *cb_maybe_client_hello.lock() = rama_client_hello.clone();
            }

            let ssl_ref = client_hello.ssl_mut();
            let identity = to_opt_identity(ssl_ref, fallback_identity.as_ref()).map_err(|err| {
                tracing::error!("boring: failed getting host: {err:?}");
                AsyncSelectCertError {}
            })?;

            let source = self.clone();
            Ok(Box::pin(async move {
                let signing_prefs = source.signing_prefs.clone();
                let issued_cert = source
                    .issue_for(identity.clone(), rama_client_hello)
                    .await
                    .map_err(|err| {
                        tracing::error!(
                            "boring: select certificate callback: issue failed: {err:?}"
                        );
                        AsyncSelectCertError {}
                    })?;

                let apply_cert = Box::new(move |client_hello: ClientHello<'_>| {
                    let mut client_hello = client_hello;
                    let ssl_ref = client_hello.ssl_mut();

                    add_issued_cert_to_ssl_ref(
                        identity.as_ref(),
                        &issued_cert,
                        signing_prefs.as_deref(),
                        ssl_ref,
                    )
                    .map_err(|err| {
                        tracing::error!(
                            "boring: select certificate callback: add certs to ssl ref: {err:?}"
                        );
                        AsyncSelectCertError {}
                    })?;
                    Ok(())
                }) as BoxSelectCertFinish;

                Ok(apply_cert)
            }))
        });

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
                let cert_cache = issuer_data.cache();
                let fallback_identity = issuer_data.fallback_identity().cloned();

                match issuer_data.kind().clone() {
                    ServerCertIssuerKind::GeneratedCa { ca, leaf } => {
                        let ca_material = issuer_data.ca_material(|| {
                            let (cert, key) =
                                rama_crypto::cert::boring::generate_certificate_authority_x509(&ca)
                                    .context("boring/TlsAcceptorData: CA: self-signed ca")?;
                            Ok(CaMaterial {
                                key,
                                chain: vec![cert],
                            })
                        })?;
                        TlsCertSourceKind::InMemoryIssuer {
                            cert_cache,
                            ca_key: ca_material.key,
                            ca_chain: ca_material.chain,
                            leaf_config: leaf,
                            fallback_identity,
                        }
                    }
                    ServerCertIssuerKind::ProvidedCa { ca, leaf } => {
                        let ca_material = issuer_data.ca_material(|| {
                            let (chain, key) = certificate_authority_data_to_chain_and_key(&ca)?;
                            Ok(CaMaterial { key, chain })
                        })?;
                        TlsCertSourceKind::InMemoryIssuer {
                            cert_cache,
                            ca_key: ca_material.key,
                            ca_chain: ca_material.chain,
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

        let cipher_list = value.cipher_suites.and_then(|suites| {
            let suites: Vec<_> = suites.0.iter().copied().filter(|s| !s.is_tls13()).collect();
            openssl_cipher_list_str_from_cipher_list(&suites)
        });
        let curves = value
            .supported_groups
            .map(|groups| native_unique(groups.0.iter().filter_map(|g| (*g).rama_try_into().ok())));
        let signing_prefs = value.signature_schemes.map(|schemes| {
            native_unique(schemes.0.iter().filter_map(|s| (*s).rama_try_into().ok())).into()
        });

        Ok(Self {
            cert_source: TlsCertSource {
                kind: cert_source_kind,
                signing_prefs,
            },
            cipher_list,
            curves,
            cert_compression: value.cert_compression.map(|c| c.0.clone()),
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

/// Select the first configured protocol the client offers: configured order is preference order.
pub(crate) fn select_alpn_by_server_preference<'a>(
    protocols: &[ApplicationProtocol],
    offered: &'a [u8],
) -> Result<&'a [u8], AlpnError> {
    let mut reader = std::io::Cursor::new(offered);
    let mut candidates = Vec::new();
    while (reader.position() as usize) < offered.len() {
        let start = reader.position() as usize;
        let protocol = ApplicationProtocol::decode_wire_format(&mut reader)
            .map_err(|_malformed| AlpnError::ALERT_FATAL)?;
        candidates.push((protocol, &offered[start + 1..reader.position() as usize]));
    }
    protocols
        .iter()
        .find_map(|preferred| {
            candidates
                .iter()
                .find(|(protocol, _)| protocol == preferred)
                .map(|(_, wire)| *wire)
        })
        .ok_or(AlpnError::NOACK)
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

    IssuedCert::try_new_with_ocsp(&cert_chain, &private_key, data.ocsp.as_deref())
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
    IssuedCert::try_new(&cert_chain, &key)
}

fn add_issued_cert_to_ssl_ref(
    identity: Option<&CertificateIdentity>,
    issued_cert: &IssuedCert,
    signing_prefs: Option<&[SslSignatureAlgorithm]>,
    builder: &mut SslRef,
) -> Result<(), BoxError> {
    tracing::trace!(?identity, "add issued cert to BoringSSL acceptor");
    let credential = issued_cert.credential(signing_prefs)?;
    builder
        .add_credential(&credential)
        .context("boring add issued cert to ssl ref: add server credential")
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use rama_crypto::cert::CertificateValidity;
    use rama_tls::{
        client::ClientHelloExtension,
        server::{DynamicCertIssuer, SelfSignedCaConfig, TlsServerConfig},
    };
    use tokio::sync::Barrier;

    use super::*;
    use crate::server::{
        BoringServerConfigExt as _, CacheKind, ServerCertIssuerData, ServerCertIssuerKind,
    };

    #[test]
    fn generated_ca_is_shared_across_config_conversions() {
        let config = rama_tls::server::TlsServerConfig::new()
            .with_cert_issuer(ServerCertIssuerData::default());
        let first = TlsAcceptorData::try_from(&config).expect("first acceptor config");
        let second = TlsAcceptorData::try_from(&config).expect("second acceptor config");

        fn generated_ca_der(data: TlsAcceptorData) -> Vec<u8> {
            match data.config.cert_source.kind {
                TlsCertSourceKind::InMemoryIssuer { ca_chain, .. } => ca_chain[0]
                    .to_der()
                    .expect("serialize generated CA certificate"),
                other => panic!("expected in-memory issuer, got {other:?}"),
            }
        }

        assert_eq!(generated_ca_der(first), generated_ca_der(second));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_cache_misses_coalesce_certificate_issuance() {
        const WORKERS: usize = 8;
        let (ca_cert, ca_key) = rama_crypto::cert::boring::generate_certificate_authority_x509(
            &rama_tls::server::SelfSignedCaConfig::default(),
        )
        .expect("generate CA");
        let (cert, key) = rama_crypto::cert::boring::issue_leaf_certificate(
            &LeafCertRequest::default(),
            &ca_cert,
            &ca_key,
        )
        .expect("issue leaf");
        let issued = IssuedCert::try_new(&[cert], &key).expect("issued certificate");
        let identity = CertificateIdentity::Dns(Domain::from_static("coalesced.example"));
        let cache = Cache::new(16);
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(WORKERS));

        let workers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let cache = cache.clone();
                let calls = calls.clone();
                let barrier = barrier.clone();
                let identity = identity.clone();
                let issued = issued.clone();
                tokio::spawn(async move {
                    barrier.wait().await;
                    get_or_issue_cached(&cache, &identity, async move {
                        calls.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        Ok(issued)
                    })
                    .await
                    .expect("get or issue certificate")
                })
            })
            .collect();

        for worker in workers {
            worker.await.expect("join cache worker");
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    fn hello(name: &'static str) -> RamaClientHello {
        RamaClientHello::new(
            ProtocolVersion::TLSv1_3,
            Vec::new(),
            Vec::new(),
            vec![ClientHelloExtension::ServerName(Some(Domain::from_static(
                name,
            )))],
        )
    }

    fn acceptor_data(issuer: ServerCertIssuerData) -> TlsAcceptorData {
        let config = TlsServerConfig::new().with_cert_issuer(issuer);
        TlsAcceptorData::try_from(&config).expect("acceptor config")
    }

    #[tokio::test]
    async fn only_certificates_issued_before_are_reusable() {
        let cached = acceptor_data(ServerCertIssuerData::default());
        assert!(
            cached
                .reusable_certificate(&hello("a.example"))
                .await
                .is_none()
        );
        cached
            .issue_certificate(&hello("a.example"))
            .await
            .expect("issue a.example");
        let reused = cached
            .reusable_certificate(&hello("a.example"))
            .await
            .expect("a.example is cached");
        assert_eq!(
            reused.identity(),
            Some(&CertificateIdentity::Dns(Domain::from_static("a.example")))
        );
        assert!(
            cached
                .reusable_certificate(&hello("b.example"))
                .await
                .is_none()
        );

        let uncached =
            acceptor_data(ServerCertIssuerData::default().with_cache_kind(CacheKind::Disabled));
        uncached
            .issue_certificate(&hello("a.example"))
            .await
            .expect("issue a.example");
        assert!(
            uncached
                .reusable_certificate(&hello("a.example"))
                .await
                .is_none()
        );

        let fixed = TlsAcceptorData::try_from(
            &TlsServerConfig::new().with_server_auth(
                ServerAuthData::new_self_signed_leaf(LeafCertRequest::default())
                    .expect("self-signed leaf"),
            ),
        )
        .expect("acceptor config");
        assert!(
            fixed
                .reusable_certificate(&hello("a.example"))
                .await
                .is_some()
        );
    }

    /// A cached certificate that expired is issued again, so it is not reusable.
    #[tokio::test]
    async fn an_expired_cached_certificate_is_not_reusable() {
        let expiring = acceptor_data(ServerCertIssuerData::new(
            ServerCertIssuerKind::GeneratedCa {
                ca: SelfSignedCaConfig::default(),
                leaf: LeafCertConfig {
                    validity: CertificateValidity::new(
                        Duration::from_secs(1),
                        Duration::from_secs(1),
                    ),
                    ..LeafCertConfig::default()
                },
            },
        ));
        expiring
            .issue_certificate(&hello("a.example"))
            .await
            .expect("issue a.example");
        assert!(
            expiring
                .reusable_certificate(&hello("a.example"))
                .await
                .is_none()
        );
    }

    #[test]
    fn alpn_selection_follows_server_preference_order() {
        let server = [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11];
        let wire = |protocols: &[ApplicationProtocol]| {
            ApplicationProtocol::encode_alpns(protocols).expect("encode ALPN offer")
        };
        for (offered, selected) in [
            (
                vec![ApplicationProtocol::HTTP_11, ApplicationProtocol::HTTP_2],
                Some("h2"),
            ),
            (
                vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11],
                Some("h2"),
            ),
            (vec![ApplicationProtocol::HTTP_11], Some("http/1.1")),
            (vec![ApplicationProtocol::HTTP_3], None),
        ] {
            let offer = wire(&offered);
            let result = select_alpn_by_server_preference(&server, &offer);
            assert_eq!(
                result.ok(),
                selected.map(str::as_bytes),
                "offered: {offered:?}"
            );
        }
    }

    /// Issues one certificate for every name, cached under one identity.
    struct OneIdentity(Arc<CertificateAuthorityData>);

    impl DynamicCertIssuer for OneIdentity {
        async fn issue_cert(
            &self,
            _: CertificateIssuanceContext,
        ) -> Result<ServerAuthData, BoxError> {
            ServerAuthData::new_issued_by(&self.0, LeafCertRequest::default())
        }

        fn normalize_identity(&self, _: &CertificateIdentity) -> Option<CertificateIdentity> {
            Some(CertificateIdentity::Dns(Domain::from_static("one.example")))
        }
    }

    #[tokio::test]
    async fn a_dynamic_issuer_counts_names_by_their_normalized_identity() {
        let ca =
            CertificateAuthorityData::generate(SelfSignedCaConfig::default()).expect("generate CA");
        let data = acceptor_data(ServerCertIssuerData::new(OneIdentity(Arc::new(ca))));
        assert!(
            data.reusable_certificate(&hello("a.example"))
                .await
                .is_none()
        );
        data.issue_certificate(&hello("a.example"))
            .await
            .expect("issue a.example");
        assert!(
            data.reusable_certificate(&hello("b.example"))
                .await
                .is_some()
        );
    }
}
