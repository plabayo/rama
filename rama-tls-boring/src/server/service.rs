use super::TlsAcceptorData;
use super::acceptor_data::{ConnectionState, bind_connection, prepare_server_cert_issuer};
use super::config::{BoringTlsAcceptorConfig, BoringTlsAuth};
use crate::{TlsStream, types::SecureTransport};
use parking_lot::Mutex;
use rama_boring::ssl::{Ssl, SslContext, SslSessionCacheMode};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Service,
    conversion::{RamaInto as _, RamaTryInto},
    error::{BoxError, ErrorContext, ErrorExt},
    extensions::{Extensions, ExtensionsRef},
    io::Io,
};
use rama_net::{client::ConnectorTarget, extensions::StreamTransformed, tls::ApplicationProtocol};
use rama_tls::{
    client::NegotiatedTlsParameters,
    server::{CertificateIdentity, TlsServerConfig},
};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::sync::{Arc, OnceLock};

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
#[derive(Debug, Clone)]
pub struct TlsAcceptorService<S> {
    config: TlsServerConfig,
    store_client_hello: bool,
    sessions: Option<Arc<OnceLock<Acceptor>>>,
    inner: S,
}

/// A native server context with the connection settings it was built for.
#[derive(Debug, Clone)]
struct Acceptor {
    context: SslContext,
    store_client_certificate_chain: bool,
}

impl<S> TlsAcceptorService<S> {
    /// Creates a new [`TlsAcceptorService`].
    pub const fn new(config: TlsServerConfig, inner: S, store_client_hello: bool) -> Self {
        Self {
            config,
            store_client_hello,
            sessions: None,
            inner,
        }
    }

    generate_set_and_with!(
        /// Let clients resume sessions of earlier connections to this acceptor. Off by default.
        ///
        /// Connections share one native context, whose session tickets no other acceptor
        /// can decrypt; clones of this service share it. Connections that override the
        /// TLS configuration never resume. The server keeps no session state itself.
        pub fn session_resumption(mut self, enabled: bool) -> Self {
            self.sessions = enabled.then(Arc::default);
            self
        }
    );

    define_inner_service_accessors!();

    fn acceptor(&self, extensions: &Extensions) -> Result<Acceptor, BoxError> {
        let tls_config =
            TlsAcceptorData::try_from(BoringTlsAcceptorConfig::from_extensions(extensions))
                .context("boring acceptor: build acceptor data from config")?
                .config;
        let mut builder = tls_config.acceptor_builder()?;
        if self.sessions.is_some() {
            builder.set_session_cache_mode(SslSessionCacheMode::OFF);
        }
        let builder = tls_config
            .cert_source
            .install(builder, self.store_client_hello)?;
        Ok(Acceptor {
            context: builder.build().into_context(),
            store_client_certificate_chain: tls_config.store_client_certificate_chain,
        })
    }

    /// The acceptor's shared context, unless the connection overrides its configuration.
    fn connection_acceptor(
        &self,
        connection: &Extensions,
        merged: &Extensions,
    ) -> Result<Acceptor, BoxError> {
        match &self.sessions {
            Some(shared) if BoringTlsAcceptorConfig::from_extensions(connection).is_empty() => {
                if let Some(acceptor) = shared.get() {
                    return Ok(acceptor.clone());
                }
                let acceptor = self.acceptor(merged)?;
                Ok(shared.get_or_init(|| acceptor).clone())
            }
            _ => self.acceptor(merged),
        }
    }
}

// TODO provide stand-alone handshake based on pre-built acceptor...
// we need this acceptor based on server hello if possible

impl<S, IO> Service<IO> for TlsAcceptorService<S>
where
    IO: Io + Unpin + ExtensionsRef + 'static,
    S: Service<TlsStream<IO>, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        let merged = stream.extensions().with_base(self.config.as_extensions());

        let issuer_data = match BoringTlsAcceptorConfig::from_extensions(&merged).auth {
            Some(BoringTlsAuth::CertIssuer(issuer)) => Some(issuer.0.clone()),
            _ => None,
        };
        if let Some(issuer_data) = issuer_data {
            prepare_server_cert_issuer(issuer_data)
                .await
                .context("boring acceptor: prepare certificate issuer")?;
        }

        let acceptor = self.connection_acceptor(stream.extensions(), &merged)?;

        let target_identity = stream
            .extensions()
            .get_ref::<SecureTransport>()
            .and_then(|t| t.client_hello())
            .and_then(|c| c.ext_server_name().cloned())
            .map(CertificateIdentity::from)
            .or_else(|| {
                stream
                    .extensions()
                    .get_ref::<ConnectorTarget>()
                    .and_then(|target| CertificateIdentity::try_from(&target.0.host).ok())
            });

        // Certificate callbacks may run more than once per handshake, so they share
        // this slot rather than consuming a channel.
        let maybe_client_hello = self.store_client_hello.then(|| Arc::new(Mutex::new(None)));

        let mut ssl = Ssl::new(&acceptor.context).context("boring acceptor: create session")?;
        bind_connection(
            &mut ssl,
            ConnectionState {
                client_hello: maybe_client_hello.clone(),
                target_identity: target_identity.clone(),
            },
        )?;

        let stream = rama_boring_tokio::SslStreamBuilder::new(ssl, stream)
            .accept()
            .await
            .map_err(|err| {
                let maybe_ssl_code = err.code();
                if let Some(io_err) = err.as_io_error() {
                    BoxError::from(format!(
                        "boring ssl acceptor (accept): with io error: {io_err}"
                    ))
                    .context_debug_field("certificate_identity", target_identity.clone())
                    .context_debug_field("code", maybe_ssl_code)
                } else if let Some(err) = err.as_ssl_error_stack() {
                    err.context("boring ssl acceptor (accept): with ssl-error info")
                        .context_debug_field("certificate_identity", target_identity.clone())
                        .context_debug_field("code", maybe_ssl_code)
                } else {
                    BoxError::from_static_str("boring ssl acceptor (accept): without error info")
                        .context_debug_field("certificate_identity", target_identity.clone())
                        .context_debug_field("code", maybe_ssl_code)
                }
            })?;

        let negotiated_tls_params = match stream.ssl().session() {
            Some(ssl_session) => {
                let protocol_version =
                    ssl_session
                        .protocol_version()
                        .rama_try_into()
                        .map_err(|v| {
                            BoxError::from_static_str("boring ssl acceptor: cast min proto version")
                                .context_field("protocol_version", v)
                        })?;
                let application_layer_protocol = stream
                    .ssl()
                    .selected_alpn_protocol()
                    .map(ApplicationProtocol::from);

                let client_certificate_chain = if let Some(certificate) = acceptor
                    .store_client_certificate_chain
                    .then(|| stream.ssl().peer_certificate())
                    .flatten()
                {
                    // peer_cert_chain doesn't contain the leaf certificate in a server ctx
                    let mut chain = stream
                        .ssl()
                        .peer_cert_chain()
                        .map_or(Ok(vec![]), RamaTryInto::rama_try_into)?;

                    let certificate = certificate
                        .as_ref()
                        .rama_try_into()
                        .context("boring ssl session: failed to convert peer certificate to der")?;
                    chain.insert(0, certificate);
                    Some(chain)
                } else {
                    None
                };

                NegotiatedTlsParameters {
                    protocol_version,
                    application_layer_protocol,
                    peer_certificate_chain: client_certificate_chain,
                    server_name: stream
                        .ssl()
                        .servername(rama_boring::ssl::NameType::HOST_NAME)
                        .map(rama_net::address::Domain::try_from)
                        .transpose()?,
                    resumed: Some(stream.ssl().session_reused()),
                    algorithms: stream.ssl().rama_into(),
                }
            }
            None => {
                return Err(BoxError::from_static_str(
                    "boring ssl acceptor: failed to establish session",
                ));
            }
        };

        let secure_transport = maybe_client_hello
            .and_then(|maybe_client_hello| maybe_client_hello.lock().take())
            .map(SecureTransport::with_client_hello)
            .unwrap_or_default();

        let stream = TlsStream::new(stream);
        stream.extensions().insert(secure_transport);
        stream.extensions().insert(negotiated_tls_params);
        stream.extensions().insert(StreamTransformed {
            by: "rama-tls-boring::TlsAcceptor",
        });

        // NOTE(#1014): graceful TLS `close_notify` on this stream relies on the
        // inner service driving `poll_shutdown` before `stream` is dropped here.
        // The h1 dispatcher now does so on both clean finish and error, but inner
        // HTTP/2 (GOAWAY only), panics, and raw (non-http) tunnels still don't. A
        // bounded shutdown guard wrapping `stream` here (cf. the once-gated,
        // grace-timeout idiom in `rama_net::proxy::forward`; it must spawn via the
        // `Executor` since `Drop` is sync) would cover those paths uniformly.
        self.inner
            .serve(stream)
            .await
            .context("boring acceptor: service error")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        asn1::Asn1Time,
        bn::BigNum,
        hash::MessageDigest,
        pkey::PKey,
        rsa::Rsa,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
        },
    };
    use crate::{
        client::BoringClientConfigExt as _,
        server::{BoringServerConfigExt as _, ServerCertIssuerData},
    };
    use rama_core::{ServiceInput, service::service_fn};
    use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rama_tls::{
        client::{ClientAuth, ClientAuthData, ServerVerifyMode, TlsClientConfig},
        server::{
            CertificateIssuanceContext, ClientVerifyMode, DynamicCertIssuer,
            GeneratedServerAuthConfig, SelfSignedCaConfig, ServerAuthData,
        },
    };

    fn client_identity() -> (CertificateDer<'static>, ClientAuthData) {
        let (ca, ca_key) = rama_crypto::cert::boring::generate_certificate_authority_x509(
            &SelfSignedCaConfig::default(),
        )
        .unwrap();
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Rama test client").unwrap();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        cert.set_subject_name(&name.build()).unwrap();
        cert.set_issuer_name(ca.subject_name()).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.append_extension(&BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        cert.append_extension(&KeyUsage::new().digital_signature().build().unwrap())
            .unwrap();
        cert.append_extension(&ExtendedKeyUsage::new().client_auth().build().unwrap())
            .unwrap();
        cert.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let root = CertificateDer::from(ca.to_der().unwrap());
        (
            root.clone(),
            ClientAuthData {
                cert_chain: vec![CertificateDer::from(cert.build().to_der().unwrap()), root],
                private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    key.private_key_to_der_pkcs8().unwrap(),
                )),
            },
        )
    }

    #[tokio::test]
    async fn client_auth_requires_a_certificate_from_configured_trust() {
        let (root, trusted) = client_identity();
        let (_, untrusted) = client_identity();
        let server_auth =
            ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        for (identity, roots, accepted) in [
            (Some(trusted.clone()), vec![root.clone()], true),
            (Some(untrusted), vec![root.clone()], false),
            (None, vec![root], false),
            (Some(trusted), vec![], false),
        ] {
            let server = TlsAcceptorService::new(
                TlsServerConfig::new()
                    .with_server_auth(server_auth.clone())
                    .with_client_verify(ClientVerifyMode::ClientAuth(roots)),
                service_fn(
                    |stream: TlsStream<ServiceInput<tokio::io::DuplexStream>>| async move {
                        Ok::<_, BoxError>(
                            stream
                                .extensions()
                                .get_ref::<NegotiatedTlsParameters>()
                                .unwrap()
                                .clone(),
                        )
                    },
                ),
                false,
            );
            let mut client = TlsClientConfig::new()
                .with_server_name(rama_net::address::Host::from_static("localhost"))
                .try_with_server_trust_anchors([server_auth.cert_chain.last().unwrap().clone()])
                .unwrap();
            if let Some(identity) = identity {
                client = client.with_client_auth(ClientAuth::Single(identity));
            }
            let data = crate::client::TlsConnectorData::try_from(&client).unwrap();
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (_, result) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::join!(
                    crate::client::tls_connect(ServiceInput::new(client_io), Some(data)),
                    server.serve(ServiceInput::new(server_io)),
                )
            })
            .await
            .expect("client-auth handshake timeout");
            assert_eq!(result.is_ok(), accepted, "server result: {result:?}");
            if let Ok(metadata) = result {
                assert_eq!(
                    metadata.server_name,
                    Some(rama_net::address::Domain::from_static("localhost"))
                );
                assert_eq!(metadata.resumed, Some(false));
                let algorithms = metadata.algorithms;
                assert!(algorithms.cipher_suite.is_some(), "{algorithms:?}");
                assert!(algorithms.key_exchange_group.is_some(), "{algorithms:?}");
                // An authenticated client signs its CertificateVerify.
                assert!(algorithms.peer_signature_scheme.is_some(), "{algorithms:?}");
            }
        }
    }

    struct StaplingIssuer(ServerAuthData);

    impl DynamicCertIssuer for StaplingIssuer {
        async fn issue_cert(
            &self,
            _: CertificateIssuanceContext,
        ) -> Result<ServerAuthData, BoxError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn server_auth_ocsp_response_is_stapled_for_every_identity_source() {
        const OCSP: &[u8] = b"opaque ocsp response";
        let mut server_auth =
            ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        server_auth.ocsp = Some(OCSP.to_vec());
        let configs = [
            TlsServerConfig::new().with_server_auth(server_auth.clone()),
            TlsServerConfig::new()
                .with_cert_issuer(ServerCertIssuerData::new(StaplingIssuer(server_auth))),
        ];
        for (index, config) in configs.into_iter().enumerate() {
            for request in [false, true] {
                let server = TlsAcceptorService::new(
                    config.clone(),
                    service_fn(
                        |_: TlsStream<ServiceInput<tokio::io::DuplexStream>>| async {
                            Ok::<_, BoxError>(())
                        },
                    ),
                    false,
                );
                let client = TlsClientConfig::new()
                    .with_server_name(rama_net::address::Host::from_static("localhost"))
                    .with_server_verify(ServerVerifyMode::Disable)
                    .with_ocsp_stapling(request);
                let data = crate::client::TlsConnectorData::try_from(&client).unwrap();
                let (client_io, server_io) = tokio::io::duplex(64 * 1024);
                let (client, server) = tokio::join!(
                    crate::client::tls_connect(ServiceInput::new(client_io), Some(data)),
                    server.serve(ServiceInput::new(server_io)),
                );
                server.unwrap();
                let stapled = client.unwrap().ssl_ref().ocsp_status().map(<[u8]>::to_vec);
                assert_eq!(
                    stapled.as_deref(),
                    request.then_some(OCSP),
                    "source #{index}, requested: {request}"
                );
            }
        }
    }
}
