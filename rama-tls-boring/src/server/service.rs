use super::TlsAcceptorData;
use super::acceptor_data::prepare_server_cert_issuer;
use super::config::{BoringTlsAcceptorConfig, BoringTlsAuth};
use crate::{TlsStream, types::SecureTransport};
use parking_lot::Mutex;
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Service,
    conversion::RamaTryInto,
    error::{BoxError, ErrorContext, ErrorExt},
    extensions::ExtensionsRef,
    io::Io,
};
use rama_net::{client::ConnectorTarget, extensions::StreamTransformed, tls::ApplicationProtocol};
use rama_tls::{
    client::NegotiatedTlsParameters,
    server::{CertificateIdentity, TlsServerConfig},
};
use rama_utils::macros::define_inner_service_accessors;
use std::sync::Arc;

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
#[derive(Debug, Clone)]
pub struct TlsAcceptorService<S> {
    config: TlsServerConfig,
    store_client_hello: bool,
    inner: S,
}

impl<S> TlsAcceptorService<S> {
    /// Creates a new [`TlsAcceptorService`].
    pub const fn new(config: TlsServerConfig, inner: S, store_client_hello: bool) -> Self {
        Self {
            config,
            store_client_hello,
            inner,
        }
    }

    define_inner_service_accessors!();
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

        let tls_config =
            TlsAcceptorData::try_from(BoringTlsAcceptorConfig::from_extensions(&merged))
                .context("boring acceptor: build acceptor data from config")?
                .config;

        let acceptor_builder = tls_config.acceptor_builder()?;

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

        // We use arc mutex instead of oneshot channel since it is possible that certificate callbacks
        // are called multiples times (fn closures type). But in testing it seems fnOnce should also
        // work (at least for how we use it). When we integrate boringssl bindings we should reconsider
        // this and see if we can expose this in a better way.
        let mut maybe_client_hello = self
            .store_client_hello
            .then_some(Arc::new(Mutex::new(None)));

        let acceptor_builder = tls_config
            .cert_source
            .issue_certs(
                acceptor_builder,
                target_identity.clone(),
                maybe_client_hello.as_ref(),
            )
            .await?;

        let acceptor = acceptor_builder.build();

        let stream = rama_boring_tokio::accept(&acceptor, stream)
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

                let client_certificate_chain = if let Some(certificate) = tls_config
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
                }
            }
            None => {
                return Err(BoxError::from_static_str(
                    "boring ssl acceptor: failed to establish session",
                ));
            }
        };

        let secure_transport = maybe_client_hello
            .take()
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
    use crate::tests::client_identity;
    use rama_core::{ServiceInput, service::service_fn};
    use rama_tls::{
        client::{ClientAuth, TlsClientConfig},
        server::{ClientVerifyMode, GeneratedServerAuthConfig, ServerAuthData},
    };

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
            }
        }
    }
}
