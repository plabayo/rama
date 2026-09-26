use super::client_auth::{
    TlsMitmCertificateRequest, TlsMitmClientAuthInput, TlsMitmClientAuthPolicy,
    TlsMitmClientIdentity,
};
use super::{
    AcceptorKey, HandshakeRelayClassification, TlsMitmRelay, TlsMitmRelayError,
    TlsMitmRelayErrorDirection, TlsMitmRelayErrorKind, server_name_as_sni,
};
use crate::{TlsStream, client};
use rama_boring::{
    ssl::{
        AsyncSelectCertError, BoxCertificateFinish, CertificateSelection, NameType,
        SelectCertError, Ssl, SslAcceptor, SslCredential, SslRef, SslVersion,
    },
    x509::X509,
};
use rama_core::{
    Service,
    conversion::RamaTryInto as _,
    error::{ArcError, BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::{self, Extensions, ExtensionsRef as _},
    io::{BridgeIo, Io},
    telemetry::tracing,
};
use rama_crypto::pki_types::CertificateDer;
#[cfg(feature = "http")]
use rama_net::http::{TargetHttpVersion, Version};
use rama_net::{
    address::Domain, client::ConnectorTarget, extensions::StreamTransformed,
    tls::ApplicationProtocol,
};
use rama_tls::client::NegotiatedTlsParameters;
use std::sync::Arc;
use tokio::sync::oneshot;

struct Snapshot {
    cert: X509,
    version: Option<SslVersion>,
    params: Option<NegotiatedTlsParameters>,
    alpn: Option<ApplicationProtocol>,
}

impl Snapshot {
    fn new(ssl: &SslRef, store_chain: bool) -> Result<Self, TlsMitmRelayError> {
        let cert = ssl.peer_certificate().ok_or_else(|| {
            TlsMitmRelayError::config(BoxError::from_static_str(
                "tls mitm relay: upstream has no certificate",
            ))
        })?;
        let version = ssl.version();
        let alpn = ssl.selected_alpn_protocol().map(ApplicationProtocol::from);
        let params = version
            .map(|version| {
                Ok::<_, TlsMitmRelayError>(NegotiatedTlsParameters {
                    protocol_version: version.rama_try_into().map_err(|version| {
                        TlsMitmRelayError::config(
                            BoxError::from_static_str(
                                "tls mitm relay: invalid upstream TLS version",
                            )
                            .context_field("protocol_version", version),
                        )
                    })?,
                    application_layer_protocol: alpn.clone(),
                    peer_certificate_chain: if store_chain {
                        ssl.peer_cert_chain()
                            .map(|chain| chain.rama_try_into())
                            .transpose()
                            .map_err(TlsMitmRelayError::config)?
                    } else {
                        None
                    },
                    server_name: None,
                    resumed: Some(ssl.session_reused()),
                })
            })
            .transpose()?;
        Ok(Self {
            cert,
            version,
            params,
            alpn,
        })
    }
}

impl<Issuer> TlsMitmRelay<Issuer>
where
    Issuer: super::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
{
    /// Establish both TLS legs. Explicit connector data supplies upstream TLS
    /// settings, but the relay's client-auth policy remains authoritative.
    /// With no policy, upstream client-certificate requests are rejected.
    /// Configured server verification and pins are preserved.
    ///
    /// Ingress authentication disables ingress resumption. Preselected egress
    /// sessions are rejected, so authentication cannot be skipped or shared across flows.
    /// TLS 1.3 completion does not establish upstream acceptance of our certificate;
    /// later TLS alerts still propagate through the returned stream.
    /// Dropping this future drops in-flight policy futures and the supplied I/O.
    /// Callers retain ownership when supplying borrowed I/O. Detached work spawned
    /// by a policy remains that policy's responsibility.
    pub async fn handshake<Ingress, Egress>(
        &self,
        input: BridgeIo<Ingress, Egress>,
        connector_data: Option<client::TlsConnectorData>,
    ) -> Result<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, TlsMitmRelayError>
    where
        Ingress: Io + Unpin + extensions::ExtensionsRef,
        Egress: Io + Unpin + extensions::ExtensionsRef,
    {
        let handshake = self.handshake_inner(input, connector_data);
        match self.handshake_timeout {
            Some(deadline) => tokio::time::timeout(deadline, handshake)
                .await
                .map_err(|error| TlsMitmRelayError {
                    kind: TlsMitmRelayErrorKind::Timeout,
                    connector_target: None,
                    sni: None,
                    inner: error.into(),
                })?,
            None => handshake.await,
        }
    }

    async fn acceptor_for(
        &self,
        snapshot: &Snapshot,
        ingress_auth: bool,
    ) -> Result<SslAcceptor, TlsMitmRelayError> {
        let mint = self.mint_acceptor(
            snapshot.cert.clone(),
            snapshot.version,
            snapshot.alpn.clone(),
            ingress_auth,
        );
        match &self.acceptors {
            Some(cache) => {
                let key = AcceptorKey {
                    upstream_signature: Arc::from(snapshot.cert.signature().as_slice()),
                    protocol_version: snapshot.params.as_ref().map(|p| p.protocol_version),
                    alpn: snapshot.alpn.clone(),
                    ingress_auth,
                };
                cache
                    .try_get_with(key, async {
                        mint.await
                            .map_err(|err| ArcError::from_box_error(err.into()))
                    })
                    .await
                    .map_err(|err: Arc<ArcError>| TlsMitmRelayError::config(ArcError::clone(&err)))
            }
            None => mint.await,
        }
    }

    async fn handshake_inner<Ingress, Egress>(
        &self,
        input: BridgeIo<Ingress, Egress>,
        connector_data: Option<client::TlsConnectorData>,
    ) -> Result<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, TlsMitmRelayError>
    where
        Ingress: Io + Unpin + extensions::ExtensionsRef,
        Egress: Io + Unpin + extensions::ExtensionsRef,
    {
        let extensions: Extensions = input.extensions().clone();
        let policy = extensions
            .get_ref::<TlsMitmClientAuthPolicy>()
            .cloned()
            .or_else(|| self.client_auth.clone());
        let mut data = if let Some(data) = connector_data {
            data
        } else {
            let target = extensions
                .get_ref::<ConnectorTarget>()
                .map(|target| &target.0);
            let auth = self.egress_server_auth_ref();
            let config = super::egress::tls_client_config(
                None,
                super::egress::server_name(None, target, auth),
                self.keylog_intent.clone(),
                auth,
            );
            client::TlsConnectorData::try_from(&config)
                .context("tls mitm relay: build direct egress connector data")
                .map_err(TlsMitmRelayError::config)?
        };
        if data.config.session().is_some() {
            return Err(TlsMitmRelayError::config(BoxError::from_static_str(
                "tls mitm client auth: preselected egress sessions can bypass authentication",
            )));
        }
        let server_name = data.server_name.clone();
        let store_chain = data.store_server_certificate_chain;
        let request_rx = if policy.is_some() {
            let (request_tx, request_rx) = oneshot::channel();
            let exchange = parking_lot::Mutex::new(Some(request_tx));
            data.config
                .set_async_certificate_callback(move |selection| {
                    let request = exchange.lock().take().ok_or(AsyncSelectCertError)?;
                    let (reply, credential) =
                        oneshot::channel::<Option<SslCredential>>();
                    let snapshot = Snapshot::new(selection.ssl(), store_chain).map_err(|error| {
                        tracing::debug!(%error, "cannot snapshot upstream certificate request");
                        AsyncSelectCertError
                    })?;
                    let hints = TlsMitmCertificateRequest::from_selection(selection);
                    request
                        .send((snapshot, hints, reply))
                        .map_err(|_error| AsyncSelectCertError)?;
                    Ok(Box::pin(async move {
                        let credential = credential.await.map_err(|_error| AsyncSelectCertError)?;
                        Ok(Box::new(
                            move |mut selection: CertificateSelection<'_>| {
                                let ssl = selection.ssl_mut();
                                ssl.clear_certificates();
                                if let Some(credential) = credential {
                                    ssl.add_credential(&credential)
                                        .map_err(|error| {
                                            tracing::debug!(%error, "cannot install relay client credential");
                                            AsyncSelectCertError
                                        })?;
                                }
                                Ok(())
                            },
                        ) as BoxCertificateFinish)
                    }))
                });
            Some(request_rx)
        } else {
            data.config
                .set_certificate_callback(|_| Err(SelectCertError::ERROR));
            None
        };
        let BridgeIo(ingress, egress) = input;
        let connect = async {
            client::tls_connect(egress, Some(data))
                .await
                .map_err(egress_error)
        };
        tokio::pin!(connect);
        let (snapshot, request, completed_egress) = if let Some(request_rx) = request_rx {
            tokio::select! {
                biased;
                // The callback can report a request and fail in the same poll.
                result = &mut connect => {
                    let stream = result?;
                    (Snapshot::new(stream.ssl_ref(), store_chain)?, None, Some(stream))
                }
                request = request_rx => {
                    let (snapshot, request, reply) = request.map_err(|_error| TlsMitmRelayError::config(
                        BoxError::from_static_str("tls mitm client auth: request channel closed"),
                    ))?;
                    (snapshot, Some((request, reply)), None)
                }
            }
        } else {
            let stream = (&mut connect).await?;
            (
                Snapshot::new(stream.ssl_ref(), store_chain)?,
                None,
                Some(stream),
            )
        };
        let (request, reply) = match request {
            Some((request, reply)) => (Some(request), Some(reply)),
            None => (None, None),
        };
        let plan = if let Some(policy) = &policy {
            Some(
                policy
                    .0
                    .serve(TlsMitmClientAuthInput {
                        request,
                        extensions,
                        server_name,
                        server_certificate: snapshot.cert.clone(),
                    })
                    .await
                    .map_err(TlsMitmRelayError::client_auth)?,
            )
        } else {
            None
        };
        let authenticates_ingress = plan.as_ref().is_some_and(|plan| plan.configure.is_some());
        let acceptor = self.acceptor_for(&snapshot, authenticates_ingress).await?;
        let mut ssl = Ssl::new(acceptor.context()).map_err(TlsMitmRelayError::config)?;
        let ingress_handshake = async move {
            let mut plan = plan;
            if let Some(configure) = plan.as_mut().and_then(|plan| plan.configure.take()) {
                configure(&mut ssl).map_err(TlsMitmRelayError::client_auth)?;
            }
            let stream = rama_boring_tokio::SslStreamBuilder::new(ssl, ingress)
                .accept()
                .await
                .map_err(|error| {
                    let error = ingress_error(&error);
                    // A trust failure under client-auth policy must not teach
                    // transparent-proxy callers to bypass that policy.
                    if plan.is_some()
                        && matches!(
                            error.kind(),
                            TlsMitmRelayErrorKind::Handshake {
                                classification: HandshakeRelayClassification::CertTrust,
                                ..
                            }
                        )
                    {
                        TlsMitmRelayError::client_auth(error)
                    } else {
                        error
                    }
                })?;
            if let Some(plan) = plan {
                if authenticates_ingress && stream.ssl().session_reused() {
                    return Err(TlsMitmRelayError::config(BoxError::from_static_str(
                        "tls mitm client auth: resumed ingress session",
                    )));
                }
                let identity = TlsMitmClientIdentity::from_completed_handshake(stream.ssl());
                let credential = plan
                    .resolve
                    .serve(identity)
                    .await
                    .map_err(TlsMitmRelayError::client_auth)?;
                if let Some(reply) = reply {
                    reply.send(credential).map_err(|_error| {
                        TlsMitmRelayError::config(BoxError::from_static_str(
                            "tls mitm client auth: upstream handshake closed",
                        ))
                    })?;
                } else if credential.is_some() {
                    return Err(TlsMitmRelayError::client_auth(BoxError::from_static_str(
                        "tls mitm client auth: credential supplied without an upstream request",
                    )));
                }
            }
            Ok(stream)
        };
        let (ingress, egress) = if let Some(egress) = completed_egress {
            (ingress_handshake.await?, egress)
        } else {
            tokio::try_join!(ingress_handshake, &mut connect)?
        };
        let identity = TlsMitmClientIdentity::from_completed_handshake(ingress.ssl());
        let ssl = ingress.ssl();
        let ingress_params = NegotiatedTlsParameters {
            protocol_version: ssl
                .version()
                .ok_or_else(|| {
                    TlsMitmRelayError::config(BoxError::from_static_str(
                        "tls mitm relay: ingress has no TLS version",
                    ))
                })?
                .rama_try_into()
                .map_err(|version| {
                    TlsMitmRelayError::config(
                        BoxError::from_static_str("tls mitm relay: invalid ingress TLS version")
                            .context_field("protocol_version", version),
                    )
                })?,
            application_layer_protocol: ssl.selected_alpn_protocol().map(ApplicationProtocol::from),
            peer_certificate_chain: if identity.leaf().is_some() {
                Some(
                    identity
                        .certificate_chain()
                        .iter()
                        .map(|cert| cert.to_der().map(CertificateDer::from))
                        .collect::<Result<_, _>>()
                        .map_err(TlsMitmRelayError::config)?,
                )
            } else {
                None
            },
            server_name: ssl
                .servername(NameType::HOST_NAME)
                .map(Domain::try_from)
                .transpose()
                .map_err(TlsMitmRelayError::config)?,
            resumed: Some(ssl.session_reused()),
        };
        if let Some(params) = snapshot.params {
            #[cfg(feature = "http")]
            if let Some(proto) = params.application_layer_protocol.as_ref()
                && let Ok(version) = Version::try_from(proto)
            {
                egress.extensions().insert(TargetHttpVersion(version));
            }
            egress.extensions().insert(params);
        }
        let ingress = TlsStream::new(ingress);
        ingress.extensions().insert(ingress_params);
        for extensions in [ingress.extensions(), egress.extensions()] {
            extensions.insert(StreamTransformed {
                by: "rama-tls-boring::TlsMitmRelay",
            });
        }
        Ok(BridgeIo(ingress, egress))
    }
}

fn ingress_error<T>(error: &rama_boring_tokio::HandshakeError<T>) -> TlsMitmRelayError {
    let code = error.code();
    if let Some(io) = error.as_io_error() {
        TlsMitmRelayError::handshake_io(
            TlsMitmRelayErrorDirection::Ingress,
            BoxError::from_static_str("tls mitm relay: ingress TLS I/O failed")
                .context_field("io_error", io.to_string())
                .context_debug_field("code", code),
        )
    } else if let Some(stack) = error.as_ssl_error_stack() {
        TlsMitmRelayError::handshake_ssl(TlsMitmRelayErrorDirection::Ingress, stack)
    } else {
        TlsMitmRelayError::handshake(
            TlsMitmRelayErrorDirection::Ingress,
            BoxError::from_static_str("tls mitm relay: ingress handshake failed")
                .context_debug_field("code", code),
            code,
        )
    }
}

fn egress_error<T>(error: client::TlsConnectError<T>) -> TlsMitmRelayError {
    match error {
        client::TlsConnectError::Builder(error) => TlsMitmRelayError::handshake(
            TlsMitmRelayErrorDirection::Egress,
            error.context("tls connect builder error"),
            None,
        ),
        client::TlsConnectError::Handshake { error, server_name } => {
            let code = error.code();
            let error = if let Some(io) = error.as_io_error() {
                TlsMitmRelayError::handshake_io(
                    TlsMitmRelayErrorDirection::Egress,
                    BoxError::from_static_str("tls mitm relay: egress TLS I/O failed")
                        .context_field("io_error", io.to_string())
                        .context_debug_field("code", code)
                        .context_debug_field("server_identity", server_name.clone()),
                )
            } else if let Some(stack) = error.as_ssl_error_stack() {
                TlsMitmRelayError::handshake_ssl(TlsMitmRelayErrorDirection::Egress, stack)
            } else {
                TlsMitmRelayError::handshake(
                    TlsMitmRelayErrorDirection::Egress,
                    BoxError::from_static_str("tls mitm relay: egress handshake failed")
                        .context_debug_field("code", code)
                        .context_debug_field("server_identity", server_name.clone()),
                    code,
                )
            };
            error.maybe_with_sni(server_name.as_ref().and_then(server_name_as_sni))
        }
    }
}
