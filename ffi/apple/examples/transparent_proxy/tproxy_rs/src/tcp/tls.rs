use std::{sync::Arc, time::Duration};

use rama::{
    Layer, Service,
    combinators::Either,
    error::{BoxError, ErrorContext as _},
    extensions::{ExtensionsMut, ExtensionsRef},
    net::{
        address::Domain,
        apple::networkextension::TcpFlow,
        client::{ConnectorService, EstablishedClientConnection},
        proxy::{ProxyTarget, StreamBridge, StreamForwardService},
        tls::{
            client::ServerVerifyMode,
            server::{
                ClientHelloRequest, PeekTlsClientHelloService, PeekTlsClientHelloStream,
                peek_client_hello_from_stream,
            },
        },
    },
    proxy::socks5::server::Socks5PeekStream,
    rt::Executor,
    stream::Stream,
    tcp::{
        TcpStream,
        client::{
            Request as TcpRequest, default_tcp_connect,
            service::{DefaultForwarder, TcpConnector},
        },
    },
    telemetry::tracing,
    tls::boring::{
        TlsStream,
        client::{TlsConnectorDataBuilder, TlsConnectorLayer},
        proxy::{
            TlsMitmRelay,
            cert_issuer::{CachedBoringMitmCertIssuer, InMemoryBoringMitmCertIssuer},
        },
        server::{TlsAcceptorData, TlsAcceptorLayer},
    },
};

use crate::{tls::certs::load_or_create_mitm_ca_crt_key_pair, utils::executor_from_input};

#[derive(Debug, Clone)]
/// SNI found by optional Tls service for tls traffic, if one was found at all,
/// in which case it will be injected in the extensions of the input.
pub struct TargetSni(pub Domain);

#[derive(Debug, Clone)]
pub struct OptionalTlsMitmService<S> {
    inner: S,
    relay: TlsMitmRelay<CachedBoringMitmCertIssuer<InMemoryBoringMitmCertIssuer>>,
}

impl<S> OptionalTlsMitmService<S> {
    #[inline(always)]
    pub fn try_new(inner: S) -> Result<Self, BoxError> {
        let (ca_crt, ca_key) =
            load_or_create_mitm_ca_crt_key_pair().context("load or create MITM tls CA crt/key")?;
        let relay =
            TlsMitmRelay::new_with_cached_issuer(InMemoryBoringMitmCertIssuer::new(ca_crt, ca_key));
        Ok(Self { inner, relay })
    }
}

impl<S> Service<Socks5PeekStream<TcpFlow>> for OptionalTlsMitmService<S>
where
    S: Service<MaybeTlsStreamBridge<Socks5PeekStream<TcpFlow>, TcpStream>, Error: Into<BoxError>>,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        ingress_stream: Socks5PeekStream<TcpFlow>,
    ) -> Result<Self::Output, Self::Error> {
        let Some(ProxyTarget(egress_socket_address)) = ingress_stream.extensions().get().cloned()
        else {
            tracing::warn!(
                "failed to find egress socket address in input... this is unexpected (rama NE bridge bug!?)"
            );
            return Err(BoxError::from(
                "missing egress socket address (ProxyTarget ext)",
            ));
        };

        let exec = executor_from_input(&ingress_stream);
        let (mut egress_stream, _) = tokio::time::timeout(
            Duration::from_mins(2),
            default_tcp_connect(ingress_stream.extensions(), egress_socket_address, exec),
        )
        .await
        .context("tcp connection to egress (maybe tls) server timed out")?
        .context("tcp connection to egress (maybe tls) server failed")?;

        // TODO: fix this

        self.serve(StreamBridge {
            left: ingress_stream,
            right: egress_stream,
        })
        .await
    }
}

type MaybeTlsStreamBridge<Ingress, Egress> = StreamBridge<
    Either<TlsStream<PeekTlsClientHelloStream<Ingress>>, PeekTlsClientHelloStream<Ingress>>,
    Either<TlsStream<Egress>, Egress>,
>;

impl<S, Ingress, Egress> Service<StreamBridge<Ingress, Egress>> for OptionalTlsMitmService<S>
where
    S: Service<MaybeTlsStreamBridge<Ingress, Egress>, Error: Into<BoxError>>,
    Ingress: Stream + Unpin + ExtensionsMut,
    Egress: Stream + Unpin + ExtensionsMut,
{
    type Output = ();
    type Error = BoxError;

    async fn serve(
        &self,
        StreamBridge {
            left: ingress_stream,
            right: egress_stream,
        }: StreamBridge<Ingress, Egress>,
    ) -> Result<Self::Output, Self::Error> {
        let (peeked_ingress_stream, maybe_client_hello) =
            peek_client_hello_from_stream(ingress_stream)
                .await
                .context("I/O error while peeking TLS:CH from existing input stream")?;

        if let Some(client_hello) = maybe_client_hello {
            let tls_data_builder =
            TlsConnectorDataBuilder::try_from(client_hello)
                .inspect_err(|err| {
                    tracing::debug!("build boring tls connector data builder from CH (try anyway with a default one...): {err}");
                }).unwrap_or_default()
                .with_store_server_certificate_chain(true)
                .with_server_verify_mode(ServerVerifyMode::Disable);

            let tls_data = match tls_data_builder.build() {
                Ok(tls_data) => tls_data,
                Err(err) => {
                    tracing::debug!(
                        "failed to build tls (connector) data from builder: {err} ; abort TLS intercept to be safe...; revert to L4-forwarding..."
                    );
                    if let Err(err) = StreamForwardService::default()
                        .serve(StreamBridge {
                            left: peeked_ingress_stream,
                            right: egress_stream,
                        })
                        .await
                    {
                        tracing::debug!(
                            "failed to L4-relay TCP Non-TLS traffic (failed to build tls connector data): {err}"
                        );
                    }
                    return Ok(());
                }
            };

            let StreamBridge {
                left: tls_ingress_stream,
                right: tls_egress_stream,
            } = self
                .relay
                .handshake(
                    StreamBridge {
                        left: peeked_ingress_stream,
                        right: egress_stream,
                    },
                    Some(tls_data),
                )
                .await
                .context("failed to MITM handshake... connection is now unstable")?;

            if let Err(err) = self
                .inner
                .serve(StreamBridge {
                    left: Either::A(tls_ingress_stream),
                    right: Either::A(tls_egress_stream),
                })
                .await
            {
                tracing::debug!("failed to L7 App (over TLS) MITM traffic: {}", err.into());
            }
        } else if let Err(err) = self
            .inner
            .serve(StreamBridge {
                left: Either::B(peeked_ingress_stream),
                right: Either::B(egress_stream),
            })
            .await
        {
            tracing::debug!(
                "failed to L7 App (not over TLS) MITM traffic: {}",
                err.into()
            );
        }

        Ok(())
    }
}
