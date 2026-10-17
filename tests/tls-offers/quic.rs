//! The H3 connector preserves the offer seen by a real loopback QUIC peer.

use std::{sync::Arc, time::Duration};

use rama::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef as _,
    http::client::Http3Connector,
    net::{
        Protocol,
        address::{HostWithPort, SocketAddress},
        client::{ConnectRequest, ConnectorTarget},
        tls::{ApplicationProtocol, TlsAlpn},
    },
    quic::{
        Endpoint, ServerConfig,
        proto::capture::CaptureLimits,
        tls::{QuicClientConfigProvider, TlsOptions},
    },
    rt::Executor,
    tls::{
        SecureTransport,
        client::TlsClientConfig,
        server::{LeafCertRequest, ServerAuthData, TlsServerConfig},
    },
};

#[cfg(feature = "boring")]
use rama::quic::tls::BoringTlsProvider;
#[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
use rama::quic::tls::default_tls_provider;

async fn peer_offers() -> Result<(), BoxError> {
    let providers: Vec<Arc<dyn QuicClientConfigProvider>> = vec![
        #[cfg(feature = "boring")]
        Arc::new(BoringTlsProvider),
        #[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
        default_tls_provider()?,
    ];

    let identity = ServerAuthData::new_self_signed_leaf(LeafCertRequest::default())?;
    let trust = identity.cert_chain.last().cloned().into_iter();
    let client_settings = TlsClientConfig::new()
        .try_with_server_trust_anchors(trust)?
        .with_alpn_http_auto();
    let server_settings = TlsServerConfig::new()
        .with_server_auth(identity)
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
    let mut config = ServerConfig::try_from_rama_tls(&server_settings, TlsOptions::default())?;
    config.set_capture(CaptureLimits::default());
    let server =
        Endpoint::bind_server(Executor::new(), config, SocketAddress::local_ipv4(0)).await?;
    let address = server.local_addr()?;
    let accepted = server.clone();
    let count = 2 * providers.len();
    let peer = tokio::spawn(async move {
        let mut observations = Vec::new();
        for _ in 0..count {
            let connection = accepted.accept().await?.accept().ok()?.await.ok()?;
            let offer = connection
                .extensions()
                .get_ref::<SecureTransport>()?
                .client_hello()?
                .ext_alpn()?
                .to_vec();
            // Hold each connection until every client has completed its handshake.
            observations.push((offer, connection));
        }
        Some(observations)
    });

    let explicit = TlsAlpn(
        [
            ApplicationProtocol::from(b"rama-h3-first"),
            ApplicationProtocol::HTTP_3,
            ApplicationProtocol::from(b"rama-h3-last"),
        ]
        .into_iter()
        .collect(),
    );
    let mut expected = Vec::new();
    let mut transports = Vec::new();
    for provider in providers {
        let connector = Http3Connector::builder(Executor::new())
            .with_tls_provider(provider)
            .with_tls_config(client_settings.clone())
            .build_lazy()?;
        for offer in [Some(explicit.clone()), None] {
            let input =
                ConnectRequest::new(HostWithPort::localhost_domain_with_port(address.port()))
                    .with_application_protocol(Protocol::HTTPS);
            input
                .extensions()
                .insert(ConnectorTarget(HostWithPort::local_ipv4(address.port())));
            expected.push(match offer {
                Some(offer) => {
                    let protocols = offer.0.clone().into_vec();
                    input.extensions().insert(offer);
                    protocols
                }
                None => vec![ApplicationProtocol::HTTP_3],
            });
            transports.push(connector.serve(input).await?);
        }
    }
    let observations = peer.await?;
    match observations {
        Some(observations) => {
            let actual: Vec<_> = observations
                .iter()
                .map(|(offer, _)| offer.clone())
                .collect();
            if actual != expected {
                return Err(BoxError::from_static_str(
                    "H3 connector rewrote the native ALPN offer",
                ));
            }
            for (_, connection) in observations {
                connection.close(0u32, b"test complete");
            }
        }
        None => {
            return Err(BoxError::from_static_str(
                "QUIC peer could not capture ClientHello",
            ));
        }
    }
    drop(transports);
    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn h3_request_alpn_reaches_the_peer_unchanged() {
    tokio::time::timeout(Duration::from_secs(10), peer_offers())
        .await
        .unwrap()
        .unwrap();
}
