//! The connector completes every handshake before requests, even when early requests are allowed.

use crate::client::{HttpClientService, HttpConnector, h3::Http3Connector};
use rama_core::{
    Service as _,
    extensions::ExtensionsRef as _,
    rt::{Executor, spawn},
};
use rama_http_core::h3::{connection::Config, server as h3_server};
use rama_http_types::{Body, Request, Response, Version, body::util::BodyExt as _};
use rama_net::{
    Protocol,
    address::{HostWithPort, SocketAddress},
    client::{ConnectRequest, ConnectorTarget},
    tls::ApplicationProtocol,
};
use rama_quic::{
    Endpoint, ServerConfig,
    tls::{QuicClientConfigProvider, TlsOptions, default_tls_provider},
};
use rama_tls::{
    client::{NegotiatedTlsParameters, TlsClientConfig},
    server::{LeafCertRequest, ServerAuthData, TlsServerConfig},
};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;

#[cfg(feature = "boring")]
use rama_quic::tls::BoringTlsProvider;

fn providers() -> Vec<Arc<dyn QuicClientConfigProvider>> {
    vec![
        default_tls_provider().unwrap(),
        #[cfg(feature = "boring")]
        Arc::new(BoringTlsProvider),
    ]
}

#[tokio::test]
async fn resumed_connections_complete_their_handshake_before_requests() {
    for provider in providers() {
        timeout(Duration::from_secs(15), resumed_round_trips(provider))
            .await
            .unwrap();
    }
}

async fn resumed_round_trips(provider: Arc<dyn QuicClientConfigProvider>) {
    let identity = ServerAuthData::new_self_signed_leaf(LeafCertRequest::default()).unwrap();
    let server_tls = TlsServerConfig::new()
        .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect())
        .with_server_auth(identity.clone());
    // The server would accept early data; the connector must still never send any.
    let server = Endpoint::bind_server(
        Executor::new(),
        ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default().with_early_data(true))
            .unwrap(),
        SocketAddress::local_ipv4(0),
    )
    .await
    .unwrap();
    let port = server.local_addr().unwrap().port();
    let serving = spawn(serve(server.clone()));

    let tls = TlsClientConfig::new()
        .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
        .unwrap();
    let quic = Http3Connector::builder(Executor::new())
        .with_tls_provider(provider)
        .with_tls_config(tls)
        .with_config(Config {
            early_requests: true,
            ..Config::default()
        })
        .build_lazy()
        .unwrap();
    let connector = HttpConnector::<_, Body>::new(quic, Executor::new());

    for resumed in [false, true] {
        let service = connect(&connector, port).await;
        let connection = service.quic_connection().unwrap();
        assert!(!connection.early_data_keys_enabled());
        let parameters = connection
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .cloned()
            .expect("handshake facts published before requests");
        assert_eq!(parameters.resumed, Some(resumed));
        let request = Request::builder()
            .uri(format!("https://localhost:{port}/"))
            .version(Version::HTTP_3)
            .body(Body::empty())
            .unwrap();
        let response = service.serve(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "served");
    }

    serving.abort();
    server.close(0u32, b"fixture complete");
}

async fn connect(
    connector: &HttpConnector<Http3Connector, Body>,
    port: u16,
) -> HttpClientService<Body> {
    let input = ConnectRequest::new(HostWithPort::localhost_domain_with_port(port))
        .with_application_protocol(Protocol::HTTPS);
    input
        .extensions()
        .insert(ConnectorTarget(HostWithPort::local_ipv4(port)));
    connector.serve(input).await.unwrap().conn
}

async fn serve(server: Endpoint) {
    while let Some(incoming) = server.accept().await {
        let Ok(connecting) = incoming.accept() else {
            continue;
        };
        spawn(async move {
            let Ok(connection) = connecting.await else {
                return;
            };
            let Ok((mut h3, driver)) = h3_server::handshake(connection, Config::default()) else {
                return;
            };
            spawn(driver.run());
            while let Ok(stream) = h3.accept().await {
                if let Ok((_, response)) = stream.resolve().await {
                    _ = response
                        .send_response(Response::new(Body::from("served")))
                        .await;
                }
            }
        });
    }
}
