use rama::{
    Layer, Service,
    graceful::Shutdown,
    http::{
        Body, HeaderValue, Request, Response, Version, client::EasyHttpWebClient, header,
        header::HOST, server::HttpServer,
    },
    layer::AddInputExtensionLayer,
    net::{
        test_utils::client::MockConnectorService,
        tls::{
            ApplicationProtocol,
            server::{SelfSignedData, ServerAuth, ServerConfig},
        },
    },
    rt::Executor,
    service::service_fn,
    tls::boring::{client::TlsConnectorDataBuilder, server::TlsAcceptorLayer},
};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use std::{convert::Infallible, time::Duration};

#[tokio::test]
async fn h2_with_connection_pooling() {
    let http_server =
        HttpServer::h2(Executor::default()).service(service_fn(async |req: Request| {
            // We are actually quite forgiving when we receive a http1 request instead of H2,
            // if we see a Host header here it means we received http1, something we don't expect.
            assert_eq!(req.headers().get(HOST), None);
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));

    let tls_service_data = {
        let tls_server_config = ServerConfig {
            application_layer_protocol_negotiation: Some(vec![ApplicationProtocol::HTTP_2]),
            ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
                organisation_name: Some("Example Server Acceptor".to_owned()),
                ..Default::default()
            }))
        };
        tls_server_config
            .try_into()
            .expect("create tls server config")
    };
    let server = TlsAcceptorLayer::new(tls_service_data).into_layer(http_server);
    let direct_connection = MockConnectorService::new(move || server.clone());

    let tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(rama_net::tls::client::ServerVerifyMode::Disable)
        .into_shared_builder();

    let client = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(direct_connection)
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config))
        .with_default_http_connector(Executor::default())
        .try_with_default_connection_pool()
        .unwrap()
        .build_client();

    let create_req = || {
        Request::builder()
            .uri("https://localhost/test")
            .body(Body::empty())
            .unwrap()
    };

    let _resp = client.serve(create_req()).await.unwrap();
    let _resp = client.serve(create_req()).await.unwrap();
}

#[tokio::test]
async fn h1_with_connection_pooling_detects_closed_connections() {
    let http_server =
        HttpServer::http1(Executor::default()).service(service_fn(async |_req: Request| {
            let mut resp = Response::new(Body::empty());
            resp.headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("close"));
            Ok::<_, Infallible>(resp)
        }));

    let tls_service_data = {
        let tls_server_config = ServerConfig {
            application_layer_protocol_negotiation: Some(vec![ApplicationProtocol::HTTP_11]),
            ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
                organisation_name: Some("Example Server Acceptor".to_owned()),
                ..Default::default()
            }))
        };
        tls_server_config
            .try_into()
            .expect("create tls server config")
    };
    let server = TlsAcceptorLayer::new(tls_service_data).into_layer(http_server);
    let direct_connection = MockConnectorService::new(move || server.clone());

    let tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(rama_net::tls::client::ServerVerifyMode::Disable)
        .into_shared_builder();

    let client = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(direct_connection)
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config))
        .with_default_http_connector(Executor::default())
        .try_with_default_connection_pool()
        .unwrap()
        .build_client();

    let create_req = || {
        Request::builder()
            .uri("https://localhost/test")
            .body(Body::empty())
            .unwrap()
    };

    let _resp = client.serve(create_req()).await.unwrap();
    let _resp = client.serve(create_req()).await.unwrap();
}

async fn connection_pooling_detects_closed_connections(version: Version, delay: Option<Duration>) {
    let direct_connection = MockConnectorService::new(move || {
        let token = CancellationToken::new();
        let shutdown = Shutdown::new(token.clone().cancelled_owned());

        let executor = Executor::graceful(shutdown.guard());
        let http_server =
            HttpServer::auto(executor.clone()).service(service_fn(move |_req: Request| {
                // Trigger graceful shutdown after single response
                let token = token.clone();
                tokio::spawn(async move {
                    if let Some(delay) = delay {
                        sleep(delay).await;
                    }
                    token.cancel();
                });

                async move {
                    let resp = Response::new(Body::empty());
                    Ok::<_, Infallible>(resp)
                }
            }));

        let tls_service_data = {
            let tls_server_config = ServerConfig {
                application_layer_protocol_negotiation: Some(match version {
                    Version::HTTP_11 => vec![ApplicationProtocol::HTTP_11],
                    Version::HTTP_2 => vec![ApplicationProtocol::HTTP_2],
                    _ => panic!("not supported by this test"),
                }),
                ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
                    organisation_name: Some("Example Server Acceptor".to_owned()),
                    ..Default::default()
                }))
            };
            tls_server_config
                .try_into()
                .expect("create tls server config")
        };

        (
            AddInputExtensionLayer::new(executor),
            TlsAcceptorLayer::new(tls_service_data),
        )
            .into_layer(http_server)
    });

    let tls_config = TlsConnectorDataBuilder::new_http_auto()
        .with_server_verify_mode(rama_net::tls::client::ServerVerifyMode::Disable)
        .into_shared_builder();

    let client = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(direct_connection)
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(Some(tls_config))
        .with_default_http_connector(Executor::default())
        .try_with_default_connection_pool()
        .unwrap()
        .build_client();

    let create_req = || {
        Request::builder()
            .uri("https://localhost/test")
            .body(Body::empty())
            .unwrap()
    };

    let _resp = client.serve(create_req()).await.unwrap();

    // Make sure we are slower then breaking the connection and give internal state machine some
    // time to handle this.
    sleep(Duration::from_millis(100)).await;
    if let Some(delay) = delay {
        sleep(delay).await;
    }

    let _resp = client.serve(create_req()).await.unwrap();
}

#[tokio::test]
async fn h1_with_connection_pooling_detects_instant_close() {
    // Here we break the connection immediately which should get picked up before is is even
    // returned to the pool, or after it is returned. Either way the pool should filter this connection.
    connection_pooling_detects_closed_connections(Version::HTTP_11, None).await;
}

#[tokio::test]
async fn h1_with_connection_pooling_detects_late_close() {
    // Here we break the connection after some time. By now the connection is definitely in the pool
    // again. But our logic should also pick this up and filter this connection
    connection_pooling_detects_closed_connections(
        Version::HTTP_11,
        Some(Duration::from_millis(50)),
    )
    .await;
}

#[tokio::test]
async fn h2_with_connection_pooling_detects_instant_goaway() {
    // Here we break the connection immediately which should get picked up before is is even
    // returned to the pool, or after it is returned. Either way the pool should filter this connection.
    connection_pooling_detects_closed_connections(Version::HTTP_2, None).await;
}

#[tokio::test]
async fn h2_with_connection_pooling_detects_late_goaway() {
    // Here we break the connection after some time. By now the connection is definitely in the pool
    // again. But our logic should also pick this up and filter this connection
    connection_pooling_detects_closed_connections(Version::HTTP_2, Some(Duration::from_millis(50)))
        .await;
}

// TODO more test for things like resets, hard crashes...
