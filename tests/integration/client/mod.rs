use rama::{
    Layer, Service,
    http::{Body, Request, Response, client::EasyHttpWebClient, header::HOST, server::HttpServer},
    net::{
        test_utils::client::MockConnectorService,
        tls::{
            ApplicationProtocol,
            server::SelfSignedData,
            server::{ServerAuth, ServerConfig},
        },
    },
    rt::Executor,
    service::service_fn,
    tls::boring::{client::TlsConnectorDataBuilder, server::TlsAcceptorLayer},
};

use std::convert::Infallible;

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
            application_layer_protocol_negotiation: Some(vec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11,
            ]),
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
        .with_default_http_connector()
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
