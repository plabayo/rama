use super::utils;
use rama::{
    Layer,
    http::service::web::response::Json,
    http::{BodyExtractExt, Request, server::HttpServer},
    net::{address::ProxyAddress, client::ProxyRoute},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::KeyLogIntent,
    tls::rustls::server::TlsAcceptorLayer,
    tls::server::{GeneratedServerAuthConfig, TlsServerConfig},
};
use serde_json::{Value, json};

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_mitm_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63005",
                service_fn(async |req: Request| {
                    Ok(Json(json!({
                        "method": req.method().as_str(),
                        "path": req.uri().path_or_root(),
                    })))
                }),
            )
            .await
            .unwrap();
    });

    let data = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .expect("self-signed")
        .with_alpn_http_auto()
        .with_keylog(KeyLogIntent::Environment);

    let executor = Executor::default();

    let tcp_service = TlsAcceptorLayer::new(data).into_layer(HttpServer::auto(executor).service(
        service_fn(async |req: Request| {
            Ok(Json(json!({
                "method": req.method().as_str(),
                "path": req.uri().path_or_root(),
            })))
        }),
    ));

    tokio::spawn(async {
        TcpListener::bind_address("127.0.0.1:63006", Executor::default())
            .await
            .unwrap_or_else(|e| panic!("bind TCP Listener: secure web service: {e}"))
            .serve(tcp_service)
            .await;
    });

    let mut runner = utils::ExampleRunner::interactive(utils::example!("http_mitm_proxy_rustls"));
    runner.wait_for_tcp(([127, 0, 0, 1], 62019)).await;

    // test http request proxy flow
    let result = runner
        .get("http://127.0.0.1:63005/foo/bar")
        .extension(ProxyRoute::Proxy(
            ProxyAddress::try_from("http://john:secret@127.0.0.1:62019").unwrap(),
        ))
        .send()
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);

    // test https request proxy flow
    let result = runner
        .get("https://127.0.0.1:63006/foo/bar")
        .extension(ProxyRoute::Proxy(
            ProxyAddress::try_from("http://john:secret@127.0.0.1:62019").unwrap(),
        ))
        .send()
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);
}
