use super::utils;
use rama::{
    http::{response::Json, server::HttpServer, BodyExtractExt, Request},
    net::address::ProxyAddress,
    net::tls::{
        server::{SelfSignedData, ServerAuth, ServerConfig},
        ApplicationProtocol,
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::rustls::server::TlsAcceptorLayer,
    Context, Layer,
};
use serde_json::{json, Value};

#[tokio::test]
#[ignore]
async fn test_http_mitm_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63003",
                service_fn(|req: Request| async move {
                    Ok(Json(json!({
                        "method": req.method().as_str(),
                        "path": req.uri().path(),
                    })))
                }),
            )
            .await
            .unwrap();
    });

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
    let tls_service_data = tls_server_config
        .try_into()
        .expect("create tls server config");

    let executor = Executor::default();

    // TODO: rethink stateTransformer... it is putting silly bounds...
    // why did we introduce this in first place... Do we really need it?
    let tcp_service = TlsAcceptorLayer::new(tls_service_data).layer(
        HttpServer::auto(executor).service(service_fn(|req: Request| async move {
            Ok(Json(json!({
                "method": req.method().as_str(),
                "path": req.uri().path(),
            })))
        })),
    );

    tokio::spawn(async {
        TcpListener::bind("127.0.0.1:63004")
            .await
            .unwrap_or_else(|e| panic!("bind TCP Listener: secure web service: {e}"))
            .serve(tcp_service)
            .await;
    });

    let runner = utils::ExampleRunner::interactive("http_mitm_proxy", Some("rustls"));

    let mut ctx = Context::default();
    ctx.insert(ProxyAddress::try_from("http://john:secret@127.0.0.1:62017").unwrap());

    // test http request proxy flow
    let result = runner
        .get("http://127.0.0.1:63003/foo/bar")
        .send(ctx.clone())
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);

    // test https request proxy flow
    let result = runner
        .get("https://127.0.0.1:63004/foo/bar")
        .send(ctx.clone())
        .await
        .unwrap()
        .try_into_json::<Value>()
        .await
        .unwrap();
    let expected_value = json!({"method":"GET","path":"/foo/bar"});
    assert_eq!(expected_value, result);
}
