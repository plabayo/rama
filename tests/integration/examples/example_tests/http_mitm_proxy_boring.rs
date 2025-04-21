use super::utils;
use rama::{
    Context, Layer,
    http::{BodyExtractExt, Request, response::Json, server::HttpServer},
    net::address::ProxyAddress,
    net::tls::server::SelfSignedData,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::rustls::server::{TlsAcceptorDataBuilder, TlsAcceptorLayer},
};
use serde_json::{Value, json};

#[tokio::test]
#[ignore]
async fn test_http_mitm_proxy() {
    utils::init_tracing();

    tokio::spawn(async {
        HttpServer::auto(Executor::default())
            .listen(
                "127.0.0.1:63003",
                service_fn(async |req: Request| {
                    Ok(Json(json!({
                        "method": req.method().as_str(),
                        "path": req.uri().path(),
                    })))
                }),
            )
            .await
            .unwrap();
    });

    let data = TlsAcceptorDataBuilder::new_self_signed(SelfSignedData {
        organisation_name: Some("Example Server Acceptor".to_owned()),
        ..Default::default()
    })
    .expect("self signed acceptor data")
    .with_alpn_protocols_http_auto()
    .with_env_key_logger()
    .expect("with env key logger")
    .build();

    let executor = Executor::default();

    let tcp_service = TlsAcceptorLayer::new(data).into_layer(HttpServer::auto(executor).service(
        service_fn(async |req: Request| {
            Ok(Json(json!({
                "method": req.method().as_str(),
                "path": req.uri().path(),
            })))
        }),
    ));

    tokio::spawn(async {
        TcpListener::bind("127.0.0.1:63004")
            .await
            .unwrap_or_else(|e| panic!("bind TCP Listener: secure web service: {e}"))
            .serve(tcp_service)
            .await;
    });

    let runner = utils::ExampleRunner::interactive("http_mitm_proxy_boring", Some("boring"));

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
