use std::time::Duration;

use super::utils;

use rama::{
    Layer,
    extensions::ExtensionsRef,
    http::{
        BodyExtractExt, Request, header::USER_AGENT, server::HttpServer,
        service::web::response::Json,
    },
    net::{address::ProxyAddress, client::ProxyRoute},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::{
        boring::server::TlsAcceptorLayer,
        fingerprint::Ja4,
        server::{GeneratedServerAuthConfig, TlsServerConfig},
    },
};

use serde_json::{Value, json};

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_mitm_proxy_emulate() {
    utils::init_tracing();

    // The origin reports the identity the proxy presented to it.
    let tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .expect("self-signed")
        .with_alpn_http_auto();
    let origin = TlsAcceptorLayer::new(tls)
        .with_store_client_hello(true)
        .into_layer(HttpServer::auto(Executor::default()).service(service_fn(
            async |req: Request| {
                Ok(Json(json!({
                    "user_agent": req
                        .headers()
                        .get(USER_AGENT)
                        .and_then(|value| value.to_str().ok()),
                    "ja4": Ja4::compute(req.extensions())
                        .map(|ja4| ja4.to_string())
                        .ok(),
                })))
            },
        )));
    tokio::spawn(async {
        TcpListener::bind_address("127.0.0.1:63048", Executor::default())
            .await
            .unwrap_or_else(|e| panic!("bind TCP Listener: emulation origin: {e}"))
            .serve(origin)
            .await;
    });

    let mut runner =
        utils::ExampleRunner::interactive(utils::example!("http_mitm_proxy_emulate_boring"));
    // Loading the embedded profile database is CPU-heavy in unoptimized CI builds.
    runner
        .wait_for_tcp_within(([127, 0, 0, 1], 62066), Duration::from_mins(1))
        .await;

    let observe = async |username: &str| -> Value {
        let proxy =
            ProxyAddress::try_from(format!("http://{username}:secret@127.0.0.1:62066")).unwrap();
        runner
            .get("https://127.0.0.1:63048/")
            .header(USER_AGENT, "rama-example-test")
            .extension(ProxyRoute::Proxy(proxy))
            .send()
            .await
            .unwrap()
            .try_into_json::<Value>()
            .await
            .unwrap()
    };

    let firefox = observe("john-ua_firefox").await;
    let chrome = observe("john-ua_chrome-ua_macos").await;
    let any = observe("john").await;

    let user_agent = |observed: &Value| observed["user_agent"].as_str().unwrap().to_owned();
    assert!(user_agent(&firefox).contains("Firefox/"), "{firefox}");
    let chrome_agent = user_agent(&chrome);
    assert!(
        chrome_agent.contains("Chrome/") && chrome_agent.contains("Macintosh"),
        "{chrome}"
    );
    assert_ne!(user_agent(&any), "rama-example-test", "{any}");

    let ja4 = |observed: &Value| observed["ja4"].as_str().unwrap().to_owned();
    assert_ne!(ja4(&firefox), ja4(&chrome));
}
