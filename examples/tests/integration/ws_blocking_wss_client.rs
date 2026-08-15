use super::utils;
use rama::{
    Layer,
    http::{
        layer::error_handling::ErrorHandlerLayer, server::HttpServer, service::web::Router,
        ws::handshake::server::WebSocketAcceptor,
    },
    layer::{ArcLayer, ConsumeErrLayer},
    rt::Executor,
    tcp::server::TcpListener,
    tls::boring::server::TlsAcceptorLayer,
};

const ADDRESS: &str = "127.0.0.1:62074";
const MESSAGE: &str = "Hello from the blocking WSS client test.";

#[tokio::test]
#[ignore]
async fn test_ws_blocking_wss_client() {
    utils::init_tracing();

    let tls = utils::TestTlsConfig::new();
    let web_service = (ArcLayer::new(), ErrorHandlerLayer::new()).into_layer(
        Router::new().with_get(
            "/echo",
            ConsumeErrLayer::trace_as_debug()
                .into_layer(WebSocketAcceptor::new().into_echo_service()),
        ),
    );
    let service = TlsAcceptorLayer::new(tls.server.clone())
        .into_layer(HttpServer::new_http1(Executor::default()).service(web_service));
    let listener = TcpListener::bind_address(ADDRESS, Executor::default())
        .await
        .expect("bind WSS test server");
    let server = tokio::spawn(listener.serve(service));

    let output = utils::ExampleRunner::run_with_args_and_envs_output(
        "ws_blocking_wss_client",
        [
            format!("wss://{ADDRESS}/echo"),
            MESSAGE.to_owned(),
            "example.com".to_owned(),
        ],
        [(
            "SSL_CERT_FILE".to_owned(),
            tls.certificate_file_path().as_os_str().to_owned(),
        )],
    )
    .await;
    server.abort();

    assert!(
        output.status.success(),
        "blocking WSS example failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("example output is UTF-8");
    assert!(
        stdout.contains(&format!("Echo: {MESSAGE}")),
        "output: {stdout}"
    );
}
