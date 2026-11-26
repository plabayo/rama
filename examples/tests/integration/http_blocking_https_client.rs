use super::utils;
use rama::{
    Layer,
    graceful::WeakScope,
    http::{layer::error_handling::ErrorHandlerLayer, server::HttpServer, service::web::Router},
    layer::ArcLayer,
    tcp::server::TcpListener,
    tls::boring::server::TlsAcceptorLayer,
};

const BODY: &str = "Hello from the blocking HTTPS client test.";

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_http_blocking_https_client() {
    utils::init_tracing();

    let tls = utils::TestTlsConfig::new();
    let service = TlsAcceptorLayer::new(tls.server.clone()).into_layer(
        HttpServer::new_http1(WeakScope::detached()).service(
            (ArcLayer::new(), ErrorHandlerLayer::new())
                .into_layer(Router::new().with_get("/", BODY)),
        ),
    );
    let listener = TcpListener::bind_address("127.0.0.1:0", WeakScope::detached())
        .await
        .expect("bind HTTPS test server");
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.serve(service));

    let output = utils::ExampleRunner::run_with_args_and_envs_output(
        utils::example!("http_blocking_https_client"),
        [format!("https://{address}/"), "example.com".to_owned()],
        [(
            "SSL_CERT_FILE".to_owned(),
            tls.certificate_file_path().as_os_str().to_owned(),
        )],
    )
    .await;
    server.abort();

    assert!(
        output.status.success(),
        "blocking HTTPS example failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("example output is UTF-8");
    assert!(stdout.contains("Status: 200 OK"), "output: {stdout}");
    assert!(stdout.contains(BODY), "output: {stdout}");
}
