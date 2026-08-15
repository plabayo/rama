use super::utils;
use rama::{
    Layer,
    http::{server::HttpServer, service::web::WebService},
    rt::Executor,
    tcp::server::TcpListener,
    tls::boring::server::TlsAcceptorLayer,
};

const ADDRESS: &str = "127.0.0.1:62073";
const BODY: &str = "Hello from the blocking HTTPS client test.";

#[tokio::test]
#[ignore]
async fn test_http_blocking_https_client() {
    utils::init_tracing();

    let tls = utils::TestTlsConfig::new();
    let service = TlsAcceptorLayer::new(tls.server.clone()).into_layer(
        HttpServer::new_http1(Executor::default())
            .service(WebService::default().with_get("/", BODY)),
    );
    let listener = TcpListener::bind_address(ADDRESS, Executor::default())
        .await
        .expect("bind HTTPS test server");
    let server = tokio::spawn(listener.serve(service));

    let output = utils::ExampleRunner::run_with_args_and_envs_output(
        "http_blocking_https_client",
        [format!("https://{ADDRESS}/"), "example.com".to_owned()],
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
