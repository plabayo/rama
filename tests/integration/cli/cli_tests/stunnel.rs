use super::utils;

#[tokio::test]
#[ignore]
async fn test_stunnel_full() {
    utils::init_tracing();

    let _echo = utils::RamaService::echo(8080, "http");

    // stunnel server on 8002 (TLS termination -> forwards to 8080)
    let _stunnel_server = utils::RamaService::stunnel_server();

    // stunnel client on 8003 (TLS origination -> connects to 8002)
    let _stunnel_client = utils::RamaService::stunnel_client_insecure();

    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    // Test: rama http client -> stunnel client (8003) -> stunnel server (8002) -> http server (8080)
    let lines =
        utils::RamaService::http(vec!["127.0.0.1:8003", "message=Hello through tunnel!"]).unwrap();

    // Verify the response
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(
        lines.contains(r##""message":"Hello through tunnel!""##),
        "Should contain request body, lines: {lines:?}"
    );
}
