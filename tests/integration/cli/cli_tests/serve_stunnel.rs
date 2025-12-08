use super::utils;

#[tokio::test]
#[ignore]
async fn test_stunnel_full() {
    utils::init_tracing();

    let _echo = utils::RamaService::serve_echo(63121, utils::EchoMode::Http);

    // stunnel exit node on 63122 (TLS termination -> forwards to localhost:63121)
    let _stunnel_exit_node =
        utils::RamaService::serve_stunnel_exit("127.0.0.1:63122", "127.0.0.1:63121");

    // stunnel entry node on 63123 (TLS origination -> connects to 63122)
    let _stunnel_entry_node =
        utils::RamaService::serve_stunnel_entry_insecure("127.0.0.1:63123", "127.0.0.1:63122");

    // Test: rama http client -> stunnel entry node (63123) -> stunnel exit node (63122) -> http server (63121)
    let lines = utils::RamaService::http(vec![
        "127.0.0.1:63123",
        "-d",
        r##"{"message":"Hello through tunnel!""##,
        "--json",
    ])
    .unwrap();

    // Verify the response
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(
        lines.contains("7b226d657373616765223a2248656c6c6f207468726f7567682074756e6e656c2122"), // hex-encoded json payload
        "Should contain request body echo'd back, lines: {lines:?}"
    );
}
