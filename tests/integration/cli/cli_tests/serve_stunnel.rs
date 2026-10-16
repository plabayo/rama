use super::utils;

#[tokio::test]
#[ignore]
async fn test_stunnel_full() {
    utils::init_tracing();

    let echo = utils::RamaService::serve_echo(0, utils::EchoMode::Http);
    let exit = utils::RamaService::serve_stunnel_exit("127.0.0.1:0", &echo.address().to_string());
    let entry = utils::RamaService::serve_stunnel_entry_insecure(
        "127.0.0.1:0",
        &exit.address().to_string(),
    );

    // Client -> entry -> exit -> HTTP origin, each retaining its own socket.
    let lines = utils::RamaService::http(vec![
        &entry.address().to_string(),
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
