use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_proxy_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63125, utils::EchoMode::Http);
    let _guard = utils::RamaService::serve_proxy(63126);

    let lines = utils::RamaService::http(vec![
        "http://127.0.0.1:63125",
        "-x",
        "http://127.0.0.1:63126",
    ])
    .unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(lines.contains(r##""method":"GET""##), "lines: {lines:?}");
}

#[tokio::test]
#[ignore]
async fn test_https_proxy_echo() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_echo(63127, utils::EchoMode::Https);
    let _guard = utils::RamaService::serve_proxy(63128);

    let lines = utils::RamaService::http(vec![
        "https://127.0.0.1:63127",
        "-x",
        "http://127.0.0.1:63128",
    ])
    .unwrap();
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {lines:?}");
    assert!(
        lines.contains("ALPN: server selected h2"),
        "lines: {lines:?}"
    );
    assert!(lines.contains(r##""method":"GET""##), "lines: {lines:?}");
}
