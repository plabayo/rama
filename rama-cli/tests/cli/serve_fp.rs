use super::utils;

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_http_fp() {
    utils::init_tracing();

    let server = utils::RamaService::serve_fp(0, false);
    let port = server.port();

    let lines = utils::RamaService::http(vec![&format!("http://127.0.0.1:{port}/report")]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(lines.contains("Fingerprint Report"), "lines: {lines:?}");
    assert!(lines.contains("Http Headers"), "lines: {lines:?}");
}

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_https_fp() {
    utils::init_tracing();

    let server = utils::RamaService::serve_fp(0, true);
    let port = server.port();

    let lines =
        utils::RamaService::http(vec![&format!("https://127.0.0.1:{port}/report")]).unwrap();
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {lines:?}");
    assert!(lines.contains("Fingerprint Report"), "lines: {lines:?}");
    assert!(lines.contains("Http Headers"), "lines: {lines:?}");
    assert!(
        lines.contains("TLS Client Hello — Header"),
        "lines: {lines:?}"
    );
}

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_http3_fp() {
    utils::init_tracing();

    let server = utils::RamaService::serve_fp(0, true);
    let port = server.port();

    let lines =
        utils::RamaService::http(vec!["--http3", &format!("https://127.0.0.1:{port}/report")])
            .unwrap();
    assert!(lines.contains("HTTP/3.0 200 OK"), "lines: {lines:?}");
    assert!(lines.contains("Fingerprint Report"), "lines: {lines:?}");
    assert!(lines.contains("Http Headers"), "lines: {lines:?}");
    assert!(lines.contains("HTTP/3 SETTINGS"), "lines: {lines:?}");

    let lines =
        utils::RamaService::http(vec!["--http2", &format!("https://127.0.0.1:{port}/report")])
            .unwrap();
    assert!(
        lines.contains(&format!(r#"alt-svc: h3=":{port}"; ma=86400"#)),
        "lines: {lines:?}"
    );
}
