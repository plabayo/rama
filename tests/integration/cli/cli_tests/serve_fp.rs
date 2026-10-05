use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_fp() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_fp(63129, false);

    let lines = utils::RamaService::http(vec!["http://127.0.0.1:63129/report"]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {lines:?}");
    assert!(lines.contains("Fingerprint Report"), "lines: {lines:?}");
    assert!(lines.contains("Http Headers"), "lines: {lines:?}");
}

#[tokio::test]
#[ignore]
async fn test_https_fp() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_fp(63130, true);

    let lines = utils::RamaService::http(vec!["https://127.0.0.1:63130/report"]).unwrap();
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {lines:?}");
    assert!(lines.contains("Fingerprint Report"), "lines: {lines:?}");
    assert!(lines.contains("Http Headers"), "lines: {lines:?}");
    assert!(
        lines.contains("TLS Client Hello — Header"),
        "lines: {lines:?}"
    );
}

#[tokio::test]
#[ignore]
async fn test_http3_fp() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_fp(63146, true);

    let lines =
        utils::RamaService::http(vec!["--http3", "https://127.0.0.1:63146/report"]).unwrap();
    assert!(lines.contains("HTTP/3.0 200 OK"), "lines: {lines:?}");
    assert!(lines.contains("Fingerprint Report"), "lines: {lines:?}");
    assert!(lines.contains("Http Headers"), "lines: {lines:?}");
    // HTTP/3 is shown, never collected into the profile storage (yet).
    assert!(lines.contains("not collected yet"), "lines: {lines:?}");

    let lines =
        utils::RamaService::http(vec!["--http2", "https://127.0.0.1:63146/report"]).unwrap();
    assert!(
        lines.contains(r#"alt-svc: h3=":63146""#),
        "lines: {lines:?}"
    );
    assert!(!lines.contains("not collected yet"), "lines: {lines:?}");
}
