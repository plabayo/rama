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
