use std::path::PathBuf;

use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_serve_placeholder() {
    let _guard = utils::RamaService::serve(63104, None);
    let lines = utils::RamaService::http(vec!["https://127.0.0.1:63104"]).unwrap();

    assert!(lines.contains("GET /"), "req method, lines: {lines:?}",);
    assert!(
        lines.contains("HTTP/2.0 200 OK"),
        "http res status, lines: {lines:?}",
    );
    assert!(
        lines.contains("content-type: text/html"),
        "res content-type, lines: {lines:?}",
    );
    assert!(
        lines.contains(r##"href="https://github.com/plabayo/rama"##),
        "res html rama link, lines: {lines:?}",
    );
}

#[tokio::test]
#[ignore]
async fn test_http_serve_file() {
    let _guard = utils::RamaService::serve(63105, Some(PathBuf::from("test-files/hello.txt")));
    let lines = utils::RamaService::http(vec!["https://127.0.0.1:63105"]).unwrap();

    assert!(lines.contains("GET /"), "req method, lines: {lines:?}",);
    assert!(
        lines.contains("HTTP/2.0 200 OK"),
        "res status, lines: {lines:?}",
    );
    assert!(
        lines.contains("content-type: text/plain"),
        "res content-type, lines: {lines:?}",
    );
    assert!(
        lines.contains("Hello, World!"),
        "res body, lines: {lines:?}",
    );
}

#[tokio::test]
#[ignore]
async fn test_http_serve_dir() {
    let _guard = utils::RamaService::serve(63106, Some(PathBuf::from("test-files")));
    let lines = utils::RamaService::http(vec!["https://127.0.0.1:63106/hello.txt"]).unwrap();

    assert!(
        lines.contains("GET /hello.txt"),
        "req method, lines: {lines:?}",
    );
    assert!(
        lines.contains("HTTP/2.0 200 OK"),
        "res status, lines: {lines:?}",
    );
    assert!(
        lines.contains("content-type: text/plain"),
        "res content-type, lines: {lines:?}",
    );
    assert!(
        lines.contains("Hello, World!"),
        "res body, lines: {lines:?}",
    );
}

#[tokio::test]
#[ignore]
async fn test_http_serve_dir_index() {
    let _guard = utils::RamaService::serve(63107, Some(PathBuf::from("test-files")));

    let cases = vec![
        "https://127.0.0.1:63107",
        "https://127.0.0.1:63107/index.html",
    ];

    for url in cases {
        let lines = utils::RamaService::http(vec![url]).unwrap();
        assert!(lines.contains("GET /"), "req method, lines: {lines:?}",);
        assert!(
            lines.contains("HTTP/2.0 200 OK"),
            "res status, lines: {lines:?}",
        );
        assert!(
            lines.contains("content-type: text/html"),
            "res content-type, lines: {lines:?}",
        );
        assert!(
            lines.contains("<b>HTML!</b>"),
            "res index.html, lines: {lines:?}",
        );
    }
}

#[tokio::test]
#[ignore]
async fn test_http_serve_dir_404() {
    let _guard = utils::RamaService::serve(63108, Some(PathBuf::from("test-files")));
    let lines = utils::RamaService::http(vec!["https://127.0.0.1:63108/missing.txt"]).unwrap();
    assert!(
        lines.contains("GET /missing.txt"),
        "req method, lines: {lines:?}",
    );
    assert!(
        lines.contains("HTTP/2.0 404 Not Found"),
        "res status, lines: {lines:?}",
    );
}
