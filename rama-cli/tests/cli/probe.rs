use super::utils;

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_probe_tls() {
    utils::init_tracing();

    let server = utils::RamaService::serve_discard(0, "tls");
    let port = server.port();

    let output = utils::RamaService::probe_tls(&format!("127.0.0.1:{port}")).unwrap();

    assert!(output.contains("Certificate #1"), "output: {output}");
    assert!(output.contains("CN=plabayo.tech"), "output: {output}");
}

#[tokio::test]
#[ignore = "spawns rama processes"]
async fn test_probe_tcp() {
    utils::init_tracing();

    let server = utils::RamaService::serve_discard(0, "tcp");
    let port = server.port();

    let output = utils::RamaService::probe_tcp(&format!("127.0.0.1:{port}")).unwrap();

    assert!(
        output.contains(&format!("connected to: 127.0.0.1:{port}")),
        "output: {output}"
    );
}
