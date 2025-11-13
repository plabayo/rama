use super::utils;

#[tokio::test]
#[ignore]
async fn test_probe_tls() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_discard(63124, "tls");

    let output = utils::RamaService::probe_tls("127.0.0.1:63124").unwrap();

    assert!(output.contains("Certificate #1"), "output: {output}");
    assert!(output.contains("CN=plabayo.tech"), "output: {output}");
}

#[tokio::test]
#[ignore]
async fn test_probe_tcp() {
    utils::init_tracing();

    let _guard = utils::RamaService::serve_discard(63125, "tcp");

    let output = utils::RamaService::probe_tcp("127.0.0.1:63125").unwrap();

    assert!(
        output.contains("connected to: 127.0.0.1:63125"),
        "output: {output}"
    );
}
