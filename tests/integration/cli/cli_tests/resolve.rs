use super::utils;

#[tokio::test]
#[ignore]
async fn test_resolve_default() {
    utils::init_tracing();
    let output = utils::RamaService::resolve("localhost", None).unwrap();

    assert!(
        output.contains("Resolving A for domain: localhost"),
        "output: {output}"
    );
    assert!(output.contains("* 127.0.0.1"), "output: {output}");
}

#[tokio::test]
#[ignore]
async fn test_resolve_a() {
    utils::init_tracing();
    let output = utils::RamaService::resolve("localhost", Some("A")).unwrap();

    assert!(
        output.contains("Resolving A for domain: localhost"),
        "output: {output}"
    );
    assert!(output.contains("* 127.0.0.1"), "output: {output}");
}
