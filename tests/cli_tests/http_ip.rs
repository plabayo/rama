use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_ip() {
    let _guard = utils::RamaService::ip(64100);

    let lines = utils::RamaService::http(vec![":64100"]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"));
    assert!(lines.contains("127.0.0.1:"));
}
