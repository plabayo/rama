use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_echo() {
    let _guard = utils::RamaService::echo(63101);

    let lines = utils::RamaService::http(vec!["http://127.0.0.1:63101"]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {:?}", lines);

    let lines =
        utils::RamaService::http(vec!["http://127.0.0.1:63101", "foo:bar", "a=4", "q==1"]).unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {:?}", lines);
    assert!(lines.contains(r##""method":"POST""##), "lines: {:?}", lines);
    assert!(lines.contains(r##""foo","bar""##), "lines: {:?}", lines);
    assert!(
        lines.contains(r##""content-type","application/json""##),
        "lines: {:?}",
        lines
    );
    assert!(lines.contains(r##""a":"4""##), "lines: {:?}", lines);
    assert!(lines.contains(r##""path":"/""##), "lines: {:?}", lines);
    assert!(lines.contains(r##""query":"q=1""##), "lines: {:?}", lines);
}
