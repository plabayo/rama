use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_echo() {
    let _guard = utils::RamaService::echo(63101, false, None);

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

#[tokio::test]
#[ignore]
async fn test_http_echo_acme_data() {
    let _guard = utils::RamaService::echo(63102, false, Some("hello,world".to_owned()));

    let lines = utils::RamaService::http(vec![
        "http://127.0.0.1:63102/.well-known/acme-challenge/hello",
    ])
    .unwrap();
    assert!(lines.contains("HTTP/1.1 200 OK"), "lines: {:?}", lines);
    assert!(lines.contains("world"), "lines: {:?}", lines);
}

#[cfg(feature = "boring")]
#[tokio::test]
#[ignore]
async fn test_http_echo_secure() {
    let _guard = utils::RamaService::echo(63103, true, None);

    let lines = utils::RamaService::http(vec!["https://127.0.0.1:63103", "foo:bar", "a=4", "q==1"])
        .unwrap();

    // same http test as the plain text version
    assert!(lines.contains("HTTP/2.0 200 OK"), "lines: {:?}", lines);
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
    assert!(lines.contains(r##""query":"q=1""##), "lines: {:?}", lines);

    // do test however that we now also get tls info
    assert!(lines.contains(r##""cipher_suites""##), "lines: {:?}", lines);
}
