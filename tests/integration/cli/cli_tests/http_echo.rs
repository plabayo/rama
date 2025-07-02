use super::utils;

#[tokio::test]
#[ignore]
async fn test_http_echo() {
    utils::init_tracing();

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
    utils::init_tracing();

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
    utils::init_tracing();

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

#[cfg(feature = "boring")]
#[tokio::test]
#[ignore]
async fn test_http_forced_version() {
    utils::init_tracing();

    let _guard = utils::RamaService::echo(63103, true, None);

    struct Test {
        cli_flag: &'static str,
        version_response: &'static str,
        tls_alpn: &'static str,
    }

    let tests = vec![
        Test {
            cli_flag: "--http1.0",
            version_response: "HTTP/1.0 200 OK",
            tls_alpn: "http/1.0",
        },
        Test {
            cli_flag: "--http1.1",
            version_response: "HTTP/1.1 200 OK",
            tls_alpn: "http/1.1",
        },
        Test {
            cli_flag: "--http2",
            version_response: "HTTP/2.0 200 OK",
            tls_alpn: "h2",
        },
    ];

    for test in tests.iter() {
        let tls_alpn = format!(
            r#"{{"data":["{}"],"id":"APPLICATION_LAYER_PROTOCOL_NEGOTIATION (0x0010)"}}"#,
            test.tls_alpn
        );

        let lines = utils::RamaService::http(vec![
            test.cli_flag,
            "https://127.0.0.1:63103",
            "foo:bar",
            "a=4",
            "q==1",
        ])
        .unwrap();

        assert!(
            lines.contains(test.version_response),
            "cli flag {}, didn't find '{}' lines: {:?}",
            test.cli_flag,
            test.version_response,
            lines
        );
        assert!(
            lines.contains(&tls_alpn),
            "cli flag {}, didn't find '{}' lines: {:?}",
            test.cli_flag,
            tls_alpn,
            lines
        );
    }
}
