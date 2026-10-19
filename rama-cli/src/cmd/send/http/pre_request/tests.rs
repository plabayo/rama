use super::*;
use clap::Parser;
use rama::{
    http::{Version, body::util::BodyExt as _, conn::TargetHttpVersion},
    net::mode::DnsResolveIpMode,
    utils::fs::tempdir,
};

#[derive(Debug, Parser)]
struct Arguments {
    #[command(flatten)]
    config: SendCommand,
}

fn config(arguments: &[&str]) -> SendCommand {
    Arguments::try_parse_from(
        ["pre-request-test"]
            .into_iter()
            .chain(arguments.iter().copied()),
    )
    .unwrap()
    .config
}

#[tokio::test]
async fn explicit_body_headers_and_context_do_not_inherit_main_request_state() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("pre.json");
    tokio::fs::write(
        &path,
        br#"{
            "method": "POST",
            "uri": "https://current.test/pre?owned=1",
            "headers": [
                ["x-order", "first"],
                ["x-order", "second"],
                ["authorization", "explicit"],
                ["content-type", "application/json"]
            ],
            "body_base64": "eyJudW1iZXIiOjd9",
            "emulate_initiator": "fetch"
        }"#,
    )
    .await
    .unwrap();
    let mut cfg = config(&[
        "--http3",
        "--ipv4",
        "--data",
        "MAIN",
        "--header",
        "Authorization: main",
        "--header",
        "Cookie: main",
        "--header",
        "x-main: private",
        "https://current.test/main",
    ]);
    cfg.pre_requests.push(path);
    let main = super::super::request::build(&cfg, false).await.unwrap();
    let mut requests = load(&cfg).await.unwrap();
    assert_eq!(requests.len(), 1);
    let preliminary = requests.pop().unwrap();
    assert_eq!(preliminary.method(), Method::POST);
    assert_eq!(
        preliminary.uri().to_string(),
        "https://current.test/pre?owned=1"
    );
    assert_eq!(
        preliminary.extensions().get_ref::<RequestInitiator>(),
        Some(&RequestInitiator::Fetch)
    );
    assert_eq!(
        preliminary
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .unwrap()
            .0,
        Version::HTTP_3
    );
    assert!(preliminary.extensions().contains::<DnsResolveIpMode>());
    assert!(preliminary.extensions().contains::<WarmupRequest>());
    assert!(!preliminary.headers().contains_key("cookie"));
    assert!(!preliminary.headers().contains_key("x-main"));
    assert_eq!(preliminary.headers()["authorization"], "explicit");
    assert_eq!(preliminary.headers()[CONTENT_LENGTH], "12");
    let (parts, body) = preliminary.into_parts();
    let order: Vec<_> = parts
        .headers
        .into_ordered_iter()
        .filter(|(name, _)| name == "x-order")
        .map(|(_, value)| value)
        .collect();
    assert_eq!(
        order,
        [
            HeaderValue::from_static("first"),
            HeaderValue::from_static("second")
        ]
    );
    assert_eq!(
        body.collect().await.unwrap().to_bytes(),
        br#"{"number":7}"#.as_slice()
    );
    assert_eq!(
        main.into_body().collect().await.unwrap().to_bytes(),
        b"MAIN".as_slice()
    );
}

#[tokio::test]
async fn all_inputs_are_bounded_and_validated_before_requests_are_returned() {
    let directory = tempdir().unwrap();
    let first = directory.path().join("first.json");
    let last = directory.path().join("last.json");
    tokio::fs::write(
        &first,
        br#"{"method":"GET","uri":"http://current.test/first"}"#,
    )
    .await
    .unwrap();
    for invalid in [
        br#"{"method":"GET","uri":"http://current.test/last","unknown":true}"#.as_slice(),
        br#"{"method":"GET","uri":"http://current.test/last","method":"POST"}"#,
        br#"{"method":"GET","uri":"file:///private"}"#,
        br#"{"method":"GET","uri":"current.test/path"}"#,
        br#"{"method":"POST","uri":"http://current.test/last","body_base64":"%%%"}"#,
        br#"{"method":"GET","uri":"http://current.test/last","headers":[["x-test","bad\r\nheader"]]}"#,
        br#"{"method":"GET","uri":"http://user:password@current.test/last"}"#,
        br#"{"method":"GET","uri":"http://current.test/last#fragment"}"#,
    ] {
        tokio::fs::write(&last, invalid).await.unwrap();
        let mut cfg = config(&["http://current.test/main"]);
        cfg.pre_requests = vec![first.clone(), last.clone()];
        load(&cfg).await.unwrap_err();
    }
    let mut cfg = config(&["http://current.test/main"]);
    cfg.pre_requests = vec![first.clone(); MAX_REQUESTS + 1];
    load(&cfg).await.unwrap_err();
    tokio::fs::write(&last, vec![b' '; MAX_INPUT_BYTES + 1])
        .await
        .unwrap();
    cfg.pre_requests = vec![last];
    load(&cfg).await.unwrap_err();
}

#[test]
fn explicit_plans_cannot_mix_with_the_existing_get_only_warmup_order() {
    let result = Arguments::try_parse_from([
        "pre-request-test",
        "--pre-request",
        "pre.json",
        "--emulate-warmup-connection-variant",
        &"01".repeat(32),
        "https://current.test/main",
    ]);
    result.unwrap_err();
}

#[tokio::test]
async fn per_operation_pins_replace_main_pins_and_require_explicit_coordinates() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("pre.json");
    let bytes = serde_json::to_vec(&serde_json::json!({
        "method": "GET",
        "uri": "https://current.test/pre",
        "emulate_connection_variant": "04".repeat(32),
        "emulate_request_variant": "05".repeat(32)
    }))
    .unwrap();
    tokio::fs::write(&path, bytes).await.unwrap();
    let mut cfg = config(&["https://current.test/main"]);
    cfg.pre_requests.push(path);
    load(&cfg).await.unwrap_err();
    cfg.emulate = Some(EmulationProfiles::File(
        directory.path().join("caller.json"),
    ));
    cfg.emulate_seed = Some(EmulationHex([1; 32]));
    cfg.emulate_connection_key = Some(EmulationHex([2; 32]));
    cfg.emulate_request_key = Some(EmulationHex([3; 32]));
    cfg.emulate_connection_variant = Some(EmulationHex([8; 32]));
    cfg.emulate_request_variant = Some(EmulationHex([9; 32]));
    let request = load(&cfg).await.unwrap().pop().unwrap();
    let pins = request.extensions().get_ref::<VariantPins>().unwrap();
    assert_eq!(pins.connection, Some(ValueId([4; 32])));
    assert_eq!(pins.request, Some(ValueId([5; 32])));
    tokio::fs::write(
        &cfg.pre_requests[0],
        br#"{"method":"GET","uri":"https://current.test/pre"}"#,
    )
    .await
    .unwrap();
    let unpinned = load(&cfg).await.unwrap().pop().unwrap();
    let pins = unpinned.extensions().get_ref::<VariantPins>().unwrap();
    assert_eq!(pins.connection, None);
    assert_eq!(pins.request, None);
}

#[tokio::test]
async fn preliminary_body_and_header_limits_are_checked_before_transport() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("bounded.json");
    let mut cfg = config(&["https://current.test/main"]);
    cfg.pre_requests.push(path.clone());
    for input in [
        serde_json::json!({"method":"POST","uri":"https://current.test/pre","body_base64":STANDARD.encode(vec![0; MAX_BODY_BYTES + 1])}),
        serde_json::json!({"method":"GET","uri":"https://current.test/pre","headers":vec![("x-test","value");257]}),
        serde_json::json!({"method":"GET","uri":"https://current.test/pre","emulate_initiator":"ws"}),
    ] {
        tokio::fs::write(&path, serde_json::to_vec(&input).unwrap())
            .await
            .unwrap();
        load(&cfg).await.unwrap_err();
    }
    tokio::fs::write(&path, serde_json::to_vec(&serde_json::json!({
        "method":"POST","uri":"https://current.test/pre","body_base64":STANDARD.encode(vec![0; MAX_BODY_BYTES])
    })).unwrap()).await.unwrap();
    let request = load(&cfg).await.unwrap().pop().unwrap();
    assert_eq!(
        request
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .len(),
        MAX_BODY_BYTES
    );
}

#[tokio::test]
async fn explicit_framing_is_preserved_and_inconsistent_framing_is_rejected() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("framing.json");
    let mut cfg = config(&["--http1.1", "http://current.test/main"]);
    cfg.pre_requests.push(path.clone());
    for (headers, valid) in [
        (
            serde_json::json!([
                ["x-before", "one"],
                ["CoNtEnT-LeNgTh", "5"],
                ["x-after", "two"]
            ]),
            true,
        ),
        (serde_json::json!([["Content-Length", "4"]]), false),
        (
            serde_json::json!([["Content-Length", "5"], ["Content-Length", "4"]]),
            false,
        ),
        (
            serde_json::json!([["Content-Length", "5"], ["Transfer-Encoding", "chunked"]]),
            false,
        ),
        (serde_json::json!([["Transfer-Encoding", "chunked"]]), true),
        (
            serde_json::json!([["Transfer-Encoding", "gzip, chunked"]]),
            false,
        ),
    ] {
        tokio::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "method":"POST", "uri":"http://current.test/pre", "headers":headers,
                "body_base64":"aGVsbG8="
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let result = load(&cfg).await;
        assert_eq!(result.is_ok(), valid, "{headers}");
        if valid {
            let request = result.unwrap().pop().unwrap();
            let actual: Vec<_> = request
                .headers()
                .clone()
                .into_ordered_iter()
                .map(|(name, value)| {
                    (
                        name.as_original_str().into_owned(),
                        value.to_str().unwrap().to_owned(),
                    )
                })
                .collect();
            let expected: Vec<(String, String)> = serde_json::from_value(headers).unwrap();
            assert_eq!(actual, expected);
        }
    }
    cfg.http_11 = false;
    cfg.http_2 = true;
    tokio::fs::write(
        &path,
        br#"{
            "method": "POST",
            "uri": "https://current.test/pre",
            "headers": [["Transfer-Encoding", "chunked"]],
            "body_base64": "aGVsbG8="
        }"#,
    )
    .await
    .unwrap();
    load(&cfg).await.unwrap_err();
}
