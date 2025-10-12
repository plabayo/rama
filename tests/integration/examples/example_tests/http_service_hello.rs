use super::utils;
use rama::http::BodyExtractExt;
use rama::utils::thirdparty::regex::Regex;

#[tokio::test]
#[ignore]
async fn test_http_service_fs() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("http_service_hello", None);

    let res_str = runner
        .get("http://127.0.0.1:62010")
        .send()
        .await
        .unwrap()
        .try_into_string()
        .await
        .unwrap();

    assert!(res_str.contains("<h1>Hello</h1>"));
    assert!(res_str.contains("<p>Path: /</p>"));

    let peer = Regex::new(r"<p>Peer: 127.0.0.1:\d+</p>").unwrap();
    assert!(peer.is_match(&res_str));
}
