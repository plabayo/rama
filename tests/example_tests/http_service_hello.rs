use super::utils;
use rama::{http::BodyExtractExt, service::Context};
use regex::Regex;

#[tokio::test]
#[ignore]
async fn test_http_service_fs() {
    let runner = utils::ExampleRunner::interactive("http_service_hello");

    let res_str = runner
        .get("http://127.0.0.1:40010")
        .send(Context::default())
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
