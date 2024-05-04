mod test_server;

use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;
use regex::Regex;

const ADDRESS: &str = "127.0.0.1:40009";

#[tokio::test]
#[ignore]
async fn test_http_service_fs() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_service_hello");

    let res_str = test_server::client()
        .get(format!("http://{ADDRESS}"))
        .send(Context::default())
        .await?
        .try_into_string()
        .await?;

    let peer = Regex::new(r"Peer: 127.0.0.1:[56][0-9]{4}")?;
    assert!(peer.is_match(&res_str));
    Ok(())
}
