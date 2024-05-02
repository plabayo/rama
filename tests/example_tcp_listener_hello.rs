pub mod test_server;

use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;

const ADDRESS: &str = "127.0.0.1:49000";
const SRC: &str = include_str!("../examples/tcp_listener_hello.rs");

#[tokio::test]
async fn test_tcp_listener_hello() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("tcp_listener_hello");

    let res_str = test_server::client()
        .get(format!("http://{ADDRESS}"))
        .send(Context::default())
        .await?
        .try_into_string()
        .await?;
    assert_eq!(res_str, SRC);

    Ok(())
}
