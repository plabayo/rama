mod test_server;

use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;

const ADDRESS: &str = "127.0.0.1:40012";

#[tokio::test]
async fn test_mtls_tunnel_and_service() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("mtls_tunnel_and_service");

    let res_str = test_server::client()
        .get(format!("http://{ADDRESS}{}", "/hello"))
        .send(Context::default())
        .await?
        .try_into_string()
        .await?;

    assert_eq!(res_str, "<h1>Hello, authorized client!</h1>");

    // TODO: connect by mTLS
    Ok(())
}
