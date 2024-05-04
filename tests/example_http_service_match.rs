mod test_server;

use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;
use serde_json::{json, Value};

const ADDRESS: &str = "127.0.0.1:40010";

#[tokio::test]
#[ignore]
async fn test_http_service_match() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_service_match");

    let res_json = test_server::client()
        .patch(format!("http://{ADDRESS}/echo"))
        .send(Context::default())
        .await?
        .try_into_json::<Value>()
        .await?;

    let test_json = json!({"method":"PATCH","path": "/echo"});
    assert_eq!(res_json, test_json);
    Ok(())
}
