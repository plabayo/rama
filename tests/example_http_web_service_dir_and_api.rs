pub mod test_server;

use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;

const ADDRESS: &str = "127.0.0.1:40011";

#[tokio::test]
#[ignore]
async fn test_http_web_service_dir_and_api() -> Result<(), BoxError> {
    let coin_count = r##"<h1 id="coinCount">{count}</h1>"##;
    let _example = test_server::run_example_server("http_web_service_dir_and_api");

    let res_str = test_server::client()
        .get(format!("http://{ADDRESS}{}", "/coin"))
        .send(Context::default())
        .await?
        .try_into_string()
        .await?;
    assert!(res_str.contains(&coin_count.replace("{count}", "0")));

    let res_str = test_server::client()
        .post(format!("http://{ADDRESS}{}", "/coin"))
        .send(Context::default())
        .await?
        .try_into_string()
        .await?;
    assert!(res_str.contains(&coin_count.replace("{count}", "1")));
    Ok(())
}
