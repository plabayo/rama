mod test_server;

use rama::error::BoxError;
use rama::http::client::HttpClientExt;
use rama::http::BodyExtractExt;
use rama::service::Context;
use std::fs::read_to_string;

const ADDRESS: &str = "127.0.0.1:40008";

#[tokio::test]
#[ignore]
async fn test_http_service_fs() -> Result<(), BoxError> {
    let _example = test_server::run_example_server("http_service_fs");
    let cwd = std::env::current_dir().expect("current working dir");
    let path = "test-files/index.html";

    let request = test_server::client()
        .get(format!("http://{ADDRESS}/{}", path))
        .send(Context::default())
        .await
        .unwrap();

    let res_str = request.try_into_string().await?;
    let index_path = cwd.join(path);
    let test_file_index = read_to_string(index_path)?;
    assert_eq!(res_str, test_file_index);
    Ok(())
}
