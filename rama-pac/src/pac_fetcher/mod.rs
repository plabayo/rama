use std::fmt::Debug;

use rama_core::{Context, error::BoxError};
use rama_http::{Body, Uri, dep::http::Request, service::client::HttpClientExt};

pub async fn fetch_pac<W>(web_client: &W, pac_uri: Uri) -> Result<String, BoxError>
where
    W: HttpClientExt + Send + Sync + 'static,
    <W as HttpClientExt>::ExecuteResponse: Into<String>,
    <W as HttpClientExt>::ExecuteError: Debug,
{
    let request = Request::builder()
        .method("GET")
        .uri(pac_uri)
        .body(Body::empty())
        .unwrap();
    let response = web_client
        .execute(Context::default(), request)
        .await
        .unwrap();
    let pac_file = response.try_into().unwrap();
    Ok(pac_file)
}
