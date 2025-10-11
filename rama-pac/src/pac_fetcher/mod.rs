use rama_core::{Context, error::BoxError};
use rama_http::{Body, Request, Uri, service::client::HttpClientExt};

pub async fn fetch_pac<W>(web_client: &W, pac_uri: &Uri) -> Result<String, BoxError>
where
    W: HttpClientExt,
    W::ExecuteError: std::error::Error + Send + Sync + 'static,
    W::ExecuteResponse: Into<String>,
{
    let request = Request::builder()
        .method("GET")
        .uri(pac_uri)
        .body(Body::empty())
        .map_err(Into::<BoxError>::into)?;

    let response = web_client.execute(Context::default(), request).await?;

    let pac_file: String = response.into();

    Ok(pac_file)
}
