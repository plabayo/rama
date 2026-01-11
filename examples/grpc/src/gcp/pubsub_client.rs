use rama::{
    error::BoxError,
    http::{
        Uri,
        client::EasyHttpWebClient,
        grpc::{Request, metadata::MetadataValue, service::interceptor::InterceptedService},
    },
    service::service_fn,
};
use rama_grpc_examples::gcp::pubsub::{ListTopicsRequest, publisher_client::PublisherClient};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let token = std::env::var("GCP_AUTH_TOKEN").map_err(|_| {
        "Pass a valid 0Auth bearer token via `GCP_AUTH_TOKEN` environment variable.".to_owned()
    })?;

    let project = std::env::args()
        .nth(1)
        .ok_or_else(|| "Expected a project name as the first argument.".to_owned())?;

    let bearer_token = format!("Bearer {token}");
    let header_value: MetadataValue<_> = bearer_token.parse()?;

    let http_client = InterceptedService::new(
        EasyHttpWebClient::default(),
        service_fn(move |mut req: Request<()>| {
            let header_value = header_value.clone();
            async move {
                req.metadata_mut().insert("authorization", header_value);
                Ok(req)
            }
        }),
    );

    let service = PublisherClient::new(
        http_client,
        Uri::from_static("https://pubsub.googleapis.com"),
    );

    let response = service
        .list_topics(Request::new(ListTopicsRequest {
            project: format!("projects/{project}"),
            page_size: 10,
            ..Default::default()
        }))
        .await?;

    println!("RESPONSE={response:?}");

    Ok(())
}
