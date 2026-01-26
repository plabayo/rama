use rama::{
    error::BoxError,
    http::{
        Uri,
        client::EasyHttpWebClient,
        grpc::{Request, codec::CompressionEncoding},
    },
};
use rama_grpc_examples::hello_world::{HelloRequest, greeter_client::GreeterClient};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let http_client = EasyHttpWebClient::default();

    let client = GreeterClient::new(http_client, Uri::from_static("http://[::1]:50051"))
        .with_send_compressed(CompressionEncoding::Gzip)
        .with_accept_compressed(CompressionEncoding::Gzip);

    let request = Request::new(HelloRequest {
        name: "Rama".into(),
    });

    let response = client.say_hello(request).await?;

    dbg!(response);

    Ok(())
}
