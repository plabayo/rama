use rama::{
    error::BoxError,
    http::{Uri, client::EasyHttpWebClient, grpc},
};

use rama_grpc_examples::hello_world::{HelloRequest, greeter_client::GreeterClient};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let http_client = EasyHttpWebClient::default();

    // TOOD: do something about origin and Uri
    let client = GreeterClient::new(http_client, Uri::from_static("http://[::1]:50051"));

    let request = grpc::Request::new(HelloRequest {
        name: "Rama".into(),
    });

    let response = client.say_hello(request).await?;

    println!("RESPONSE={response:?}");

    Ok(())
}
