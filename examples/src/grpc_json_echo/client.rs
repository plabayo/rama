//! An example showing how to call a gRPC service which speaks JSON instead of protobuf,
//! defined inline in Rust without a `.proto` file or a build script.
//!
//! The service itself is defined in [`echo`], next to this example, and shared with the
//! `grpc_json_echo_server` example which serves it.
//!
//! Its sibling `grpc_echo` calls the very same `Echo` service the classic way: a `.proto`
//! contract compiled by a build script into protobuf stubs. Run both to compare.
//!
//! # Run the example
//!
//! Start the server first:
//!
//! ```sh
//! cargo run -p rama-examples --bin grpc_json_echo_server --features=grpc,http-full
//! ```
//!
//! Then call it:
//!
//! ```sh
//! cargo run -p rama-examples --bin grpc_json_echo_client --features=grpc,http-full
//! ```

#![expect(
    clippy::print_stdout,
    reason = "example: print-for-output is the standard pattern for demos"
)]

use rama::{
    error::BoxError,
    http::{client::EasyHttpWebClient, grpc::Request},
    net::uri::Uri,
};

mod echo;
use echo::{EchoRequest, echo_client::EchoClient};

const ORIGIN: &str = "http://127.0.0.1:62071";

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let client = EchoClient::new(EasyHttpWebClient::default(), Uri::from_static(ORIGIN));

    let response = client
        .unary_echo(Request::new(EchoRequest {
            message: "hello rama".to_owned(),
        }))
        .await?;
    let message = response.into_inner().message;
    println!("unary echo: {message:?}");
    assert_eq!(message, "hello rama");

    let mut stream = client
        .server_streaming_echo(Request::new(EchoRequest {
            message: "hello rama".to_owned(),
        }))
        .await?
        .into_inner();
    let mut messages = Vec::new();
    while let Some(response) = stream.message().await? {
        println!("streaming echo: {:?}", response.message);
        messages.push(response.message);
    }
    assert_eq!(messages, ["hello", "rama"]);

    Ok(())
}
