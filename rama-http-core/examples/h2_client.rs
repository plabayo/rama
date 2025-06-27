//! Client h2 example with a local h2 server,
//! example in sync with `hyperium/h2`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-http-core --example h2_client
//! ```
//!
//! This example is best run together with the `h2_server` or
//! any other h2 server that you have running for this purpose.
//!
//! # Expected output
//!
//! When you use this client to connect to a local h2 server (e.g. `h2_server.rs`)
//! you should see the following output:
//!
//! ```text
//! sending request
//! GOT RESPONSE: Response { status: 200, version: HTTP/2.0, headers: {}, body: RecvStream { inner: FlowControl { inner: OpaqueStreamRef { stream_id: StreamId(1), ref_count: 2 } } } }
//! GOT CHUNK = b"hello "
//! GOT CHUNK = b"world\n
//! ```
//!
//! You should see an HTTP Status 200 OK with a HTML payload containing the
//! connection index and count of requests within that connection.

use rama_error::BoxError;
use rama_http_core::h2::client;
use rama_http_types::{
    HeaderMap, HeaderName, Request, proto::h1::headers::original::OriginalHttp1Headers,
};

use tokio::net::TcpStream;

#[tokio::main]
pub async fn main() -> Result<(), BoxError> {
    let _ = env_logger::try_init();

    let tcp = TcpStream::connect("127.0.0.1:5928").await?;
    let (mut client, h2) = client::handshake(tcp).await?;

    println!("sending request");

    let request = Request::builder()
        .uri("https://example.com/")
        .body(())
        .unwrap();

    let mut trailers = HeaderMap::new();
    trailers.insert("zomg", "hello".parse().unwrap());

    let mut trailer_order = OriginalHttp1Headers::new();
    trailer_order.push(HeaderName::from_static("zomg").into());

    let (response, mut stream) = client.send_request(request, false).unwrap();

    // send trailers
    stream.send_trailers(trailers, trailer_order).unwrap();

    // Spawn a task to run the conn...
    tokio::spawn(async move {
        if let Err(e) = h2.await {
            println!("GOT ERR={e:?}");
        }
    });

    let response = response.await?;
    println!("GOT RESPONSE: {response:?}");

    // Get the body
    let mut body = response.into_body();

    while let Some(chunk) = body.data().await {
        println!("GOT CHUNK = {:?}", chunk?);
    }

    if let Some(trailers) = body.trailers().await? {
        println!("GOT TRAILERS: {trailers:?}");
    }

    Ok(())
}
