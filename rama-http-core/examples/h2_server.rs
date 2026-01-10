//! Server h2 example running a local h2 server,
//! example in sync with `hyperium/h2`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-http-core --example h2_server
//! ```
//!
//! This example is best run together with the `h2_client` or
//! any other h2 client that you can use for this purpose.
//!
//! # Expected output
//!
//! When starting the server you'll see a confirmation that the server is listening:
//!
//! ```text
//! listening on Ok(127.0.0.1:5928)
//! ```
//!
//! Once you made a h2 request with a client to this server you
//! should see more or less the following output:
//!
//! ```text
//! H2 connection bound
//! GOT request: Request { method: GET, uri: https://example.com/, version: HTTP/2.0, headers: {}, body: RecvStream { inner: FlowControl { inner: OpaqueStreamRef { stream_id: StreamId(1), ref_count: 2 } } } }
//! >>>> send
//! ~~~~~~~~~~~ H2 connection CLOSE !!!!!! ~~~~~~~~~~~
//! ```

use rama_core::ServiceInput;
use rama_core::telemetry::tracing;
use rama_error::BoxError;
use rama_http_core::h2::RecvStream;
use rama_http_core::h2::server::{self, SendResponse};
use rama_http_types::Request;

use rama_core::bytes::Bytes;
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
#[tracing_test::traced_test]
async fn main() -> Result<(), BoxError> {
    let listener = TcpListener::bind("127.0.0.1:5928").await?;

    tracing::info!("listening on {:?}", listener.local_addr());

    loop {
        if let Ok((socket, _peer_addr)) = listener.accept().await {
            tokio::spawn(async move {
                if let Err(e) = serve(socket).await {
                    tracing::info!("  -> err={e:?}");
                }
            });
        }
    }
}

async fn serve(socket: TcpStream) -> Result<(), BoxError> {
    let socket = ServiceInput::new(socket);
    let mut connection = server::handshake(socket).await?;
    tracing::info!("H2 connection bound");

    while let Some(result) = connection.accept().await {
        let (request, respond) = result?;
        tokio::spawn(async move {
            if let Err(e) = handle_request(request, respond).await {
                tracing::info!("error while handling request: {e}");
            }
        });
    }

    tracing::info!("~~~~~~~~~~~ H2 connection CLOSE !!!!!! ~~~~~~~~~~~");
    Ok(())
}

async fn handle_request(
    mut request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
) -> Result<(), BoxError> {
    tracing::info!("GOT request: {request:?}");

    let body = request.body_mut();
    while let Some(data) = body.data().await {
        let data = data?;
        tracing::info!("<<<< recv {data:?}");
        let _ = body.flow_control().release_capacity(data.len());
    }

    let response = rama_http_types::Response::new(());
    let mut send = respond.send_response(response, false)?;
    tracing::info!(">>>> send");
    send.send_data(Bytes::from_static(b"hello "), false)?;
    send.send_data(Bytes::from_static(b"world\n"), true)?;

    Ok(())
}
