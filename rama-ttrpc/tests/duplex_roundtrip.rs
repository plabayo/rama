//! End-to-end parity test: drive a ttRPC `Client` and `ServerConnection` against each other
//! over an in-memory `tokio::io::duplex` pair (no sockets, no codegen). This exercises the whole
//! stack — framing/codec, the request/response correlation, stream-id handling and dispatch —
//! which is exactly the shape a consumer (e.g. the NRI multiplexer) wires up: hand each half of a
//! stream to `Client::new` / `ServerConnection::new`.

use std::sync::Arc;

use rama_ttrpc::__codegen_prelude::{
    MethodHandler, RequestHandler as _, ServerStreamingMethod, Service, UnaryMethod,
};
use rama_ttrpc::{Client, Result, ServerConnection};

#[derive(Clone, PartialEq, ::prost::Message)]
struct EchoRequest {
    #[prost(string, tag = "1")]
    msg: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct EchoReply {
    #[prost(string, tag = "1")]
    msg: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct CountReply {
    #[prost(uint32, tag = "1")]
    n: u32,
}

/// A hand-rolled service (the shape `rama-ttrpc-build` would generate): a `Service` whose
/// `methods()` maps `"/{package.Service}/{method}"` to a `MethodHandler`.
struct Greeter;

impl Service for Greeter {
    fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
        vec![
            (
                "/echo.Greeter/Hello",
                Arc::new(UnaryMethod::new(|req: EchoRequest| async move {
                    Ok(EchoReply {
                        msg: format!("hello {}", req.msg),
                    })
                })),
            ),
            (
                "/echo.Greeter/Count",
                Arc::new(ServerStreamingMethod::new(|req: EchoRequest| {
                    rama_ttrpc::stream::stream_fn(move |mut yielder| async move {
                        for n in 0..req.msg.len() as u32 {
                            yielder.yield_item(Ok(CountReply { n })).await;
                        }
                    })
                })),
            ),
        ]
    }
}

fn spawn_server(conn: tokio::io::DuplexStream) {
    tokio::spawn(async move {
        let mut server = ServerConnection::new(conn);
        server.register(Greeter);
        _ = server.start().await;
    });
}

#[tokio::test]
async fn unary_roundtrip() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    spawn_server(server_io);
    let client = Client::new(client_io);

    let reply: EchoReply = client
        .handle_unary_request(
            "echo.Greeter".to_owned(),
            "Hello".to_owned(),
            EchoRequest {
                msg: "world".to_owned(),
            },
        )
        .await
        .expect("unary call should succeed");

    assert_eq!(reply.msg, "hello world");
}

/// A service whose handler triggers a graceful shutdown from inside the request, exercising
/// `ServerController::shutdown` reached via `get_server`.
struct ShutdownService;

impl Service for ShutdownService {
    fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
        vec![(
            "/echo.Greeter/Stop",
            Arc::new(UnaryMethod::new(|_req: EchoRequest| async move {
                rama_ttrpc::get_server().shutdown();
                Ok(EchoReply {
                    msg: "stopping".to_owned(),
                })
            })),
        )]
    }
}

#[tokio::test]
async fn graceful_shutdown_from_handler_ends_start() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        let mut server = ServerConnection::new(server_io);
        server.register(ShutdownService);
        server.start().await
    });
    let client = Client::new(client_io);

    let reply: EchoReply = client
        .handle_unary_request(
            "echo.Greeter".to_owned(),
            "Stop".to_owned(),
            EchoRequest { msg: String::new() },
        )
        .await
        .expect("in-flight reply must be delivered on graceful shutdown");
    assert_eq!(reply.msg, "stopping");

    // Without `shutdown()` the loop would keep serving (the client half stays open, so the read
    // branch never completes), so `start()` returning at all proves the handler's `shutdown()`
    // took effect and the in-flight request drained.
    let start = tokio::time::timeout(std::time::Duration::from_secs(2), server_task)
        .await
        .expect("server did not shut down after shutdown() from a handler")
        .expect("server task panicked");
    assert!(
        start.is_ok(),
        "start() should return Ok on graceful shutdown"
    );
}

#[tokio::test]
async fn server_streaming_roundtrip() {
    use rama_core::futures::StreamExt as _;

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    spawn_server(server_io);
    let client = Client::new(client_io);

    let stream = client.handle_server_streaming_request(
        "echo.Greeter".to_owned(),
        "Count".to_owned(),
        EchoRequest {
            msg: "abcd".to_owned(),
        },
    );
    let got: Vec<Result<CountReply>> = Box::pin(stream).collect().await;

    let ns: Vec<u32> = got.into_iter().map(|r| r.expect("stream item").n).collect();
    assert_eq!(ns, vec![0, 1, 2, 3]);
}
