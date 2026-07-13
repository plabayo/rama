//! End-to-end parity test: drive a ttRPC `Client` and `ServerConnection` against each other
//! over an in-memory `tokio::io::duplex` pair (no sockets, no codegen). This exercises the whole
//! stack — framing/codec, the request/response correlation, stream-id handling and dispatch —
//! which is exactly the shape a consumer (e.g. the NRI multiplexer) wires up: hand each half of a
//! stream to `Client::new` / `ServerConnection::new`.

use std::sync::Arc;

use std::time::Duration;

use rama_core::stream::wrappers::ReceiverStream;
use rama_ttrpc::__codegen_prelude::{
    ClientStreamingMethod, DuplexStreamingMethod, MethodHandler, RequestHandler as _,
    ServerStreamingMethod, Service, UnaryMethod,
};
use rama_ttrpc::{Client, ClientExt as _, Result, ServerConnection};

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
            (
                "/echo.Greeter/Collect",
                Arc::new(ClientStreamingMethod::new(
                    |input: ReceiverStream<EchoRequest>| async move {
                        use rama_core::futures::StreamExt as _;
                        let msgs: Vec<String> = input.map(|r| r.msg).collect().await;
                        Ok(EchoReply {
                            msg: format!("collected {}", msgs.join(",")),
                        })
                    },
                )),
            ),
            (
                "/echo.Greeter/Chat",
                Arc::new(DuplexStreamingMethod::new(
                    |input: ReceiverStream<EchoRequest>| {
                        rama_ttrpc::stream::stream_fn(move |mut yielder| async move {
                            use rama_core::futures::StreamExt as _;
                            let mut input = input;
                            while let Some(req) = input.next().await {
                                yielder
                                    .yield_item(Ok(EchoReply {
                                        msg: format!("echo {}", req.msg),
                                    }))
                                    .await;
                            }
                        })
                    },
                )),
            ),
            (
                // Never responds — used to exercise the client-side request timeout.
                "/echo.Greeter/Hang",
                Arc::new(UnaryMethod::new(|_req: EchoRequest| async move {
                    std::future::pending::<Result<EchoReply>>().await
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
            "echo.Greeter",
            "Hello",
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
                if let Some(server) = rama_ttrpc::get_server() {
                    server.shutdown();
                }
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
        .handle_unary_request("echo.Greeter", "Stop", EchoRequest { msg: String::new() })
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
async fn client_streaming_roundtrip() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    spawn_server(server_io);
    let client = Client::new(client_io);

    let input = rama_core::futures::stream::iter(vec![
        EchoRequest {
            msg: "a".to_owned(),
        },
        EchoRequest {
            msg: "b".to_owned(),
        },
        EchoRequest {
            msg: "c".to_owned(),
        },
    ]);

    let reply: EchoReply = client
        .handle_client_streaming_request("echo.Greeter", "Collect", input)
        .await
        .expect("client-streaming call should succeed");

    assert_eq!(reply.msg, "collected a,b,c");
}

#[tokio::test]
async fn duplex_roundtrip() {
    use rama_core::futures::StreamExt as _;

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    spawn_server(server_io);
    let client = Client::new(client_io);

    let input = rama_core::futures::stream::iter(vec![
        EchoRequest {
            msg: "x".to_owned(),
        },
        EchoRequest {
            msg: "y".to_owned(),
        },
    ]);

    let stream = client.handle_duplex_streaming_request("echo.Greeter", "Chat", input);
    let got: Vec<Result<EchoReply>> = Box::pin(stream).collect().await;

    let msgs: Vec<String> = got
        .into_iter()
        .map(|r| r.expect("stream item").msg)
        .collect();
    assert_eq!(msgs, vec!["echo x".to_owned(), "echo y".to_owned()]);
}

#[tokio::test]
async fn client_call_times_out_when_server_never_responds() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    spawn_server(server_io);
    let client = Client::new(client_io).with_timeout(Duration::from_millis(150));

    let result: Result<EchoReply> = client
        .handle_unary_request("echo.Greeter", "Hang", EchoRequest { msg: String::new() })
        .await;

    assert!(result.is_err(), "expected a timeout error");
}

#[tokio::test]
async fn server_streaming_roundtrip() {
    use rama_core::futures::StreamExt as _;

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    spawn_server(server_io);
    let client = Client::new(client_io);

    let stream = client.handle_server_streaming_request(
        "echo.Greeter",
        "Count",
        EchoRequest {
            msg: "abcd".to_owned(),
        },
    );
    let got: Vec<Result<CountReply>> = Box::pin(stream).collect().await;

    let ns: Vec<u32> = got.into_iter().map(|r| r.expect("stream item").n).collect();
    assert_eq!(ns, vec![0, 1, 2, 3]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_server_stream_aborts_the_work() {
    use rama_core::futures::StreamExt as _;

    struct Endless;
    impl Service for Endless {
        fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
            vec![(
                "/echo.Endless/Stream",
                Arc::new(ServerStreamingMethod::new(|_req: EchoRequest| {
                    rama_ttrpc::stream::stream_fn(|mut yielder| async move {
                        let mut n = 0u32;
                        loop {
                            yielder.yield_item(Ok(CountReply { n })).await;
                            n = n.wrapping_add(1);
                        }
                    })
                })),
            )]
        }
    }

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut server = ServerConnection::new(server_io);
        server.register(Endless);
        _ = server.start().await;
    });
    let client = Client::new(client_io);

    let mut stream = Box::pin(
        client.handle_server_streaming_request::<EchoRequest, CountReply>(
            "echo.Endless",
            "Stream",
            EchoRequest { msg: String::new() },
        ),
    );
    // Pull one item so the connection-owned work task is definitely spawned and running.
    let first = stream.next().await.expect("first item").expect("ok item");
    assert_eq!(first.n, 0);

    let metrics = tokio::runtime::Handle::current().metrics();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let before = metrics.num_alive_tasks();

    drop(stream);

    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = metrics.num_alive_tasks();

    assert!(
        after < before,
        "streaming work was not aborted when the client dropped the stream ({before} -> {after})"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_server_stream_consumer_backpressures_producer() {
    use rama_core::futures::StreamExt as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let produced = Arc::new(AtomicUsize::new(0));

    struct Endless {
        produced: Arc<AtomicUsize>,
    }
    impl Service for Endless {
        fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
            let produced = self.produced.clone();
            vec![(
                "/echo.Endless/Stream",
                Arc::new(ServerStreamingMethod::new(move |_req: EchoRequest| {
                    let produced = produced.clone();
                    rama_ttrpc::stream::stream_fn(move |mut yielder| async move {
                        let mut n = 0u32;
                        loop {
                            yielder.yield_item(Ok(CountReply { n })).await;
                            produced.fetch_add(1, Ordering::SeqCst);
                            n = n.wrapping_add(1);
                        }
                    })
                })),
            )]
        }
    }

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let service = Endless {
        produced: Arc::clone(&produced),
    };
    tokio::spawn(async move {
        let mut server = ServerConnection::new(server_io);
        server.register(service);
        _ = server.start().await;
    });
    let client = Client::new(client_io);

    let mut stream = Box::pin(
        client.handle_server_streaming_request::<EchoRequest, CountReply>(
            "echo.Endless",
            "Stream",
            EchoRequest { msg: String::new() },
        ),
    );
    // Read one item, then stop consuming (but keep the stream alive).
    let first = stream.next().await.expect("first item").expect("ok item");
    assert_eq!(first.n, 0);

    tokio::time::sleep(Duration::from_millis(200)).await;
    let c1 = produced.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let c2 = produced.load(Ordering::SeqCst);

    assert_eq!(
        c1,
        c2,
        "producer generated {} more messages while the consumer was idle (queue is unbounded)",
        c2 - c1
    );
}
