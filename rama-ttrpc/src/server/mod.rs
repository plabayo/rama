use std::io::Result as IoResult;

use ahash::HashMap;
use rama_core::io::Io;
use std::sync::Arc;

use rama_core::futures::FutureExt as _;
use rama_core::futures::pin_mut;
use rama_core::telemetry::tracing;
use rama_utils::macros::generate_set_and_with;
use tokio::task::JoinSet;

use crate::context::timeout::Timeout;
use crate::context::{Context, WithContext};
use crate::io::MessageIo;
use crate::server::method_handlers::MethodHandler;
use crate::service::Service;
use crate::types::frame::StreamFrame;
use crate::types::message::MessageType;
use crate::types::protos::{Request, Status};

pub(crate) mod controller;
pub(crate) mod method_handlers;

pub use controller::ServerController;

/// Method handlers keyed by service name, then method name, so dispatch is two borrow-based
/// `&str` lookups instead of allocating a `"/service/method"` path string on every request.
type MethodMap = HashMap<&'static str, HashMap<&'static str, Arc<dyn MethodHandler + Send + Sync>>>;

/// Default per-connection limit on concurrently-executing request handlers. Once reached, new
/// requests are rejected with `RESOURCE_EXHAUSTED` rather than dispatched. This bounds the handler
/// tasks, their per-stream buffers, and the encoded frames queued for the writer, each in-flight
/// stream self-throttles to +-one unwritten frame, so the writer queue is bounded by this cap.
///
/// Note the worst-case inbound memory a peer can pin is `this × per-stream buffer × 4 MiB`
/// (it must actually send those bytes); lower the cap for untrusted peers.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: usize = 1024;

/// Split each generated `"/service/method"` path and insert its handler into the two-level map.
fn insert_methods(
    map: &mut MethodMap,
    methods: Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)>,
) {
    for (path, handler) in methods {
        let Some((service, method)) = path.strip_prefix('/').and_then(|p| p.split_once('/')) else {
            tracing::warn!(
                path,
                "ignoring ttRPC method with a malformed path (expected /service/method)"
            );
            continue;
        };
        if map
            .entry(service)
            .or_default()
            .insert(method, handler)
            .is_some()
        {
            tracing::warn!(
                service,
                method,
                "overwriting a duplicate ttRPC method registration"
            );
        }
    }
}

/// A ttRPC server as a rama [`Service`](rama_core::Service): it serves one
/// [`ServerConnection`] per accepted stream, so it can be handed straight to a rama
/// listener (`rama-tcp`, `rama-unix`, ...) instead of writing the per-connection loop by hand.
///
/// For a single, already-established connection (e.g. one virtual stream of an NRI mux),
/// use the lower-level [`ServerConnection`] directly instead.
#[derive(Clone)]
pub struct TtrpcServer {
    methods: Arc<MethodMap>,
    max_concurrent_streams: usize,
}

impl Default for TtrpcServer {
    fn default() -> Self {
        Self {
            methods: Arc::default(),
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
        }
    }
}

impl TtrpcServer {
    /// Create a new, empty [`TtrpcServer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Set the maximum number of concurrently-executing request handlers per connection. Past
        /// this, requests are rejected with `RESOURCE_EXHAUSTED`. Defaults to
        /// [`DEFAULT_MAX_CONCURRENT_STREAMS`].
        pub fn max_concurrent_streams(mut self, max: usize) -> Self {
            self.max_concurrent_streams = max;
            self
        }
    }

    /// Register a (generated) ttRPC service's methods on this server.
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "builder-style registration mirrors the generated service API"
    )]
    pub fn register(mut self, service: impl Service) -> Self {
        insert_methods(Arc::make_mut(&mut self.methods), service.methods());
        self
    }
}

impl<IO> rama_core::Service<IO> for TtrpcServer
where
    IO: rama_core::io::Io,
{
    type Output = ();
    type Error = std::io::Error;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        ServerConnection::new_with_methods(stream, self.methods.clone())
            .with_max_concurrent_streams(self.max_concurrent_streams)
            .start()
            .await
    }
}

pub struct ServerConnection {
    io: MessageIo,
    methods: Arc<MethodMap>,
    tasks: JoinSet<IoResult<()>>,
    io_tasks: JoinSet<IoResult<()>>,
    controller: ServerController,
    max_concurrent_streams: usize,
}

impl ServerConnection {
    pub fn new<C: Io>(connection: C) -> Self {
        Self::new_with(connection, [])
    }

    pub fn new_with<'a, C: Io>(
        connection: C,
        services: impl IntoIterator<Item = &'a dyn Service>,
    ) -> Self {
        let mut methods = MethodMap::default();
        for service in services {
            insert_methods(&mut methods, service.methods());
        }

        Self::new_with_methods(connection, Arc::new(methods))
    }

    fn new_with_methods<C: Io>(connection: C, methods: Arc<MethodMap>) -> Self {
        let mut io_tasks = JoinSet::<IoResult<()>>::new();
        let io = MessageIo::new(
            &mut io_tasks,
            connection,
            crate::io::DEFAULT_MAX_BUFFERED_FRAMES,
        );
        let controller = ServerController::default();
        let tasks = JoinSet::<IoResult<()>>::new();

        Self {
            io,
            methods,
            tasks,
            io_tasks,
            controller,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
        }
    }

    generate_set_and_with! {
        /// Set the maximum number of concurrently-executing request handlers on this connection.
        /// Once reached, further requests are rejected with `RESOURCE_EXHAUSTED` until a handler
        /// completes. Defaults to [`DEFAULT_MAX_CONCURRENT_STREAMS`].
        pub fn max_concurrent_streams(mut self, max: usize) -> Self {
            self.max_concurrent_streams = max;
            self
        }
    }

    #[expect(clippy::needless_pass_by_value)]
    pub fn register(&mut self, service: impl Service) -> &mut Self {
        insert_methods(Arc::make_mut(&mut self.methods), service.methods());
        self
    }

    pub async fn start(&mut self) -> IoResult<()> {
        let shutdown = self.controller.token.clone();
        let shutdown = shutdown.cancelled();
        pin_mut!(shutdown);
        loop {
            // Once a shutdown is requested we drain: stop dispatching new requests and finish as
            // soon as the in-flight tasks are done.
            if self.controller.token.is_cancelled() && self.tasks.is_empty() {
                break;
            }
            tokio::select! {
                Some(res) = self.io_tasks.join_next() => {
                    res??;
                },
                Some(res) = self.tasks.join_next() => {
                    res??;
                },
                Some((id, frame)) = self.io.rx.recv() => {
                    // `recv` has already routed any in-flight stream data internally, so this is a
                    // brand-new request. While draining we no longer dispatch it; reject it with
                    // `UNAVAILABLE` so the client gets an explicit signal instead of only seeing the
                    // imminent connection close.
                    if self.controller.token.is_cancelled() {
                        _ = self.io.tx.send(id, Status::unavailable("server is shutting down")).await;
                    } else {
                        self.handle_message(id, &frame).await;
                    }
                },
                () = &mut shutdown, if self.tasks.is_empty() => break,
                else => {
                    // no more messages to read, and no more tasks to process; we are done
                    break;
                },
            }
        }
        Ok(())
    }

    // Rejections await their `SendResult` (which resolves once the writer has flushed the
    // frame), parking this dispatch loop instead of the unbounded writer queue: a peer
    // flooding invalid requests without reading our responses gets TCP backpressure, not an
    // unbounded pile of queued error frames.
    async fn handle_message(&mut self, id: u32, frame: &StreamFrame) {
        let flags = frame.flags;
        let ty = frame.message.ty;

        // Only Request (new call) and Data (late frame for a finished stream, answered below)
        // are meaningful here. Anything else is ignored for future compatibility, mirroring
        // the Go server (containerd/ttrpc server.go `run`: non-Request/Data types are skipped).
        if !matches!(ty, MessageType::Request | MessageType::Data) {
            tracing::debug!(id, ?ty, "ignoring ttRPC frame of unhandled message type");
            return;
        }

        let Some(mut stream) = self.io.stream(id) else {
            // The stream is not receiving any more messages.
            // This is probably a race condition between the stream finishing and
            // the cleanup of the stream forking.
            _ = self.io.tx.send(id, Status::stream_in_use(id)).await;
            return;
        };

        if (id % 2) != 1 {
            _ = stream.tx.send(Status::invalid_stream_id(id)).await;
            return;
        }

        let req = match frame.message.decode::<Request>() {
            Ok(req) => req,
            // A Data frame here means the stream it belonged to is gone (or never existed).
            Err(_) if ty != MessageType::Request => {
                _ = stream.tx.error(Status::expected_request(id, ty)).await;
                return;
            }
            // A Request that fails to decode: oversized payloads answer with
            // RESOURCE_EXHAUSTED (Go parity, containerd/ttrpc server.go handling of
            // `recv` status errors), anything else with INVALID_ARGUMENT.
            Err(err) => {
                _ = stream.tx.error(Status::failed_to_decode(err)).await;
                return;
            }
        };

        let Request {
            service,
            method,
            payload,
            timeout_nano,
            metadata,
        } = req;

        let ctx = Context {
            metadata: metadata.as_slice().into(),
            timeout: Timeout::from_nanos(timeout_nano),
        };

        // Two borrow-based `&str` lookups, no per-request path string to allocate.
        let Some(handler) = self
            .methods
            .get(service.as_ref())
            .and_then(|methods| methods.get(method.as_ref()))
            .cloned()
        else {
            _ = stream
                .tx
                .error(Status::method_unimplemented(service, method))
                .await;
            return;
        };

        // Shed load past the per-connection cap. `recv` has already routed in-flight stream data,
        // so rejecting here bounds concurrent handlers (and, transitively, buffered frames and
        // memory) without stalling the reader for streams already running.
        if self.tasks.len() >= self.max_concurrent_streams {
            _ = stream
                .tx
                .error(Status::resource_exhausted(
                    "too many concurrent requests on this connection",
                ))
                .await;
            return;
        }

        self.tasks.spawn(
            async move {
                // Contain handler panics to their request — answer INTERNAL and keep the
                // connection's other calls alive. (The Go implementation has no recover here;
                // a panicking handler takes the whole process down.)
                let result =
                    std::panic::AssertUnwindSafe(handler.handle(flags, payload, &mut stream))
                        .catch_unwind()
                        .await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(status)) => {
                        _ = stream.tx.error(status).await;
                    }
                    Err(_panic) => {
                        _ = stream
                            .tx
                            .error(Status::internal("method handler panicked"))
                            .await;
                    }
                }
                Ok(())
            }
            .with_context(ctx, self.controller.clone()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::StreamIo;
    use crate::types::flags::Flags;
    use crate::types::protos::raw_bytes::RawBytes;
    use std::future::Future;
    use std::pin::Pin;

    struct Dummy;
    impl MethodHandler for Dummy {
        fn handle<'a>(
            &'a self,
            _flags: Flags,
            _payload: RawBytes,
            _stream: &'a mut StreamIo,
        ) -> Pin<Box<dyn Future<Output = crate::Result<()>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn dummy() -> Arc<dyn MethodHandler + Send + Sync> {
        Arc::new(Dummy)
    }

    #[test]
    fn insert_methods_drops_malformed_and_overwrites_duplicates() {
        let mut map = MethodMap::default();
        insert_methods(
            &mut map,
            vec![
                ("/svc/m", dummy()),
                ("no-slash", dummy()), // malformed path -> dropped
                ("/svc/m", dummy()),   // duplicate -> last wins, no extra entry
            ],
        );

        assert_eq!(map.len(), 1, "only the well-formed service is registered");
        let svc = map.get("svc").expect("service registered");
        assert_eq!(
            svc.len(),
            1,
            "duplicate method must not create a second entry"
        );
        assert!(svc.contains_key("m"));
    }

    /// Go parity: unknown service/method answers `UNIMPLEMENTED`
    /// (containerd/ttrpc services.go `codes.Unimplemented`), which capability-probing
    /// clients such as NRI branch on — `NOT_FOUND` would break that detection.
    #[tokio::test]
    async fn unknown_method_is_rejected_with_unimplemented() {
        use crate::io::MessageIo;
        use crate::types::protos::{Request, Response};
        use std::borrow::Cow;

        struct One;
        impl Service for One {
            fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
                vec![("/svc/m", dummy())]
            }
        }

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut server = ServerConnection::new(server_io);
            server.register(One);
            _ = server.start().await;
        });

        let mut tasks = JoinSet::<std::io::Result<()>>::new();
        let mut io = MessageIo::new(&mut tasks, client_io, 64);
        io.tx
            .send(
                1,
                StreamFrame {
                    flags: crate::types::flags::Flags::empty(),
                    message: Request {
                        service: Cow::Borrowed("svc"),
                        method: Cow::Borrowed("nope"),
                        payload: (),
                        metadata: vec![],
                        timeout_nano: 0,
                    },
                },
            )
            .await
            .expect("send request");

        let (id, frame) = io.rx.recv().await.expect("a response frame");
        assert_eq!(id, 1);
        let response: Response = frame.message.decode().expect("decode response");
        assert_eq!(
            response.status.unwrap_or_default().code,
            crate::Code::Unimplemented as i32,
            "an unknown method must be answered with UNIMPLEMENTED"
        );
    }

    /// Go parity (containerd/ttrpc channel.go `recv` + server.go): an oversized frame is
    /// discarded and answered with `RESOURCE_EXHAUSTED` on its own stream; the connection
    /// (and the requests behind the oversized frame) keeps working.
    #[tokio::test]
    async fn oversized_frame_is_answered_per_stream_and_connection_survives() {
        use crate::service::UnaryMethod;
        use crate::types::flags::Flags;
        use crate::types::protos::Request;
        use rama_utils::octets::mib;
        use std::borrow::Cow;
        use tokio::io::AsyncWriteExt as _;

        struct Echo;
        impl Service for Echo {
            fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
                vec![(
                    "/svc/echo",
                    Arc::new(UnaryMethod::new(|_input: ()| async { Ok(()) })),
                )]
            }
        }

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut server = ServerConnection::new(server_io);
            server.register(Echo);
            _ = server.start().await;
        });

        let (client_rd, mut client_wr) = tokio::io::split(client_io);

        // Frame 1 (stream id 1): a Request whose declared length is one MiB past the cap.
        let oversized_len = mib(4) + mib(1);
        let mut header = Vec::with_capacity(crate::types::frame::HEADER_LENGTH);
        #[expect(clippy::cast_possible_truncation)]
        header.extend_from_slice(&(oversized_len as u32).to_be_bytes());
        header.extend_from_slice(&1u32.to_be_bytes()); // stream id
        header.push(1); // type: Request
        header.push(0); // flags
        client_wr.write_all(&header).await.expect("write header");
        client_wr
            .write_all(&vec![0u8; oversized_len])
            .await
            .expect("write oversized payload");

        // Frame 2 (stream id 3): a well-formed request behind the oversized one.
        let frame = crate::types::frame::Frame {
            id: 3,
            flags: Flags::empty(),
            message: Request {
                service: Cow::Borrowed("svc"),
                method: Cow::Borrowed("echo"),
                payload: (),
                metadata: vec![],
                timeout_nano: 0,
            },
        };
        let bytes = crate::types::encoding::Encodeable::encode_to_bytes(&frame).expect("encode");
        client_wr.write_all(&bytes).await.expect("write request");

        // Reuse the demuxing receiver for the raw read half.
        let mut tasks = JoinSet::<std::io::Result<()>>::new();
        let mut rx = crate::io::MessageReceiver::new(&mut tasks, client_rd, 64);
        async fn recv(rx: &mut crate::io::MessageReceiver) -> (u32, i32) {
            let (id, frame) = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                .await
                .expect("a response in time")
                .expect("a response frame");
            let response: crate::types::protos::Response =
                frame.message.decode().expect("decode response");
            (id, response.status.unwrap_or_default().code)
        }

        let (id, code) = recv(&mut rx).await;
        assert_eq!(id, 1, "the oversized request is answered on its stream");
        assert_eq!(
            code,
            crate::Code::ResourceExhausted as i32,
            "oversized frames are rejected with RESOURCE_EXHAUSTED"
        );

        let (id, code) = recv(&mut rx).await;
        assert_eq!(id, 3, "the request behind the oversized frame is served");
        assert_eq!(code, crate::Code::Ok as i32, "the connection must survive");
    }

    /// Go parity (containerd/ttrpc server.go `run`: non-Request/Data message types are
    /// skipped "for future compat"): an unknown frame type is ignored, not answered.
    #[tokio::test]
    async fn unknown_message_type_is_ignored() {
        use crate::types::flags::Flags;
        use crate::types::protos::{Request, Response};
        use std::borrow::Cow;
        use tokio::io::AsyncWriteExt as _;

        struct Echo;
        impl Service for Echo {
            fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
                vec![(
                    "/svc/echo",
                    Arc::new(crate::service::UnaryMethod::new(|_input: ()| async {
                        Ok(())
                    })),
                )]
            }
        }

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut server = ServerConnection::new(server_io);
            server.register(Echo);
            _ = server.start().await;
        });

        let (client_rd, mut client_wr) = tokio::io::split(client_io);

        // Frame 1 (stream id 5): an empty frame with an unknown message type.
        let mut header = vec![0u8; 4]; // data length 0
        header.extend_from_slice(&5u32.to_be_bytes()); // stream id
        header.push(9); // type: unknown
        header.push(0); // flags
        client_wr.write_all(&header).await.expect("write unknown");

        // Frame 2 (stream id 7): a well-formed request.
        let frame = crate::types::frame::Frame {
            id: 7,
            flags: Flags::empty(),
            message: Request {
                service: Cow::Borrowed("svc"),
                method: Cow::Borrowed("echo"),
                payload: (),
                metadata: vec![],
                timeout_nano: 0,
            },
        };
        let bytes = crate::types::encoding::Encodeable::encode_to_bytes(&frame).expect("encode");
        client_wr.write_all(&bytes).await.expect("write request");

        let mut tasks = JoinSet::<std::io::Result<()>>::new();
        let mut rx = crate::io::MessageReceiver::new(&mut tasks, client_rd, 64);
        // The server answers frames in order, so the first (and only) response arriving
        // for stream 7 proves the unknown-type frame on stream 5 was silently ignored.
        let (id, frame) = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("a response in time")
            .expect("a response frame");
        assert_eq!(id, 7, "the unknown-type frame must not be answered");
        let response: Response = frame.message.decode().expect("decode response");
        assert_eq!(
            response.status.unwrap_or_default().code,
            crate::Code::Ok as i32
        );
    }

    #[tokio::test]
    async fn concurrency_cap_rejects_excess_with_resource_exhausted() {
        use crate::io::MessageIo;
        use crate::service::UnaryMethod;
        use crate::types::protos::{Request, Response};
        use std::borrow::Cow;
        use tokio::sync::Notify;

        let release = Arc::new(Notify::new());

        struct BlockService {
            release: Arc<Notify>,
        }
        impl Service for BlockService {
            fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
                let rel = self.release.clone();
                vec![(
                    "/svc/block",
                    Arc::new(UnaryMethod::new(move |_input: ()| {
                        let rel = rel.clone();
                        async move {
                            rel.notified().await; // occupy the slot until the test releases us
                            Ok(())
                        }
                    })),
                )]
            }
        }

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let service = BlockService {
            release: Arc::clone(&release),
        };
        let server_task = tokio::spawn(async move {
            let mut server = ServerConnection::new(server_io).with_max_concurrent_streams(1);
            server.register(service);
            server.start().await
        });

        let mut tasks = JoinSet::<std::io::Result<()>>::new();
        let mut io = MessageIo::new(&mut tasks, client_io, 64);
        let request = || StreamFrame {
            flags: Flags::empty(),
            message: Request {
                service: Cow::Borrowed("svc"),
                method: Cow::Borrowed("block"),
                payload: (),
                metadata: vec![],
                timeout_nano: 0,
            },
        };

        // First request occupies the only slot and blocks; the second exceeds the cap.
        io.tx.send(1, request()).await.expect("send first");
        io.tx.send(3, request()).await.expect("send second");

        let (id, frame) = tokio::time::timeout(std::time::Duration::from_secs(2), io.rx.recv())
            .await
            .expect("the over-cap request must be answered, not left in flight")
            .expect("a response frame");
        assert_eq!(id, 3, "the rejected (second) request is answered");
        let response: Response = frame.message.decode().expect("decode response");
        let status = response.status.unwrap_or_default();
        assert_eq!(
            status.code,
            crate::Code::ResourceExhausted as i32,
            "over-cap request must be rejected with RESOURCE_EXHAUSTED"
        );

        release.notify_one();
        _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
    }

    /// A panicking handler is contained to its request: the caller gets INTERNAL and the
    /// connection keeps serving. (Deliberately stronger than Go, which has no recover in
    /// the handler goroutine and crashes the process.)
    #[tokio::test]
    async fn handler_panic_is_contained_to_the_request() {
        use crate::client::request_handlers::RequestHandler as _;
        use crate::service::UnaryMethod;

        struct PanicService;
        impl Service for PanicService {
            fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
                vec![
                    (
                        "/svc/boom",
                        Arc::new(UnaryMethod::new(|_input: ()| async {
                            panic!("handler exploded");
                            #[expect(unreachable_code)]
                            crate::Result::<()>::Ok(())
                        })),
                    ),
                    (
                        "/svc/echo",
                        Arc::new(UnaryMethod::new(|_input: ()| async { Ok(()) })),
                    ),
                ]
            }
        }

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut server = ServerConnection::new(server_io);
            server.register(PanicService);
            _ = server.start().await;
        });
        let client = crate::Client::new(client_io);

        let err = client
            .handle_unary_request::<(), ()>("svc", "boom", ())
            .await
            .expect_err("a panicking handler must answer with an error");
        assert_eq!(
            err.code,
            crate::Code::Internal as i32,
            "handler panic must surface as INTERNAL"
        );

        client
            .handle_unary_request::<(), ()>("svc", "echo", ())
            .await
            .expect("the connection must keep serving after a handler panic");
    }

    /// A peer flooding requests that only produce rejections — while never reading our
    /// responses — must be backpressured (rejections await the writer flush), not buffered
    /// without bound in the writer queue.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejection_flood_is_backpressured() {
        use crate::types::flags::Flags;
        use crate::types::protos::Request;
        use std::borrow::Cow;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncWriteExt as _;

        let (client_io, server_io) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut server = ServerConnection::new(server_io); // no methods registered
            _ = server.start().await;
        });

        let (client_rd, mut client_wr) = tokio::io::split(client_io);
        // Hold the read half open but never read: responses pile up in the transport...
        let _client_rd = client_rd;

        const FLOOD: usize = 10_000;
        let written = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&written);
        tokio::spawn(async move {
            for n in 0..FLOOD {
                // Even stream ids: every one of these is answered with a rejection.
                #[expect(clippy::cast_possible_truncation)]
                let frame = crate::types::frame::Frame {
                    id: 2 * (n as u32 + 1),
                    flags: Flags::empty(),
                    message: Request {
                        service: Cow::Borrowed("svc"),
                        method: Cow::Borrowed("m"),
                        payload: (),
                        metadata: vec![],
                        timeout_nano: 0,
                    },
                };
                let bytes =
                    crate::types::encoding::Encodeable::encode_to_bytes(&frame).expect("encode");
                if client_wr.write_all(&bytes).await.is_err() {
                    break;
                }
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });

        // ...so the server must park its dispatch loop on the unflushed rejection and stop
        // reading, which in turn blocks the flooding writer well short of the full flood.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let count = written.load(Ordering::SeqCst);
        assert!(
            count < FLOOD / 10,
            "server absorbed {count} of {FLOOD} rejection-only requests; writer queue unbounded"
        );
    }

    #[tokio::test]
    async fn shutdown_stops_dispatching_new_requests() {
        use crate::get_server;
        use crate::io::MessageIo;
        use crate::service::UnaryMethod;
        use crate::types::protos::Request;
        use std::borrow::Cow;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::Notify;

        let echo_count = Arc::new(AtomicUsize::new(0));
        let shutdown_done = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());

        struct DrainService {
            echo_count: Arc<AtomicUsize>,
            shutdown_done: Arc<Notify>,
            release: Arc<Notify>,
        }
        impl Service for DrainService {
            fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)> {
                let (sd, rel) = (self.shutdown_done.clone(), self.release.clone());
                let ec = self.echo_count.clone();
                vec![
                    (
                        "/svc/trigger",
                        Arc::new(UnaryMethod::new(move |_input: ()| {
                            let (sd, rel) = (sd.clone(), rel.clone());
                            async move {
                                if let Some(server) = get_server() {
                                    server.shutdown();
                                }
                                sd.notify_one();
                                rel.notified().await; // stay in-flight until the test releases us
                                Ok(())
                            }
                        })),
                    ),
                    (
                        "/svc/echo",
                        Arc::new(UnaryMethod::new(move |_input: ()| {
                            let ec = ec.clone();
                            async move {
                                ec.fetch_add(1, Ordering::SeqCst);
                                Ok(())
                            }
                        })),
                    ),
                ]
            }
        }

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let service = DrainService {
            echo_count: Arc::clone(&echo_count),
            shutdown_done: Arc::clone(&shutdown_done),
            release: Arc::clone(&release),
        };
        let server_task = tokio::spawn(async move {
            let mut server = ServerConnection::new(server_io);
            server.register(service);
            server.start().await
        });

        // Raw client so we can fire new requests without awaiting their responses.
        let mut tasks = JoinSet::<std::io::Result<()>>::new();
        let mut io = MessageIo::new(&mut tasks, client_io, 64);

        let request = |method: &'static str| StreamFrame {
            flags: Flags::empty(),
            message: Request {
                service: Cow::Borrowed("svc"),
                method: Cow::Borrowed(method),
                payload: (),
                metadata: vec![],
                timeout_nano: 0,
            },
        };

        io.tx
            .send(1, request("trigger"))
            .await
            .expect("send trigger");
        // Wait until the handler has actually requested the shutdown.
        shutdown_done.notified().await;

        // Now the server is draining; a new request must NOT be dispatched.
        io.tx.send(3, request("echo")).await.expect("send echo");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            echo_count.load(Ordering::SeqCst),
            0,
            "a new request was dispatched after shutdown was requested"
        );

        // ...and it is answered with UNAVAILABLE rather than silently dropped.
        let (id, frame) = tokio::time::timeout(std::time::Duration::from_secs(1), io.rx.recv())
            .await
            .expect("a rejection response should arrive")
            .expect("a response frame");
        assert_eq!(id, 3, "the rejected request is answered on its own stream");
        let response: crate::types::protos::Response =
            frame.message.decode().expect("decode response");
        assert_eq!(
            response.status.unwrap_or_default().code,
            crate::Code::Unavailable as i32,
            "a request arriving during drain must be rejected with UNAVAILABLE"
        );

        // Release the in-flight request; the server should now drain and `start` return.
        release.notify_one();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), server_task).await;
        assert!(
            result.is_ok(),
            "server did not drain and shut down under continued traffic"
        );
    }
}
