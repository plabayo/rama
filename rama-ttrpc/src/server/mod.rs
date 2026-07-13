use std::io::Result as IoResult;

use ahash::HashMap;
use rama_core::io::Io;
use std::sync::Arc;

use rama_core::futures::pin_mut;
use rama_core::telemetry::tracing;
use tokio::task::JoinSet;

use crate::context::timeout::Timeout;
use crate::context::{Context, WithContext};
use crate::io::MessageIo;
use crate::server::method_handlers::MethodHandler;
use crate::service::Service;
use crate::types::frame::StreamFrame;
use crate::types::protos::{Request, Status};

pub(crate) mod controller;
pub(crate) mod method_handlers;

pub use controller::ServerController;

/// Method handlers keyed by service name, then method name, so dispatch is two borrow-based
/// `&str` lookups instead of allocating a `"/service/method"` path string on every request.
type MethodMap = HashMap<&'static str, HashMap<&'static str, Arc<dyn MethodHandler + Send + Sync>>>;

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
#[derive(Clone, Default)]
pub struct TtrpcServer {
    methods: Arc<MethodMap>,
}

impl TtrpcServer {
    /// Create a new, empty [`TtrpcServer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        ServerConnection::new_with_methods(stream, (*self.methods).clone())
            .start()
            .await
    }
}

pub struct ServerConnection {
    io: MessageIo,
    methods: MethodMap,
    tasks: JoinSet<IoResult<()>>,
    io_tasks: JoinSet<IoResult<()>>,
    controller: ServerController,
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

        Self::new_with_methods(connection, methods)
    }

    fn new_with_methods<C: Io>(connection: C, methods: MethodMap) -> Self {
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
        }
    }

    #[expect(clippy::needless_pass_by_value)]
    pub fn register(&mut self, service: impl Service) -> &mut Self {
        insert_methods(&mut self.methods, service.methods());
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
                    // imminent connection close. Best-effort: the send may not flush before teardown.
                    if self.controller.token.is_cancelled() {
                        self.io.tx.send(id, Status::unavailable("server is shutting down"));
                    } else {
                        self.handle_message(id, &frame);
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

    fn handle_message(&mut self, id: u32, frame: &StreamFrame) {
        let flags = frame.flags;

        let Some(mut stream) = self.io.stream(id) else {
            // The stream is not receiving any more messages.
            // This is probably a race condition between the stream finishing and
            // the cleanup of the stream forking.
            self.io.tx.send(id, Status::stream_in_use(id));
            return;
        };

        if (id % 2) != 1 {
            stream.tx.send(Status::invalid_stream_id(id));
            return;
        }

        let Ok(req) = frame.message.decode::<Request>() else {
            let ty = frame.message.ty;
            stream.tx.error(Status::expected_request(id, ty));
            return;
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
            stream.tx.error(Status::method_not_found(service, method));
            return;
        };

        self.tasks.spawn(
            async move {
                if let Err(status) = handler.handle(flags, payload, &mut stream).await {
                    stream.tx.error(status);
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
