//! CONNECT upgrades keep the local HTTP/2 stream's metadata and do not retain
//! their handshake messages or upgrade receivers.

#![expect(clippy::unwrap_used, clippy::expect_used, reason = "test fixtures")]

use rama_core::{
    ServiceInput,
    extensions::{Egress, Extension, Extensions, ExtensionsRef},
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    Body, Method, Request, Response, StatusCode, Version,
    conn::PeerH2Settings,
    io::upgrade::{self, OnUpgrade, Upgraded},
};
use rama_http_core::{client::conn, server, service::RamaHttpService};
use rama_net::extensions::StreamMultiplexed;
use std::{
    convert::Infallible,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::mpsc,
};

#[derive(Debug, PartialEq)]
struct Transport(&'static str);
impl Extension for Transport {}
#[derive(Debug, PartialEq)]
struct StreamMarker(usize);
impl Extension for StreamMarker {}
#[derive(Debug)]
struct MessageOnly;
impl Extension for MessageOnly {}
#[derive(Debug)]
struct DropProbe(Arc<AtomicUsize>);
impl Extension for DropProbe {}
impl Drop for DropProbe {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

// Observe the actual socket separately from its shared extension storage.
struct TrackedIo {
    inner: DuplexStream,
    _drop: DropProbe,
}
impl AsyncRead for TrackedIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for TrackedIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Session {
    sender: conn::http2::SendRequest<Body>,
    upgrades: mpsc::UnboundedReceiver<OnUpgrade>,
    client_extensions: Extensions,
    server_extensions: Extensions,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    socket_drops: [Arc<AtomicUsize>; 2],
}
impl Drop for Session {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn session(inherit_request: bool, accept_upgrade: bool, status: StatusCode) -> Session {
    let (tx, upgrades) = mpsc::unbounded_channel();
    let sequence = Arc::new(AtomicUsize::new(0));
    let service = service_fn(move |req: Request| {
        let tx = tx.clone();
        let sequence = sequence.clone();
        async move {
            req.extensions()
                .ingress()
                .unwrap()
                .insert(StreamMarker(sequence.fetch_add(1, Ordering::SeqCst)));
            req.extensions().insert(MessageOnly);
            if accept_upgrade {
                tx.send(req.extensions().get_ref::<OnUpgrade>().unwrap().clone())
                    .unwrap();
            }
            let extensions = if inherit_request {
                req.extensions().clone()
            } else {
                Extensions::new()
            };
            // A proxy response may carry unrelated outgoing transport metadata.
            let other_transport = Extensions::new();
            other_transport.insert(Transport("unrelated egress"));
            extensions.insert(Egress(other_transport));
            extensions.insert(MessageOnly);
            Ok::<_, Infallible>(
                Response::builder_with_extensions(extensions)
                    .version(Version::HTTP_2)
                    .status(status)
                    .body(Body::empty())
                    .unwrap(),
            )
        }
    });
    let (client_io, server_io) = tokio::io::duplex(65536);
    let socket_drops = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let client_io = ServiceInput::new(TrackedIo {
        inner: client_io,
        _drop: DropProbe(socket_drops[0].clone()),
    });
    let server_io = ServiceInput::new(TrackedIo {
        inner: server_io,
        _drop: DropProbe(socket_drops[1].clone()),
    });
    client_io.extensions().insert(Transport("client"));
    server_io.extensions().insert(Transport("server"));
    let client_extensions = client_io.extensions().clone();
    let server_extensions = server_io.extensions().clone();
    let server_task = tokio::spawn(async move {
        _ = server::conn::http2::Builder::new(Executor::new())
            .with_max_concurrent_streams(17)
            .serve_connection(server_io, RamaHttpService::new(service))
            .await;
    });
    let (sender, connection) = conn::http2::Builder::new(Executor::new())
        .handshake(client_io)
        .await
        .unwrap();
    let client_task = tokio::spawn(async move {
        _ = connection.await;
    });
    Session {
        sender,
        upgrades,
        client_extensions,
        server_extensions,
        tasks: vec![server_task, client_task],
        socket_drops,
    }
}

fn request() -> Request {
    let req = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri("https://example.test:443")
        .body(Body::empty())
        .unwrap();
    req.extensions().insert(MessageOnly);
    req
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("HTTP/2 operation timed out")
}

async fn connect(session: &mut Session) -> (Upgraded, Upgraded) {
    let res = bounded(session.sender.send_request(request()))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let response_settings = res.extensions().self_get_arc::<PeerH2Settings>().unwrap();
    assert_eq!(response_settings.0.config.max_concurrent_streams, Some(17));
    let client = bounded(upgrade::handle_upgrade(&res)).await.unwrap();
    let upgraded_settings = client
        .extensions()
        .self_get_arc::<PeerH2Settings>()
        .unwrap();
    assert!(Arc::ptr_eq(&response_settings, &upgraded_settings));
    assert_eq!(upgraded_settings.0.config.max_concurrent_streams, Some(17));
    let server = bounded(session.upgrades.recv()).await.unwrap();
    (client, bounded(server).await.unwrap())
}

#[tokio::test]
async fn h2_upgraded_metadata_belongs_to_local_stream() {
    for inherit_request in [false, true] {
        let mut session = session(inherit_request, true, StatusCode::OK).await;
        let (mut client, mut server) = connect(&mut session).await;
        assert_eq!(
            client.extensions().get_ref::<Transport>(),
            Some(&Transport("client"))
        );
        assert_eq!(
            server.extensions().get_ref::<Transport>(),
            Some(&Transport("server"))
        );
        assert_eq!(
            server.extensions().get_ref::<StreamMarker>(),
            Some(&StreamMarker(0))
        );
        for io in [&client, &server] {
            assert!(io.extensions().get_ref::<StreamMultiplexed>().is_some());
            assert!(io.extensions().get_ref::<MessageOnly>().is_none());
            assert!(io.extensions().get_ref::<OnUpgrade>().is_none());
        }
        client.extensions().insert(StreamMarker(42));
        assert!(
            session
                .client_extensions
                .get_ref::<StreamMarker>()
                .is_none()
        );
        assert!(
            session
                .server_extensions
                .get_ref::<StreamMarker>()
                .is_none()
        );
        let (other_client, other_server) = connect(&mut session).await;
        assert!(
            other_client
                .extensions()
                .get_ref::<StreamMarker>()
                .is_none()
        );
        assert_eq!(
            other_server.extensions().get_ref::<StreamMarker>(),
            Some(&StreamMarker(1))
        );
        assert_eq!(
            server.extensions().get_ref::<StreamMarker>(),
            Some(&StreamMarker(0))
        );
        // Extension selection must not disturb the tunnel's read/write halves.
        bounded(client.write_all(b"ping")).await.unwrap();
        let mut buf = [0; 4];
        bounded(server.read_exact(&mut buf)).await.unwrap();
        assert_eq!(&buf, b"ping");
        bounded(server.write_all(b"pong")).await.unwrap();
        bounded(client.read_exact(&mut buf)).await.unwrap();
        assert_eq!(&buf, b"pong");
    }
}

#[tokio::test]
async fn h2_dropping_unconsumed_client_upgrade_releases_response_and_stream() {
    let mut session = session(false, true, StatusCode::OK).await;
    let res = bounded(session.sender.send_request(request()))
        .await
        .unwrap();
    let mut server = bounded(bounded(session.upgrades.recv()).await.unwrap())
        .await
        .unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    res.extensions().insert(DropProbe(drops.clone()));
    drop(res);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "response owns its queued upgrade cyclically"
    );
    let mut buf = [0; 1];
    assert_eq!(bounded(server.read(&mut buf)).await.unwrap(), 0);
    // Cancelling one CONNECT must leave the multiplexed connection usable.
    _ = connect(&mut session).await;
}

#[tokio::test]
async fn h2_dropping_unconsumed_server_upgrade_closes_stream() {
    // The response deliberately retains the request's OnUpgrade. The upgraded
    // IO must not retain that response and keep its own receiver alive.
    let mut session = session(true, false, StatusCode::OK).await;
    let res = bounded(session.sender.send_request(request()))
        .await
        .unwrap();
    let mut client = bounded(upgrade::handle_upgrade(&res)).await.unwrap();
    let mut buf = [0; 1];
    assert_eq!(bounded(client.read(&mut buf)).await.unwrap(), 0);
}

#[tokio::test]
async fn h2_rejected_connect_cancels_server_upgrade() {
    let mut session = session(true, true, StatusCode::FORBIDDEN).await;
    let res = bounded(session.sender.send_request(request()))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(res.extensions().get_ref::<OnUpgrade>().is_none());
    bounded(bounded(session.upgrades.recv()).await.unwrap())
        .await
        .expect_err("rejected CONNECT must cancel the server upgrade");
}

#[tokio::test]
async fn h2_connection_shutdown_releases_transports_and_upgrade_metadata() {
    for consume_upgrade in [false, true] {
        let mut session = session(true, true, StatusCode::OK).await;
        let socket_drops = session.socket_drops.clone();
        let metadata_drops = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        session
            .client_extensions
            .insert(DropProbe(metadata_drops[0].clone()));
        session
            .server_extensions
            .insert(DropProbe(metadata_drops[1].clone()));
        let response = bounded(session.sender.send_request(request()))
            .await
            .unwrap();
        let upgrades = if consume_upgrade {
            let client = bounded(upgrade::handle_upgrade(&response)).await.unwrap();
            let server = bounded(bounded(session.upgrades.recv()).await.unwrap())
                .await
                .unwrap();
            Some((client, server))
        } else {
            None
        };
        drop(response);
        // Abort the connection drivers and release every application-held
        // connection handle, including unconsumed server upgrade receivers.
        drop(session);
        bounded(async {
            while socket_drops
                .iter()
                .any(|drops| drops.load(Ordering::SeqCst) == 0)
            {
                tokio::task::yield_now().await;
            }
        })
        .await;
        for drops in &socket_drops {
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
        if consume_upgrade {
            // An upgraded stream continues to own its metadata even after the
            // physical connection is gone.
            for drops in &metadata_drops {
                assert_eq!(drops.load(Ordering::SeqCst), 0);
            }
        }
        drop(upgrades);
        bounded(async {
            while metadata_drops
                .iter()
                .any(|drops| drops.load(Ordering::SeqCst) == 0)
            {
                tokio::task::yield_now().await;
            }
        })
        .await;
        for drops in &metadata_drops {
            assert_eq!(drops.load(Ordering::SeqCst), 1);
        }
    }
}
