//! Exercise `rama send ws(s)://` through its executable over HTTP/1.1, HTTP/2 and HTTP/3.

#![cfg(test)]

use parking_lot::Mutex;
use rama::{
    Layer, Service,
    crypto::pem::PemEncode as _,
    graceful::Shutdown,
    http::{
        Request, Response, Version,
        header::{HOST, SEC_WEBSOCKET_EXTENSIONS},
        io::upgrade::{Upgraded, handle_upgrade},
        layer::error_handling::ErrorHandlerLayer,
        layer::validate_request::ValidateRequestHeaderLayer,
        server::HttpServer,
        service::web::Router,
        ws::handshake::server::WebSocketAcceptor,
    },
    layer::{ArcLayer, ConsumeErrLayer},
    net::{
        address::{Domain, SocketAddress},
        tls::ApplicationProtocol,
        user::credentials::basic,
    },
    quic::{Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::{
        boring::server::TlsAcceptorLayer,
        server::{
            CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, SelfSignedCaConfig,
            ServerAuthData, TlsServerConfig,
        },
    },
    utils::fs::{TempDir, tempdir},
};
use std::{
    collections::VecDeque,
    convert::Infallible,
    error::Error,
    net::SocketAddr,
    path::PathBuf,
    process::{Output, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs,
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::{Child, ChildStdin, Command},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(20);

struct Fixture {
    directory: TempDir,
    ca: PathBuf,
    auth: ServerAuthData,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        Self::with_config(GeneratedServerAuthConfig::default()).await
    }

    /// A server certificate valid for `name` only.
    async fn for_name(name: &'static str) -> TestResult<Self> {
        Self::with_config(GeneratedServerAuthConfig::GeneratedCa {
            ca: SelfSignedCaConfig::default(),
            leaf: LeafCertRequest {
                identities: vec![CertificateIdentity::Dns(Domain::from_static(name))],
                ..LeafCertRequest::default()
            },
        })
        .await
    }

    async fn with_config(config: GeneratedServerAuthConfig) -> TestResult<Self> {
        let directory = tempdir()?;
        let auth = ServerAuthData::new_generated(config)?;
        let ca = directory.path().join("ca.pem");
        let mut pem = Vec::new();
        for cert in &auth.cert_chain {
            pem.extend_from_slice(cert.to_pem().as_bytes());
        }
        fs::write(&ca, pem).await?;
        Ok(Self {
            directory,
            ca,
            auth,
        })
    }

    /// Run `rama send` with `input` on stdin, as a script or pipe would.
    async fn send(&self, url: &str, args: &[&str], input: &[u8]) -> TestResult<Output> {
        let mut child = self.spawn(url, args)?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(input).await?;
        drop(stdin);
        Ok(timeout(DEADLINE, child.wait_with_output()).await??)
    }

    /// Run `rama send` fed with `input` by a writer that never closes stdin.
    async fn send_keeping_stdin_open(
        &self,
        url: &str,
        args: &[&str],
        input: Vec<u8>,
    ) -> TestResult<Output> {
        let (child, writer) = self.spawn_feeding(url, args, input)?;
        let output = timeout(DEADLINE, child.wait_with_output()).await??;
        // The process exited while its stdin was still open.
        drop(writer.await??);
        Ok(output)
    }

    fn spawn_feeding(
        &self,
        url: &str,
        args: &[&str],
        input: Vec<u8>,
    ) -> TestResult<(Child, JoinHandle<std::io::Result<ChildStdin>>)> {
        let mut child = self.spawn(url, args)?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let writer = tokio::spawn(async move {
            stdin.write_all(&input).await?;
            Ok(stdin)
        });
        Ok((child, writer))
    }

    fn spawn(&self, url: &str, args: &[&str]) -> TestResult<Child> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rama"));
        let no_proxy = if args.contains(&"--proxy") { "" } else { "*" };
        command
            .kill_on_drop(true)
            .arg("send")
            .arg(url)
            .args(args)
            .arg("--trace")
            .arg(self.directory.path().join("trace.log"))
            .env("SSL_CERT_FILE", &self.ca)
            .env_remove("SSL_CERT_DIR")
            .env("NO_PROXY", no_proxy)
            .env("no_proxy", no_proxy)
            .env("RUST_LOG", "off")
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for variable in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            command.env_remove(variable);
        }
        Ok(command.spawn()?)
    }
}

struct WsServer {
    address: SocketAddr,
    endpoint: Option<Endpoint>,
    stop: oneshot::Sender<()>,
    shutdown: Shutdown,
}

impl WsServer {
    /// A `wss://…/echo` WebSocket echo server on `version`.
    async fn echo(
        auth: ServerAuthData,
        version: Version,
        extended_connect: bool,
    ) -> TestResult<Self> {
        let echo = ConsumeErrLayer::trace_as_debug()
            .into_layer(WebSocketAcceptor::new().into_echo_service());
        Self::start(auth, version, extended_connect, echo).await
    }

    /// A `wss://…/echo` WebSocket server on `version`, handled by `ws`.
    async fn start<S>(
        auth: ServerAuthData,
        version: Version,
        extended_connect: bool,
        ws: S,
    ) -> TestResult<Self>
    where
        S: Service<Request, Output = Response, Error = Infallible> + Clone,
    {
        let (stop, stopped) = oneshot::channel::<()>();
        let shutdown = Shutdown::new(stopped);
        let executor = Executor::graceful(shutdown.guard());
        let echo = || ws.clone();
        let tls = TlsServerConfig::new().with_server_auth(auth);
        if version == Version::HTTP_3 {
            let tls = tls.with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
            let mut server = HttpServer::new_http3(executor.clone());
            server.http3_mut().extended_connect = extended_connect;
            let mut transport = TransportConfig::default();
            server.http3().configure_transport(&mut transport)?;
            let mut config = ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())?;
            config.set_transport_config(Arc::new(transport));
            let endpoint = Endpoint::build(executor.clone())
                .with_server_config(config)
                .bind_address(SocketAddress::local_ipv4(0))
                .await?;
            let address = endpoint.local_addr()?;
            let service = server.service(
                (ArcLayer::new(), ErrorHandlerLayer::new())
                    .into_layer(Router::new().with_connect("/echo", echo())),
            );
            executor.spawn_task({
                let endpoint = endpoint.clone();
                let executor = executor.clone();
                async move {
                    while let Some(incoming) = endpoint.accept().await {
                        let service = service.clone();
                        executor.spawn_task(async move {
                            if let Ok(connection) = incoming.await {
                                _ = rama::Service::serve(&service, connection).await;
                            }
                        });
                    }
                }
            });
            return Ok(Self {
                address,
                endpoint: Some(endpoint),
                stop,
                shutdown,
            });
        }
        let tls = if version == Version::HTTP_2 {
            tls.with_alpn_http_2()
        } else {
            tls.with_alpn_http_1()
        };
        let listener =
            TcpListener::bind_address(SocketAddress::local_ipv4(0), executor.clone()).await?;
        let address = listener.local_addr()?;
        let mut server = HttpServer::auto(executor.clone());
        server.h2_mut().set_enable_connect_protocol();
        let service = TlsAcceptorLayer::new(tls).into_layer(
            server.service(
                (ArcLayer::new(), ErrorHandlerLayer::new()).into_layer(
                    Router::new()
                        .with_get("/echo", echo())
                        .with_connect("/echo", echo()),
                ),
            ),
        );
        executor.spawn_task(listener.serve(service));
        Ok(Self {
            address,
            endpoint: None,
            stop,
            shutdown,
        })
    }

    fn url(&self) -> String {
        format!("wss://localhost:{}/echo", self.address.port())
    }

    async fn close(self) -> TestResult {
        self.stop.send(()).unwrap_or_default();
        if let Some(endpoint) = self.endpoint {
            endpoint.close(0u32, b"test complete");
            timeout(DEADLINE, endpoint.shutdown()).await?;
        }
        self.shutdown.shutdown_with_limit(DEADLINE).await?;
        Ok(())
    }
}

/// A message larger than every flow-control window on the way.
const LARGE: usize = 8 * 1024 * 1024;
const CLOSE_NORMAL: [u8; 2] = 1000u16.to_be_bytes();

fn check(condition: bool, violation: &'static str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(violation.into())
    }
}

/// What the raw peer does on the wire with the next WebSocket it accepts.
enum Scenario {
    /// Close first, then expect a masked close reply and an orderly end (not a reset).
    CloseFirst,
    /// Echo `hello`, answer the client's close and expect an orderly end.
    CloseSecond,
    /// Send a large message while the client's own large message is stuck mid-frame.
    Duplex,
    /// Close while the client's large message is stuck mid-frame.
    CloseDuringSend,
    /// Stop reading mid-frame, tell the test, and once released expect the (killed)
    /// client's message to be aborted.
    Stall(oneshot::Sender<()>, oneshot::Receiver<()>),
    /// Expect these text messages, then a client close with this status (none: empty).
    Lines(&'static [&'static str], Option<u16>),
}

struct FrameHeader {
    first: u8,
    len: usize,
    mask: Option<[u8; 4]>,
}

async fn read_header(io: &mut Upgraded) -> std::io::Result<FrameHeader> {
    let first = io.read_u8().await?;
    let second = io.read_u8().await?;
    let len = match second & 0x7f {
        126 => usize::from(io.read_u16().await?),
        127 => usize::try_from(io.read_u64().await?).map_err(std::io::Error::other)?,
        len => usize::from(len),
    };
    let mask = if second & 0x80 == 0 {
        None
    } else {
        let mut mask = [0; 4];
        io.read_exact(&mut mask).await?;
        Some(mask)
    };
    Ok(FrameHeader { first, len, mask })
}

async fn read_payload(io: &mut Upgraded, header: &FrameHeader) -> std::io::Result<Vec<u8>> {
    let mut payload = vec![0; header.len];
    io.read_exact(&mut payload).await?;
    if let Some(mask) = header.mask {
        for (byte, mask) in payload.iter_mut().zip(mask.iter().cycle()) {
            *byte ^= mask;
        }
    }
    Ok(payload)
}

/// An unmasked server frame (RFC 6455 §5.1).
fn server_frame(first: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![first];
    match payload.len() {
        len @ ..126 => frame.push(u8::try_from(len).expect("short length")),
        len @ ..=0xffff => {
            frame.push(126);
            frame.extend_from_slice(&u16::try_from(len).expect("medium length").to_be_bytes());
        }
        len => {
            frame.push(127);
            frame.extend_from_slice(&u64::try_from(len).expect("long length").to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}

/// Read one client frame, which must be masked (RFC 6455 §5.3).
async fn read_client_frame(io: &mut Upgraded) -> TestResult<(u8, Vec<u8>)> {
    let header = read_header(io).await?;
    check(header.mask.is_some(), "an unmasked client frame")?;
    let payload = read_payload(io, &header).await?;
    Ok((header.first, payload))
}

async fn expect_close_reply(io: &mut Upgraded) -> TestResult {
    let (first, payload) = read_client_frame(io).await?;
    check(first == 0x88, "no close reply")?;
    check(
        payload == CLOSE_NORMAL,
        "the close reply changed the status",
    )
}

/// End our side first (RFC 6455 §7.1.1), then the client must end its side cleanly: FIN or
/// END_STREAM, never a reset.
async fn expect_orderly_end(io: &mut Upgraded) -> TestResult {
    io.shutdown().await?;
    let mut rest = Vec::new();
    io.read_to_end(&mut rest).await?;
    check(rest.is_empty(), "bytes after the close handshake")
}

/// Read `first`, then the header of the large text message that follows it.
async fn read_until_large_message(io: &mut Upgraded) -> TestResult<FrameHeader> {
    let (first, payload) = read_client_frame(io).await?;
    check(first == 0x81 && payload == b"first", "the first message")?;
    let header = read_header(io).await?;
    check(
        header.first == 0x81 && header.len == LARGE && header.mask.is_some(),
        "the large message",
    )?;
    Ok(header)
}

impl Scenario {
    async fn run(self, mut io: Upgraded) -> TestResult {
        let io = &mut io;
        match self {
            Self::CloseFirst => {
                io.write_all(&server_frame(0x88, &CLOSE_NORMAL)).await?;
                io.flush().await?;
                expect_close_reply(io).await?;
                expect_orderly_end(io).await
            }
            Self::CloseSecond => {
                let (first, payload) = read_client_frame(io).await?;
                check(first == 0x81 && payload == b"hello", "the message")?;
                io.write_all(&server_frame(0x81, b"hello")).await?;
                io.flush().await?;
                let (first, _) = read_client_frame(io).await?;
                check(first == 0x88, "no client close")?;
                io.write_all(&server_frame(0x88, &[])).await?;
                io.flush().await?;
                expect_orderly_end(io).await
            }
            Self::Duplex => {
                let header = read_until_large_message(io).await?;
                // The client's message cannot progress until we read it, so this write only
                // completes if the client keeps receiving while its send is blocked.
                io.write_all(&server_frame(0x82, &vec![b'b'; LARGE]))
                    .await?;
                io.flush().await?;
                let payload = read_payload(io, &header).await?;
                check(
                    payload.iter().all(|byte| *byte == b'a'),
                    "the large message",
                )?;
                io.write_all(&server_frame(0x88, &CLOSE_NORMAL)).await?;
                io.flush().await?;
                expect_close_reply(io).await?;
                expect_orderly_end(io).await
            }
            Self::CloseDuringSend => {
                let header = read_until_large_message(io).await?;
                io.write_all(&server_frame(0x88, &CLOSE_NORMAL)).await?;
                io.flush().await?;
                // The client finishes the frame it is in, then replies.
                read_payload(io, &header).await?;
                expect_close_reply(io).await?;
                expect_orderly_end(io).await
            }
            Self::Lines(lines, status) => {
                for line in lines {
                    let (first, payload) = read_client_frame(io).await?;
                    check(first == 0x81 && payload == line.as_bytes(), "a message")?;
                }
                let (first, payload) = read_client_frame(io).await?;
                check(first == 0x88, "no client close")?;
                let expected = status.map(u16::to_be_bytes);
                check(
                    payload.get(..2) == expected.as_ref().map(<[u8; 2]>::as_slice)
                        && (status.is_some() || payload.is_empty()),
                    "the close status",
                )?;
                io.write_all(&server_frame(0x88, &payload[..payload.len().min(2)]))
                    .await?;
                io.flush().await?;
                expect_orderly_end(io).await
            }
            Self::Stall(stalled, release) => {
                let header = read_until_large_message(io).await?;
                _ = stalled.send(());
                _ = release.await;
                let rest = read_payload(io, &header).await;
                check(rest.is_err(), "a killed client completed its message")
            }
        }
    }
}

/// Accepts WebSockets and runs the next expected [`Scenario`] on the raw stream.
#[derive(Clone, Default)]
struct RawPeer(Arc<Mutex<VecDeque<(Scenario, oneshot::Sender<TestResult>)>>>);

impl RawPeer {
    fn expect(&self, scenario: Scenario) -> oneshot::Receiver<TestResult> {
        let (report, outcome) = oneshot::channel();
        self.0.lock().push_back((scenario, report));
        outcome
    }
}

impl Service<Request> for RawPeer {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
        let accepted = match WebSocketAcceptor::new().serve(request).await {
            Ok(accepted) => accepted,
            Err(response) => return Ok(response),
        };
        let (scenario, report) = self.0.lock().pop_front().expect("an expected WebSocket");
        let request = accepted.request;
        tokio::spawn(async move {
            let outcome = match handle_upgrade(&request).await {
                Ok(io) => scenario.run(io).await,
                Err(error) => Err(error),
            };
            _ = report.send(outcome);
        });
        Ok(accepted.response)
    }
}

async fn outcome(version: Version, outcome: oneshot::Receiver<TestResult>) -> TestResult {
    timeout(DEADLINE, outcome)
        .await??
        .map_err(|error| format!("{version:?} peer: {error}").into())
}

const VERSIONS: [(Version, &str); 3] = [
    (Version::HTTP_11, "--http1.1"),
    (Version::HTTP_2, "--http2"),
    (Version::HTTP_3, "--http3"),
];

/// `first`, then a single line of [`LARGE`] bytes.
fn large_input() -> Vec<u8> {
    let mut input = b"first\n".to_vec();
    input.resize(input.len() + LARGE, b'a');
    input.push(b'\n');
    input
}

fn report(output: &Output) -> String {
    format!(
        "status: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test]
async fn websockets_echo_through_the_executable_on_every_http_version() -> TestResult {
    let fixture = Fixture::new().await?;
    for (version, flag) in [
        (Version::HTTP_11, "--http1.1"),
        (Version::HTTP_2, "--http2"),
        (Version::HTTP_3, "--http3"),
    ] {
        let server = WsServer::echo(fixture.auth.clone(), version, true).await?;
        let output = fixture
            .send(&server.url(), &[flag], b"first message\nsecond message\n")
            .await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "first message\nsecond message\n",
            "{version:?}\n{}",
            report(&output)
        );
        server.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn h3_websockets_require_the_server_setting_and_a_secure_uri() -> TestResult {
    let fixture = Fixture::new().await?;
    // Without SETTINGS_ENABLE_CONNECT_PROTOCOL the client refuses before opening a stream.
    let server = WsServer::echo(fixture.auth.clone(), Version::HTTP_3, false).await?;
    let output = fixture
        .send(&server.url(), &["--http3"], b"never sent\n")
        .await?;
    assert_eq!(output.status.code(), Some(1), "{}", report(&output));
    assert!(output.stdout.is_empty(), "{}", report(&output));
    server.close().await?;

    let output = fixture
        .send("ws://localhost:1/echo", &["--http3"], b"")
        .await?;
    assert_eq!(output.status.code(), Some(1), "{}", report(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requires a wss:// URI"),
        "{}",
        report(&output)
    );
    Ok(())
}

#[tokio::test]
async fn h3_websockets_never_bypass_an_explicit_proxy() -> TestResult {
    let fixture = Fixture::new().await?;
    let origin = WsServer::echo(fixture.auth.clone(), Version::HTTP_3, true).await?;
    let proxy =
        tokio::net::TcpListener::bind(SocketAddr::from(SocketAddress::local_ipv4(0))).await?;
    let proxy_url = format!("http://{}", proxy.local_addr()?);
    let output = fixture
        .send(
            &origin.url(),
            &["--http3", "--proxy", &proxy_url],
            b"hello\n",
        )
        .await?;
    assert_eq!(output.status.code(), Some(1), "{}", report(&output));
    assert!(output.stdout.is_empty(), "{}", report(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("QUIC connector does not support proxy routes"),
        "{}",
        report(&output)
    );
    timeout(Duration::from_millis(20), proxy.accept())
        .await
        .unwrap_err();
    origin.close().await
}

#[tokio::test]
async fn the_executable_answers_a_peer_close_while_stdin_stays_open() -> TestResult {
    let fixture = Fixture::new().await?;
    for (version, flag) in VERSIONS {
        let peer = RawPeer::default();
        let server = WsServer::start(fixture.auth.clone(), version, true, peer.clone()).await?;
        let closed = peer.expect(Scenario::CloseFirst);
        let output = fixture
            .send_keeping_stdin_open(&server.url(), &[flag], Vec::new())
            .await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        outcome(version, closed).await?;
        server.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn the_executable_closes_cleanly_at_the_end_of_its_input() -> TestResult {
    let fixture = Fixture::new().await?;
    for (version, flag) in VERSIONS {
        let peer = RawPeer::default();
        let server = WsServer::start(fixture.auth.clone(), version, true, peer.clone()).await?;
        let closed = peer.expect(Scenario::CloseSecond);
        let output = fixture.send(&server.url(), &[flag], b"hello\n").await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        assert_eq!(
            output.stdout,
            b"hello\n",
            "{version:?}\n{}",
            report(&output)
        );
        outcome(version, closed).await?;
        server.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn the_executable_keeps_receiving_while_a_send_is_blocked() -> TestResult {
    let fixture = Fixture::new().await?;
    for (version, flag) in VERSIONS {
        let peer = RawPeer::default();
        let server = WsServer::start(fixture.auth.clone(), version, true, peer.clone()).await?;
        let url = server.url();

        let duplex = peer.expect(Scenario::Duplex);
        let output = fixture
            .send_keeping_stdin_open(&url, &[flag], large_input())
            .await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        assert!(
            output.stdout.len() == LARGE && output.stdout.iter().all(|byte| *byte == b'b'),
            "{version:?}: {} bytes received",
            output.stdout.len()
        );
        outcome(version, duplex).await?;

        let closed = peer.expect(Scenario::CloseDuringSend);
        let output = fixture
            .send_keeping_stdin_open(&url, &[flag], large_input())
            .await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        assert!(output.stdout.is_empty(), "{version:?}\n{}", report(&output));
        outcome(version, closed).await?;

        // Killed while its send is blocked.
        let (stall, stalled) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let aborted = peer.expect(Scenario::Stall(stall, released));
        let (mut child, writer) = fixture.spawn_feeding(&url, &[flag], large_input())?;
        timeout(DEADLINE, stalled).await??;
        // The peer reads nothing more until released: the send is still stuck mid-frame.
        assert!(
            child.try_wait()?.is_none(),
            "{version:?}: exited while blocked"
        );
        child.kill().await?;
        writer.abort();
        _ = release.send(());
        // A killed process sends no QUIC CONNECTION_CLOSE: only the idle timeout would tell.
        if version != Version::HTTP_3 {
            outcome(version, aborted).await?;
        }

        // The server serves the next client as before.
        let recovered = peer.expect(Scenario::CloseSecond);
        let output = fixture.send(&url, &[flag], b"hello\n").await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        assert_eq!(
            output.stdout,
            b"hello\n",
            "{version:?}\n{}",
            report(&output)
        );
        outcome(version, recovered).await?;
        server.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn unreadable_input_fails_the_executable_after_a_clean_close() -> TestResult {
    let fixture = Fixture::new().await?;
    for (version, flag) in VERSIONS {
        let peer = RawPeer::default();
        let server = WsServer::start(fixture.auth.clone(), version, true, peer.clone()).await?;
        let url = server.url();

        let control = peer.expect(Scenario::Lines(&["before", "after"], None));
        let output = fixture.send(&url, &[flag], b"before\nafter\n").await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        outcome(version, control).await?;

        // Invalid UTF-8: the line and everything after it are refused, not treated as EOF.
        let refused = peer.expect(Scenario::Lines(&["before"], Some(1011)));
        let output = fixture
            .send(&url, &[flag], b"before\n\xff\nafter\n")
            .await?;
        assert_eq!(
            output.status.code(),
            Some(1),
            "{version:?}\n{}",
            report(&output)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("UTF-8"),
            "{version:?}\n{}",
            report(&output)
        );
        outcome(version, refused).await?;
        server.close().await?;
    }
    Ok(())
}

/// Records each request's target and `Host`, with what `inspect` reports of its response.
fn recording<S>(
    inner: S,
    seen: Arc<Mutex<Vec<String>>>,
    inspect: fn(&Response) -> String,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone
where
    S: Service<Request, Output = Response, Error = Infallible> + Clone,
{
    let inner = Arc::new(inner);
    service_fn(move |request: Request| {
        let inner = inner.clone();
        let seen = seen.clone();
        async move {
            let summary = format!("{} {:?}", request.uri(), request.headers().get(HOST));
            let response = inner.serve(request).await?;
            seen.lock()
                .push(format!("{summary} {}", inspect(&response)));
            Ok(response)
        }
    })
}

#[tokio::test]
async fn websockets_authenticate_on_every_http_version() -> TestResult {
    let fixture = Fixture::new().await?;
    for (version, flag) in VERSIONS {
        let echo = ConsumeErrLayer::trace_as_debug()
            .into_layer(WebSocketAcceptor::new().into_echo_service());
        let guarded = ValidateRequestHeaderLayer::auth(basic!("john", "secret")).into_layer(echo);
        let server = WsServer::start(fixture.auth.clone(), version, true, guarded).await?;
        let url = server.url();
        for args in [vec![flag], vec![flag, "-u", "john:wrong"]] {
            let output = fixture.send(&url, &args, b"denied\n").await?;
            assert_eq!(
                output.status.code(),
                Some(1),
                "{args:?}\n{}",
                report(&output)
            );
            assert!(output.stdout.is_empty(), "{args:?}\n{}", report(&output));
        }
        // The same server accepts the right credentials afterwards.
        let output = fixture
            .send(&url, &[flag, "-u", "john:secret"], b"allowed\n")
            .await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        assert_eq!(
            output.stdout,
            b"allowed\n",
            "{version:?}\n{}",
            report(&output)
        );
        server.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn websockets_keep_the_logical_name_behind_a_resolve_override() -> TestResult {
    const NAME: &str = "ws.example.test";
    let fixture = Fixture::for_name(NAME).await?;
    for (version, flag) in VERSIONS {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let echo = ConsumeErrLayer::trace_as_debug()
            .into_layer(WebSocketAcceptor::new().into_echo_service());
        let service = recording(echo, seen.clone(), |response| response.status().to_string());
        let server = WsServer::start(fixture.auth.clone(), version, true, service).await?;
        let port = server.address.port();
        let url = format!("wss://{NAME}:{port}/echo");

        // A `.test` name never resolves on its own (checked once: a lookup takes seconds).
        if version == Version::HTTP_11 {
            let output = fixture.send(&url, &[flag], b"unresolved\n").await?;
            assert_eq!(output.status.code(), Some(1), "{}", report(&output));
            assert!(seen.lock().is_empty());
        }

        let resolve = format!("{NAME}:{port}:127.0.0.1");
        let output = fixture
            .send(&url, &[flag, "--resolve", &resolve], b"resolved\n")
            .await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        assert_eq!(
            output.stdout,
            b"resolved\n",
            "{version:?}\n{}",
            report(&output)
        );
        // The certificate only names NAME, and the request still addresses it.
        let seen = seen.lock().clone();
        assert_eq!(seen.len(), 1, "{version:?}: {seen:?}");
        assert!(
            seen[0].contains(&format!("{NAME}:{port}")),
            "{version:?}: {seen:?}"
        );
        server.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn websockets_negotiate_per_message_deflate_on_every_http_version() -> TestResult {
    let fixture = Fixture::new().await?;
    let long = "compressible ".repeat(20_000);
    let input = format!("short\n{long}\n");
    for (version, flag) in VERSIONS {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let echo = ConsumeErrLayer::trace_as_debug().into_layer(
            WebSocketAcceptor::new()
                .with_per_message_deflate()
                .into_echo_service(),
        );
        let service = recording(echo, seen.clone(), |response| {
            format!("{:?}", response.headers().get(SEC_WEBSOCKET_EXTENSIONS))
        });
        let server = WsServer::start(fixture.auth.clone(), version, true, service).await?;
        let output = fixture
            .send(&server.url(), &[flag], input.as_bytes())
            .await?;
        assert!(output.status.success(), "{version:?}\n{}", report(&output));
        assert!(
            output.stdout == input.as_bytes(),
            "{version:?}: echo differs"
        );
        let seen = seen.lock().clone();
        assert!(
            seen.len() == 1 && seen[0].contains("permessage-deflate"),
            "{version:?}: {seen:?}"
        );
        server.close().await?;
    }
    Ok(())
}
