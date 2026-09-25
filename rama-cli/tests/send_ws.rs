//! Exercise `rama send ws(s)://` through its executable over HTTP/1.1, HTTP/2 and HTTP/3.

#![cfg(test)]

use rama::{
    Layer,
    crypto::pem::PemEncode as _,
    graceful::Shutdown,
    http::{
        Version, layer::error_handling::ErrorHandlerLayer, server::HttpServer,
        service::web::Router, ws::handshake::server::WebSocketAcceptor,
    },
    layer::{ArcLayer, ConsumeErrLayer},
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{Endpoint, ServerConfig, TransportConfig, tls::TlsOptions},
    rt::Executor,
    tcp::server::TcpListener,
    tls::{
        boring::server::TlsAcceptorLayer,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::fs::{TempDir, tempdir},
};
use std::{
    error::Error, net::SocketAddr, path::PathBuf, process::Output, sync::Arc, time::Duration,
};
use tokio::{fs, io::AsyncWriteExt as _, process::Command, sync::oneshot, time::timeout};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const DEADLINE: Duration = Duration::from_secs(20);

struct Fixture {
    directory: TempDir,
    ca: PathBuf,
    auth: ServerAuthData,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let directory = tempdir()?;
        let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default())?;
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
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
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
        let mut child = command.spawn()?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(input).await?;
        drop(stdin);
        Ok(timeout(DEADLINE, child.wait_with_output()).await??)
    }
}

struct EchoServer {
    address: SocketAddr,
    endpoint: Option<Endpoint>,
    stop: oneshot::Sender<()>,
    shutdown: Shutdown,
}

impl EchoServer {
    /// A `wss://…/echo` WebSocket echo server on `version`.
    async fn start(
        auth: ServerAuthData,
        version: Version,
        extended_connect: bool,
    ) -> TestResult<Self> {
        let (stop, stopped) = oneshot::channel::<()>();
        let shutdown = Shutdown::new(stopped);
        let executor = Executor::graceful(shutdown.guard());
        let echo = || {
            ConsumeErrLayer::trace_as_debug()
                .into_layer(WebSocketAcceptor::new().into_echo_service())
        };
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
        let server = EchoServer::start(fixture.auth.clone(), version, true).await?;
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
    let server = EchoServer::start(fixture.auth.clone(), Version::HTTP_3, false).await?;
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
    let origin = EchoServer::start(fixture.auth.clone(), Version::HTTP_3, true).await?;
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
