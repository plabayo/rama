//! Exercise `rama send` through its executable against local HTTP servers.

#![cfg(test)]

use parking_lot::Mutex;
use rama::{
    Layer,
    bytes::Bytes,
    crypto::pem::PemEncode as _,
    futures::stream,
    graceful::Shutdown,
    http::{
        Body, HeaderMap, Request, Response, StatusCode, Version,
        body::{Frame, util::BodyExt as _},
        header,
        server::HttpServer,
    },
    layer::MapInputLayer,
    net::{address::SocketAddress, tls::ApplicationProtocol, uri::Uri},
    quic::{Endpoint, ServerConfig, tls::TlsOptions},
    rt::Executor,
    service::service_fn,
    tcp::{TcpStream, server::TcpListener},
    tls::{
        boring::server::TlsAcceptorLayer,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::fs::{TempDir, tempdir},
};
use std::{
    collections::VecDeque,
    convert::Infallible,
    error::Error,
    fmt::Display,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Output,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    fs,
    net::{TcpListener as TokioTcpListener, UdpSocket},
    process::Command,
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

    async fn send(&self, url: impl Display, args: &[&str]) -> TestResult<Output> {
        let mut command = Command::new(env!("CARGO_BIN_EXE_rama"));
        let no_proxy = if args.contains(&"--proxy") { "" } else { "*" };
        command
            .kill_on_drop(true)
            .arg("send")
            .arg(url.to_string())
            .args(args)
            .arg("--trace")
            .arg(self.directory.path().join("trace.log"))
            .env("SSL_CERT_FILE", &self.ca)
            .env_remove("SSL_CERT_DIR")
            .env("NO_PROXY", no_proxy)
            .env("no_proxy", no_proxy)
            .env("RUST_LOG", "off")
            .env("NO_COLOR", "1");
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
        Ok(timeout(DEADLINE, command.output()).await??)
    }
}

#[derive(Default)]
struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Option<Body>,
}

impl Reply {
    fn redirect(alternative: Option<SocketAddr>) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(header::LOCATION, "/next".parse().unwrap());
        if let Some(address) = alternative {
            headers.insert(
                header::ALT_SVC,
                format!("h3=\":{}\"; ma=60", address.port())
                    .parse()
                    .unwrap(),
            );
        }
        Self {
            status: StatusCode::FOUND,
            headers,
            body: None,
        }
    }
}

#[derive(Debug)]
struct Observation {
    version: Version,
    authority: String,
    body: Bytes,
}

struct Server {
    address: SocketAddr,
    endpoint: Option<Endpoint>,
    requests: Arc<Mutex<Vec<Observation>>>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
    accepted: Arc<AtomicUsize>,
    stop: oneshot::Sender<()>,
    shutdown: Shutdown,
    task: JoinHandle<()>,
}

impl Server {
    async fn start(auth: ServerAuthData, version: Version) -> TestResult<Self> {
        Self::start_with_alpn(auth, version, ApplicationProtocol::HTTP_3).await
    }

    async fn start_with_alpn(
        auth: ServerAuthData,
        version: Version,
        quic_alpn: ApplicationProtocol,
    ) -> TestResult<Self> {
        let (stop, stopped) = oneshot::channel::<()>();
        let shutdown = Shutdown::new(stopped);
        let executor = Executor::graceful(shutdown.guard());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let replies = Arc::new(Mutex::new(VecDeque::<Reply>::new()));
        let accepted = Arc::new(AtomicUsize::new(0));
        let handler = service_fn({
            let requests = requests.clone();
            let replies = replies.clone();
            move |request: Request| {
                let requests = requests.clone();
                let replies = replies.clone();
                async move {
                    let version = request.version();
                    let authority = request
                        .uri()
                        .authority()
                        .map(|authority| authority.to_string())
                        .or_else(|| {
                            request
                                .headers()
                                .get(header::HOST)
                                .map(|value| value.to_str().unwrap().to_owned())
                        })
                        .unwrap();
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    requests.lock().push(Observation {
                        version,
                        authority,
                        body: body.clone(),
                    });
                    let reply = replies.lock().pop_front().unwrap_or_default();
                    let mut response = Response::new(reply.body.unwrap_or_else(|| {
                        if body.is_empty() {
                            Body::from("hello from rama")
                        } else {
                            Body::from(body)
                        }
                    }));
                    *response.status_mut() = reply.status;
                    *response.headers_mut() = reply.headers;
                    Ok::<_, Infallible>(response)
                }
            }
        });
        let tls = TlsServerConfig::new().with_server_auth(auth);
        if version == Version::HTTP_3 {
            let tls = tls.with_alpn([quic_alpn].into_iter().collect());
            let endpoint = Endpoint::build(executor.clone())
                .with_server_config(ServerConfig::try_from_rama_tls(
                    &tls,
                    TlsOptions::default(),
                )?)
                .bind_address(SocketAddress::local_ipv4(0))
                .await?;
            let address = endpoint.local_addr()?;
            let task = tokio::spawn({
                let endpoint = endpoint.clone();
                let accepted = accepted.clone();
                let server = HttpServer::new_http3(executor.clone());
                async move {
                    while let Some(incoming) = endpoint.accept().await {
                        accepted.fetch_add(1, Ordering::Relaxed);
                        let server = server.clone();
                        let handler = handler.clone();
                        executor.spawn_task(async move {
                            if let Ok(connection) = incoming.await {
                                server.serve(connection, handler).await.unwrap_or_default();
                            }
                        });
                    }
                }
            });
            return Ok(Self {
                address,
                endpoint: Some(endpoint),
                requests,
                replies,
                accepted,
                stop,
                shutdown,
                task,
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
        let service = (
            MapInputLayer::new({
                let accepted = accepted.clone();
                move |stream: TcpStream| {
                    accepted.fetch_add(1, Ordering::Relaxed);
                    stream
                }
            }),
            TlsAcceptorLayer::new(tls),
        )
            .into_layer(HttpServer::auto(executor).service(handler));
        let task = tokio::spawn(listener.serve(service));
        Ok(Self {
            address,
            endpoint: None,
            requests,
            replies,
            accepted,
            stop,
            shutdown,
            task,
        })
    }

    fn url(&self) -> String {
        format!("https://localhost:{}/", self.address.port())
    }

    fn reply(&self, reply: Reply) {
        self.replies.lock().push_back(reply);
    }

    async fn close(self) -> TestResult {
        self.stop.send(()).unwrap_or_default();
        if let Some(endpoint) = self.endpoint {
            endpoint.close(0u32, b"test complete");
            timeout(DEADLINE, endpoint.shutdown()).await?;
        }
        self.shutdown.shutdown_with_limit(DEADLINE).await?;
        self.task.await?;
        Ok(())
    }
}

fn succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn failed(output: &Output) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn explicit_h3_get_streamed_post_resolve_and_diagnostics() -> TestResult {
    let fixture = Fixture::new().await?;
    let server = Server::start(fixture.auth.clone(), Version::HTTP_3).await?;
    let har = fixture.directory.path().join("capture.har");
    let resolve = format!("localhost:{}:127.0.0.1", server.address.port());
    let output = fixture
        .send(
            server.url(),
            &[
                "--http3",
                "--ipv4",
                "--resolve",
                &resolve,
                "--verbose",
                "--har",
                har.to_str().unwrap(),
            ],
        )
        .await?;
    succeeded(&output);
    assert_eq!(output.stdout, b"hello from rama");
    let stderr = String::from_utf8(output.stderr)?;
    let version_line = format!("* using {:?}", Version::HTTP_3);
    assert!(stderr.lines().any(|line| line == version_line), "{stderr}");
    let alpn_line = format!("* ALPN: server selected {}", ApplicationProtocol::HTTP_3);
    assert!(stderr.lines().any(|line| line == alpn_line), "{stderr}");
    assert!(
        !stderr.contains(&format!("[{:?}]", Version::HTTP_2)),
        "{stderr}"
    );
    let har: serde_json::Value = serde_json::from_slice(&fs::read(har).await?)?;
    assert_eq!(
        har["log"]["entries"][0]["response"]["httpVersion"],
        "HTTP/3"
    );

    let body = fixture.directory.path().join("upload.txt");
    fs::write(&body, b"streamed h3 upload").await?;
    let data = format!("@{}", body.display());
    let output = fixture
        .send(server.url(), &["--http3", "--data", &data])
        .await?;
    succeeded(&output);
    assert_eq!(output.stdout, b"streamed h3 upload");
    {
        let requests = server.requests.lock();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.version == Version::HTTP_3
                    && request.authority == format!("localhost:{}", server.address.port()))
        );
        assert_eq!(requests[1].body, Bytes::from_static(b"streamed h3 upload"));
    }
    server.close().await
}

#[tokio::test]
async fn redirects_discover_h3_and_reuse_its_connection() -> TestResult {
    let fixture = Fixture::new().await?;
    let origin = Server::start(fixture.auth.clone(), Version::HTTP_2).await?;
    let alternative = Server::start(fixture.auth.clone(), Version::HTTP_3).await?;
    origin.reply(Reply::redirect(Some(alternative.address)));
    alternative.reply(Reply::redirect(None));
    let output = fixture
        .send(origin.url(), &["--location", "--alt-svc"])
        .await?;
    succeeded(&output);
    assert_eq!(output.stdout, b"hello from rama");
    assert_eq!(origin.requests.lock().len(), 1);
    assert_eq!(alternative.requests.lock().len(), 2);
    assert_eq!(alternative.accepted.load(Ordering::Relaxed), 1);

    let output = fixture.send(origin.url(), &["--alt-svc"]).await?;
    succeeded(&output);
    assert_eq!(origin.requests.lock().len(), 2);
    assert_eq!(alternative.requests.lock().len(), 2);
    origin.close().await?;
    alternative.close().await
}

#[tokio::test]
async fn alternative_services_require_opt_in_and_respect_explicit_versions() -> TestResult {
    let fixture = Fixture::new().await?;
    let origin = Server::start(fixture.auth.clone(), Version::HTTP_2).await?;
    let alternative = Server::start(fixture.auth.clone(), Version::HTTP_3).await?;

    for args in [
        vec!["--location"],
        vec!["--location", "--alt-svc", "--http2"],
    ] {
        origin.reply(Reply::redirect(Some(alternative.address)));
        let before = origin.requests.lock().len();
        let output = fixture.send(origin.url(), &args).await?;
        succeeded(&output);
        assert_eq!(output.stdout, b"hello from rama");
        assert_eq!(origin.requests.lock().len(), before + 2);
        assert!(alternative.requests.lock().is_empty());
        assert_eq!(alternative.accepted.load(Ordering::Relaxed), 0);
    }

    origin.close().await?;
    alternative.close().await
}

#[tokio::test]
async fn h3_response_trailers_complete_the_streamed_body() -> TestResult {
    let fixture = Fixture::new().await?;
    let server = Server::start(fixture.auth.clone(), Version::HTTP_3).await?;
    let mut trailers = HeaderMap::new();
    trailers.insert("x-complete", "yes".parse()?);
    server.reply(Reply {
        body: Some(Body::from_frame_stream(stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"streamed "))),
            Ok(Frame::data(Bytes::from_static(b"response"))),
            Ok(Frame::trailers(trailers)),
        ]))),
        ..Default::default()
    });
    let output = fixture.send(server.url(), &["--http3"]).await?;
    succeeded(&output);
    assert_eq!(output.stdout, b"streamed response");
    assert_eq!(server.requests.lock().len(), 1);
    server.close().await
}

#[tokio::test]
async fn h2_alternatives_require_opt_in_independently_of_h3_transport() -> TestResult {
    let fixture = Fixture::new().await?;
    let origin = Server::start(fixture.auth.clone(), Version::HTTP_2).await?;
    let alternative = Server::start(fixture.auth.clone(), Version::HTTP_2).await?;

    for (args, expected_alternative_requests) in [
        (vec!["--location"], 0),
        (vec!["--location", "--alt-svc"], 1),
    ] {
        let mut redirect = Reply::redirect(None);
        redirect.headers.insert(
            header::ALT_SVC,
            format!("h2=\":{}\"; ma=60", alternative.address.port()).parse()?,
        );
        origin.reply(redirect);
        let output = fixture.send(origin.url(), &args).await?;
        succeeded(&output);
        assert_eq!(output.stdout, b"hello from rama");
        assert_eq!(
            alternative.requests.lock().len(),
            expected_alternative_requests
        );
    }

    origin.close().await?;
    alternative.close().await
}

#[tokio::test]
async fn failed_alternative_authentication_falls_back_to_verified_origin() -> TestResult {
    let fixture = Fixture::new().await?;
    let origin = Server::start(fixture.auth.clone(), Version::HTTP_2).await?;
    let untrusted = Server::start(
        ServerAuthData::new_generated(Default::default())?,
        Version::HTTP_3,
    )
    .await?;
    origin.reply(Reply::redirect(Some(untrusted.address)));
    let output = fixture
        .send(origin.url(), &["--location", "--alt-svc"])
        .await?;
    succeeded(&output);
    assert_eq!(origin.requests.lock().len(), 2);
    assert!(untrusted.requests.lock().is_empty());
    let output = fixture
        .send(untrusted.url(), &["--http3", "--insecure"])
        .await?;
    succeeded(&output);
    origin.close().await?;
    untrusted.close().await
}

#[tokio::test]
async fn unavailable_h3_obeys_explicit_version_and_connection_deadline() -> TestResult {
    let fixture = Fixture::new().await?;
    let origin = Server::start(fixture.auth.clone(), Version::HTTP_11).await?;
    // Retain a silent UDP socket so failure is a timeout on every platform.
    let silent = UdpSocket::bind(SocketAddr::from(SocketAddress::local_ipv4(0))).await?;
    let address = silent.local_addr()?;
    origin.reply(Reply::redirect(Some(address)));
    let output = fixture
        .send(
            origin.url(),
            &[
                "--location",
                "--alt-svc",
                "--connect-timeout",
                "1",
                "--max-time",
                "5",
            ],
        )
        .await?;
    succeeded(&output);
    assert_eq!(origin.requests.lock().len(), 2);
    let output = fixture
        .send(
            format!("https://localhost:{}/", address.port()),
            &["--http3", "--connect-timeout", "1", "--max-time", "2"],
        )
        .await?;
    failed(&output);
    let output = fixture
        .send(
            origin.url(),
            &["--http3", "--connect-timeout", "1", "--max-time", "2"],
        )
        .await?;
    failed(&output);
    assert_eq!(
        origin.requests.lock().len(),
        2,
        "explicit H3 must not send an HTTP/1 request"
    );
    let output = fixture
        .send(
            format!("https://localhost:{}/", address.port()),
            &["--http3", "--max-time", "0.2"],
        )
        .await?;
    failed(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("max timeout"));
    origin.close().await
}

// Filesystem paths are not URI text: Windows drive paths need a leading
// slash, and names can contain spaces or URI delimiters.
fn local_file_uri(path: &Path) -> Uri {
    let mut path = path
        .to_str()
        .expect("UTF-8 fixture path")
        .replace('\\', "/");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    "file://".parse::<Uri>().unwrap().with_path(path)
}

#[test]
fn local_file_uri_encodes_windows_and_unix_paths() {
    for (path, expected) in [
        (
            r"C:\Users\rama user\local #1.txt",
            "file:///C:/Users/rama%20user/local%20%231.txt",
        ),
        ("/tmp/local #1.txt", "file:///tmp/local%20%231.txt"),
    ] {
        assert_eq!(local_file_uri(Path::new(path)).to_string(), expected);
    }
}

#[tokio::test]
async fn h1_h2_tls_limits_and_local_uri_schemes_remain_usable() -> TestResult {
    let fixture = Fixture::new().await?;
    for (version, flag) in [
        (Version::HTTP_11, "--http1.1"),
        (Version::HTTP_2, "--http2"),
    ] {
        let server = Server::start(fixture.auth.clone(), version).await?;
        let output = fixture
            .send(server.url(), &[flag, "--tls-max", "1.2", "--verbose"])
            .await?;
        succeeded(&output);
        assert_eq!(server.requests.lock()[0].version, version);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let expected = format!("* using {version:?}");
        assert!(stderr.lines().any(|line| line == expected), "{stderr}");
        if version == Version::HTTP_2 {
            assert!(stderr.contains(&format!("[{version:?}]")), "{stderr}");
        }
        let output = fixture.send(server.url(), &["--tls-max", "1.2"]).await?;
        succeeded(&output);
        assert_eq!(server.requests.lock()[1].version, version);
        server.close().await?;
    }
    let output = fixture.send("data:text/plain,local-data", &[]).await?;
    succeeded(&output);
    assert_eq!(output.stdout, b"local-data");
    let file = fixture.directory.path().join("local #1.txt");
    fs::write(&file, b"local-file").await?;
    let output = fixture.send(local_file_uri(&file), &[]).await?;
    succeeded(&output);
    assert_eq!(output.stdout, b"local-file");
    Ok(())
}

#[tokio::test]
async fn explicit_h3_rejects_wrong_alpn_and_incompatible_tls() -> TestResult {
    let fixture = Fixture::new().await?;
    let server = Server::start_with_alpn(
        fixture.auth.clone(),
        Version::HTTP_3,
        ApplicationProtocol::HTTP_2,
    )
    .await?;
    let output = fixture
        .send(server.url(), &["--http3", "--connect-timeout", "2"])
        .await?;
    failed(&output);
    assert!(server.requests.lock().is_empty());
    server.close().await?;
    let server = Server::start(fixture.auth.clone(), Version::HTTP_3).await?;
    let output = fixture
        .send(server.url(), &["--http3", "--tls-max", "1.2"])
        .await?;
    failed(&output);
    assert!(server.requests.lock().is_empty());
    let output = fixture
        .send(
            server.url().replacen("https://", "http://", 1),
            &["--http3"],
        )
        .await?;
    failed(&output);
    assert!(server.requests.lock().is_empty());
    let output = fixture.send("wss://localhost:1/", &["--http3"]).await?;
    failed(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("WebSocket over HTTP/3 requires Extended CONNECT")
    );
    server.close().await
}

#[tokio::test]
async fn explicit_h3_never_bypasses_an_explicit_proxy() -> TestResult {
    let fixture = Fixture::new().await?;
    let origin = Server::start(fixture.auth.clone(), Version::HTTP_3).await?;
    let proxy = TokioTcpListener::bind(SocketAddr::from(SocketAddress::local_ipv4(0))).await?;
    let proxy_url = format!("http://{}", proxy.local_addr()?);
    let output = fixture
        .send(origin.url(), &["--http3", "--proxy", &proxy_url])
        .await?;
    failed(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("QUIC connector does not support proxy routes"),
        "{stderr}"
    );
    assert!(origin.requests.lock().is_empty());
    assert_eq!(origin.accepted.load(Ordering::Relaxed), 0);
    timeout(Duration::from_millis(20), proxy.accept())
        .await
        .unwrap_err();
    origin.close().await
}
