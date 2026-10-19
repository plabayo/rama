//! TLS session resumption and HTTP/3 early data, end to end over loopback UDP.

mod gate;

use std::{future::Future, pin::pin, sync::Arc, time::Duration};

use rama::http::{Body, Method, Request, Response, body::util::BodyExt as _};
use rama_core::{bytes::Bytes, rt::Executor};
use rama_http_core::h3::{Error, client, connection::Config, server};
use rama_net::address::SocketAddress;
use rama_quic::{
    ClientConfig, Connecting, Connection, Endpoint, ServerConfig, TransportConfig,
    tls::{QuicClientConfigProvider as _, QuicServerConfigProvider as _, TlsOptions},
};
use rama_quic_proto::Version;
use rama_tls::{
    client::TlsClientConfig,
    server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
};
use rama_udp::UdpPacketSocket;
use tokio::{task::JoinHandle, time::timeout};

#[cfg(feature = "boring")]
use rama_quic::tls::BoringTlsProvider;
#[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
use rama_quic::tls::RustlsTlsProvider;
#[cfg(all(feature = "rustls", feature = "aws-lc"))]
use rama_tls_rustls::dep::rustls::crypto::aws_lc_rs as rustls_crypto;
#[cfg(all(feature = "rustls", feature = "ring", not(feature = "aws-lc")))]
use rama_tls_rustls::dep::rustls::crypto::ring as rustls_crypto;

use self::gate::{Gate, GatedSocket};

const LIMIT: Duration = Duration::from_secs(20);
// Long enough for buffered bytes to reach the server application; the gate makes it exact.
const PROBE: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug)]
enum Provider {
    #[cfg(feature = "boring")]
    Boring,
    #[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
    Rustls,
}

impl Provider {
    fn enabled() -> Vec<Self> {
        vec![
            #[cfg(feature = "boring")]
            Self::Boring,
            #[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
            Self::Rustls,
        ]
    }

    fn configurations(
        self,
        client: &TlsClientConfig,
        server: &TlsServerConfig,
    ) -> (ClientConfig, ServerConfig) {
        let options = TlsOptions::default().with_early_data(true);
        match self {
            #[cfg(feature = "boring")]
            Self::Boring => (
                BoringTlsProvider.client_config(client, options).unwrap(),
                BoringTlsProvider.server_config(server, options).unwrap(),
            ),
            #[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
            Self::Rustls => {
                let provider = RustlsTlsProvider::new(Arc::new(rustls_crypto::default_provider()));
                (
                    provider.client_config(client, options).unwrap(),
                    provider.server_config(server, options).unwrap(),
                )
            }
        }
    }
}

struct Fixture {
    provider: Provider,
    client: Endpoint,
    server: Endpoint,
    client_config: ClientConfig,
    client_tls: TlsClientConfig,
    server_tls: TlsServerConfig,
    transport: Arc<TransportConfig>,
    gate: Arc<Gate>,
}

impl Fixture {
    async fn new(provider: Provider, version: Version) -> Self {
        println!("h3 early data: provider={provider:?} version={version:?}");
        let identity = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let server_tls = TlsServerConfig::new()
            .with_alpn([b"h3".as_slice().into()].into_iter().collect())
            .with_server_auth(identity.clone());
        let client_tls = TlsClientConfig::new()
            .with_alpn([b"h3".as_slice().into()].into_iter().collect())
            .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
            .unwrap();
        let mut transport = TransportConfig::default();
        Config::default()
            .configure_transport(&mut transport)
            .unwrap();
        let transport = Arc::new(transport);
        let (mut client_config, mut server_config) =
            provider.configurations(&client_tls, &server_tls);
        client_config.set_version(version).unwrap();
        client_config.set_transport_config(transport.clone());
        server_config.set_transport_config(transport.clone());
        let gate = Arc::new(Gate::default());
        let socket = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let server = Endpoint::build(Executor::new())
            .with_server_config(server_config)
            .with_datagram_socket(GatedSocket {
                inner: socket,
                gate: gate.clone(),
            })
            .unwrap();
        let client = Endpoint::build(Executor::new())
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        Self {
            provider,
            client,
            server,
            client_config,
            client_tls,
            server_tls,
            transport,
            gate,
        }
    }

    fn connect(&self) -> Connecting {
        self.client
            .connect_with(
                self.client_config.clone(),
                self.server.local_addr().unwrap(),
                "localhost",
            )
            .unwrap()
    }

    async fn full_pair(&self) -> (Connection, Connection) {
        let (client, server) = tokio::join!(self.connect(), async {
            self.server.accept().await.unwrap().await
        });
        (client.unwrap(), server.unwrap())
    }

    /// A full handshake and H3 exchange leave the client holding a session ticket.
    async fn warm(&self) {
        let (client, server) = self.full_pair().await;
        assert_eq!(resumed(&client), Some(false));
        assert_eq!(round_trip(&client, &server).await, "served");
        client.close(0_u32, b"warm complete");
    }

    /// Rotate to fresh native server state, so earlier tickets can no longer be accepted.
    fn forget_tickets(&self) {
        let (_, mut server_config) = self
            .provider
            .configurations(&self.client_tls, &self.server_tls);
        server_config.set_transport_config(self.transport.clone());
        self.server.set_server_config(Some(server_config));
    }

    /// Resume with TLS early keys; the server takes its early handles as well.
    async fn early_pair(&self) -> (Connection, Connection) {
        let client = self
            .connect()
            .into_0rtt()
            .unwrap_or_else(|_| panic!("resumption supplied no early keys"));
        let server = self
            .server
            .accept()
            .await
            .unwrap()
            .accept()
            .unwrap()
            .into_0rtt()
            .unwrap_or_else(|_| panic!("server early handles unavailable"));
        (client.0, server.0)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.gate.release();
        self.client.close(0_u32, b"test complete");
        self.server.close(0_u32, b"test complete");
    }
}

fn early_config() -> Config {
    Config {
        early_requests: true,
        ..Config::default()
    }
}

fn resumed(connection: &Connection) -> Option<bool> {
    connection.handshake_data().and_then(|data| data.resumed)
}

fn request(method: Method, body: &'static str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri("https://localhost/early")
        .body(Body::from(body))
        .unwrap()
}

/// Send one request from a client task and collect its response body.
fn send(client: Connection, config: Config, request: Request<Body>) -> Task<Result<Bytes, Error>> {
    let (mut sender, driver) = client::handshake::<Body>(client, config, Executor::new()).unwrap();
    Task::spawn(async move {
        let _driver = Task::spawn(driver.run());
        let response = sender.send_request(request).await?;
        Ok(response.into_body().collect().await.unwrap().to_bytes())
    })
}

async fn serve(stream: server::RequestStream) {
    let (request, response) = stream.resolve().await.unwrap();
    request.into_body().collect().await.unwrap();
    respond(response).await;
}

async fn respond(response: server::SendResponse) {
    response
        .send_response(Response::new(Body::from("served")))
        .await
        .unwrap();
}

async fn round_trip(client: &Connection, server: &Connection) -> Bytes {
    let (mut server, driver) = server::handshake(server.clone(), Config::default()).unwrap();
    let _driver = Task::spawn(driver.run());
    let serving = Task::spawn(async move { serve(server.accept().await.unwrap()).await });
    let body = send(client.clone(), Config::default(), request(Method::GET, ""))
        .join()
        .await
        .unwrap();
    serving.join().await;
    body
}

#[tokio::test]
async fn resumed_safe_request_is_sent_early_and_dispatched_after_finished() {
    for provider in Provider::enabled() {
        for version in [Version::V1, Version::V2] {
            timeout(LIMIT, safe_request_is_sent_early(provider, version))
                .await
                .unwrap();
        }
    }
}

async fn safe_request_is_sent_early(provider: Provider, version: Version) {
    let fixture = Fixture::new(provider, version).await;
    fixture.warm().await;

    fixture.gate.hold();
    let (client, server) = fixture.early_pair().await;
    let response = send(client.clone(), early_config(), request(Method::GET, ""));
    let (mut h3, driver) = server::handshake(server.clone(), Config::default()).unwrap();
    let _driver = Task::spawn(driver.run());
    let stream = timeout(PROBE, h3.accept())
        .await
        .expect("safe request was not sent with early keys")
        .unwrap();
    // All server output is held, so the client cannot have finished: these are early bytes.
    assert!(!server.is_handshake_confirmed());
    assert_eq!(client.early_data_accepted(), None);

    let mut resolving = pin!(stream.resolve());
    assert!(
        timeout(PROBE, &mut resolving).await.is_err(),
        "early request escaped the verified-Finished dispatch barrier"
    );
    fixture.gate.release();
    let (request, sender) = resolving.await.unwrap();
    assert!(server.is_handshake_confirmed());
    assert_eq!(request.method(), Method::GET);
    respond(sender).await;

    assert_eq!(response.join().await.unwrap(), "served");
    assert_eq!(client.early_data_accepted(), Some(true));
    assert_eq!(resumed(&client), Some(true));
    assert_eq!(resumed(&server), Some(true));
}

#[tokio::test]
async fn critical_streams_open_with_early_keys() {
    for provider in Provider::enabled() {
        timeout(LIMIT, early_critical_streams(provider))
            .await
            .unwrap();
    }
}

async fn early_critical_streams(provider: Provider) {
    let fixture = Fixture::new(provider, Version::V1).await;
    fixture.warm().await;

    fixture.gate.hold();
    let (client, server) = fixture.early_pair().await;
    let (_sender, driver) =
        client::handshake::<Body>(client.clone(), early_config(), Executor::new()).unwrap();
    let _driver = Task::spawn(driver.run());
    // All server output is held, so a stream arriving now was sent with early keys.
    let mut control = timeout(PROBE, server.accept_uni())
        .await
        .expect("critical streams were not opened with early keys")
        .unwrap();
    let mut kind = [0xff];
    control.read_exact(&mut kind).await.unwrap();
    assert_eq!(kind, [0x00], "first early stream is the control stream");
}

#[tokio::test]
async fn replay_unsafe_requests_wait_for_handshake_confirmation() {
    for provider in Provider::enabled() {
        for request in [
            || request(Method::POST, ""),
            || request(Method::GET, "payload"),
        ] {
            timeout(LIMIT, unsafe_request_waits(provider, request()))
                .await
                .unwrap();
        }
    }
}

async fn unsafe_request_waits(provider: Provider, request: Request<Body>) {
    let fixture = Fixture::new(provider, Version::V1).await;
    fixture.warm().await;

    fixture.gate.hold();
    let (client, server) = fixture.early_pair().await;
    let method = request.method().clone();
    let response = send(client.clone(), early_config(), request);
    let (mut h3, driver) = server::handshake(server.clone(), Config::default()).unwrap();
    let _driver = Task::spawn(driver.run());
    let mut accepting = pin!(h3.accept());
    assert!(
        timeout(PROBE, &mut accepting).await.is_err(),
        "replay-unsafe {method} request was sent with early keys"
    );
    fixture.gate.release();
    serve(accepting.await.unwrap()).await;
    assert_eq!(response.join().await.unwrap(), "served");
    assert_eq!(resumed(&client), Some(true));
}

#[tokio::test]
async fn rejected_early_data_retires_the_attempt() {
    for provider in Provider::enabled() {
        timeout(LIMIT, early_rejection(provider)).await.unwrap();
    }
}

async fn early_rejection(provider: Provider) {
    let fixture = Fixture::new(provider, Version::V1).await;
    fixture.warm().await;
    fixture.forget_tickets();

    let client = fixture
        .connect()
        .into_0rtt()
        .unwrap_or_else(|_| panic!("resumption supplied no early keys"))
        .0;
    let response = send(client.clone(), early_config(), request(Method::GET, ""));
    // The client retires the attempt as soon as it learns the decision, maybe before the server.
    let incoming = fixture.server.accept().await.unwrap();
    let _accepting = Task::spawn(async move { _ = incoming.await });

    let error = response.join().await.unwrap_err();
    assert!(error.is_early_data_rejected(), "{error:?}");
    assert_eq!(client.early_data_accepted(), Some(false));

    // Retrying is the caller's decision; a new connection serves the request.
    let (client, server) = fixture.full_pair().await;
    assert_eq!(round_trip(&client, &server).await, "served");
}

/// Test tasks cannot outlive a failed case or hide its panic.
struct Task<T>(Option<JoinHandle<T>>);

impl<T: Send + 'static> Task<T> {
    fn spawn(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self(Some(tokio::spawn(future)))
    }

    async fn join(mut self) -> T {
        self.0.take().unwrap().await.unwrap()
    }
}

impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}
