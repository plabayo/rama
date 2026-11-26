//! Rustls TCP client connects over an in-memory transport: the native
//! configuration build alone, then a forced full handshake and sequential
//! connects on one connector, against a plain rustls origin with a shared
//! session cache and against a Rama rustls acceptor with session resumption.
//!
//! ```sh
//! cargo bench --bench tls_rustls_connect --features rustls,aws-lc
//! ```

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use std::sync::Arc;

use rama::{
    Layer as _, Service, ServiceInput,
    crypto::cert::generate_server_auth,
    extensions::ExtensionsRef as _,
    net::{
        Protocol,
        address::{Domain, HostWithPort},
        client::{ConnectRequest, ConnectionError, EstablishedClientConnection},
        stream::service::EchoService,
    },
    tls::{
        client::{ClientHandshake, NegotiatedTlsParameters, TlsClientConfig},
        rustls::{
            client::{ConnectorKindSecure, RustlsTlsConnectorConfig, TlsConnector},
            dep::{
                rustls::{ServerConfig, crypto::aws_lc_rs},
                tokio_rustls::TlsAcceptor,
            },
            server::{TlsAcceptorLayer, TlsAcceptorService},
        },
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex},
    runtime::Runtime,
};

mod bench_alloc;

fn main() {
    divan::main();
}

/// Dials an in-memory origin that serves one TLS connection per dial.
#[derive(Clone)]
enum Dial {
    /// A rustls acceptor whose connections share one configuration.
    Rustls(TlsAcceptor),
    /// A Rama rustls acceptor with session resumption.
    Rama(Arc<TlsAcceptorService<EchoService>>),
}

impl Service<ConnectRequest> for Dial {
    type Output = EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>;

    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let (client, server) = duplex(16 * 1024);
        match self.clone() {
            Self::Rustls(acceptor) => tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(server).await
                    && let Ok(byte) = stream.read_u8().await
                {
                    let _echoed = stream.write_u8(byte).await;
                }
            }),
            Self::Rama(acceptor) => tokio::spawn(async move {
                let _served = acceptor.serve(ServiceInput::new(server)).await;
            }),
        };
        Ok(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    }
}

#[derive(Debug, Clone, Copy)]
enum Origin {
    Rustls,
    Rama,
}

struct Fixture {
    runtime: Runtime,
    client: TlsClientConfig,
    dial: Dial,
}

fn fixture(origin: Origin) -> Fixture {
    // Both the connector and the origin use the process default provider.
    let _installed = aws_lc_rs::default_provider().install_default();
    let (cert_chain, private_key) =
        generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
    let anchor = cert_chain.last().unwrap().clone();
    let dial = match origin {
        Origin::Rustls => Dial::Rustls(TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .unwrap(),
        ))),
        Origin::Rama => Dial::Rama(Arc::new(
            TlsAcceptorLayer::new(TlsServerConfig::new().with_single_cert(ServerAuthData {
                cert_chain,
                private_key,
                ocsp: None,
            }))
            .with_session_resumption(true)
            .into_layer(EchoService::new()),
        )),
    };
    Fixture {
        runtime: tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
        client: TlsClientConfig::new()
            .with_server_name(Domain::tld_localhost())
            .try_with_server_trust_anchors([anchor])
            .unwrap(),
        dial,
    }
}

fn request(handshake: Option<ClientHandshake>) -> ConnectRequest {
    let request = ConnectRequest::new(HostWithPort::localhost_domain_https())
        .with_application_protocol(Protocol::HTTPS);
    if let Some(handshake) = handshake {
        request.extensions().insert(handshake);
    }
    request
}

/// One connect with a byte round trip, which also lets the client store
/// tickets. Returns whether the handshake resumed.
async fn connect(
    connector: &TlsConnector<Dial, ConnectorKindSecure>,
    handshake: Option<ClientHandshake>,
) -> bool {
    let mut conn = connector.serve(request(handshake)).await.unwrap().conn;
    conn.write_all(b"x").await.unwrap();
    assert_eq!(conn.read_u8().await.unwrap(), b'x');
    conn.extensions()
        .get_ref::<NegotiatedTlsParameters>()
        .and_then(|params| params.resumed)
        .unwrap()
}

/// The native configuration a connector builds when it has none cached.
#[divan::bench]
fn config_build(bencher: divan::Bencher) {
    let fixture = fixture(Origin::Rustls);
    let provider = Arc::new(aws_lc_rs::default_provider());
    let extensions = fixture.client.as_extensions();
    bencher.bench_local(|| {
        RustlsTlsConnectorConfig::from_extensions(extensions)
            .try_into_client_config_with_provider(provider.clone())
            .unwrap()
    });
}

/// A connect that always performs a full handshake.
#[divan::bench(args = [Origin::Rustls, Origin::Rama])]
fn connect_full(bencher: divan::Bencher, origin: Origin) {
    let fixture = fixture(origin);
    let connector = TlsConnector::secure(fixture.dial.clone()).with_base_config(fixture.client);
    bencher.bench_local(|| {
        fixture
            .runtime
            .block_on(connect(&connector, Some(ClientHandshake::Full)))
    });
}

/// Sequential connects on one connector, after a warm-up connect.
#[divan::bench(args = [Origin::Rustls, Origin::Rama])]
fn connect_repeat(bencher: divan::Bencher, origin: Origin) {
    let fixture = fixture(origin);
    let connector = TlsConnector::secure(fixture.dial.clone()).with_base_config(fixture.client);
    fixture.runtime.block_on(connect(&connector, None));
    bencher.bench_local(|| fixture.runtime.block_on(connect(&connector, None)));
}
