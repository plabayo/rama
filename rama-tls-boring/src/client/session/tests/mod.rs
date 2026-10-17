//! In-memory authenticated TLS peers and shared session-store fixtures.

mod cache;
mod contexts;
mod offers;
mod profiles;
mod resumption;

use std::{
    num::NonZeroUsize,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use parking_lot::Mutex;
use rama_boring::ssl::{GreaseValues, SslAcceptor, SslVersion};
use rama_boring_tokio::accept;
use rama_core::{
    Service, ServiceInput,
    conversion::RamaTryFrom as _,
    extensions::{Extensions, ExtensionsRef as _},
};
use rama_crypto::{
    cert::generate_server_auth,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use rama_net::{
    Protocol,
    address::{Domain, Host, HostWithPort},
    client::{ConnectRequest, ConnectionError, EstablishedClientConnection},
    tls::TlsAlpn,
};
use rama_tls::{
    CipherSuite, ExtensionId, KeyLogIntent,
    client::{
        ClientAuth, ClientHandshake, ClientHello, ClientHelloExtension, NegotiatedTlsParameters,
        ServerVerifyMode, TlsClientAuth, TlsClientConfig, TlsServerCertPins, TlsServerVerify,
        TlsSessionProfileScope,
    },
    keylog::KeyLogSink,
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData,
        TlsServerConfig,
    },
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

use super::*;
use crate::{
    TlsStream,
    client::{
        BoringCipherSuites, BoringClientConfigExt as _, BoringExtensionOrder,
        BoringPermuteExtensions, ConnectorKindSecure, TlsConnector, TlsConnectorData,
        config::BoringGreaseValues, tls_connect,
    },
    server::TlsAcceptorData,
};

const VERSIONS: [SslVersion; 2] = [SslVersion::TLS1_2, SslVersion::TLS1_3];

static AUTH: LazyLock<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> =
    LazyLock::new(|| {
        let identities = ["a.test", "b.test"]
            .map(|name| CertificateIdentity::Dns(Domain::from_static(name)))
            .into();
        generate_server_auth(GeneratedServerAuthConfig::GeneratedCa {
            ca: Default::default(),
            leaf: LeafCertRequest {
                config: Default::default(),
                identities,
            },
        })
        .unwrap()
    });

fn trusting_config() -> TlsClientConfig {
    TlsClientConfig::new()
        .try_with_server_trust_anchors([AUTH.0.last().unwrap().clone()])
        .unwrap()
}

/// A server whose one native context resumes the sessions it issues, recording the
/// ClientHello of every handshake.
#[derive(Clone)]
struct Server {
    acceptor: SslAcceptor,
    hellos: Arc<Mutex<Vec<ClientHello>>>,
}

impl Server {
    fn new(version: SslVersion) -> Self {
        let config = TlsServerConfig::new().with_single_cert(ServerAuthData {
            cert_chain: AUTH.0.clone(),
            private_key: AUTH.1.clone_key(),
            ocsp: None,
        });
        let mut builder = TlsAcceptorData::try_from(&config)
            .unwrap()
            .into_static_acceptor_builder()
            .unwrap();
        builder.set_min_proto_version(Some(version)).unwrap();
        builder.set_max_proto_version(Some(version)).unwrap();
        let hellos: Arc<Mutex<Vec<ClientHello>>> = Arc::default();
        let sink = hellos.clone();
        builder.set_select_certificate_callback(move |hello| {
            sink.lock()
                .push(ClientHello::rama_try_from(&hello).unwrap());
            Ok(())
        });
        Self {
            acceptor: builder.build(),
            hellos,
        }
    }
}

/// Whether a ClientHello offers a session: a TLS 1.3 PSK or a TLS 1.2 ticket.
fn offers_session(hello: &ClientHello) -> bool {
    hello.extensions().iter().any(|ext| {
        let id = ext.id();
        id == ExtensionId::PRE_SHARED_KEY
            || (id == ExtensionId::SESSION_TICKET && !opaque_body(ext).is_empty())
    })
}

fn opaque_body(ext: &ClientHelloExtension) -> &[u8] {
    match ext {
        ClientHelloExtension::Opaque { data, .. } => data,
        _ => &[],
    }
}

/// Dials `Server` over an in-memory transport, one fresh connection per request.
#[derive(Clone)]
struct Dial(Server);

impl Service<ConnectRequest> for Dial {
    type Output = EstablishedClientConnection<ServiceInput<DuplexStream>, ConnectRequest>;
    type Error = ConnectionError;

    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        let (client, server) = tokio::io::duplex(16 * 1024);
        let acceptor = self.0.acceptor.clone();
        tokio::spawn(async move {
            let mut stream = accept(&acceptor, server).await.unwrap();
            // Clients read this byte, which also delivers TLS 1.3 tickets before it.
            stream.write_all(b"x").await.unwrap();
        });
        Ok(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    }
}

type Connector = TlsConnector<Dial, ConnectorKindSecure>;

fn connector(server: &Server, store: Option<Arc<dyn TlsClientSessionStore>>) -> Connector {
    TlsConnector::secure(Dial(server.clone()))
        .with_base_config(trusting_config())
        .maybe_with_session_store(store)
}

#[derive(Debug, PartialEq, Eq)]
struct Handshake {
    offered: bool,
    resumed: bool,
}

const FULL: Handshake = Handshake {
    offered: false,
    resumed: false,
};
const RESUMED: Handshake = Handshake {
    offered: true,
    resumed: true,
};

async fn connect(
    connector: &Connector,
    server: &Server,
    host: &'static str,
    request: impl FnOnce(&Extensions),
) -> Handshake {
    let input = ConnectRequest::new(HostWithPort::new(Host::from_static(host), 443))
        .with_application_protocol(Protocol::HTTPS);
    request(input.extensions());
    let established = tokio::time::timeout(Duration::from_secs(5), connector.serve(input))
        .await
        .expect("handshake timeout")
        .expect("handshake");
    let mut conn: TlsStream<ServiceInput<DuplexStream>> = established.conn;
    conn.read_exact(&mut [0]).await.unwrap();
    let resumed = conn
        .extensions()
        .get_ref::<NegotiatedTlsParameters>()
        .and_then(|params| params.resumed)
        .unwrap();
    let hello = server
        .hellos
        .lock()
        .pop()
        .expect("the server saw the hello");
    Handshake {
        offered: offers_session(&hello),
        resumed,
    }
}

fn no_overrides(_: &Extensions) {}

fn cache() -> Arc<dyn TlsClientSessionStore> {
    Arc::new(TlsClientSessionCache::default())
}

/// Records the sessions taken from and stored in a cache.
#[derive(Default)]
struct RecordingStore {
    cache: TlsClientSessionCache,
    taken: Mutex<Vec<TlsClientSession>>,
    put: Mutex<Vec<TlsClientSession>>,
}

impl TlsClientSessionStore for RecordingStore {
    fn put(&self, session: TlsClientSession) {
        self.put.lock().push(session.clone());
        self.cache.put(session);
    }

    fn take(&self, key: &TlsClientSessionKey) -> Option<TlsClientSession> {
        let session = self.cache.take(key)?;
        self.taken.lock().push(session.clone());
        Some(session)
    }
}

/// Handshake with `server` from `context`, returning whether the session resumed.
async fn handshake(server: &Server, context: &TlsConnectorContext) -> bool {
    let (client, server_io) = tokio::io::duplex(16 * 1024);
    let acceptor = server.acceptor.clone();
    let accept = async move {
        let mut stream = accept(&acceptor, server_io).await.unwrap();
        stream.write_all(b"x").await.unwrap();
    };
    let connect = async {
        let data = context.configure().unwrap();
        let mut stream = tls_connect(ServiceInput::new(client), Some(data))
            .await
            .unwrap();
        stream.read_exact(&mut [0]).await.unwrap();
        stream.ssl_ref().session_reused()
    };
    tokio::join!(accept, connect).1
}

async fn connect_hello(
    connector: &Connector,
    server: &Server,
    request: impl FnOnce(&Extensions),
) -> ClientHello {
    let input = ConnectRequest::new(HostWithPort::new(Host::from_static("a.test"), 443))
        .with_application_protocol(Protocol::HTTPS);
    request(input.extensions());
    let established = tokio::time::timeout(Duration::from_secs(5), connector.serve(input))
        .await
        .expect("handshake timeout")
        .expect("handshake");
    let mut conn = established.conn;
    conn.read_exact(&mut [0]).await.unwrap();
    server
        .hellos
        .lock()
        .pop()
        .expect("the server saw the hello")
}
