use std::{
    num::NonZeroUsize,
    sync::{Arc, LazyLock},
    time::Duration,
};

use parking_lot::Mutex;
use rama_boring::ssl::{SslAcceptor, SslVersion};
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
    ExtensionId,
    client::{
        ClientHello, NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig, TlsServerVerify,
    },
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData,
        TlsServerConfig,
    },
};
use rama_ua::profile::UserAgentDatabase;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

use super::*;
use crate::{
    TlsStream,
    client::{BoringClientConfigExt as _, ConnectorKindSecure, TlsConnector},
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

fn opaque_body(ext: &rama_tls::client::ClientHelloExtension) -> &[u8] {
    match ext {
        rama_tls::client::ClientHelloExtension::Opaque { data, .. } => data,
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
            let mut stream = rama_boring_tokio::accept(&acceptor, server).await.unwrap();
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

#[tokio::test]
async fn sessions_resume_only_when_opted_in() {
    for version in VERSIONS {
        let server = Server::new(version);
        let disabled = connector(&server, None);
        for _ in 0..3 {
            assert_eq!(
                connect(&disabled, &server, "a.test", no_overrides).await,
                FULL
            );
        }
        let enabled = connector(&server, Some(cache()));
        assert_eq!(
            connect(&enabled, &server, "a.test", no_overrides).await,
            FULL
        );
        for _ in 0..3 {
            let handshake = connect(&enabled, &server, "a.test", no_overrides).await;
            assert_eq!(handshake, RESUMED, "{version:?}");
        }
    }
}

#[tokio::test]
async fn sessions_stay_with_their_server_identity() {
    for version in VERSIONS {
        let server = Server::new(version);
        let connector = connector(&server, Some(cache()));
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            FULL
        );
        assert_eq!(
            connect(&connector, &server, "b.test", no_overrides).await,
            FULL
        );
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            RESUMED
        );
        assert_eq!(
            connect(&connector, &server, "b.test", no_overrides).await,
            RESUMED
        );
    }
}

#[tokio::test]
async fn sessions_stay_with_their_connector() {
    for version in VERSIONS {
        let server = Server::new(version);
        let store = cache();
        let first = connector(&server, Some(store.clone()));
        let second = connector(&server, Some(store));
        assert_eq!(connect(&first, &server, "a.test", no_overrides).await, FULL);
        // A shared store does not make another connector's sessions resumable.
        assert_eq!(
            connect(&second, &server, "a.test", no_overrides).await,
            FULL
        );
        assert_eq!(
            connect(&first.clone(), &server, "a.test", no_overrides).await,
            RESUMED
        );
        assert_eq!(
            connect(&second, &server, "a.test", no_overrides).await,
            RESUMED
        );
    }
}

#[tokio::test]
async fn sessions_stay_with_their_effective_configuration() {
    let verify_disabled = |extensions: &Extensions| {
        extensions.insert(TlsServerVerify(ServerVerifyMode::Disable));
    };
    let http2 = |extensions: &Extensions| {
        extensions.insert(TlsAlpn::http_2());
    };
    for version in VERSIONS {
        let server = Server::new(version);
        let connector = connector(&server, Some(cache()));
        // An unverified session never resumes a verified handshake, nor the reverse.
        assert_eq!(
            connect(&connector, &server, "a.test", verify_disabled).await,
            FULL
        );
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            FULL
        );
        assert_eq!(connect(&connector, &server, "a.test", http2).await, FULL);
        assert_eq!(
            connect(&connector, &server, "a.test", verify_disabled).await,
            RESUMED
        );
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            RESUMED
        );
        assert_eq!(connect(&connector, &server, "a.test", http2).await, RESUMED);
    }
}

/// Hands out every session it holds, whatever key it is asked for.
#[derive(Default)]
struct PromiscuousStore(Mutex<Vec<TlsClientSession>>);

impl TlsClientSessionStore for PromiscuousStore {
    fn put(&self, session: TlsClientSession) {
        self.0.lock().push(session);
    }

    fn take(&self, _: &TlsClientSessionKey) -> Option<TlsClientSession> {
        self.0.lock().pop()
    }
}

#[tokio::test]
async fn a_store_cannot_move_sessions_across_keys() {
    for version in VERSIONS {
        let server = Server::new(version);
        let store = Arc::new(PromiscuousStore::default());
        let first = connector(&server, Some(store.clone()));
        let second = connector(&server, Some(store.clone()));
        assert_eq!(connect(&first, &server, "a.test", no_overrides).await, FULL);
        assert!(!store.0.lock().is_empty(), "positive control");
        assert_eq!(
            connect(&second, &server, "a.test", no_overrides).await,
            FULL
        );
        store.0.lock().clear();
        assert_eq!(connect(&first, &server, "a.test", no_overrides).await, FULL);
        assert!(!store.0.lock().is_empty(), "positive control");
        assert_eq!(connect(&first, &server, "b.test", no_overrides).await, FULL);
    }
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

#[tokio::test]
async fn tls12_sessions_are_reused_and_tls13_tickets_offered_once() {
    for version in VERSIONS {
        let server = Server::new(version);
        let store = Arc::new(RecordingStore::default());
        let connector = connector(&server, Some(store.clone()));
        connect(&connector, &server, "a.test", no_overrides).await;
        store.put.lock().clear();
        assert_eq!(
            connect(&connector, &server, "a.test", no_overrides).await,
            RESUMED
        );
        let taken = store.taken.lock().pop().unwrap();
        let put_back = store
            .put
            .lock()
            .iter()
            .any(|session| std::ptr::eq(session.session(), taken.session()));
        assert_eq!(put_back, version == SslVersion::TLS1_2, "{version:?}");
        assert_eq!(taken.is_single_use(), version == SslVersion::TLS1_3);
        assert_eq!(taken.key().server(), &Host::from_static("a.test"));
    }
}

/// Handshake with `server` from `context`, returning whether the session resumed.
async fn handshake(server: &Server, context: &TlsConnectorContext) -> bool {
    let (client, server_io) = tokio::io::duplex(16 * 1024);
    let acceptor = server.acceptor.clone();
    let accept = async move {
        let mut stream = rama_boring_tokio::accept(&acceptor, server_io)
            .await
            .unwrap();
        stream.write_all(b"x").await.unwrap();
    };
    let connect = async {
        let data = context.configure().unwrap();
        let mut stream = crate::client::tls_connect(ServiceInput::new(client), Some(data))
            .await
            .unwrap();
        stream.read_exact(&mut [0]).await.unwrap();
        stream.ssl_ref().session_reused()
    };
    tokio::join!(accept, connect).1
}

#[tokio::test]
async fn contexts_never_resume_each_others_sessions() {
    let server = Server::new(SslVersion::TLS1_3);
    let config = trusting_config().with_server_name(Host::from_static("a.test"));
    let store = cache();
    let contexts = [(); 2].map(|()| {
        TlsConnectorContextBuilder::try_from(&config)
            .unwrap()
            .with_session_store(store.clone())
            .build()
    });
    assert!(!handshake(&server, &contexts[0]).await);
    assert!(!handshake(&server, &contexts[1]).await);
    assert!(handshake(&server, &contexts[0]).await);
    assert!(handshake(&server, &contexts[1]).await);
}

#[tokio::test]
async fn sessions_only_resume_on_their_own_context_and_server() {
    let server = Server::new(SslVersion::TLS1_3);
    let config = trusting_config().with_server_name(Host::from_static("a.test"));
    let sessions: Arc<Mutex<Vec<TlsClientSession>>> = Arc::default();
    let remembering = || {
        let sink = sessions.clone();
        TlsConnectorContextBuilder::try_from(&config)
            .unwrap()
            .with_new_session_callback(move |_, session| sink.lock().push(session))
            .build()
    };
    let (issuing, other) = (remembering(), remembering());
    let plain = TlsConnectorContextBuilder::try_from(&config)
        .unwrap()
        .build();
    assert!(!handshake(&server, &issuing).await);
    let session = sessions.lock().pop().expect("the server issued tickets");
    let ssl_for = |context: &TlsConnectorContext, server: &'static str| {
        let mut data = context.configure().unwrap();
        data.server_name = Some(Host::from_static(server));
        data.into_ssl().unwrap()
    };
    session.resume_on(&mut ssl_for(&issuing, "a.test")).unwrap();
    session
        .resume_on(&mut ssl_for(&issuing, "b.test"))
        .unwrap_err();
    session
        .resume_on(&mut ssl_for(&other, "a.test"))
        .unwrap_err();
    session
        .resume_on(&mut ssl_for(&plain, "a.test"))
        .unwrap_err();
    // Bound to the issuing context, then switched away from it.
    let mut switched = ssl_for(&issuing, "a.test");
    switched
        .set_ssl_context(ssl_for(&other, "a.test").ssl_context())
        .unwrap();
    session.resume_on(&mut switched).unwrap_err();
}

#[tokio::test]
async fn emulated_profiles_resume_without_changing_their_hello() {
    let db = UserAgentDatabase::try_embedded().unwrap();
    for profile in db.iter() {
        let tls = &profile.tls;
        let mut emulated = TlsClientConfig::new_from_client_hello(&tls.client_hello);
        if tls.permute_extensions {
            emulated.set_permute_extensions(true);
        }
        let server = Server::new(SslVersion::TLS1_3);
        let connector = connector(&server, Some(cache()));
        let request = |extensions: &Extensions| emulated.write_to(extensions);
        let fresh = connect_hello(&connector, &server, request).await;
        let resumed = connect_hello(&connector, &server, request).await;
        assert!(!offers_session(&fresh), "{:?}", profile.ua_str());
        assert!(offers_session(&resumed), "{:?}", profile.ua_str());
        let psk = ExtensionId::PRE_SHARED_KEY;
        assert_eq!(resumed.extensions().last().map(|ext| ext.id()), Some(psk));
        let shape = |hello: &ClientHello| -> Vec<u16> {
            hello
                .extensions()
                .iter()
                .map(|ext| ext.id())
                .filter(|id| !id.is_grease() && *id != psk && *id != ExtensionId::PADDING)
                .map(u16::from)
                .collect()
        };
        let (mut fresh, mut resumed) = (shape(&fresh), shape(&resumed));
        if tls.permute_extensions {
            fresh.sort_unstable();
            resumed.sort_unstable();
        }
        assert_eq!(fresh, resumed, "{:?}", profile.ua_str());
    }
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

#[test]
fn the_cache_keeps_the_newest_values_of_the_most_recent_keys() {
    let cache =
        TlsClientSessionCache::new(NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(2).unwrap());
    for value in 0..3 {
        cache.insert("a", value);
    }
    assert_eq!(cache.len(), 2);
    cache.insert("b", 10);
    cache.insert("a", 3);
    // Storing to "c" evicts "b", the key stored to least recently.
    cache.insert("c", 20);
    assert_eq!(cache.most_recent(&["a", "b", "c"]), Some(&"c"));
    assert_eq!(cache.most_recent(&["a", "b"]), Some(&"a"));
    assert_eq!(cache.pop(&"b"), None);
    assert_eq!(cache.pop(&"a"), Some(3));
    assert_eq!(cache.pop(&"a"), Some(2));
    assert_eq!(cache.pop(&"a"), None);
    assert_eq!(cache.most_recent(&["a"]), None);
    assert_eq!(cache.pop(&"c"), Some(20));
    assert!(cache.is_empty());
    // Emptied keys release their slot.
    for key in ["d", "e"] {
        cache.insert(key, 0);
    }
    assert_eq!(cache.len(), 2);
}
