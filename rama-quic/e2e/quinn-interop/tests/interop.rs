//! Rama's QUIC transport against the upstream Quinn stack, both directions, through the public
//! API only: no engine internals, and no Rustls type on the Rama side of any call.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rama::crypto::pki_types::CertificateDer;
use rama::quic::tls::TlsOptions;
use rama::quic::{ClientConfig, Endpoint, ServerConfig};
use rama::tls::client::TlsClientConfig;
use rama::tls::server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig};
use rama::utils::octets;
use sha2::{Digest, Sha256};

const ALPN: &[u8] = b"rama-quinn-interop";
/// Every await in these tests is bounded: a hang has to fail the test, not stall it.
const LIMIT: Duration = Duration::from_secs(20);

/// Await one step of a scenario, naming it so a timeout says which step stalled.
async fn step<F: std::future::Future>(what: &str, future: F) -> F::Output {
    match tokio::time::timeout(LIMIT, future).await {
        Ok(value) => value,
        Err(_) => panic!("{what}: not within {LIMIT:?}"),
    }
}

/// A spawned peer. The guard owns its handle for as long as it exists, including while a wait on
/// it is in progress, so a wait that is itself cancelled leaves the task with the guard rather
/// than detached; dropping the guard aborts the task without waiting for it to unwind.
struct Peer(Option<tokio::task::JoinHandle<()>>);

impl Peer {
    fn spawn(task: impl std::future::Future<Output = ()> + Send + 'static) -> Self {
        Self(Some(tokio::spawn(task)))
    }

    async fn join(mut self, what: &str) {
        if let Err(reason) = self.try_join_within(LIMIT).await {
            panic!("{what}: {reason}");
        }
    }

    /// Wait for the task, with the handle staying in the guard throughout: awaiting it by value
    /// would drop it on a timeout and leave the task running detached, and taking it out first
    /// would do the same if this wait were itself cancelled.
    async fn try_join_within(&mut self, limit: Duration) -> Result<(), String> {
        let handle = self.0.as_mut().expect("waited on once");
        let outcome = match tokio::time::timeout(limit, handle).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.is_panic() => Err(format!("panicked: {error}")),
            Ok(Err(error)) => Err(format!("ended: {error}")),
            Err(_) => {
                let handle = self.0.as_mut().expect("still here");
                handle.abort();
                let _ = handle.await;
                Err(format!("not within {limit:?}"))
            }
        };
        // Whatever happened, the task is finished and the guard has nothing left to abort.
        self.0 = None;
        outcome
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

fn localhost() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
}

fn digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8) ^ seed).collect()
}

/// One generated identity, used by whichever side is the server and trusted by the other.
fn identity() -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
        .expect("an identity is generated")
}

fn alpn() -> impl IntoIterator<Item = rama::net::tls::ApplicationProtocol> {
    [rama::net::tls::ApplicationProtocol::from(ALPN)]
}

fn rama_server_config(auth: &ServerAuthData) -> ServerConfig {
    let tls = TlsServerConfig::new()
        .with_alpn(alpn().into_iter().collect())
        .with_server_auth(auth.clone());
    ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the server config is built")
}

fn rama_client_config(anchor: CertificateDer<'static>) -> ClientConfig {
    let tls = TlsClientConfig::new()
        .with_alpn(alpn().into_iter().collect())
        .try_with_server_trust_anchors([anchor])
        .expect("the trust anchor is accepted");
    ClientConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the client config is built")
}

fn quinn_server_config(auth: &ServerAuthData) -> quinn::ServerConfig {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 is supported")
    .with_no_client_auth()
    .with_single_cert(auth.cert_chain.clone(), auth.private_key.clone_key())
    .expect("the identity is accepted");
    tls.alpn_protocols = vec![ALPN.to_vec()];
    quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("a QUIC server config"),
    ))
}

fn quinn_client_config(anchor: CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(anchor).expect("the anchor is accepted");
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 is supported")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("a QUIC client config"),
    ))
}

/// Rama opens the connection, Quinn answers it: a unidirectional stream up and a bidirectional
/// exchange, both verified by digest, both ended with FIN, and a bounded shutdown on each side.
#[tokio::test]
async fn rama_client_to_quinn_server() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let server = quinn::Endpoint::server(quinn_server_config(&auth), localhost())
        .expect("the quinn server binds");
    let server_addr = server.local_addr().expect("its address");

    let up = payload(0x11, octets::kib(64));
    let question = payload(0x22, octets::kib(4));
    let answer = payload(0x33, octets::kib(8));
    let (up_hash, q_hash, a_hash) = (digest(&up), digest(&question), digest(&answer));

    let peer = Peer::spawn({
        let answer = answer.clone();
        async move {
            let conn = step("the quinn server accepts", server.accept())
                .await
                .expect("an attempt arrives")
                .await
                .expect("the handshake completes");
            let mut uni = step("the quinn server takes the uni stream", conn.accept_uni())
                .await
                .expect("the uni stream arrives");
            let received = step(
                "the quinn server reads the uni stream",
                uni.read_to_end(octets::mib(1)),
            )
            .await
            .expect("the uni stream completes");
            assert_eq!(digest(&received), up_hash, "the uni payload arrived whole");

            let (mut send, mut recv) =
                step("the quinn server takes the bi stream", conn.accept_bi())
                    .await
                    .expect("the bi stream arrives");
            let asked = step(
                "the quinn server reads the question",
                recv.read_to_end(octets::mib(1)),
            )
            .await
            .expect("the question completes");
            assert_eq!(digest(&asked), q_hash, "the question arrived whole");
            step(
                "the quinn server writes the answer",
                send.write_all(&answer),
            )
            .await
            .expect("the answer is written");
            send.finish().expect("the answer ends");
            step("the quinn connection closes", conn.closed()).await;
            step("the quinn server goes idle", server.wait_idle()).await;
        }
    });

    let client = step("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let conn = step(
        "the rama client connects",
        client
            .connect_with(rama_client_config(anchor), server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");

    // What the handshake settled, in Rama's own types: no `Any` to downcast, no Rustls type.
    let settled = conn
        .handshake_data()
        .expect("the handshake settled something");
    assert_eq!(
        settled.protocol,
        Some(rama::net::tls::ApplicationProtocol::from(ALPN)),
        "the protocol both sides agreed on"
    );
    let chain = conn
        .peer_identity()
        .expect("the server presented a certificate");
    assert_eq!(
        chain.first(),
        auth.cert_chain.first(),
        "which is the identity the server was given"
    );

    let mut uni = step("the rama client opens a uni stream", conn.open_uni())
        .await
        .expect("a uni stream");
    step("the rama client writes the payload", uni.write_all(&up))
        .await
        .expect("the payload is written");
    uni.finish().expect("the uni stream ends");

    let (mut send, mut recv) = step("the rama client opens a bi stream", conn.open_bi())
        .await
        .expect("a bi stream");
    step("the rama client asks", send.write_all(&question))
        .await
        .expect("the question is written");
    send.finish().expect("the question ends");
    let heard = step(
        "the rama client reads the answer",
        recv.read_to_end(octets::mib(1)),
    )
    .await
    .expect("the answer completes");
    assert_eq!(digest(&heard), a_hash, "the answer arrived whole");

    conn.close(0u32.into(), b"done");
    step("rama's shutdown", client.wait_idle()).await;
    peer.join("the quinn peer").await;
}

/// Quinn opens the connection, Rama answers it, with the same traffic in the same shapes.
#[tokio::test]
async fn quinn_client_to_rama_server() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();

    let server = step(
        "the rama server binds",
        Endpoint::server(rama_server_config(&auth), localhost()),
    )
    .await
    .expect("it binds");
    let server_addr = server.local_addr().expect("its address");

    let up = payload(0x44, octets::kib(64));
    let question = payload(0x55, octets::kib(4));
    let answer = payload(0x66, octets::kib(8));
    let (up_hash, q_hash, a_hash) = (digest(&up), digest(&question), digest(&answer));

    let served = Peer::spawn({
        let answer = answer.clone();
        let server = server.clone();
        async move {
            let conn = step("the rama server accepts", server.accept())
                .await
                .expect("an attempt arrives")
                .accept()
                .expect("it is accepted")
                .await
                .expect("the handshake completes");
            let settled = conn
                .handshake_data()
                .expect("the handshake settled something");
            assert_eq!(
                settled.protocol,
                Some(rama::net::tls::ApplicationProtocol::from(ALPN)),
                "the protocol both sides agreed on"
            );
            assert_eq!(
                settled.server_name.as_ref().map(ToString::to_string),
                Some("localhost".to_owned()),
                "and the name the client asked for"
            );

            let mut uni = step("the rama server takes the uni stream", conn.accept_uni())
                .await
                .expect("the uni stream arrives");
            let received = step(
                "the rama server reads the uni stream",
                uni.read_to_end(octets::mib(1)),
            )
            .await
            .expect("the uni stream completes");
            assert_eq!(digest(&received), up_hash, "the uni payload arrived whole");

            let (mut send, mut recv) =
                step("the rama server takes the bi stream", conn.accept_bi())
                    .await
                    .expect("the bi stream arrives");
            let asked = step(
                "the rama server reads the question",
                recv.read_to_end(octets::mib(1)),
            )
            .await
            .expect("the question completes");
            assert_eq!(digest(&asked), q_hash, "the question arrived whole");
            step("the rama server writes the answer", send.write_all(&answer))
                .await
                .expect("the answer is written");
            send.finish().expect("the answer ends");
            step("the rama connection closes", conn.closed()).await;
        }
    });

    let mut client = quinn::Endpoint::client(localhost()).expect("quinn binds");
    client.set_default_client_config(quinn_client_config(anchor));
    let conn = step(
        "the quinn client connects",
        client
            .connect(server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the handshake completes");

    let mut uni = step("the quinn client opens a uni stream", conn.open_uni())
        .await
        .expect("a uni stream");
    step("the quinn client writes the payload", uni.write_all(&up))
        .await
        .expect("the payload is written");
    uni.finish().expect("the uni stream ends");

    let (mut send, mut recv) = step("the quinn client opens a bi stream", conn.open_bi())
        .await
        .expect("a bi stream");
    step("the quinn client asks", send.write_all(&question))
        .await
        .expect("the question is written");
    send.finish().expect("the question ends");
    let heard = step(
        "the quinn client reads the answer",
        recv.read_to_end(octets::mib(1)),
    )
    .await
    .expect("the answer completes");
    assert_eq!(digest(&heard), a_hash, "the answer arrived whole");

    conn.close(0u32.into(), b"done");
    step("quinn's shutdown", client.wait_idle()).await;
    served.join("the rama peer").await;
    step("rama's shutdown", server.shutdown()).await;
}

/// Rama's client refuses a server whose identity it does not trust, and the same client accepts
/// the same server when it does. The refusal is the certificate check, named in the error.
#[tokio::test]
async fn a_rama_client_refuses_a_server_it_does_not_trust() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();
    let stranger = identity();
    let wrong_anchor = stranger.cert_chain.last().expect("a chain").clone();

    let server = quinn::Endpoint::server(quinn_server_config(&auth), localhost())
        .expect("the quinn server binds");
    let server_addr = server.local_addr().expect("its address");
    let accepting = Peer::spawn({
        let server = server.clone();
        async move {
            // The server takes both attempts to their end: the refusal must come from the
            // client's certificate check, not from an attempt nobody answered. These awaits are
            // not bounded one by one; the guard that joins this task bounds it as a whole and
            // stops it if it ever fails to finish.
            for _ in 0..2 {
                let Some(incoming) = server.accept().await else {
                    return;
                };
                let _ = incoming.await;
            }
        }
    });

    let client = step("rama binds", Endpoint::client(localhost()))
        .await
        .expect("the client binds");
    let refused = step(
        "the refused attempt",
        client
            .connect_with(rama_client_config(wrong_anchor), server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect_err("a server it does not trust must not get a connection");
    let told = refused.to_string();
    assert!(
        told.to_lowercase().contains("certificate") || told.contains("UnknownIssuer"),
        "the refusal names the certificate check: {refused:?}"
    );

    // The control: the same client, the same server, the right anchor.
    let accepted = step(
        "the trusted attempt",
        client
            .connect_with(rama_client_config(anchor), server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the identity it trusts is accepted");
    accepted.close(0u32.into(), b"done");

    step("rama's shutdown", client.wait_idle()).await;
    server.close(0u32.into(), b"done");
    step("the quinn server goes idle", server.wait_idle()).await;
    accepting.join("the quinn peer").await;
}

/// The same in the other direction: Quinn's client refuses the Rama server it does not trust, and
/// accepts it with the right anchor.
#[tokio::test]
async fn a_quinn_client_refuses_a_rama_server_it_does_not_trust() {
    let auth = identity();
    let anchor = auth.cert_chain.last().expect("a chain").clone();
    let stranger = identity();
    let wrong_anchor = stranger.cert_chain.last().expect("a chain").clone();

    let server = step(
        "the rama server binds",
        Endpoint::server(rama_server_config(&auth), localhost()),
    )
    .await
    .expect("it binds");
    let server_addr = server.local_addr().expect("its address");
    let accepting = Peer::spawn({
        let server = server.clone();
        async move {
            // As above: the guard bounds this task as a whole.
            for _ in 0..2 {
                let Some(incoming) = server.accept().await else {
                    return;
                };
                match incoming.accept() {
                    Ok(connecting) => {
                        let _ = connecting.await;
                    }
                    Err(_) => return,
                }
            }
        }
    });

    let mut client = quinn::Endpoint::client(localhost()).expect("quinn binds");
    client.set_default_client_config(quinn_client_config(wrong_anchor));
    let refused = step(
        "the refused attempt",
        client
            .connect(server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect_err("a server it does not trust must not get a connection");
    let told = refused.to_string();
    assert!(
        told.to_lowercase().contains("certificate") || told.contains("UnknownIssuer"),
        "the refusal names the certificate check: {refused:?}"
    );

    client.set_default_client_config(quinn_client_config(anchor));
    let accepted = step(
        "the trusted attempt",
        client
            .connect(server_addr, "localhost")
            .expect("the attempt starts"),
    )
    .await
    .expect("the identity it trusts is accepted");
    accepted.close(0u32.into(), b"done");

    step("quinn's shutdown", client.wait_idle()).await;
    accepting.join("the rama peer").await;
    step("rama's shutdown", server.shutdown()).await;
}

/// A peer that never finishes is stopped by the guard rather than left running: the wait keeps
/// the handle, so the timeout can abort it, and the task's own drop is observed.
#[tokio::test]
async fn a_peer_that_never_finishes_is_stopped() {
    let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    struct Guard(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let peer = Peer::spawn({
        let stopped = stopped.clone();
        async move {
            let _guard = Guard(stopped);
            std::future::pending::<()>().await;
        }
    });
    let mut peer = peer;
    let outcome = peer.try_join_within(Duration::from_millis(200)).await;
    assert!(
        outcome.is_err_and(|reason| reason.contains("not within")),
        "the wait ends by timing out"
    );
    assert!(
        stopped.load(std::sync::atomic::Ordering::SeqCst),
        "and the task it was waiting for is stopped, not detached"
    );
}
