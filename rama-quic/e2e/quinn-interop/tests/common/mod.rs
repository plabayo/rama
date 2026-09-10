//! What both interoperability test files need: the identities, the configurations for each
//! stack, and the bounded waiting that keeps a hang from stalling a run.
#![allow(
    dead_code,
    reason = "shared support for several integration test binaries, each using part of it"
)]

use std::{
    io::{self, IoSliceMut},
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};

use rama::{
    crypto::{
        cert::{CertificateIdentity, CertificateSubject, LeafCertRequest, SelfSignedCaConfig},
        pki_types::CertificateDer,
    },
    quic::{ClientConfig, ServerConfig, tls::TlsOptions},
    tls::{
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::collections::smallvec::smallvec,
};
use sha2::{Digest, Sha256};

/// The protocol every scenario negotiates, shared with the other peer projects.
pub use interop_common::{ALPN, identity::alpn as shared_alpn};
/// Every await in these tests is bounded: a hang has to fail the test, not stall it.
pub const LIMIT: Duration = Duration::from_secs(20);

/// Await one step of a scenario, naming it so a timeout says which step stalled.
pub async fn step<F: std::future::Future>(what: &str, future: F) -> F::Output {
    match tokio::time::timeout(LIMIT, future).await {
        Ok(value) => value,
        Err(_) => panic!("{what}: not within {LIMIT:?}"),
    }
}

/// A spawned peer. The guard owns its handle for as long as it exists, including while a wait on
/// it is in progress, so a wait that is itself cancelled leaves the task with the guard. Dropping
/// the guard aborts the task; it does not wait for the task to unwind.
pub struct Peer(Option<tokio::task::JoinHandle<()>>);

impl Peer {
    pub fn spawn(task: impl std::future::Future<Output = ()> + Send + 'static) -> Self {
        Self(Some(tokio::spawn(task)))
    }

    pub async fn join(mut self, what: &str) {
        if let Err(reason) = self.try_join_within(LIMIT).await {
            panic!("{what}: {reason}");
        }
    }

    /// Wait for the task, with the handle staying in the guard throughout. Awaiting it by value
    /// would drop it on a timeout, leaving the task detached; taking it out first would do the
    /// same if this wait were cancelled.
    pub async fn try_join_within(&mut self, limit: Duration) -> Result<(), String> {
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

pub fn localhost() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
}

pub fn digest(payload: &[u8]) -> [u8; 32] {
    Sha256::digest(payload).into()
}

pub fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8) ^ seed).collect()
}

/// One generated identity, used by whichever side is the server and trusted by the other.
pub fn identity() -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::default())
        .expect("an identity is generated")
}

/// Identity issued by a certificate authority with a distinct name, so a peer trusting another
/// anchor finds no issuer for it.
pub fn identity_from_a_stranger(issuer: &str) -> ServerAuthData {
    ServerAuthData::new_generated(GeneratedServerAuthConfig::GeneratedCa {
        ca: SelfSignedCaConfig {
            subject: CertificateSubject {
                organisation_name: Some(issuer.to_owned()),
                common_name: Some(issuer.to_owned()),
            },
            ..Default::default()
        },
        leaf: LeafCertRequest::default(),
    })
    .expect("an identity is generated")
}

/// An identity valid for the loopback address, so a client may name the address it connects to.
pub fn address_identity() -> ServerAuthData {
    ServerAuthData::new_self_signed_leaf(LeafCertRequest::new(CertificateIdentity::Ip(
        Ipv4Addr::LOCALHOST.into(),
    )))
    .expect("an identity is generated")
}

pub fn rama_server_config(auth: &ServerAuthData) -> ServerConfig {
    let tls = TlsServerConfig::new()
        .with_alpn(smallvec![shared_alpn()])
        .with_server_auth(auth.clone());
    ServerConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the server config is built")
}

pub fn rama_client_config(anchor: CertificateDer<'static>) -> ClientConfig {
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![shared_alpn()])
        .try_with_server_trust_anchors([anchor])
        .expect("the trust anchor is accepted");
    ClientConfig::try_from_rama_tls(&tls, TlsOptions::default())
        .expect("the client config is built")
}

pub fn quinn_server_config(auth: &ServerAuthData) -> quinn::ServerConfig {
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

pub fn quinn_client_config(anchor: CertificateDer<'static>) -> quinn::ClientConfig {
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

/// A socket that counts the datagrams through it, so what a peer did about a move is a pair
/// of numbers rather than a wait that ran out. Everything else is the socket it wraps.
#[derive(Debug)]
pub struct Counted {
    inner: Arc<dyn AsyncUdpSocket>,
    sent: AtomicUsize,
    received: AtomicUsize,
}

impl Counted {
    #[must_use]
    pub fn around(inner: Arc<dyn AsyncUdpSocket>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            sent: AtomicUsize::new(0),
            received: AtomicUsize::new(0),
        })
    }

    /// Datagrams sent from this socket.
    pub fn sent(&self) -> usize {
        self.sent.load(Ordering::Relaxed)
    }

    /// Datagrams that arrived here.
    pub fn received(&self) -> usize {
        self.received.load(Ordering::Relaxed)
    }
}

impl AsyncUdpSocket for Counted {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)?;
        // One `Transmit` carries several datagrams when the sender segments it.
        let datagrams = transmit
            .segment_size
            .map_or(1, |size| transmit.contents.len().div_ceil(size));
        self.sent.fetch_add(datagrams, Ordering::Relaxed);
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let taken = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        let datagrams: usize = meta[..taken]
            .iter()
            .map(|it| it.len.div_ceil(it.stride.max(1)))
            .sum();
        self.received.fetch_add(datagrams, Ordering::Relaxed);
        Poll::Ready(Ok(taken))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
