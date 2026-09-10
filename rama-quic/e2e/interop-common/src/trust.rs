//! The shared certificate-trust cases: a peer whose identity is not trusted is refused, and the
//! same peer with the right anchor is not.
//!
//! Both halves belong to one case. A refusal on its own says nothing: it could come from any
//! handshake failure, so the control that follows uses the same identity and the right anchor
//! and has to succeed.

use std::net::SocketAddr;

use rama::{
    crypto::pki_types::CertificateDer,
    quic::{ConnectionError, Endpoint},
    tls::rustls::dep::rustls::{self, AlertDescription, CertificateError},
};

use crate::{
    identity::{anchor_of, identity_from_a_stranger, rama_client_config, rama_server_config},
    registry::{Case, CaseRun},
    scenario::{Chunk, Received, SERVER_NAME},
    support::{Deadline, Peer, localhost},
};

/// The exchange the positive control carries, so the control proves a working connection and
/// not merely a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustScenario {
    pub probe: Chunk,
}

/// An anchor for an issuer nothing in a case was signed by. Both phases of a case serve the
/// same identity; this is what the first phase trusts instead of it, so the only thing that
/// changes between the two is the anchor.
#[must_use]
pub fn wrong_anchor() -> CertificateDer<'static> {
    anchor_of(&identity_from_a_stranger("Another Authority"))
}

/// Every trust case each eligible peer runs.
#[must_use]
pub fn trust_cases() -> Vec<Case<TrustScenario>> {
    vec![Case {
        name: "trust-refusal",
        scenario: TrustScenario {
            probe: Chunk {
                seed: 0x91,
                len: 512,
            },
        },
    }]
}

/// What a peer says about the refusal it saw. The detail is that implementation's own, kept so
/// an adapter can assert on it without the shared code pretending to understand it.
#[derive(Debug, Clone, Default)]
pub struct TrustObservation {
    /// Whether the peer's own implementation reports the handshake as refused.
    pub refused: bool,
    /// What it said about why, in its own words.
    pub detail: Option<String>,
}

impl TrustObservation {
    pub fn check(&self, what: &str) {
        assert!(
            self.refused,
            "{what}: the peer saw the handshake refused, and said: {:?}",
            self.detail
        );
    }
}

/// Rama's client against a server it has no anchor for: the attempt must fail on the
/// certificate, named as such, and no frame is at fault.
pub async fn rama_client_refuses(
    run: &CaseRun<TrustScenario>,
    peer_addr: SocketAddr,
) -> ConnectionError {
    let CaseRun { what, deadline, .. } = run;
    let client = deadline
        .wait(what, Endpoint::client(localhost()))
        .await
        .expect("the rama client binds");
    let refused = deadline
        .wait(
            what,
            client
                .connect_with(rama_client_config(wrong_anchor()), peer_addr, SERVER_NAME)
                .expect("the attempt starts"),
        )
        .await
        .expect_err("a server it does not trust must not get a connection");
    let ConnectionError::TransportError(error) = &refused else {
        panic!("{what}: the attempt ended on a transport error: {refused:?}");
    };
    // The refusal is the certificate check and not some other handshake failure: the alert
    // says the issuer is unknown, the cause is that same check, and no frame is at fault.
    assert_eq!(
        error.code().tls_alert(),
        Some(u8::from(AlertDescription::UnknownCA)),
        "{what}: the alert says the issuer is not one it trusts: {}",
        error.reason()
    );
    assert!(
        error
            .cause()
            .and_then(|cause| cause.downcast_ref::<rustls::Error>())
            .is_some_and(|error| matches!(
                error,
                rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
            )),
        "{what}: and the cause is the issuer, not something else: {:?}",
        error.cause()
    );
    assert_eq!(
        error.frame_type(),
        None,
        "{what}: a certificate refusal names no frame"
    );
    deadline.wait(what, client.wait_idle()).await;
    refused
}

/// The control: the same server, the anchor that does match, and a payload over the connection
/// it gets. A refusal only means something next to this.
pub async fn rama_client_accepts(run: &CaseRun<TrustScenario>, peer_addr: SocketAddr) {
    let CaseRun {
        what,
        deadline,
        scenario,
        ..
    } = run;
    let client = deadline
        .wait(what, Endpoint::client(localhost()))
        .await
        .expect("the rama client binds");
    let conn = deadline
        .wait(
            what,
            client
                .connect_with(
                    rama_client_config(anchor_of(&run.identity)),
                    peer_addr,
                    SERVER_NAME,
                )
                .expect("the attempt starts"),
        )
        .await
        .expect("the anchor that matches gets a connection");
    // The probe goes and comes back, so the control ends on the peer having answered rather
    // than on this side having written.
    let (mut send, mut recv) = deadline
        .wait(what, conn.open_bi())
        .await
        .expect("a bi stream");
    deadline
        .wait(what, send.write_all(&scenario.probe.bytes()))
        .await
        .expect("the probe is written");
    send.finish().expect("the probe ends");
    let back = deadline
        .wait(what, recv.read_to_end(scenario.probe.len + 1))
        .await
        .expect("the probe comes back");
    Received::Bytes(back).check(what, "probe", scenario.probe);
    conn.close(0u32.into(), b"done");
    deadline.wait(what, client.wait_idle()).await;
}

/// What Rama's server made of the attempt against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerOutcome {
    /// The peer completed the handshake and its probe came back.
    Probed,
    /// The peer's handshake failed, which is what a refused identity gives.
    Refused,
    /// Nothing happened before the case ran out of time. Never what a case expects.
    TimedOut,
}

/// Rama's server for the other direction, taking whichever identity the case gives it. The
/// peer's client decides whether it trusts that identity.
///
/// The task returns what it saw rather than swallowing it, so a caller that joins it learns
/// both the outcome and any assertion that failed inside it.
pub async fn rama_server_side(
    run: &CaseRun<TrustScenario>,
    expect_probe: bool,
) -> (Endpoint, SocketAddr, Peer<ServerOutcome>) {
    let CaseRun { what, deadline, .. } = run;
    let server = deadline
        .wait(
            what,
            Endpoint::server(rama_server_config(&run.identity), localhost()),
        )
        .await
        .expect("the rama server binds");
    let addr = server.local_addr().expect("its address");
    let serving = Peer::spawn({
        let run = run.clone();
        let server = server.clone();
        async move {
            // A refused identity may leave nothing to accept at all, so this waits for an
            // attempt without insisting on one. Running out of time is not a refusal and is
            // reported as itself.
            let attempt = match run.deadline.try_wait(server.accept()).await {
                Some(Some(attempt)) => attempt,
                Some(None) => return ServerOutcome::Refused,
                None => return ServerOutcome::TimedOut,
            };
            let conn = match run.deadline.try_wait(attempt).await {
                Some(Ok(conn)) => conn,
                Some(Err(_)) => return ServerOutcome::Refused,
                None => return ServerOutcome::TimedOut,
            };
            if !expect_probe {
                return ServerOutcome::Probed;
            }
            let (mut send, mut recv) = run
                .deadline
                .wait(&run.what, conn.accept_bi())
                .await
                .expect("the probe's stream arrives");
            let received = run
                .deadline
                .wait(&run.what, recv.read_to_end(run.scenario.probe.len + 1))
                .await
                .expect("the probe completes");
            Received::Bytes(received).check(&run.what, "probe", run.scenario.probe);
            run.deadline
                .wait(&run.what, send.write_all(&run.scenario.probe.bytes()))
                .await
                .expect("the probe goes back");
            send.finish().expect("the answer ends");
            run.deadline.wait(&run.what, conn.closed()).await;
            ServerOutcome::Probed
        }
    });
    (server, addr, serving)
}

/// Join a server task and require the outcome the case expects. A panic inside the task is
/// propagated rather than passed over.
pub async fn expect_outcome(
    serving: Peer<ServerOutcome>,
    what: &str,
    deadline: Deadline,
    expected: ServerOutcome,
) {
    let seen = serving.join(what, deadline).await;
    assert_eq!(seen, expected, "{what}: what the rama server made of it");
}
