//! The shared server-name cases: the name a client asks for, and the absence of one when it
//! connects to an address.
//!
//! Two observations are involved and they are not equally available. What **Rama's** server saw
//! is `handshake_data().server_name` and every peer can drive it. What the **peer's** server saw
//! depends on that implementation exposing it, which is a bridge question rather than a
//! protocol one; [`ReceivedName::Unavailable`] carries that, and the case still runs.

use std::net::SocketAddr;

use rama::{
    crypto::pki_types::ServerName,
    net::address::Domain,
    quic::{Connection, ConnectionError, Endpoint},
    tls::rustls::dep::rustls::{self, CertificateError},
    utils::octets,
};

use crate::{
    identity::{Identity, address_identity, anchor_of, rama_client_config, rama_server_config},
    registry::{Case, CaseRun},
    scenario::{Chunk, Received, SERVER_NAME},
    support::{Peer, localhost},
};

const READ_CAP: usize = octets::kib(64);

/// What a name case asks for, and the probe that proves the connection works afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameScenario {
    /// The name the client asks for, or none when it connects to an address literal.
    pub asked: Option<&'static str>,
    pub probe: Chunk,
}

/// A case where the server's certificate does not match what the client asks for, while still
/// chaining to an anchor the client trusts. That is what separates this from the trust family:
/// the issuer is fine and only the identity is wrong.
///
/// Both shapes the native tests cover are here, built from the two identities the shared
/// module already makes: a certificate for the address while a name is asked for, and a
/// certificate for the name while the address is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mismatch {
    /// The certificate carries the loopback address; the client asks for the name.
    CertificateForAddress,
    /// The certificate carries the name; the client asks for the address.
    CertificateForName,
}

impl Mismatch {
    /// The identity the server presents.
    #[must_use]
    pub fn identity(self) -> Identity {
        match self {
            Self::CertificateForAddress => address_identity(),
            Self::CertificateForName => crate::identity::server_identity(),
        }
    }

    /// What the client asks for, which the certificate is not valid for.
    #[must_use]
    pub fn mismatched_request(self, peer: SocketAddr) -> String {
        match self {
            Self::CertificateForAddress => SERVER_NAME.to_owned(),
            Self::CertificateForName => peer.ip().to_string(),
        }
    }

    /// What the client asks for in the control, which the same certificate is valid for.
    #[must_use]
    pub fn matching_request(self, peer: SocketAddr) -> String {
        match self {
            Self::CertificateForAddress => peer.ip().to_string(),
            Self::CertificateForName => SERVER_NAME.to_owned(),
        }
    }
}

/// The probe the control carries, so acceptance means a working connection and not merely a
/// handshake.
pub const MISMATCH_PROBE: Chunk = Chunk {
    seed: 0xb1,
    len: 320,
};

/// Every mismatched-identity case each eligible peer runs.
#[must_use]
pub fn mismatch_cases() -> Vec<Case<Mismatch>> {
    vec![
        Case {
            name: "identity-mismatch-name-asked",
            scenario: Mismatch::CertificateForAddress,
        },
        Case {
            name: "identity-mismatch-address-asked",
            scenario: Mismatch::CertificateForName,
        },
    ]
}

/// Rama's client against a server whose certificate is for something else: the attempt must
/// fail on the identity, naming what was asked for, and nothing may pass first.
pub async fn rama_client_refuses_the_identity(run: &CaseRun<Mismatch>, peer_addr: SocketAddr) {
    let CaseRun {
        what,
        deadline,
        identity,
        scenario,
        ..
    } = run;
    let client = deadline
        .wait(what, Endpoint::client(localhost()))
        .await
        .expect("the rama client binds");
    let asked = scenario.mismatched_request(peer_addr);
    let refused = deadline
        .wait(
            what,
            client
                .connect_with(rama_client_config(anchor_of(identity)), peer_addr, &asked)
                .expect("the attempt starts"),
        )
        .await
        .expect_err("a certificate for another identity must not be accepted");
    let ConnectionError::TransportError(error) = &refused else {
        panic!("{what}: the attempt ended on a transport error: {refused:?}");
    };
    // The anchor is trusted, so this must be the identity check and not the issuer.
    let cause = error
        .cause()
        .and_then(|cause| cause.downcast_ref::<rustls::Error>())
        .unwrap_or_else(|| panic!("{what}: a rustls cause was due: {:?}", error.cause()));
    let rustls::Error::InvalidCertificate(CertificateError::NotValidForNameContext {
        expected,
        presented,
    }) = cause
    else {
        panic!("{what}: the identity check was due, not {cause:?}");
    };
    // Compared as an identity rather than as text: an address is not spelled the same way in
    // the debug output as it is in the request.
    let wanted = ServerName::try_from(asked.as_str())
        .unwrap_or_else(|_| panic!("{what}: the request is a usable identity"))
        .to_owned();
    assert_eq!(
        *expected, wanted,
        "{what}: the context names the identity that was asked for"
    );
    assert!(
        !presented.is_empty(),
        "{what}: and the ones the certificate carried"
    );
    deadline.wait(what, client.wait_idle()).await;
}

/// The control: the same server certificate, and a client asking for what it is valid for.
/// The probe crosses both ways, so acceptance is a working connection.
pub async fn rama_client_accepts_the_identity(run: &CaseRun<Mismatch>, peer_addr: SocketAddr) {
    let CaseRun {
        what,
        deadline,
        identity,
        scenario,
        ..
    } = run;
    let client = deadline
        .wait(what, Endpoint::client(localhost()))
        .await
        .expect("the rama client binds");
    let asked = scenario.matching_request(peer_addr);
    let conn = deadline
        .wait(
            what,
            client
                .connect_with(rama_client_config(anchor_of(identity)), peer_addr, &asked)
                .expect("the attempt starts"),
        )
        .await
        .expect("the identity it asks for is the one presented");
    let (mut send, mut recv) = deadline
        .wait(what, conn.open_bi())
        .await
        .expect("a bi stream");
    deadline
        .wait(what, send.write_all(&MISMATCH_PROBE.bytes()))
        .await
        .expect("the probe is written");
    send.finish().expect("the probe ends");
    let back = deadline
        .wait(what, recv.read_to_end(READ_CAP))
        .await
        .expect("the probe comes back");
    Received::Bytes(back).check(what, "probe", MISMATCH_PROBE);
    conn.close(0u32.into(), b"done");
    deadline.wait(what, client.wait_idle()).await;
}

/// Every name case each eligible peer runs.
#[must_use]
pub fn name_cases() -> Vec<Case<NameScenario>> {
    vec![
        Case {
            name: "name-asked",
            scenario: NameScenario {
                asked: Some(SERVER_NAME),
                probe: Chunk {
                    seed: 0xa1,
                    len: 256,
                },
            },
        },
        // RFC 6066 §3: a client connecting to an address literal sends no name at all.
        Case {
            name: "name-absent",
            scenario: NameScenario {
                asked: None,
                probe: Chunk {
                    seed: 0xa2,
                    len: 192,
                },
            },
        },
    ]
}

/// What a peer's own side says about the name it received.
///
/// `Seen(None)` and `Unavailable` are different facts and are kept apart: the first is the peer
/// reporting that no name was sent, the second is the peer having no way to report at all. A
/// case whose diagnostic is unavailable still runs; only that one assertion is withheld.
#[derive(Debug, Clone)]
pub enum ReceivedName {
    /// The peer reported the name it received, or reported that none was sent.
    Seen(Option<String>),
    /// This peer's bridge exposes no such observation, for the reason given.
    Unavailable(&'static str),
}

/// What the peer's own side reports about the name it received.
#[derive(Debug, Clone)]
pub struct NameObservation {
    pub server_name: ReceivedName,
}

impl NameObservation {
    /// Check the peer's report where there is one. Returns whether the assertion was made, so
    /// a caller can say which combinations carried it.
    pub fn check(&self, what: &str, scenario: &NameScenario) -> bool {
        match &self.server_name {
            ReceivedName::Seen(seen) => {
                assert_eq!(
                    seen.as_deref(),
                    scenario.asked,
                    "{what}: the name the peer says the client asked for"
                );
                true
            }
            ReceivedName::Unavailable(_) => false,
        }
    }
}

/// The identity a case's server presents: one valid for the loopback address when no name is
/// asked for, and one valid for the name otherwise.
#[must_use]
pub fn identity_for(scenario: &NameScenario) -> Identity {
    match scenario.asked {
        Some(_) => crate::identity::server_identity(),
        None => address_identity(),
    }
}

/// Rama as the client, asking for the case's name or for none, then proving the connection
/// carries traffic.
pub async fn rama_client_side(run: &CaseRun<NameScenario>, peer_addr: SocketAddr) {
    let CaseRun {
        what,
        deadline,
        identity,
        scenario,
        ..
    } = run;
    let client = deadline
        .wait(what, Endpoint::client(localhost()))
        .await
        .expect("the rama client binds");
    // Asking for nothing means naming the address itself, which is how RFC 6066 §3 says a
    // client with no name to send behaves.
    let asked = scenario
        .asked
        .map_or_else(|| peer_addr.ip().to_string(), str::to_owned);
    let conn = deadline
        .wait(
            what,
            client
                .connect_with(rama_client_config(anchor_of(identity)), peer_addr, &asked)
                .expect("the attempt starts"),
        )
        .await
        .expect("the handshake completes");
    probe(what, &conn, run).await;
    conn.close(0u32.into(), b"done");
    deadline.wait(what, client.wait_idle()).await;
}

/// Rama as the server: it reports the name the peer asked for, which is the observation this
/// family is about, then answers the probe.
pub async fn rama_server_side(run: &CaseRun<NameScenario>) -> (Endpoint, SocketAddr, Peer<()>) {
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
            let attempt = run
                .deadline
                .wait(&run.what, server.accept())
                .await
                .expect("an attempt arrives");
            let conn = run
                .deadline
                .wait(&run.what, attempt)
                .await
                .expect("the handshake completes");
            let settled = conn
                .handshake_data()
                .expect("the handshake settled something");
            assert_eq!(
                settled.server_name,
                run.scenario.asked.map(Domain::from_static),
                "{}: the name rama's server says the client asked for",
                run.what
            );
            answer(&run.what, &conn, &run).await;
            run.deadline.wait(&run.what, conn.closed()).await;
        }
    });
    (server, addr, serving)
}

/// Send the probe and read it back.
async fn probe(what: &str, conn: &Connection, run: &CaseRun<NameScenario>) {
    let deadline = run.deadline;
    let (mut send, mut recv) = deadline
        .wait(what, conn.open_bi())
        .await
        .expect("a bi stream");
    deadline
        .wait(what, send.write_all(&run.scenario.probe.bytes()))
        .await
        .expect("the probe is written");
    send.finish().expect("the probe ends");
    let back = deadline
        .wait(what, recv.read_to_end(READ_CAP))
        .await
        .expect("the probe comes back");
    Received::Bytes(back).check(what, "probe", run.scenario.probe);
}

/// Read the probe and send it back.
async fn answer(what: &str, conn: &Connection, run: &CaseRun<NameScenario>) {
    let deadline = run.deadline;
    let (mut send, mut recv) = deadline
        .wait(what, conn.accept_bi())
        .await
        .expect("the probe's stream arrives");
    let received = deadline
        .wait(what, recv.read_to_end(READ_CAP))
        .await
        .expect("the probe completes");
    Received::Bytes(received).check(what, "probe", run.scenario.probe);
    deadline
        .wait(what, send.write_all(&run.scenario.probe.bytes()))
        .await
        .expect("the probe goes back");
    send.finish().expect("the answer ends");
}
