//! The shared DATAGRAM cases: what is sent each way, what each end must see, and the Rama side
//! of both roles.
//!
//! A datagram is one frame: what is sent arrives whole or not at all. Each case sends one out
//! and expects one back, so nothing here depends on the order of two deliveries.

use std::net::SocketAddr;

use rama::quic::{Connection, Endpoint, SendDatagramError};

use crate::{
    identity::{anchor_of, rama_client_config, rama_server_config},
    registry::{Case, CaseRun, Role},
    scenario::{Chunk, Received, SERVER_NAME},
    support::{Deadline, Peer, localhost, payload},
};

/// One datagram out and one back, each named by the two numbers it follows from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramScenario {
    pub out: Chunk,
    pub back: Chunk,
    /// Whether this row probes the size boundary rather than carrying the fixed payload.
    ///
    /// A boundary row pins the path so the limit cannot move under it: MTU discovery off and
    /// a fixed MTU. The payload is then the limit itself, read immediately before the send.
    pub at_the_boundary: bool,
}

/// Every datagram case each eligible peer runs, in both roles.
#[must_use]
pub fn datagram_cases() -> Vec<Case<DatagramScenario>> {
    vec![
        Case {
            name: "datagram-exchange",
            scenario: DatagramScenario {
                out: Chunk {
                    seed: 0x71,
                    len: 128,
                },
                back: Chunk {
                    seed: 0x72,
                    len: 96,
                },
                at_the_boundary: false,
            },
        },
        Case {
            name: "datagram-exchange-small",
            scenario: DatagramScenario {
                out: Chunk {
                    seed: 0x73,
                    len: 17,
                },
                back: Chunk {
                    seed: 0x74,
                    len: 41,
                },
                at_the_boundary: false,
            },
        },
        // The API's own boundary: the largest datagram the connection reports is delivered,
        // and one byte more is refused. `out` names only the seed; its length is the limit.
        // Zero-length application data is valid and is not a boundary request.
        Case {
            name: "datagram-empty-payload",
            scenario: DatagramScenario {
                out: Chunk { seed: 0x77, len: 0 },
                back: Chunk {
                    seed: 0x78,
                    len: 24,
                },
                at_the_boundary: false,
            },
        },
        Case {
            name: "datagram-at-the-boundary",
            scenario: DatagramScenario {
                // Its length is read from the connection, so this one is unused.
                out: Chunk { seed: 0x75, len: 0 },
                back: Chunk {
                    seed: 0x76,
                    len: 64,
                },
                at_the_boundary: true,
            },
        },
    ]
}

/// What a peer says about the datagram it received and the size it may send.
#[derive(Debug, Clone, Default)]
pub struct DatagramObservation {
    /// The largest datagram payload the peer's own connection says **it** may send, where its
    /// implementation exposes that. `None` where it does not: the adapter says so rather than
    /// reporting a configured input as though it were an observation.
    pub sendable: Option<usize>,
    /// The `max_datagram_frame_size` the peer advertises, which bounds what **Rama** may
    /// send. This is the peer's configuration as the adapter set or read it from the pinned
    /// API, not something the peer measured; `None` where the adapter cannot establish it.
    ///
    /// Kept apart from `sendable`, which is the other direction.
    pub advertised: Option<usize>,
    /// The datagram the peer received.
    pub received: Option<Received>,
}

impl DatagramObservation {
    /// Check the peer's account against what Rama actually sent, in the role Rama played.
    ///
    /// The two directions are separate: what the peer received is what Rama sent, and the
    /// limit it reports governs what it sends back. Comparing one against the other would pass
    /// for the wrong reason.
    pub fn check(&self, what: &str, scenario: &DatagramScenario, role: Role, rama_sent: Chunk) {
        // What Rama sent is passed in, since a boundary row sizes it from the connection
        // rather than from the case. What the peer sends is the case's other chunk.
        let peer_sends = match role {
            Role::RamaClient => scenario.back,
            Role::RamaServer => scenario.out,
        };
        if let Some(limit) = self.sendable {
            assert!(
                limit >= peer_sends.len,
                "{what}: the peer may send the datagram this case asks of it: {limit} against {}",
                peer_sends.len
            );
        }
        let received = self.received.as_ref().expect("the peer received one");
        received.check(what, "datagram", rama_sent);
    }

    /// What Rama may send towards this peer, against the frame the peer advertised. The
    /// limit is Rama's own; the bound is the peer's. Skipped where the adapter could not
    /// establish the advertisement.
    ///
    /// # Panics
    /// If Rama would send more than the peer said it would take.
    pub fn bounds(&self, what: &str, rama_limit: usize) {
        let Some(advertised) = self.advertised else {
            return;
        };
        assert!(
            rama_limit <= advertised,
            "{what}: rama's datagram limit {rama_limit} exceeds the {advertised} the peer advertised"
        );
    }
}

/// Rama as the client: connect, send one datagram, read the one that comes back.
pub async fn rama_client_side(
    run: &CaseRun<DatagramScenario>,
    peer_addr: SocketAddr,
) -> RamaDatagramClient {
    let CaseRun {
        what,
        identity,
        deadline,
        scenario,
        ..
    } = run;
    let endpoint = deadline
        .wait(what, Endpoint::client(localhost()))
        .await
        .expect("the rama client binds");
    let connection = deadline
        .wait(
            what,
            endpoint
                .connect_with(
                    rama_client_config(anchor_of(identity)),
                    peer_addr,
                    SERVER_NAME,
                )
                .expect("the attempt starts"),
        )
        .await
        .expect("the handshake completes");
    let (limit, sent) = exchange(
        what,
        &connection,
        *deadline,
        scenario.out,
        scenario.back,
        scenario.at_the_boundary,
    )
    .await;
    RamaDatagramClient {
        endpoint,
        connection,
        limit,
        sent,
    }
}

/// A Rama client that has exchanged its datagrams and not yet closed.
#[derive(Debug)]
pub struct RamaDatagramClient {
    pub endpoint: Endpoint,
    pub connection: Connection,
    /// The largest datagram Rama said it could send on this connection.
    pub limit: usize,
    /// The payload it actually sent, which is the case's own for an ordinary row and the
    /// limit itself for a boundary row.
    pub sent: Chunk,
}

impl RamaDatagramClient {
    pub async fn close(self, what: &str, deadline: Deadline) {
        self.connection.close(0u32.into(), b"done");
        deadline.wait(what, self.endpoint.wait_idle()).await;
    }
}

/// Rama as the server: accept, read the datagram that arrives, send the answering one.
pub async fn rama_server_side(
    run: &CaseRun<DatagramScenario>,
) -> (Endpoint, SocketAddr, Peer<usize>) {
    let CaseRun {
        what,
        deadline,
        identity,
        ..
    } = run;
    let server = deadline
        .wait(
            what,
            Endpoint::server(rama_server_config(identity), localhost()),
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
            // The peer sends first in this role, so the answering datagram is the one Rama
            // receives and `back` the one it sends.
            let arrived = run
                .deadline
                .wait(&run.what, conn.read_datagram())
                .await
                .expect("a datagram arrives");
            Received::Bytes(arrived.to_vec()).check(&run.what, "datagram", run.scenario.out);
            let limit = send_one(&run.what, &conn, run.scenario.back);
            run.deadline.wait(&run.what, conn.closed()).await;
            limit
        }
    });
    (server, addr, serving)
}

/// Send one datagram and read the one that answers it.
async fn exchange(
    what: &str,
    conn: &Connection,
    deadline: Deadline,
    out: Chunk,
    back: Chunk,
    boundary: bool,
) -> (usize, Chunk) {
    let (limit, out) = send_sized(what, conn, out, boundary);
    let arrived = deadline
        .wait(what, conn.read_datagram())
        .await
        .expect("a datagram comes back");
    Received::Bytes(arrived.to_vec()).check(what, "datagram", back);
    (limit, out)
}

/// The payload a row sends: the one it names, or the connection's own limit read immediately
/// before the send where the row probes the boundary. A boundary row then requires one byte
/// more to be refused, reading the limit again at that moment so a stale value cannot stand
/// in for a live one.
///
/// # Panics
/// If an oversized datagram is accepted, or refused for another reason.
fn send_sized(what: &str, conn: &Connection, out: Chunk, boundary: bool) -> (usize, Chunk) {
    let Chunk { seed, .. } = out;
    let out = match boundary {
        true => Chunk {
            seed,
            len: conn
                .max_datagram_size()
                .expect("the peer offered the extension"),
        },
        false => out,
    };
    let limit = send_one(what, conn, out);
    if boundary {
        let live = conn
            .max_datagram_size()
            .expect("the peer offered the extension");
        let refused = conn
            .send_datagram(payload(seed, live + 1).into())
            .expect_err("a datagram over the limit is refused");
        assert_eq!(
            refused,
            SendDatagramError::TooLarge,
            "{what}: unexpected refusal for {} bytes against a live limit of {live}",
            live + 1
        );
    }
    (limit, out)
}

/// Send one datagram, having checked the connection admits one of that size. Answers the
/// limit this side reported, which a case compares against what the peer advertised.
fn send_one(what: &str, conn: &Connection, chunk: Chunk) -> usize {
    let limit = conn
        .max_datagram_size()
        .expect("the peer offered the extension");
    assert!(
        limit >= chunk.len,
        "{what}: the negotiated size admits this datagram: {limit} against {}",
        chunk.len
    );
    conn.send_datagram(chunk.bytes().into())
        .expect("the datagram is accepted");
    limit
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two directions of a case, with a send limit that admits one and not the other. It is
    /// the oracle that is exercised here, not the wire: a real peer's negotiated limit is not
    /// configurable enough to sit between two payloads on every stack.
    fn asymmetric() -> (DatagramScenario, DatagramObservation, DatagramObservation) {
        let scenario = DatagramScenario {
            out: Chunk {
                seed: 0x01,
                len: 64,
            },
            back: Chunk {
                seed: 0x02,
                len: 200,
            },
            at_the_boundary: false,
        };
        // Rama is the client: it sent `out`, and the peer must be able to send `back` (200).
        let as_client = DatagramObservation {
            sendable: Some(200),
            advertised: None,
            received: Some(Received::Bytes(scenario.out.bytes())),
        };
        // Rama is the server: it sent `back`, and the peer must be able to send `out` (64).
        let as_server = DatagramObservation {
            sendable: Some(64),
            advertised: None,
            received: Some(Received::Bytes(scenario.back.bytes())),
        };
        (scenario, as_client, as_server)
    }

    #[test]
    fn the_send_limit_is_checked_against_what_the_peer_sends() {
        let (scenario, as_client, as_server) = asymmetric();
        as_client.check(
            "oracle/rama-client",
            &scenario,
            Role::RamaClient,
            scenario.out,
        );
        as_server.check(
            "oracle/rama-server",
            &scenario,
            Role::RamaServer,
            scenario.back,
        );
    }

    /// A limit one byte short of what the peer has to send is caught, in either role. This is
    /// what fails if the check takes its chunk from the wrong direction.
    #[test]
    #[should_panic(expected = "the peer may send the datagram this case asks of it")]
    fn a_limit_short_of_what_the_peer_sends_is_refused() {
        let (scenario, mut as_client, _) = asymmetric();
        as_client.sendable = Some(scenario.back.len - 1);
        as_client.check(
            "oracle/rama-client",
            &scenario,
            Role::RamaClient,
            scenario.out,
        );
    }

    /// The same, with Rama as the server, so neither direction passes by accident.
    #[test]
    #[should_panic(expected = "the peer may send the datagram this case asks of it")]
    fn a_limit_short_of_what_the_peer_sends_is_refused_in_the_other_role() {
        let (scenario, _, mut as_server) = asymmetric();
        as_server.sendable = Some(scenario.out.len - 1);
        as_server.check(
            "oracle/rama-server",
            &scenario,
            Role::RamaServer,
            scenario.back,
        );
    }
}
