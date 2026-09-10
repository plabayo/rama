//! The shared DATAGRAM cases: what is sent each way, what each end must see, and the Rama side
//! of both roles.
//!
//! A datagram is one frame: what is sent arrives whole or not at all. Each case sends one out
//! and expects one back, so nothing here depends on the order of two deliveries.

use std::net::SocketAddr;

use rama::quic::{Connection, Endpoint};

use crate::{
    identity::{anchor_of, rama_client_config, rama_server_config},
    registry::{Case, CaseRun, Role},
    scenario::{Chunk, Received, SERVER_NAME},
    support::{Deadline, Peer, localhost},
};

/// One datagram out and one back, each named by the two numbers it follows from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramScenario {
    pub out: Chunk,
    pub back: Chunk,
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
    /// The datagram the peer received.
    pub received: Option<Received>,
}

impl DatagramObservation {
    /// Check the peer's account against the case, in the role Rama played.
    ///
    /// The two directions are separate: what the peer received is what Rama sent, and the
    /// limit it reports governs what it sends back. Comparing one against the other would pass
    /// for the wrong reason.
    pub fn check(&self, what: &str, scenario: &DatagramScenario, role: Role) {
        let (rama_sent, peer_sends) = match role {
            Role::RamaClient => (scenario.out, scenario.back),
            Role::RamaServer => (scenario.back, scenario.out),
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
    exchange(what, &connection, *deadline, scenario.out, scenario.back).await;
    RamaDatagramClient {
        endpoint,
        connection,
    }
}

/// A Rama client that has exchanged its datagrams and not yet closed.
#[derive(Debug)]
pub struct RamaDatagramClient {
    pub endpoint: Endpoint,
    pub connection: Connection,
}

impl RamaDatagramClient {
    pub async fn close(self, what: &str, deadline: Deadline) {
        self.connection.close(0u32.into(), b"done");
        deadline.wait(what, self.endpoint.wait_idle()).await;
    }
}

/// Rama as the server: accept, read the datagram that arrives, send the answering one.
pub async fn rama_server_side(run: &CaseRun<DatagramScenario>) -> (Endpoint, SocketAddr, Peer<()>) {
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
            send_one(&run.what, &conn, run.scenario.back);
            run.deadline.wait(&run.what, conn.closed()).await;
        }
    });
    (server, addr, serving)
}

/// Send one datagram and read the one that answers it.
async fn exchange(what: &str, conn: &Connection, deadline: Deadline, out: Chunk, back: Chunk) {
    send_one(what, conn, out);
    let arrived = deadline
        .wait(what, conn.read_datagram())
        .await
        .expect("a datagram comes back");
    Received::Bytes(arrived.to_vec()).check(what, "datagram", back);
}

/// Send one datagram, having checked the connection admits one of that size.
fn send_one(what: &str, conn: &Connection, chunk: Chunk) {
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
        };
        // Rama is the client: it sent `out`, and the peer must be able to send `back` (200).
        let as_client = DatagramObservation {
            sendable: Some(200),
            received: Some(Received::Bytes(scenario.out.bytes())),
        };
        // Rama is the server: it sent `back`, and the peer must be able to send `out` (64).
        let as_server = DatagramObservation {
            sendable: Some(64),
            received: Some(Received::Bytes(scenario.back.bytes())),
        };
        (scenario, as_client, as_server)
    }

    #[test]
    fn the_send_limit_is_checked_against_what_the_peer_sends() {
        let (scenario, as_client, as_server) = asymmetric();
        as_client.check("oracle/rama-client", &scenario, Role::RamaClient);
        as_server.check("oracle/rama-server", &scenario, Role::RamaServer);
    }

    /// A limit one byte short of what the peer has to send is caught, in either role. This is
    /// what fails if the check takes its chunk from the wrong direction.
    #[test]
    #[should_panic(expected = "the peer may send the datagram this case asks of it")]
    fn a_limit_short_of_what_the_peer_sends_is_refused() {
        let (scenario, mut as_client, _) = asymmetric();
        as_client.sendable = Some(scenario.back.len - 1);
        as_client.check("oracle/rama-client", &scenario, Role::RamaClient);
    }

    /// The same, with Rama as the server, so neither direction passes by accident.
    #[test]
    #[should_panic(expected = "the peer may send the datagram this case asks of it")]
    fn a_limit_short_of_what_the_peer_sends_is_refused_in_the_other_role() {
        let (scenario, _, mut as_server) = asymmetric();
        as_server.sendable = Some(scenario.out.len - 1);
        as_server.check("oracle/rama-server", &scenario, Role::RamaServer);
    }
}
