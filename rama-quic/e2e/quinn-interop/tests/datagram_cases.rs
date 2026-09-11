//! The shared DATAGRAM cases, run against Quinn in both roles.

mod common;

use std::sync::Arc;

use common::{quinn_client_config, quinn_server_config};
use interop_common::{
    CaseRun, DatagramObservation, DatagramScenario, Peer, Received, Role, Unsupported,
    datagram::{rama_client_side, rama_server_side},
    datagram_cases, for_each_case,
    identity::anchor_of,
    scenario::SERVER_NAME,
    support::localhost,
};

const PEER: &str = "quinn";
/// The frame this side tells Quinn to advertise. `TransportConfig::datagram_receive_buffer_size`
/// is what Quinn derives `max_datagram_frame_size` from, as `min(value, u16::MAX)`
/// (quinn-proto 0.11.17 `transport_parameters.rs:170`), so a configured 256 is an advertised
/// 256. Small enough that it, and not the path MTU, is what bounds Rama.
const FRAME: usize = 256;
/// Why the boundary row does not run against this peer. Quinn advertises
/// `max_datagram_frame_size` from `datagram_receive_buffer_size`, which RFC 9221 §3 makes a
/// bound on the frame, but its receive check compares `data.len() + size_of::<Datagram>()`
/// against that same number (quinn-proto 0.11.17 `connection/datagrams.rs:126`). The second
/// term is the size of its own Rust struct, not the wire header, so it accepts less than it
/// advertises. Rama sends the advertised frame less its own 9-byte bound and is refused.
const QUINN_COUNTS_ITS_BUFFER: &str = "this peer measures a received datagram against its buffer size including in-memory \
     overhead, so it takes less than the frame size it advertises";

/// Quinn with that bound configured, for this family alone.
fn advertising(frame: usize) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.datagram_receive_buffer_size(Some(frame));
    Arc::new(transport)
}

/// Rama opens the connection and Quinn answers it, for every registered datagram case.
#[tokio::test]
async fn datagram_cases_rama_client() {
    for_each_case(PEER, Role::RamaClient, datagram_cases(), |run| async move {
        if run.scenario.at_the_boundary {
            // Visible with `cargo test -- --nocapture`.
            println!(
                "{}",
                Unsupported {
                    case: "datagram-at-the-boundary",
                    peer: PEER,
                    reason: QUINN_COUNTS_ITS_BUFFER,
                }
            );
            return;
        }
        let mut config = quinn_server_config(&run.identity);
        config.transport_config(advertising(FRAME));
        let server = quinn::Endpoint::server(config, localhost()).expect("the quinn server binds");
        let addr = server.local_addr().expect("its address");
        let peer = Peer::spawn({
            let run = run.clone();
            async move { quinn_answers(&run, server).await }
        });

        let rama = rama_client_side(&run, addr).await;
        let (limit, sent) = (rama.limit, rama.sent);
        rama.close(&run.what, run.deadline).await;
        let observed = peer.join(&run.what, run.deadline).await;
        observed.check(&run.what, &run.scenario, run.role, sent);
        observed.bounds(&run.what, limit);
    })
    .await;
}

/// Quinn opens the connection and Rama answers it, for every registered datagram case.
#[tokio::test]
async fn datagram_cases_rama_server() {
    for_each_case(PEER, Role::RamaServer, datagram_cases(), |run| async move {
        if skip_the_boundary(&run) {
            return;
        }
        let (endpoint, addr, serving) = rama_server_side(&run).await;
        let observed = quinn_asks(&run, anchor_of(&run.identity), addr).await;
        observed.check(&run.what, &run.scenario, run.role, run.scenario.back);
        observed.bounds(&run.what, serving.join(&run.what, run.deadline).await);
        run.deadline.wait(&run.what, endpoint.wait_idle()).await;
    })
    .await;
}

/// Quinn receives the datagram Rama sent and answers with the case's other one.
async fn quinn_answers(
    run: &CaseRun<DatagramScenario>,
    server: quinn::Endpoint,
) -> DatagramObservation {
    let (what, deadline) = (&run.what, run.deadline);
    let attempt = deadline
        .wait(what, server.accept())
        .await
        .expect("an attempt arrives");
    let conn = deadline
        .wait(what, attempt)
        .await
        .expect("the handshake completes");
    let arrived = deadline
        .wait(what, conn.read_datagram())
        .await
        .expect("a datagram arrives");
    // Quinn reports the largest datagram this connection may send.
    let observed = DatagramObservation {
        sendable: conn.max_datagram_size(),
        advertised: Some(FRAME),
        received: Some(Received::Bytes(arrived.to_vec())),
    };
    conn.send_datagram(run.scenario.back.bytes().into())
        .expect("the answering datagram is accepted");
    deadline.wait(what, conn.closed()).await;
    deadline.wait(what, server.wait_idle()).await;
    observed
}

/// Quinn sends the case's first datagram and receives the answering one.
async fn quinn_asks(
    run: &CaseRun<DatagramScenario>,
    anchor: rama::crypto::pki_types::CertificateDer<'static>,
    addr: std::net::SocketAddr,
) -> DatagramObservation {
    let (what, deadline) = (&run.what, run.deadline);
    let mut client = quinn::Endpoint::client(localhost()).expect("the quinn client binds");
    let mut config = quinn_client_config(anchor);
    config.transport_config(advertising(FRAME));
    client.set_default_client_config(config);
    let conn = deadline
        .wait(
            what,
            client
                .connect(addr, SERVER_NAME)
                .expect("the attempt starts"),
        )
        .await
        .expect("the handshake completes");
    let sendable = conn.max_datagram_size();
    conn.send_datagram(run.scenario.out.bytes().into())
        .expect("the datagram is accepted");
    let arrived = deadline
        .wait(what, conn.read_datagram())
        .await
        .expect("a datagram comes back");
    conn.close(0u32.into(), b"done");
    deadline.wait(what, client.wait_idle()).await;
    DatagramObservation {
        sendable,
        advertised: Some(FRAME),
        received: Some(Received::Bytes(arrived.to_vec())),
    }
}

/// The boundary row probes what Rama may send, so it runs where Rama opens the connection.
/// In this role Rama sends the case's fixed answer instead.
fn skip_the_boundary(run: &CaseRun<DatagramScenario>) -> bool {
    if run.scenario.at_the_boundary {
        // Visible with `cargo test -- --nocapture`.
        println!(
            "{}",
            Unsupported {
                case: "datagram-at-the-boundary",
                peer: PEER,
                reason: "the boundary is probed in the role where rama opens the connection",
            }
        );
    }
    run.scenario.at_the_boundary
}
