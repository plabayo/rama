//! The shared DATAGRAM cases, run against quiche in both roles.

mod common;

use common::{Identity, Quiche, quiche_client_config, quiche_server_config, with_datagrams};
use interop_common::{
    CaseRun, DatagramObservation, DatagramScenario, Peer, Received, Role, Unsupported,
    datagram::{rama_client_side, rama_server_side},
    datagram_cases, for_each_case,
    scenario::SERVER_NAME,
};
use rama::utils::octets;

const PEER: &str = "quiche";
/// What quiche advertises as `max_datagram_frame_size`. `Config::enable_dgram` sets it to
/// this fixed value in the pinned 0.24 and offers no way to choose another, so the bound is
/// read from that API rather than configured by a case.
const QUICHE_FRAME: usize = octets::kib(64);
const READ_CAP: usize = octets::kib(64);

/// Rama opens the connection and quiche answers it, for every registered datagram case.
#[tokio::test]
async fn datagram_cases_rama_client() {
    for_each_case(PEER, Role::RamaClient, datagram_cases(), |run| async move {
        let identity = Identity::generate(SERVER_NAME);
        let run = run.with_identity(identity.auth.clone());
        let (addr, accepting) = Quiche::bind_server(
            with_datagrams(quiche_server_config(&identity)),
            run.deadline,
        )
        .await;
        let peer = Peer::spawn({
            let run = run.clone();
            async move {
                let mut server = accepting.await;
                quiche_answers(&run, &mut server).await
            }
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

/// quiche opens the connection and Rama answers it, for every registered datagram case.
#[tokio::test]
async fn datagram_cases_rama_server() {
    for_each_case(PEER, Role::RamaServer, datagram_cases(), |run| async move {
        if skip_the_boundary(&run) {
            return;
        }
        let identity = Identity::generate(SERVER_NAME);
        let run = run.with_identity(identity.auth.clone());
        let (endpoint, addr, serving) = rama_server_side(&run).await;
        let mut client = Quiche::connect(
            addr,
            SERVER_NAME,
            with_datagrams(quiche_client_config(&identity)),
            run.deadline,
        )
        .await;
        let observed = quiche_asks(&run, &mut client).await;
        observed.check(&run.what, &run.scenario, run.role, run.scenario.back);
        observed.bounds(&run.what, serving.join(&run.what, run.deadline).await);
        run.deadline.wait(&run.what, endpoint.wait_idle()).await;
    })
    .await;
}

/// quiche receives the datagram Rama sent and answers with the case's other one.
async fn quiche_answers(
    run: &CaseRun<DatagramScenario>,
    server: &mut Quiche,
) -> DatagramObservation {
    let (what, deadline) = (&run.what, run.deadline);
    server
        .drive_until(what, deadline, |connection| connection.is_established())
        .await;
    let arrived = server.read_datagram(READ_CAP, deadline).await;
    // What quiche says this connection may write as one datagram.
    let sendable = server.connection().dgram_max_writable_len();
    server
        .send_datagram(&run.scenario.back.bytes(), deadline)
        .await;
    server
        .drive_until(what, deadline, |connection| connection.is_closed())
        .await;
    DatagramObservation {
        sendable,
        advertised: Some(QUICHE_FRAME),
        received: Some(Received::Bytes(arrived)),
    }
}

/// quiche sends the case's first datagram and receives the answering one.
async fn quiche_asks(run: &CaseRun<DatagramScenario>, client: &mut Quiche) -> DatagramObservation {
    let (what, deadline) = (&run.what, run.deadline);
    client
        .drive_until(what, deadline, |connection| connection.is_established())
        .await;
    let sendable = client.connection().dgram_max_writable_len();
    client
        .send_datagram(&run.scenario.out.bytes(), deadline)
        .await;
    let arrived = client.read_datagram(READ_CAP, deadline).await;
    client.close(deadline).await;
    DatagramObservation {
        sendable,
        advertised: Some(QUICHE_FRAME),
        received: Some(Received::Bytes(arrived)),
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
