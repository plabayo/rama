//! The shared DATAGRAM cases, run against quiche in both roles.

mod common;

use common::{Identity, Quiche, quiche_client_config, quiche_server_config, with_datagrams};
use interop_common::{
    CaseRun, DatagramObservation, DatagramScenario, Peer, Received, Role,
    datagram::{rama_client_side, rama_server_side},
    datagram_cases, for_each_case,
    scenario::SERVER_NAME,
};
use rama::utils::octets;

const PEER: &str = "quiche";
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
        rama.close(&run.what, run.deadline).await;
        let observed = peer.join(&run.what, run.deadline).await;
        observed.check(&run.what, &run.scenario, run.role);
    })
    .await;
}

/// quiche opens the connection and Rama answers it, for every registered datagram case.
#[tokio::test]
async fn datagram_cases_rama_server() {
    for_each_case(PEER, Role::RamaServer, datagram_cases(), |run| async move {
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
        observed.check(&run.what, &run.scenario, run.role);
        serving.join(&run.what, run.deadline).await;
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
        received: Some(Received::Bytes(arrived)),
    }
}
