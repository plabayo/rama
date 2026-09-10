//! The shared DATAGRAM cases, run against Quinn in both roles.

mod common;

use common::{quinn_client_config, quinn_server_config};
use interop_common::{
    CaseRun, DatagramObservation, DatagramScenario, Peer, Received, Role,
    datagram::{rama_client_side, rama_server_side},
    datagram_cases, for_each_case,
    identity::anchor_of,
    scenario::SERVER_NAME,
    support::localhost,
};

const PEER: &str = "quinn";

/// Rama opens the connection and Quinn answers it, for every registered datagram case.
#[tokio::test]
async fn datagram_cases_rama_client() {
    for_each_case(PEER, Role::RamaClient, datagram_cases(), |run| async move {
        let server = quinn::Endpoint::server(quinn_server_config(&run.identity), localhost())
            .expect("the quinn server binds");
        let addr = server.local_addr().expect("its address");
        let peer = Peer::spawn({
            let run = run.clone();
            async move { quinn_answers(&run, server).await }
        });

        let rama = rama_client_side(&run, addr).await;
        rama.close(&run.what, run.deadline).await;
        let observed = peer.join(&run.what, run.deadline).await;
        observed.check(&run.what, &run.scenario, run.role);
    })
    .await;
}

/// Quinn opens the connection and Rama answers it, for every registered datagram case.
#[tokio::test]
async fn datagram_cases_rama_server() {
    for_each_case(PEER, Role::RamaServer, datagram_cases(), |run| async move {
        let (endpoint, addr, serving) = rama_server_side(&run).await;
        let observed = quinn_asks(&run, anchor_of(&run.identity), addr).await;
        observed.check(&run.what, &run.scenario, run.role);
        serving.join(&run.what, run.deadline).await;
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
    client.set_default_client_config(quinn_client_config(anchor));
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
        received: Some(Received::Bytes(arrived.to_vec())),
    }
}
