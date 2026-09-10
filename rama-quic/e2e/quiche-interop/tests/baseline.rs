//! The shared stream scenarios, run against quiche in both roles.
//!
//! Every case in `interop_common::cases` runs here: the entry points enumerate the registry
//! rather than pick entries out of it. quiche owns neither sockets nor timers, so its side is
//! driven by hand against the same scenario deadline, and what it hands back is what its own
//! connection read.

mod common;

use common::{Identity, Quiche, quiche_client_config, quiche_server_config};
use interop_common::{
    CaseRun, Peer, PeerObservation, Received, Role, SERVER_NAME, for_each_case,
    scenario::{rama_client_side, rama_server_side},
};
use rama::utils::octets;

const PEER: &str = "quiche";
/// A client's first unidirectional stream, and its first bidirectional one.
const UNI: u64 = 2;
const BI: u64 = 0;
const READ_CAP: usize = octets::mib(1);

/// Rama opens the connection and quiche answers it, for every registered case.
#[tokio::test]
async fn stream_cases_rama_client() {
    for_each_case(PEER, Role::RamaClient, |run| async move {
        // quiche reads its identity from files, so it makes its own and the run takes it.
        let identity = Identity::generate(SERVER_NAME);
        let run = run.with_identity(identity.auth.clone());
        let (addr, accepting) =
            Quiche::bind_server(quiche_server_config(&identity), run.deadline).await;
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

/// quiche opens the connection and Rama answers it, for every registered case.
#[tokio::test]
async fn stream_cases_rama_server() {
    for_each_case(PEER, Role::RamaServer, |run| async move {
        let identity = Identity::generate(SERVER_NAME);
        let run = run.with_identity(identity.auth.clone());
        let (endpoint, addr, serving) = rama_server_side(&run).await;
        let mut client = Quiche::connect(
            addr,
            SERVER_NAME,
            quiche_client_config(&identity),
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

/// quiche as the answering end.
async fn quiche_answers(run: &CaseRun, server: &mut Quiche) -> PeerObservation {
    let (what, deadline) = (&run.what, run.deadline);
    server
        .drive_until(what, deadline, |connection| connection.is_established())
        .await;
    let protocol = server.connection().application_proto().to_vec();

    let received = server.read_stream(UNI, READ_CAP, deadline).await;
    let asked = server.read_stream(BI, READ_CAP, deadline).await;
    server
        .write_stream(BI, &run.scenario.answer.bytes(), deadline)
        .await;
    server
        .drive_until(what, deadline, |connection| connection.is_closed())
        .await;
    PeerObservation {
        protocol: Some(protocol),
        up: Some((Received::Bytes(received), true)),
        question: Some((Received::Bytes(asked), true)),
        answer: None,
        closed: server.connection().is_closed(),
    }
}

/// quiche as the asking end.
async fn quiche_asks(run: &CaseRun, client: &mut Quiche) -> PeerObservation {
    let (what, deadline) = (&run.what, run.deadline);
    client
        .drive_until(what, deadline, |connection| connection.is_established())
        .await;
    let protocol = client.connection().application_proto().to_vec();
    client
        .write_stream(UNI, &run.scenario.up.bytes(), deadline)
        .await;
    client
        .write_stream(BI, &run.scenario.question.bytes(), deadline)
        .await;
    let heard = client.read_stream(BI, READ_CAP, deadline).await;
    client.close(deadline).await;
    PeerObservation {
        protocol: Some(protocol),
        up: None,
        question: None,
        answer: Some((Received::Bytes(heard), true)),
        closed: client.connection().is_closed(),
    }
}
