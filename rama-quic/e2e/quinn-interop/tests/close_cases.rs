//! The shared close cases, run against Quinn in both roles.
//!
//! Quinn reports an application close as `ConnectionError::ApplicationClosed`, carrying the
//! code and the reason, which is what each case reads back.

mod common;

use common::{quinn_client_config, quinn_server_config};
use interop_common::{
    CloseObservation, Received, Role,
    close::{close_cases, rama_client_closes, rama_server_side},
    for_each_case,
    identity::anchor_of,
    scenario::{Chunk, SERVER_NAME},
    support::{Deadline, Peer, localhost},
};
use rama::utils::octets;

const PEER: &str = "quinn";
const READ_CAP: usize = octets::mib(1);

/// Rama's client closes, and Quinn's server says what it was told.
#[tokio::test]
async fn close_cases_rama_client() {
    for_each_case(PEER, Role::RamaClient, close_cases(), |run| async move {
        let server = quinn::Endpoint::server(quinn_server_config(&run.identity), localhost())
            .expect("the quinn server binds");
        let addr = server.local_addr().expect("its address");
        let (settled, is_settled) = tokio::sync::oneshot::channel();
        let observing = Peer::spawn({
            let run = run.clone();
            let server = server.clone();
            async move {
                let connection = run
                    .deadline
                    .wait(&run.what, server.accept())
                    .await
                    .expect("an attempt arrives")
                    .await
                    .expect("the handshake completes");
                settled.send(()).expect("the case is listening");
                if let Some(first) = run.scenario.first {
                    answer(&run.what, run.deadline, &connection, first).await;
                }
                told(
                    &run.what,
                    run.deadline.wait(&run.what, connection.closed()).await,
                )
            }
        });

        rama_client_closes(&run, addr, || async {
            run.deadline
                .wait(&run.what, is_settled)
                .await
                .expect("the peer settled its handshake");
        })
        .await;
        let observed = observing.join(&run.what, run.deadline).await;
        observed.check(&run.what, &run.scenario);
        server.close(0u32.into(), b"done");
        run.deadline.wait(&run.what, server.wait_idle()).await;
    })
    .await;
}

/// A Quinn client closes, and Rama's server says what it was told.
#[tokio::test]
async fn close_cases_rama_server() {
    for_each_case(PEER, Role::RamaServer, close_cases(), |run| async move {
        let (endpoint, addr, serving) = rama_server_side(&run).await;
        let mut client = quinn::Endpoint::client(localhost()).expect("the quinn client binds");
        client.set_default_client_config(quinn_client_config(anchor_of(&run.identity)));
        let connection = run
            .deadline
            .wait(
                &run.what,
                client
                    .connect(addr, SERVER_NAME)
                    .expect("the attempt starts"),
            )
            .await
            .expect("the handshake completes");
        if let Some(first) = run.scenario.first {
            exchange(&run.what, run.deadline, &connection, first).await;
        }
        connection.close(run.scenario.code.into(), run.scenario.reason);
        run.deadline.wait(&run.what, client.wait_idle()).await;
        let observed = serving.join(&run.what, run.deadline).await;
        observed.check(&run.what, &run.scenario);
        run.deadline.wait(&run.what, endpoint.wait_idle()).await;
    })
    .await;
}

/// What Quinn's side was told when the other closed.
fn told(what: &str, ended: quinn::ConnectionError) -> CloseObservation {
    let quinn::ConnectionError::ApplicationClosed(ref close) = ended else {
        panic!("{what}: the peer closed the connection rather than it failing: {ended:?}");
    };
    CloseObservation {
        code: close.error_code.into_inner(),
        reason: close.reason.to_vec(),
        by_the_peer: true,
    }
}

/// A case's exchange, from the opening side.
async fn exchange(what: &str, deadline: Deadline, connection: &quinn::Connection, payload: Chunk) {
    let (mut send, mut recv) = deadline
        .wait(what, connection.open_bi())
        .await
        .expect("a bi stream");
    deadline
        .wait(what, send.write_all(&payload.bytes()))
        .await
        .expect("the payload is written");
    send.finish().expect("the stream ends");
    let back = deadline
        .wait(what, recv.read_to_end(READ_CAP))
        .await
        .expect("the answer completes");
    Received::Bytes(back).check(what, "exchange", payload);
}

/// The same exchange, from the answering side.
async fn answer(what: &str, deadline: Deadline, connection: &quinn::Connection, payload: Chunk) {
    let (mut send, mut recv) = deadline
        .wait(what, connection.accept_bi())
        .await
        .expect("the stream arrives");
    let got = deadline
        .wait(what, recv.read_to_end(READ_CAP))
        .await
        .expect("it completes");
    Received::Bytes(got.clone()).check(what, "exchange", payload);
    deadline
        .wait(what, send.write_all(&got))
        .await
        .expect("the answer is written");
    send.finish().expect("the answer ends");
}
