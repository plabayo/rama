//! The shared DATAGRAM cases, run against quiche in both roles.
//!
//! quiche advertises 65536 when datagrams are enabled, from draft-ietf-quic-datagram-01 rather
//! than RFC 9221's 65535, and either value is far above the path budget: against this peer the
//! binding limit is the path. That is the other half of what the aioquic project shows, where
//! the peer's advertised size is small enough to bind.

mod common;

use common::{Identity, Quiche, quiche_client_config, quiche_server_config, with_datagrams};
use interop_common::{
    CaseRun, DatagramObservation, DatagramScenario, Deadline, Peer, Received, Role, Unsupported,
    UnsupportedObservation, UnsupportedScenario, backpressure_cases,
    datagram::{rama_client_side, rama_server_side},
    datagram_cases, for_each_case,
    scenario::SERVER_NAME,
    unsupported::{rama_client_without_datagrams, rama_server_without_datagrams},
    unsupported_cases,
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
        let (limit, sent) = serving.join(&run.what, run.deadline).await;
        observed.check(&run.what, &run.scenario, run.role, sent);
        observed.bounds(&run.what, limit);
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

/// The client-initiated bidirectional stream a case's exchange runs on.
const CLIENT_BI: u64 = 0;

/// Rama opens the connection and a quiche that never enabled datagrams answers it.
#[tokio::test]
async fn unsupported_cases_rama_client() {
    for_each_case(
        PEER,
        Role::RamaClient,
        unsupported_cases(),
        |run| async move {
            let identity = Identity::generate(SERVER_NAME);
            let run = run.with_identity(identity.auth.clone());
            let (addr, accepting) =
                Quiche::bind_server(quiche_server_config(&identity), run.deadline).await;
            let peer = Peer::spawn({
                let run = run.clone();
                async move {
                    let mut server = accepting.await;
                    quiche_carries(&run, &mut server).await
                }
            });

            let rama = rama_client_without_datagrams(&run, addr).await;
            rama.close(&run.what, run.deadline).await;
            peer.join(&run.what, run.deadline)
                .await
                .check(&run.what, &run.scenario);
        },
    )
    .await;
}

/// A quiche that never enabled datagrams opens the connection and Rama answers it.
#[tokio::test]
async fn unsupported_cases_rama_server() {
    for_each_case(
        PEER,
        Role::RamaServer,
        unsupported_cases(),
        |run| async move {
            let identity = Identity::generate(SERVER_NAME);
            let run = run.with_identity(identity.auth.clone());
            let (endpoint, addr, serving) = rama_server_without_datagrams(&run).await;
            let mut client = Quiche::connect(
                addr,
                SERVER_NAME,
                quiche_client_config(&identity),
                run.deadline,
            )
            .await;
            let observed = quiche_opens_without_datagrams(&run, &mut client).await;
            client.close(run.deadline).await;
            serving.join(&run.what, run.deadline).await;
            observed.check(&run.what, &run.scenario);
            run.deadline.wait(&run.what, endpoint.wait_idle()).await;
        },
    )
    .await;
}

/// quiche answers the exchange Rama opens, and says whether a datagram reached it.
async fn quiche_carries(
    run: &CaseRun<UnsupportedScenario>,
    server: &mut Quiche,
) -> UnsupportedObservation {
    let (what, deadline) = (&run.what, run.deadline);
    server
        .drive_until(what, deadline, |connection| connection.is_established())
        .await;
    let got = server.read_stream(CLIENT_BI, READ_CAP, deadline).await;
    server.write_stream(CLIENT_BI, &got, deadline).await;
    server
        .drive_until(what, deadline, |connection| connection.is_closed())
        .await;
    UnsupportedObservation {
        datagram: nothing_arrived(server, deadline).await,
        carried: Some(Received::Bytes(got)),
    }
}

/// quiche opens the exchange instead, and says the same.
async fn quiche_opens_without_datagrams(
    run: &CaseRun<UnsupportedScenario>,
    client: &mut Quiche,
) -> UnsupportedObservation {
    let (what, deadline) = (&run.what, run.deadline);
    client
        .drive_until(what, deadline, |connection| connection.is_established())
        .await;
    client
        .write_stream(CLIENT_BI, &run.scenario.carried.bytes(), deadline)
        .await;
    let back = client.read_stream(CLIENT_BI, READ_CAP, deadline).await;
    client.close(deadline).await;
    UnsupportedObservation {
        datagram: nothing_arrived(client, deadline).await,
        carried: Some(Received::Bytes(back)),
    }
}

/// Whatever quiche has queued once the connection has ended. The queue keeps every datagram
/// that arrived, so asking it here answers for the whole case rather than for a window.
async fn nothing_arrived(peer: &mut Quiche, deadline: Deadline) -> Option<Received> {
    match peer.connection().dgram_recv_queue_len() {
        0 => None,
        _ => Some(Received::Bytes(
            peer.read_datagram(READ_CAP, deadline).await,
        )),
    }
}

/// Why the backpressure case does not run against this peer yet. quiche can be withheld and
/// then driven again — that is what a pause is — but this adapter drives its connection from
/// the case's own task, so it has nothing to implement `Ears` against. The gap is here, not
/// in the peer.
const THIS_ADAPTER_HAS_NO_PAUSE: &str = "this adapter drives the peer from the case's own task, so it has no reader to pause; \
     the peer itself can be withheld and driven again";

/// The backpressure case needs a peer that can stop reading while this side keeps sending.
#[tokio::test]
async fn backpressure_cases_rama_client() {
    for_each_case(
        PEER,
        Role::RamaClient,
        backpressure_cases(),
        |_run| async move {
            // Visible with `cargo test -- --nocapture`.
            println!(
                "{}",
                Unsupported {
                    case: "datagram-no-room",
                    peer: PEER,
                    reason: THIS_ADAPTER_HAS_NO_PAUSE,
                }
            );
        },
    )
    .await;
}
