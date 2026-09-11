//! The shared DATAGRAM cases, run against aioquic in both roles.
//!
//! The child takes each datagram as the two numbers it follows from, so its payloads come from
//! the same case the Rama side is given, and it reports what it received for itself.

mod common;

use common::*;
use interop_common::{
    CaseRun, DatagramObservation, DatagramScenario, Received, Role, Unsupported,
    datagram::{rama_client_side, rama_server_side},
    datagram_cases, for_each_case_within,
    scenario::SERVER_NAME,
};
use rama::utils::hex;

const PEER: &str = "aioquic";
/// The frame size the child advertises: large enough for either case's datagrams, small enough
/// that it, and not the path, is what limits them.
const FRAME: usize = 256;

/// This case's datagrams as the child takes them.
fn datagram_arguments(scenario: &DatagramScenario) -> Vec<String> {
    [
        ("--datagram-frame", FRAME),
        ("--datagram-out-seed", usize::from(scenario.out.seed)),
        ("--datagram-out-length", scenario.out.len),
        ("--datagram-answer-seed", usize::from(scenario.back.seed)),
        ("--datagram-answer-length", scenario.back.len),
    ]
    .into_iter()
    .flat_map(|(name, value)| [name.to_owned(), value.to_string()])
    .collect()
}

/// Rama opens the connection and aioquic answers it, for every registered datagram case.
#[tokio::test]
async fn datagram_cases_rama_client() {
    prepare().await;
    for_each_case_within(
        PEER,
        Role::RamaClient,
        datagram_cases(),
        LIMIT,
        |run| async move {
            let identity = Identity::generate(SERVER_NAME);
            let run = run.with_identity(identity.auth.clone());
            let mut arguments = vec![
                "--cert".to_owned(),
                identity.certificate().to_owned(),
                "--key".to_owned(),
                identity.key().to_owned(),
            ];
            arguments.extend(datagram_arguments(&run.scenario));
            let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
            let mut peer = AioQuic::spawn("server", &borrowed).await;
            let addr = peer.listening(run.deadline).await;

            let rama = rama_client_side(&run, addr).await;
            peer.expect("handshake", run.deadline).await;
            let reported = peer.expect("datagram", run.deadline).await;
            let (limit, sent) = (rama.limit, rama.sent);
            rama.close(&run.what, run.deadline).await;
            peer.expect("ended", run.deadline).await;
            let observed = observation(&reported);
            peer.finished(run.deadline).await;
            observed.check(&run.what, &run.scenario, run.role, sent);
            observed.bounds(&run.what, limit);
        },
    )
    .await;
}

/// aioquic opens the connection and Rama answers it, for every registered datagram case.
#[tokio::test]
async fn datagram_cases_rama_server() {
    prepare().await;
    for_each_case_within(
        PEER,
        Role::RamaServer,
        datagram_cases(),
        LIMIT,
        |run| async move {
            if skip_the_boundary(&run) {
                return;
            }
            let identity = Identity::generate(SERVER_NAME);
            let run = run.with_identity(identity.auth.clone());
            let (endpoint, addr, serving) = rama_server_side(&run).await;

            let mut arguments = vec![
                "--ca".to_owned(),
                identity.certificate().to_owned(),
                "--port".to_owned(),
                addr.port().to_string(),
                "--streams".to_owned(),
                "0".to_owned(),
                "--datagrams".to_owned(),
                "1".to_owned(),
            ];
            arguments.extend(datagram_arguments(&run.scenario));
            let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
            let mut peer = AioQuic::spawn("client", &borrowed).await;

            peer.expect("handshake", run.deadline).await;
            peer.expect("connected", run.deadline).await;
            let reported = peer.expect("datagram", run.deadline).await;
            peer.expect("ended", run.deadline).await;
            let observed = observation(&reported);
            peer.finished(run.deadline).await;

            observed.check(&run.what, &run.scenario, run.role, run.scenario.back);
            observed.bounds(&run.what, serving.join(&run.what, run.deadline).await);
            run.deadline.wait(&run.what, endpoint.wait_idle()).await;
        },
    )
    .await;
}

/// What the child said about the datagram it received.
///
/// The child reports no send limit of its own: `--datagram-frame` is what this side told it to
/// advertise, an input rather than an observation, and aioquic exposes no usable send-payload
/// size through the event bridge. So `sendable` is left unset and the shared check makes no
/// claim about it; that it did send the answering datagram is shown by the delivery itself.
fn observation(reported: &Event) -> DatagramObservation {
    let mut digest = [0u8; 32];
    let written = hex::decode_into(reported.sha256(), &mut digest).expect("a sha256 as text");
    assert_eq!(written, digest.len(), "a whole sha256 digest");
    DatagramObservation {
        sendable: None,
        // What this side told the child to advertise with `--datagram-frame`.
        advertised: Some(FRAME),
        received: Some(Received::Reported {
            digest,
            len: reported.len(),
        }),
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
