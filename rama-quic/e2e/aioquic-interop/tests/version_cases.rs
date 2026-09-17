//! The shared QUIC version cases (RFC 9368, RFC 9369), run against aioquic in both roles.
//!
//! aioquic speaks v1 and v2, starts a client in the first of its configured versions, lists
//! them all as compatible, and moves a connection as a server to the first version the client
//! listed that it supports. It reports the version it settled on in its handshake event.

mod common;

use common::*;
use interop_common::{
    PeerObservation, Role, VersionScenario, for_each_case_within,
    registry::CaseRun,
    scenario::SERVER_NAME,
    version::{check_peer_version, rama_client_side, rama_server_side, version_cases},
};
use rama::quic::proto::Version;

const PEER: &str = "aioquic";
/// A client's first unidirectional stream, and its first bidirectional one.
const UNI: u64 = 2;
const BI: u64 = 0;

fn versions_argument(versions: &[Version]) -> String {
    versions
        .iter()
        .map(|version| format!("{:#x}", version.as_u32()))
        .collect::<Vec<_>>()
        .join(",")
}

fn traffic_arguments(run: &CaseRun<VersionScenario>) -> Vec<String> {
    let scenario = &run.scenario.traffic;
    [
        ("--up-seed", usize::from(scenario.up.seed)),
        ("--up-length", scenario.up.len),
        ("--down-seed", usize::from(scenario.down.seed)),
        ("--down-length", scenario.down.len),
        ("--question-seed", usize::from(scenario.question.seed)),
        ("--question-length", scenario.question.len),
        ("--answer-seed", usize::from(scenario.answer.seed)),
        ("--answer-length", scenario.answer.len),
    ]
    .into_iter()
    .flat_map(|(name, value)| [name.to_owned(), value.to_string()])
    .collect()
}

/// Rama opens the connection with the case's version policy and aioquic, speaking the case's
/// versions, answers it.
#[tokio::test]
async fn version_cases_rama_client() {
    prepare().await;
    for_each_case_within(
        PEER,
        Role::RamaClient,
        version_cases(),
        LIMIT,
        |run| async move {
            let identity = Identity::generate(SERVER_NAME);
            let run = run.with_identity(identity.auth.clone());
            let mut arguments = vec![
                "--cert".to_owned(),
                identity.certificate().to_owned(),
                "--key".to_owned(),
                identity.key().to_owned(),
                "--versions".to_owned(),
                versions_argument(run.scenario.peer_versions),
            ];
            arguments.extend(traffic_arguments(&run));
            let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
            let mut peer = AioQuic::spawn("server", &borrowed).await;
            let addr = peer.listening(run.deadline).await;

            let rama = match rama_client_side(&run, addr).await {
                Ok(rama) => rama,
                Err(reason) => {
                    // Visible with `cargo test -- --nocapture`; the case is named in full.
                    println!("{PEER} does not run {}: {reason}", run.what);
                    drop(peer);
                    return;
                }
            };
            let expected = rama.connection.version();

            let handshake = peer.expect("handshake", run.deadline).await;
            check_peer_version(&run.what, handshake.version(), expected);
            let reported = peer.streams(2, run.deadline).await;
            let seen = |id: u64| {
                reported
                    .iter()
                    .find(|stream| stream.id() == id)
                    .unwrap_or_else(|| panic!("{}: the peer reported stream {id}", run.what))
            };
            let (up, question) = (seen(UNI), seen(BI));

            rama.close(&run.what, run.deadline).await;
            let ended = peer.expect("ended", run.deadline).await;
            let observed = PeerObservation {
                protocol: Some(handshake.alpn().as_bytes().to_vec()),
                up: Some((up.reported(), true)),
                down: None,
                question: Some((question.reported(), true)),
                answer: None,
                closed: ended.name() == "ended",
            };
            peer.finished(run.deadline).await;
            observed.check(&run.what, &run.scenario.traffic, run.role);
        },
    )
    .await;
}

/// aioquic opens the connection in the case's versions and Rama, accepting and preferring
/// what the case says, answers it.
#[tokio::test]
async fn version_cases_rama_server() {
    prepare().await;
    for_each_case_within(
        PEER,
        Role::RamaServer,
        version_cases(),
        LIMIT,
        |run| async move {
            let identity = Identity::generate(SERVER_NAME);
            let run = run.with_identity(identity.auth.clone());
            let (endpoint, addr, serving) = rama_server_side(&run).await;
            let expected = run.scenario.as_server.expected(true);

            // The peer speaks both versions here, most preferred first, unless the case says
            // it only speaks one; its first flight is v1 unless it only speaks v2.
            let peer_versions = if run.scenario.restarts {
                vec![Version::V1, Version::V2]
            } else {
                run.scenario.peer_versions.to_vec()
            };
            let mut arguments = vec![
                "--ca".to_owned(),
                identity.certificate().to_owned(),
                "--port".to_owned(),
                addr.port().to_string(),
                "--versions".to_owned(),
                versions_argument(&peer_versions),
            ];
            arguments.extend(traffic_arguments(&run));
            let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
            let mut peer = AioQuic::spawn("client", &borrowed).await;

            let handshake = peer.expect("handshake", run.deadline).await;
            check_peer_version(&run.what, handshake.version(), expected);
            peer.expect("connected", run.deadline).await;
            let reported = peer.streams(2, run.deadline).await;
            let seen = |id: u64| {
                reported
                    .iter()
                    .find(|stream| stream.id() == id)
                    .unwrap_or_else(|| panic!("{}: the peer reported stream {id}", run.what))
            };
            let (down, question) = (seen(3), seen(BI));
            let ended = peer.expect("ended", run.deadline).await;
            peer.finished(run.deadline).await;
            serving.join(&run.what, run.deadline).await;
            run.deadline.wait(&run.what, endpoint.wait_idle()).await;
            let observed = PeerObservation {
                protocol: Some(handshake.alpn().as_bytes().to_vec()),
                up: None,
                down: Some((down.reported(), true)),
                question: None,
                answer: Some((question.reported(), true)),
                closed: ended.name() == "ended",
            };
            observed.check(&run.what, &run.scenario.traffic, run.role);
        },
    )
    .await;
}
