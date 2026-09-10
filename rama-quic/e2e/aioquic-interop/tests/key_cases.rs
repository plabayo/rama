//! The shared key-update cases, run against aioquic in both roles.
//!
//! This peer says the most of the three: it asks through `request_key_update` and reports the
//! phase its 1-RTT keys are in, so a case here has both Rama's count and the peer's own phase.
//! In the rama-client role the child takes an order at the moment the case says; in the
//! rama-server role the flag on its command line is enough, because Rama's server has already
//! answered the first exchange and read its count before that child can ask.

mod common;

use common::*;
use interop_common::{
    Initiator, KeyObservation, KeyScenario, Received, Reported, Role, for_each_case_within,
    keys::{
        key_cases, rama_client_connects, rama_client_updates, rama_server_side,
        settle_before_measuring,
    },
    registry::CaseRun,
    scenario::SERVER_NAME,
};
use tokio::sync::Mutex;

const PEER: &str = "aioquic";

/// Rama's client asks an aioquic server for an update, is asked by it, or neither.
#[tokio::test]
async fn key_cases_rama_client() {
    prepare().await;
    for_each_case_within(
        PEER,
        Role::RamaClient,
        key_cases(),
        LIMIT,
        |run| async move {
            let served = Identity::generate(SERVER_NAME);
            let run = run.with_identity(served.auth.clone());
            let mut peer = AioQuic::spawn(
                "server",
                &[
                    "--cert",
                    served.certificate(),
                    "--key",
                    served.key(),
                    "--orders",
                ],
            )
            .await;
            let addr = peer.listening(run.deadline).await;
            let (client, connection) = rama_client_connects(&run, addr).await;
            peer.expect("handshake", run.deadline).await;
            // The settling update and the exchange that carries it over there, so the phases
            // read here and at the end are either side of the case's own update.
            settle_before_measuring(&run, &connection).await;
            one_exchange(&mut peer, &run).await;
            let before = phase(&mut peer, &run).await;

            let asking = Mutex::new(peer);
            rama_client_updates(&run, &connection, || {
                let asking = &asking;
                let run = run.clone();
                async move {
                    let mut peer = asking.lock().await;
                    // The exchange before the ask is reported before anything is said to the
                    // child, so its answer to an order is the next line and not a stream
                    // report.
                    one_exchange(&mut peer, &run).await;
                    if run.scenario.initiator == Initiator::Peer {
                        peer.tell("update-keys", run.deadline).await;
                    }
                }
            })
            .await;
            let mut peer = asking.into_inner();
            // Whatever else the case carried — a probe exchange for each try at asking — up
            // to and including its last payload.
            exchanges_until_the_last(&mut peer, &run).await;
            let after = phase(&mut peer, &run).await;
            record(&run, before, after);

            connection.close(0u32.into(), b"done");
            run.deadline.wait(&run.what, client.wait_idle()).await;
            peer.expect("ended", run.deadline).await;
            peer.finished(run.deadline).await;
        },
    )
    .await;
}

/// An aioquic client asks Rama's server for an update, is asked by it, or neither.
#[tokio::test]
async fn key_cases_rama_server() {
    prepare().await;
    for_each_case_within(
        PEER,
        Role::RamaServer,
        key_cases(),
        LIMIT,
        |run| async move {
            let served = Identity::generate(SERVER_NAME);
            let run = run.with_identity(served.auth.clone());
            // This peer never asks, so it has no use for the connection handed back here.
            let (endpoint, addr, serving, _accepted) = rama_server_side(&run).await;
            let mut arguments = vec![
                "--ca".to_owned(),
                served.certificate().to_owned(),
                "--port".to_owned(),
                addr.port().to_string(),
                "--settling-seed".to_owned(),
                run.scenario.settling.seed.to_string(),
                "--settling-length".to_owned(),
                run.scenario.settling.len.to_string(),
                "--before-seed".to_owned(),
                run.scenario.before.seed.to_string(),
                "--before-length".to_owned(),
                run.scenario.before.len.to_string(),
                "--after-seed".to_owned(),
                run.scenario.after.seed.to_string(),
                "--after-length".to_owned(),
                run.scenario.after.len.to_string(),
            ];
            if run.scenario.initiator == Initiator::Peer {
                arguments.push("--ask-for-a-key-update".to_owned());
            }
            let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
            let mut peer = AioQuic::spawn("key-client", &borrowed).await;
            peer.expect("handshake", run.deadline).await;
            // The echo it read on the first exchange and its phase then, which is after the
            // settling update where the case has one; then the same at the end.
            // The child reports every exchange it read back, and their number is not fixed:
            // one carries the settling update and one follows the ask where the case has it.
            // They are read on the way to each phase it says.
            let before = read_until_a_phase(&mut peer, &run).await;
            let after = read_until_a_phase(&mut peer, &run).await;
            peer.expect("ended", run.deadline).await;
            peer.expect("done", run.deadline).await;
            peer.finished(run.deadline).await;
            // Rama's own count is checked inside the shared server side, and a failure there is
            // raised by this join.
            serving.join(&run.what, run.deadline).await;
            record(&run, before, after);
            run.deadline.wait(&run.what, endpoint.wait_idle()).await;
        },
    )
    .await;
}

/// One exchange the child reports, checked against the payloads this case named.
async fn one_exchange(peer: &mut AioQuic, run: &CaseRun<KeyScenario>) {
    let seen = peer.expect("stream", run.deadline).await.reported();
    assert!(
        one_of_this_case(&seen, run),
        "{}: every exchange carries one of this case's payloads",
        run.what
    );
}

/// Every exchange the child still has to report, up to the case's last payload.
async fn exchanges_until_the_last(peer: &mut AioQuic, run: &CaseRun<KeyScenario>) {
    loop {
        let seen = peer.expect("stream", run.deadline).await.reported();
        assert!(
            one_of_this_case(&seen, run),
            "{}: every exchange carries one of this case's payloads",
            run.what
        );
        if seen.len() == run.scenario.after.len && seen.digest() == run.scenario.after.digest() {
            return;
        }
    }
}

/// Read what the child says until it says a phase, checking every echo on the way.
async fn read_until_a_phase(peer: &mut AioQuic, run: &CaseRun<KeyScenario>) -> u64 {
    loop {
        let event = peer.event(&run.what, run.deadline).await;
        match event.name() {
            "phase" => return event.phase(),
            "stream" => assert!(
                one_of_this_case(&event.reported(), run),
                "{}: every exchange carries one of this case's payloads",
                run.what
            ),
            other => panic!("{}: the child reported {other}", run.what),
        }
    }
}

/// Whether what the child read is one of the payloads this case named.
fn one_of_this_case(seen: &Received, run: &CaseRun<KeyScenario>) -> bool {
    [
        run.scenario.settling,
        run.scenario.before,
        run.scenario.after,
    ]
    .into_iter()
    .any(|chunk| seen.len() == chunk.len && seen.digest() == chunk.digest())
}

/// The phase the child says its keys are in.
async fn phase(peer: &mut AioQuic, run: &CaseRun<KeyScenario>) -> u64 {
    peer.tell("key-phase", run.deadline).await.phase()
}

/// What the child said about its keys, either side of the update.
fn record(run: &CaseRun<KeyScenario>, before: u64, after: u64) {
    let observed = KeyObservation {
        phase_changed: Reported::Seen(before != after),
        detail: Some(format!("key phase {before} then {after}")),
    };
    assert!(
        observed.check(&run.what, &run.scenario).is_none(),
        "{}: this peer reports its phase itself",
        run.what
    );
}
