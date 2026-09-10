//! The shared migration cases, run against aioquic in both roles.
//!
//! Its client can move: `QuicConnectionProtocol` sends through the transport it holds, so the
//! child hands it a second datagram endpoint and routes what arrives there back into the same
//! connection. Its own path state describes the address it is sending *to*, so in that role it
//! holds no verdict on the tuple it moved from. As a server the path is the peer's, so there
//! its `is_validated` does refer to the client that moved.
//!
//! Neither role can withhold an identifier: aioquic issues its own and rama issues its own.

mod common;

use common::*;
use interop_common::{
    MigrationScenario, Role, Unsupported, for_each_case_within,
    migration::{migration_cases, rama_client_side, rama_server_side},
    registry::CaseRun,
    scenario::SERVER_NAME,
};

const PEER: &str = "aioquic";
/// What nobody reports about the tuple aioquic's client moved to.
const NO_VALIDATION_VERDICT: &str = "no validation verdict for the moved tuple: this peer's path state is about the address \
     it sends to, and rama exposes none for the path it validated";
/// Why the case that withholds an identifier does not run in the rama-server role.
const RAMA_ISSUES_ITS_OWN: &str = "rama issues its own connection identifiers, so this side cannot withhold the one the peer \
     would move with";
/// Why the forbidden case is not expressed in the rama-server role yet. Rama's server does
/// decide this (`ServerConfig::with_migration`); what is missing is the expectation.
const NOT_ANSWERED_AFTER_A_MOVE: &str = "a peer that moves while rama forbids migration is not answered at its new address, so \
     this case needs an expectation of its own";
/// Why neither of those cases runs in the rama-client role.
const NOTHING_TO_WITHHOLD: &str = "this peer issues its own connection identifiers and its server configuration cannot \
     refuse a move";

/// Rama's client moves under an aioquic server, which says where it saw the datagrams come
/// from and whether it validated the path they arrived on.
#[tokio::test]
async fn migration_cases_rama_client() {
    prepare().await;
    for_each_case_within(
        PEER,
        Role::RamaClient,
        migration_cases(),
        LIMIT,
        |run| async move {
            if !run.scenario.moves {
                // Visible with `cargo test -- --nocapture`.
                println!(
                    "{}",
                    Unsupported {
                        case: withheld_case(&run),
                        peer: PEER,
                        reason: NOTHING_TO_WITHHOLD,
                    }
                );
                return;
            }
            let served = Identity::generate(SERVER_NAME);
            let run = run.with_identity(served.auth.clone());
            // Echoing is what the shared client-side exchange expects back.
            let mut peer = AioQuic::spawn(
                "server",
                &[
                    "--cert",
                    served.certificate(),
                    "--key",
                    served.key(),
                    "--connections",
                    "1",
                    "--report-paths",
                ],
            )
            .await;
            let addr = peer.listening(run.deadline).await;

            // The child reports as it goes and its lines wait to be read, so the exchange runs
            // first and what it saw is taken afterwards. What is checked here is where its
            // datagrams came from, not the payload: the shared scenario covers that.
            let (first, second) = rama_client_side(&run, addr).await;
            peer.expect("handshake", run.deadline).await;
            let mut seen = Vec::new();
            for _ in 0..2 {
                peer.expect("stream", run.deadline).await;
                seen.push(peer.expect("path", run.deadline).await);
            }
            peer.expect("ended", run.deadline).await;
            peer.finished(run.deadline).await;
            assert_eq!(
                seen[0].endpoint(),
                same_endpoint(first),
                "{}: the peer saw the socket the connection was made on",
                run.what
            );
            assert_eq!(
                seen[1].endpoint(),
                same_endpoint(second),
                "{}: and afterwards the one it rebound to",
                run.what
            );
            assert!(
                seen[1].validated(),
                "{}: and it validated the path the client moved to",
                run.what
            );
        },
    )
    .await;
}

/// An aioquic client moves under Rama's server, which follows it.
#[tokio::test]
async fn migration_cases_rama_server() {
    prepare().await;
    for_each_case_within(
        PEER,
        Role::RamaServer,
        migration_cases(),
        LIMIT,
        |run| async move {
            if !run.scenario.moves {
                // Visible with `cargo test -- --nocapture`.
                println!(
                    "{}",
                    Unsupported {
                        case: withheld_case(&run),
                        peer: PEER,
                        reason: match run.scenario.spare_identifier {
                            true => NOT_ANSWERED_AFTER_A_MOVE,
                            false => RAMA_ISSUES_ITS_OWN,
                        },
                    }
                );
                return;
            }
            let served = Identity::generate(SERVER_NAME);
            let run = run.with_identity(served.auth.clone());
            let (endpoint, addr, serving) = rama_server_side(&run).await;
            let mut peer = AioQuic::spawn(
                "moving-client",
                &[
                    "--ca",
                    served.certificate(),
                    "--port",
                    &addr.port().to_string(),
                    "--before-seed",
                    &run.scenario.before.seed.to_string(),
                    "--before-length",
                    &run.scenario.before.len.to_string(),
                    "--after-seed",
                    &run.scenario.after.seed.to_string(),
                    "--after-length",
                    &run.scenario.after.len.to_string(),
                ],
            )
            .await;
            peer.expect("handshake", run.deadline).await;
            let first = peer.expect("address", run.deadline).await.port();
            peer.expect("stream", run.deadline).await.reported().check(
                &run.what,
                "first exchange",
                run.scenario.before,
            );
            let second = peer.expect("address", run.deadline).await.port();
            assert_ne!(first, second, "{}: the child moved socket", run.what);
            peer.expect("stream", run.deadline).await.reported().check(
                &run.what,
                "second exchange",
                run.scenario.after,
            );

            // What this peer can say about the path it ends on: its path model is about the
            // address it is talking *to*, so moving its own socket creates no path there and
            // it holds no verdict on the tuple that moved. What it does say is that it is
            // still talking to rama's server, at the address rama bound.
            let path = peer.expect("path", run.deadline).await;
            assert!(
                path.validated(),
                "{}: the path it is talking to is validated",
                run.what
            );
            assert_eq!(
                path.endpoint(),
                same_endpoint(addr),
                "{}: and it is rama's server",
                run.what
            );
            // Visible with `cargo test -- --nocapture`.
            println!("{}: {NO_VALIDATION_VERDICT}", run.what);
            peer.expect("ended", run.deadline).await;
            peer.expect("done", run.deadline).await;
            peer.finished(run.deadline).await;

            // The child's socket may be dual-stack, so what it calls its address is not what
            // rama sees; the port is the same on both views.
            let observed = serving.join(&run.what, run.deadline).await;
            assert_eq!(
                observed.from_before.port(),
                first,
                "{}: rama saw the socket the connection was made on",
                run.what
            );
            assert_eq!(
                observed.from_after.port(),
                second,
                "{}: and afterwards the one it moved to",
                run.what
            );
            run.deadline.wait(&run.what, endpoint.wait_idle()).await;
        },
    )
    .await;
}

/// Which of the two cases that hold something back this is.
fn withheld_case(run: &CaseRun<MigrationScenario>) -> &'static str {
    match run.scenario.spare_identifier {
        true => "migration-forbidden",
        false => "migration-without-an-identifier",
    }
}
