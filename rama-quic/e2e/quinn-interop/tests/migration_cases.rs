//! The shared migration cases, run against Quinn in both roles.
//!
//! Quinn's server can be told to forbid a move (`ServerConfig::migration`) and reports where a
//! connection is coming from, so those cases run. It issues connection identifiers itself,
//! with nothing in its configuration to withhold them, so the case that withholds one is
//! recorded rather than run as something else.

mod common;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

use common::{quinn_client_config, quinn_server_config};
use interop_common::{
    MigrationObservation, MigrationScenario, Received, Role, Unsupported, for_each_case,
    identity::anchor_of,
    migration::{migration_cases, rama_client_side, rama_server_side},
    registry::CaseRun,
    scenario::{Chunk, SERVER_NAME},
    support::{Deadline, Peer, localhost},
};
use rama::utils::octets;

const PEER: &str = "quinn";
const READ_CAP: usize = octets::mib(1);
/// Why the case that withholds an identifier does not run in the rama-server role.
const RAMA_ISSUES_ITS_OWN: &str = "rama issues its own connection identifiers, so this side cannot withhold the one the peer \
     would move with";
/// Why the forbidden case is not expressed in the rama-server role yet.
const NOT_ANSWERED_AFTER_A_MOVE: &str = "a peer that moves while rama forbids migration is not answered at its new address, so \
     this case needs an expectation of its own";
/// Why the case that withholds an identifier does not run against this peer.
const ISSUES_ITS_OWN: &str = "quinn issues connection identifiers itself, with nothing in its configuration to withhold \
     them";

/// Rama's client moves, or is kept where it is, and Quinn says where it saw the connection.
#[tokio::test]
async fn migration_cases_rama_client() {
    for_each_case(
        PEER,
        Role::RamaClient,
        migration_cases(),
        |run| async move {
            if !runs_here(&run) {
                return;
            }
            let mut config = quinn_server_config(&run.identity);
            if !run.scenario.migration_allowed {
                config.migration(false);
            }
            let server =
                quinn::Endpoint::server(config, localhost()).expect("the quinn server binds");
            let addr = server.local_addr().expect("its address");
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
                    answer(&run.what, run.deadline, &connection, run.scenario.before).await;
                    let from_before = connection.remote_address();
                    answer(&run.what, run.deadline, &connection, run.scenario.after).await;
                    let from_after = seen_from(&run, &connection, from_before).await;
                    run.deadline.wait(&run.what, connection.closed()).await;
                    MigrationObservation {
                        from_before,
                        from_after,
                    }
                }
            });

            let bound = rama_client_side(&run, addr).await;
            let observed = observing.join(&run.what, run.deadline).await;
            observed.check(&run.what, &run.scenario, bound);
            server.close(0u32.into(), b"done");
            run.deadline.wait(&run.what, server.wait_idle()).await;
        },
    )
    .await;
}

/// A Quinn client moves under Rama's server, which follows it.
///
/// One of the three cases runs here. Withholding an identifier is not this side's to do: Rama
/// issues its own. Forbidding a move is (`ServerConfig::with_migration`), but a peer that
/// moves anyway is then not answered at its new address, so that case needs an expectation of
/// its own; both are recorded rather than skipped.
#[tokio::test]
async fn migration_cases_rama_server() {
    for_each_case(
        PEER,
        Role::RamaServer,
        migration_cases(),
        |run| async move {
            if !run.scenario.moves {
                // Visible with `cargo test -- --nocapture`.
                println!(
                    "{}",
                    Unsupported {
                        case: if run.scenario.spare_identifier {
                            "migration-forbidden"
                        } else {
                            "migration-without-an-identifier"
                        },
                        peer: PEER,
                        reason: if run.scenario.spare_identifier {
                            NOT_ANSWERED_AFTER_A_MOVE
                        } else {
                            RAMA_ISSUES_ITS_OWN
                        },
                    }
                );
                return;
            }
            let (endpoint, addr, serving) = rama_server_side(&run).await;
            let mut client = quinn::Endpoint::client(localhost()).expect("the quinn client binds");
            client.set_default_client_config(quinn_client_config(anchor_of(&run.identity)));
            let first = client.local_addr().expect("its address");
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
            exchange(&run.what, run.deadline, &connection, run.scenario.before).await;

            client
                .rebind(UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).unwrap())
                .expect("the endpoint rebinds");
            let second = client.local_addr().expect("its address");
            assert_ne!(
                first, second,
                "{}: the client is on another socket",
                run.what
            );
            exchange(&run.what, run.deadline, &connection, run.scenario.after).await;
            connection.close(0u32.into(), b"done");
            run.deadline.wait(&run.what, client.wait_idle()).await;

            let observed = serving.join(&run.what, run.deadline).await;
            observed.check(&run.what, &run.scenario, (first, second));
            run.deadline.wait(&run.what, endpoint.wait_idle()).await;
        },
    )
    .await;
}

/// Whether this case can run against this peer at all, and the record when it cannot.
fn runs_here(run: &CaseRun<MigrationScenario>) -> bool {
    if !run.scenario.spare_identifier {
        // Visible with `cargo test -- --nocapture`.
        println!(
            "{}",
            Unsupported {
                case: "migration-without-an-identifier",
                peer: PEER,
                reason: ISSUES_ITS_OWN,
            }
        );
        return false;
    }
    true
}

/// Where the connection is coming from now, waited for where the case expects a move: the new
/// path counts once it has been validated, not the moment a datagram arrives on it.
async fn seen_from(
    run: &CaseRun<MigrationScenario>,
    connection: &quinn::Connection,
    before: SocketAddr,
) -> SocketAddr {
    if run.scenario.moves {
        run.deadline
            .wait(&run.what, async {
                while connection.remote_address() == before {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await;
    }
    connection.remote_address()
}

/// One exchange from the opening side.
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

/// The same exchange from the answering side.
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
