//! The shared mismatched-identity cases, run against Quinn.
//!
//! The anchor is trusted throughout and only the identity the certificate carries is wrong,
//! which is what separates these from the trust cases. The refusal and its control use the
//! same server certificate; only what the client asks for changes.

mod common;

use common::quinn_server_config;
use interop_common::{
    MISMATCH_PROBE, Peer, Received, Role, for_each_case, mismatch_cases,
    names::{rama_client_accepts_the_identity, rama_client_refuses_the_identity},
    support::localhost,
};
use rama::utils::octets;

const PEER: &str = "quinn";
const READ_CAP: usize = octets::kib(64);

/// Rama's client refuses an identity the certificate does not carry, and accepts the one it
/// does.
#[tokio::test]
async fn mismatch_cases_rama_client() {
    for_each_case(PEER, Role::RamaClient, mismatch_cases(), |run| async move {
        let served = run.scenario.identity();
        let run = run.clone().with_identity(served.clone());
        let server = quinn::Endpoint::server(quinn_server_config(&served), localhost())
            .expect("the quinn server binds");
        let addr = server.local_addr().expect("its address");

        let refusing = Peer::spawn({
            let deadline = run.deadline;
            let what = run.what.clone();
            let server = server.clone();
            async move {
                let Some(attempt) = deadline.wait(&what, server.accept()).await else {
                    return;
                };
                let ended = deadline.wait(&what, attempt).await;
                assert!(
                    ended.is_err(),
                    "{what}: the peer saw no connection established, so nothing passed"
                );
            }
        });
        rama_client_refuses_the_identity(&run, addr).await;
        refusing.join(&run.what, run.deadline).await;

        // The control: the same certificate, asked for what it is valid for.
        let serving = Peer::spawn({
            let deadline = run.deadline;
            let what = run.what.clone();
            let server = server.clone();
            async move {
                let attempt = deadline
                    .wait(&what, server.accept())
                    .await
                    .expect("an attempt arrives");
                let conn = deadline
                    .wait(&what, attempt)
                    .await
                    .expect("the matching identity is accepted");
                let (mut send, mut recv) = deadline
                    .wait(&what, conn.accept_bi())
                    .await
                    .expect("the probe's stream arrives");
                let got = deadline
                    .wait(&what, recv.read_to_end(READ_CAP))
                    .await
                    .expect("the probe completes");
                Received::Bytes(got).check(&what, "probe", MISMATCH_PROBE);
                deadline
                    .wait(&what, send.write_all(&MISMATCH_PROBE.bytes()))
                    .await
                    .expect("the probe goes back");
                send.finish().expect("the answer ends");
                deadline.wait(&what, conn.closed()).await;
            }
        });
        rama_client_accepts_the_identity(&run, addr).await;
        serving.join(&run.what, run.deadline).await;
        server.close(0u32.into(), b"done");
    })
    .await;
}
