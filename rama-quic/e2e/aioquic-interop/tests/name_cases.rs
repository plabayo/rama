//! The shared server-name cases, run against aioquic.
//!
//! aioquic's server parses the name a client sends and uses it, but discards it afterwards:
//! `pull_client_hello` fills `ClientHello.server_name` and nothing on the server keeps it, so
//! the child has nothing to report. That is a missing observation in the bridge, not missing
//! protocol support, and it is recorded rather than worked around. The role where Rama is the
//! server needs no such observation and runs both cases.

mod common;

use common::*;
use interop_common::{
    NameObservation, Received, ReceivedName, Role, for_each_case,
    names::{name_cases, rama_client_side, rama_server_side},
};
use rama::utils::hex;

/// Why the child cannot report the name it received: aioquic's `pull_client_hello` fills
/// `ClientHello.server_name` and the server uses it, but nothing on the server side keeps it,
/// so there is no field for the bridge to read. The protocol side works; the observation does
/// not exist without patching the library.
const UNAVAILABLE: &str = "aioquic's server does not retain the name from the client hello";

const PEER: &str = "aioquic";

/// Rama asks aioquic for the case's name, or sends none. The connection, its certificate
/// verification and the probe all run; only the child's report of the name it received is
/// unavailable, and that one assertion is withheld rather than the case being skipped.
#[tokio::test]
async fn name_cases_rama_client() {
    prepare().await;
    for_each_case(PEER, Role::RamaClient, name_cases(), |run| async move {
        let served = Identity::generate_for(run.scenario.asked);
        let run = run.clone().with_identity(served.auth.clone());
        let mut peer = AioQuic::spawn(
            "server",
            &[
                "--cert",
                served.certificate(),
                "--key",
                served.key(),
                "--connections",
                "1",
            ],
        )
        .await;
        let addr = peer.listening(run.deadline).await;

        rama_client_side(&run, addr).await;

        // The child read the probe and echoed it; that is checked here the same way the other
        // peers' probes are.
        peer.expect("handshake", run.deadline).await;
        let reported = peer.expect("stream", run.deadline).await;
        let mut digest = [0u8; 32];
        let written = hex::decode_into(reported.sha256(), &mut digest).expect("a sha256 as text");
        assert_eq!(written, digest.len(), "a whole sha256 digest");
        Received::Reported {
            digest,
            len: reported.len(),
        }
        .check(&run.what, "probe", run.scenario.probe);
        peer.expect("ended", run.deadline).await;
        peer.finished(run.deadline).await;

        let observed = NameObservation {
            server_name: ReceivedName::Unavailable(UNAVAILABLE),
        };
        assert!(
            !observed.check(&run.what, &run.scenario),
            "{}: this peer has no name to report, so no name was asserted",
            run.what
        );
        // Visible with `cargo test -- --nocapture`, which is how the runner surfaces the
        // capabilities a run did not assert.
        println!("{}: received-SNI unavailable: {UNAVAILABLE}", run.what);
    })
    .await;
}

/// aioquic asks Rama for the case's name, or names the address, and Rama reports what it
/// received.
#[tokio::test]
async fn name_cases_rama_server() {
    prepare().await;
    for_each_case(PEER, Role::RamaServer, name_cases(), |run| async move {
        let served = Identity::generate_for(run.scenario.asked);
        let run = run.clone().with_identity(served.auth.clone());
        let (endpoint, addr, serving) = rama_server_side(&run).await;
        let asked = run
            .scenario
            .asked
            .map_or_else(|| addr.ip().to_string(), str::to_owned);
        let mut peer = AioQuic::spawn(
            "client",
            &[
                "--ca",
                served.certificate(),
                "--port",
                &addr.port().to_string(),
                "--server-name",
                &asked,
                "--probe-seed",
                &run.scenario.probe.seed.to_string(),
                "--probe-length",
                &run.scenario.probe.len.to_string(),
            ],
        )
        .await;
        peer.expect("handshake", run.deadline).await;
        peer.expect("connected", run.deadline).await;
        let back = peer.expect("stream", run.deadline).await;
        let mut digest = [0u8; 32];
        let written = hex::decode_into(back.sha256(), &mut digest).expect("a sha256 as text");
        assert_eq!(written, digest.len(), "a whole sha256 digest");
        Received::Reported {
            digest,
            len: back.len(),
        }
        .check(&run.what, "probe", run.scenario.probe);
        peer.expect("ended", run.deadline).await;
        peer.finished(run.deadline).await;
        serving.join(&run.what, run.deadline).await;
        run.deadline.wait(&run.what, endpoint.wait_idle()).await;
    })
    .await;
}
