//! End-to-end test for the `quic_client_server` example.
//!
//! The example runs as its own process and checks its own exchange: the protocol both ends
//! negotiated, the answer's bytes, the upload's bytes as the server read them, and a shared
//! shutdown that joins. Any of those failing makes it exit non-zero, so its exit status is
//! what this asserts.

use super::utils;

#[tokio::test]
#[ignore]
async fn test_quic_client_server() {
    utils::init_tracing();

    let exit_status = utils::ExampleRunner::run("quic_client_server").await;
    assert!(
        exit_status.success(),
        "the example completed its exchange and its shutdown joined: {exit_status}"
    );
}
