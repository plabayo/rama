//! End-to-end test for the `quic_client_server` example.
//!
//! The example runs as its own process and checks its own exchange: the protocol both ends
//! negotiated, the answer's bytes, the upload's bytes as the server read them, and a shared
//! shutdown that joins. Any of those failing makes it exit non-zero, so its exit status is
//! what this asserts. The opt-in trace is read after exit, once graceful shutdown has flushed it.

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

#[tokio::test]
#[ignore]
async fn test_quic_client_server_qlog_is_complete_on_exit() {
    utils::init_tracing();
    let directory = rama::utils::fs::tempdir().unwrap();
    let path = directory.path().join("client.qlog");
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_quic_client_server"))
            .kill_on_drop(true)
            .arg("--qlog")
            .arg(&path)
            .output(),
    )
    .await
    .expect("the exchange and graceful shutdown finish")
    .unwrap();
    assert!(
        output.status.success(),
        "the traced example completed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read(path).unwrap();
    assert_eq!(bytes.first(), Some(&0x1e));
    let records: Vec<serde_json::Value> = bytes[1..]
        .split(|byte| *byte == 0x1e)
        .map(|record| {
            assert_eq!(record.last(), Some(&b'\n'), "every record is complete");
            serde_json::from_slice(record).unwrap()
        })
        .collect();
    assert_eq!(
        records[0]["file_schema"],
        "urn:ietf:params:qlog:file:sequential"
    );
    assert_eq!(
        records[0]["serialization_format"],
        "application/qlog+json-seq"
    );
    for name in [
        "quic:connection_started",
        "quic:packet_sent",
        "quic:packet_received",
    ] {
        assert!(
            records.iter().any(|record| record["name"] == name),
            "missing {name}"
        );
    }
    let closes: Vec<_> = records
        .iter()
        .filter(|record| record["name"] == "quic:connection_closed")
        .collect();
    assert_eq!(closes.len(), 1, "only the client side is recorded");
    assert_eq!(closes[0]["data"]["initiator"], "local");
    assert_eq!(closes[0]["data"]["trigger"], "application");
    assert_eq!(closes[0]["data"]["reason"], "done");
    let last_state = records
        .iter()
        .rev()
        .find(|record| record["name"] == "quic:connection_state_updated")
        .unwrap();
    assert_eq!(last_state["data"]["new"], "closed");
}
