//! Exit statuses are part of the runner's supported-case discovery protocol.

use std::process::Command;

#[test]
fn testcase_probe_needs_neither_mounts_nor_network() {
    for binary in [
        env!("CARGO_BIN_EXE_rama-quic-interop-client"),
        env!("CARGO_BIN_EXE_rama-quic-interop-server"),
    ] {
        for testcase in ["handshake", "transfer", "retry", "multiconnect"] {
            let status = Command::new(binary)
                .arg("--check-testcase")
                .env_clear()
                .env("TESTCASE", testcase)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(0), "{binary}: {testcase}");
        }
        for testcase in [
            "http3",
            "chacha20",
            "resumption",
            "zerortt",
            "keyupdate",
            "v2",
            "connectionmigration",
            "unknown",
        ] {
            let status = Command::new(binary)
                .arg("--check-testcase")
                .env_clear()
                .env("TESTCASE", testcase)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(127), "{binary}: {testcase}");
        }
    }
}
