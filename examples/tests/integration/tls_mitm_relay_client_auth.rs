//! Run the shipped example as a subprocess, using real TCP/TLS on both relay legs.
use std::{process::Output, time::Duration};

async fn run(args: &[&str]) -> Output {
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_tls_mitm_relay_client_auth"))
            .args(args)
            .env("RUST_LOG", "info")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("example must finish before the test deadline")
    .expect("example process must start")
}

#[tokio::test]
#[ignore]
async fn maps_identity_and_exchanges_application_data() {
    for tls12 in [false, true] {
        for upstream_auth in [false, true] {
            let mut args = vec![];
            if tls12 {
                args.push("--tls12");
            }
            if !upstream_auth {
                args.push("--no-upstream-auth");
            }
            let output = run(&args).await;
            assert!(
                output.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let version = if tls12 { "TLS1.2" } else { "TLS1.3" };
            let upstream = if upstream_auth { "mapped" } else { "none" };
            assert!(output.stdout.is_empty(), "the example logs to stderr");
            let logs = String::from_utf8_lossy(&output.stderr);
            let completed: Vec<_> = logs
                .lines()
                .filter(|line| line.contains("exchange complete"))
                .collect();
            assert_eq!(completed.len(), 1, "{logs}");
            for field in [
                format!("tls_version=\"{version}\""),
                "ingress=\"trusted-client\"".to_owned(),
                format!("upstream=\"{upstream}\""),
                "request=\"ping\"".to_owned(),
                "response=\"pong\"".to_owned(),
            ] {
                assert!(completed[0].contains(&field), "missing {field}: {logs}");
            }
        }
    }
}

#[tokio::test]
#[ignore]
async fn rejects_missing_unmapped_and_untrusted_clients() {
    for tls12 in [false, true] {
        for upstream_auth in [false, true] {
            for client in ["missing", "unmapped", "untrusted"] {
                let mut args = vec!["--client", client];
                if tls12 {
                    args.push("--tls12");
                }
                if !upstream_auth {
                    args.push("--no-upstream-auth");
                }
                let output = run(&args).await;
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(!output.status.success(), "{args:?}: admission must fail");
                assert!(
                    output.stdout.is_empty(),
                    "rejected client must not complete the exchange"
                );
                assert!(error.contains("exchange failed"), "{error}");
                assert!(
                    !error.contains("exchange complete"),
                    "rejected client completed: {error}"
                );
                if client == "missing" {
                    assert!(
                        error.contains("PEER_DID_NOT_RETURN_A_CERTIFICATE"),
                        "{args:?}: {error}"
                    );
                    assert!(error.contains("direction: Ingress"), "{error}");
                } else {
                    assert!(
                        error.contains("ClientAuth"),
                        "{args:?}: wrong failure: {error}"
                    );
                }
                assert!(
                    !error.contains("timed out"),
                    "rejection must not depend on a deadline"
                );
                if client == "untrusted" {
                    assert!(error.contains("CERTIFICATE_VERIFY_FAILED"), "{error}");
                    assert!(error.contains("classification: CertTrust"), "{error}");
                }
                if client == "unmapped" {
                    assert!(error.contains("unmapped ingress identity"), "{error}");
                }
            }
        }
    }
}
