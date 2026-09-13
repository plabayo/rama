//! Unix subprocess checks of file transfers, container shutdown signals, and TLS diagnostics.

#![cfg(unix)]

use rama::{
    crypto::dep::rcgen,
    utils::{fs::TempDir, octets},
};
use std::{
    collections::BTreeSet,
    fs,
    path::Path,
    process::{ExitStatus, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader},
    process::{Child, Command},
};

#[tokio::test]
async fn runner_file_transfer_and_retry() {
    for testcase in ["handshake", "transfer", "retry", "multiconnect"] {
        let directory = TempDir::with_prefix("rama-runner-smoke-").unwrap();
        let root = directory.path();
        let www = root.join("www");
        let downloads = root.join("downloads");
        fs::create_dir(&www).unwrap();
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        fs::write(root.join("cert.pem"), identity.cert.pem()).unwrap();
        fs::write(root.join("priv.key"), identity.signing_key.serialize_pem()).unwrap();
        let payload = vec![0x5a; octets::mib(2)];
        fs::write(www.join("large.bin"), &payload).unwrap();
        fs::write(www.join("empty.bin"), []).unwrap();
        // More than one advertised stream window catches missing MAX_STREAMS updates.
        let count = if testcase == "transfer" { 130 } else { 2 };
        let mut names = vec!["large.bin".to_owned(), "empty.bin".to_owned()];
        for index in 0..count {
            let name = format!("small-{index}.bin");
            fs::write(www.join(&name), name.as_bytes()).unwrap();
            names.push(name);
        }
        let mut server = Command::new(env!("CARGO_BIN_EXE_rama-quic-interop-server"))
            .env_clear()
            .env("TESTCASE", testcase)
            .env("CERTS", root)
            .env("WWW", &www)
            .env("SSLKEYLOGFILE", root.join("server.keys"))
            .env("QLOGDIR", root.join("server-qlog"))
            .arg("--listen")
            .arg("[::]:0")
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut logs = BufReader::new(server.stderr.take().unwrap());
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(10), logs.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        assert!(line.contains("interop server listening"), "{line}");
        let port = line
            .split("[::]:")
            .nth(1)
            .unwrap()
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap();
        let address = format!("https://127.0.0.1:{port}");
        let requests = names
            .iter()
            .map(|name| format!("{address}/{name}"))
            .collect::<Vec<_>>()
            .join(" ");
        let server_logs = tokio::spawn(async move {
            let mut output = String::new();
            logs.read_to_string(&mut output).await.unwrap();
            output
        });
        let output = tokio::time::timeout(
            Duration::from_secs(60),
            Command::new(env!("CARGO_BIN_EXE_rama-quic-interop-client"))
                .env_clear()
                .env("TESTCASE", testcase)
                .env("REQUESTS", requests)
                .env("DOWNLOADS", &downloads)
                .env("SSLKEYLOGFILE", root.join("client.keys"))
                .env("QLOGDIR", root.join("qlog"))
                .arg("--timeout-seconds")
                .arg("45")
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        let status = signal_and_wait(&mut server, "TERM").await;
        assert_eq!(status.code(), Some(0), "server did not exit gracefully");
        let server_logs = server_logs.await.unwrap();
        assert!(
            output.status.success(),
            "{testcase}: client={} server={server_logs}",
            String::from_utf8_lossy(&output.stderr)
        );
        for name in &names {
            assert_eq!(
                fs::read(downloads.join(name)).unwrap(),
                fs::read(www.join(name)).unwrap(),
                "{testcase}: {name}"
            );
        }
        for side in ["client", "server"] {
            let keys = fs::read_to_string(root.join(format!("{side}.keys"))).unwrap();
            assert!(
                keys.contains("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
                "{side}: missing secrets"
            );
        }
        assert_complete_qlog(&root.join("qlog/rama-client.sqlog"));
        assert_complete_qlog(&root.join("server-qlog/rama-server.sqlog"));
    }
}

async fn signal_and_wait(process: &mut Child, signal: &str) -> ExitStatus {
    let id = process.id().expect("child is running");
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(id.to_string())
        .status()
        .await
        .expect("send Unix signal to our child");
    assert!(status.success());
    tokio::time::timeout(Duration::from_secs(15), process.wait())
        .await
        .expect("child shuts down within its deadline")
        .expect("wait for child")
}

fn assert_complete_qlog(path: &Path) {
    let bytes = fs::read(path).unwrap();
    assert_eq!(
        bytes.first(),
        Some(&0x1e),
        "{}: missing record separator",
        path.display()
    );
    let mut records = bytes[1..].split(|byte| *byte == 0x1e);
    let header: serde_json::Value = serde_json::from_slice(records.next().unwrap()).unwrap();
    assert!(
        header.is_object(),
        "{}: header is not an object",
        path.display()
    );
    let mut started = BTreeSet::new();
    let mut closed = BTreeSet::new();
    let mut retired = BTreeSet::new();
    let mut count = 0;
    for record in records {
        assert!(
            record.ends_with(b"\n"),
            "{}: incomplete record",
            path.display()
        );
        let event: serde_json::Value = serde_json::from_slice(record).unwrap();
        assert!(
            event.is_object(),
            "{}: event is not an object",
            path.display()
        );
        let group = event["group_id"]
            .as_str()
            .expect("event has a connection group")
            .to_owned();
        match event["name"].as_str() {
            Some("quic:connection_started") => {
                started.insert(group);
            }
            Some("quic:connection_closed") => {
                closed.insert(group);
            }
            Some("quic:connection_state_updated") if event["data"]["new"] == "closed" => {
                retired.insert(group);
            }
            _ => {}
        }
        count += 1;
    }
    assert!(count > 0, "{}: no events", path.display());
    assert!(
        !started.is_empty(),
        "{}: no connections started",
        path.display()
    );
    assert_eq!(
        started,
        closed,
        "{}: missing connection-close events",
        path.display()
    );
    assert_eq!(
        started,
        retired,
        "{}: recorder stopped before transport retirement",
        path.display()
    );
}

#[tokio::test]
async fn interrupted_client_drains_qlog_and_reports_failure() {
    for signal in ["TERM", "INT"] {
        let directory = TempDir::with_prefix("rama-runner-cancel-").unwrap();
        let root = directory.path();
        // Keep a UDP receiver alive without replying: the client's handshake remains pending.
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut client = Command::new(env!("CARGO_BIN_EXE_rama-quic-interop-client"))
            .env_clear()
            .env("TESTCASE", "transfer")
            .env(
                "REQUESTS",
                format!("https://{}/pending.bin", peer.local_addr().unwrap()),
            )
            .env("DOWNLOADS", root.join("downloads"))
            .env("QLOGDIR", root.join("qlog"))
            .stderr(Stdio::piped())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut packet = [0_u8; octets::kib(2)];
        tokio::time::timeout(Duration::from_secs(10), peer.recv_from(&mut packet))
            .await
            .expect("client sends an Initial")
            .unwrap();
        let status = signal_and_wait(&mut client, signal).await;
        assert_eq!(
            status.code(),
            Some(1),
            "client must report interruption, not signal termination"
        );
        let mut stderr = String::new();
        client
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .await
            .unwrap();
        assert!(
            stderr.contains("download batch interrupted by shutdown signal"),
            "{stderr}"
        );
        assert_complete_qlog(&root.join("qlog/rama-client.sqlog"));
    }
}
