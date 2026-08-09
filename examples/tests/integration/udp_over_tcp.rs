use super::utils;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::net::UdpSocket;

const TCP_PORT: u16 = 62700;
const LISTENER_UDP_BIND: u16 = 62701;
const CONNECTOR_UDP_BIND: u16 = 62702;
const SERVER_APP_PORT: u16 = 62703;
const CLIENT_APP_PORT: u16 = 62704;

/// Build the example binary once and return its path.
fn example_binary() -> std::path::PathBuf {
    escargot::CargoBuild::new()
        .arg("--features=udp,tcp")
        .bin("udp_over_tcp")
        .manifest_path("Cargo.toml")
        .target_dir("./target/")
        .run()
        .unwrap()
        .path()
        .to_path_buf()
}

struct Kids(Vec<Child>);
impl Drop for Kids {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _drop = c.kill();
            let _drop = c.wait();
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_udp_over_tcp() {
    utils::init_tracing();
    let bin = example_binary();

    let listener = Command::new(&bin)
        .args([
            "listen",
            &format!("127.0.0.1:{TCP_PORT}"),
            &format!("127.0.0.1:{LISTENER_UDP_BIND}"),
            &format!("127.0.0.1:{SERVER_APP_PORT}"),
        ])
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut kids = Kids(vec![listener]);
    wait_for_listener(&mut kids.0[0]).await;
    let connector = Command::new(&bin)
        .args([
            "connect",
            &format!("127.0.0.1:{TCP_PORT}"),
            &format!("127.0.0.1:{CONNECTOR_UDP_BIND}"),
            &format!("127.0.0.1:{CLIENT_APP_PORT}"),
        ])
        .spawn()
        .unwrap();
    kids.0.push(connector);
    let _kids = kids;
    // Let both bridge halves settle.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Two UDP apps, one on each side of the tunnel.
    let server_app = UdpSocket::bind(("127.0.0.1", SERVER_APP_PORT))
        .await
        .unwrap();
    let client_app = UdpSocket::bind(("127.0.0.1", CLIENT_APP_PORT))
        .await
        .unwrap();

    // Client → tunnel → server. The bridge process can still be finishing its
    // TCP accept/connect handshake under release-mode load, so retry the UDP
    // datagram until the server app observes it.
    let mut buf = vec![0u8; 1024];
    let (n, src) = send_until_recv(
        &client_app,
        ("127.0.0.1", CONNECTOR_UDP_BIND),
        &server_app,
        &mut buf,
        b"hello",
        "server app did not see datagram",
    )
    .await;
    assert_eq!(&buf[..n], b"hello");
    // Source is the listener-side UDP bind — that's what the tunnel forwarded from.
    assert_eq!(src.port(), LISTENER_UDP_BIND);

    // Server → tunnel → client.
    let (n, src) = send_until_recv(
        &server_app,
        src,
        &client_app,
        &mut buf,
        b"world",
        "client app did not see reply",
    )
    .await;
    assert_eq!(&buf[..n], b"world");
    assert_eq!(src.port(), CONNECTOR_UDP_BIND);
}

async fn wait_for_listener(listener: &mut Child) {
    let stdout = listener.stdout.take().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let _stdout_task = tokio::task::spawn_blocking(move || {
        let mut ready_tx = Some(ready_tx);
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.contains("tcp listening on")
                && let Some(ready_tx) = ready_tx.take()
            {
                let _send_result = ready_tx.send(());
            }
        }
    });

    tokio::time::timeout(Duration::from_secs(10), ready_rx)
        .await
        .unwrap_or_else(|_| panic!("TCP listener did not become ready within 10s"))
        .unwrap_or_else(|_| panic!("TCP listener exited before becoming ready"));
}

async fn send_until_recv(
    sender: &UdpSocket,
    target: impl tokio::net::ToSocketAddrs + Clone,
    receiver: &UdpSocket,
    buf: &mut [u8],
    payload: &[u8],
    timeout_message: &str,
) -> (usize, std::net::SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        sender.send_to(payload, target.clone()).await.unwrap();

        match tokio::time::timeout(Duration::from_millis(100), receiver.recv_from(buf)).await {
            Ok(Ok(result)) => return result,
            Ok(Err(err)) => panic!("{timeout_message}: {err}"),
            Err(_) if tokio::time::Instant::now() < deadline => {}
            Err(_) => panic!("{timeout_message} within 10s"),
        }
    }
}
