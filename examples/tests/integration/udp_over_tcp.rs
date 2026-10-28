use super::utils;
use rama::net::transport::TransportProtocol;
use std::process::{Child, Command};
use std::time::Duration;
use tokio::net::UdpSocket;

fn example_binary() -> &'static std::path::Path {
    utils::example!("udp_over_tcp").path()
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
#[ignore = "spawns example processes"]
async fn test_udp_over_tcp() {
    utils::init_tracing();
    let bin = example_binary();

    // Every port is chosen by the OS: fixed ports can fall in a platform's reserved range.
    let server_app = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let client_app = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();

    let listener = Command::new(bin)
        .stdin(std::process::Stdio::null())
        .args([
            "listen".to_owned(),
            "127.0.0.1:0".to_owned(),
            "127.0.0.1:0".to_owned(),
            server_app.local_addr().unwrap().to_string(),
        ])
        .spawn()
        .unwrap();
    let mut kids = Kids(vec![listener]);
    let tcp_addr = utils::wait_for_protocol_socket(&mut kids.0[0], TransportProtocol::Tcp)
        .await
        .unwrap();
    let listener_udp = utils::wait_for_protocol_socket(&mut kids.0[0], TransportProtocol::Udp)
        .await
        .unwrap();
    let connector = Command::new(bin)
        .stdin(std::process::Stdio::null())
        .args([
            "connect".to_owned(),
            tcp_addr.to_string(),
            "127.0.0.1:0".to_owned(),
            client_app.local_addr().unwrap().to_string(),
        ])
        .spawn()
        .unwrap();
    kids.0.push(connector);
    let connector_udp = utils::wait_for_protocol_socket(&mut kids.0[1], TransportProtocol::Udp)
        .await
        .unwrap();

    // Client → tunnel → server. The bridge process can still be finishing its
    // TCP accept/connect handshake under release-mode load, so retry the UDP
    // datagram until the server app observes it.
    let mut buf = vec![0u8; 1024];
    let (n, src) = send_until_recv(
        &client_app,
        connector_udp,
        &server_app,
        &mut buf,
        b"hello",
        "server app did not see datagram",
        &mut kids.0,
    )
    .await;
    assert_eq!(&buf[..n], b"hello");
    // Source is the listener-side UDP bind — that's what the tunnel forwarded from.
    assert_eq!(src.port(), listener_udp.port());

    // Server → tunnel → client.
    let (n, src) = send_until_recv(
        &server_app,
        src,
        &client_app,
        &mut buf,
        b"world",
        "client app did not see reply",
        &mut kids.0,
    )
    .await;
    assert_eq!(&buf[..n], b"world");
    assert_eq!(src.port(), connector_udp.port());
}

async fn send_until_recv(
    sender: &UdpSocket,
    target: impl tokio::net::ToSocketAddrs + Clone,
    receiver: &UdpSocket,
    buf: &mut [u8],
    payload: &[u8],
    timeout_message: &str,
    children: &mut [Child],
) -> (usize, std::net::SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        for child in &mut *children {
            assert!(
                child.try_wait().unwrap().is_none(),
                "bridge process {} exited before forwarding the datagram",
                child.id(),
            );
        }
        sender.send_to(payload, target.clone()).await.unwrap();

        match tokio::time::timeout(Duration::from_millis(100), receiver.recv_from(buf)).await {
            Ok(Ok(result)) => return result,
            Ok(Err(err)) => panic!("{timeout_message}: {err}"),
            Err(_) if tokio::time::Instant::now() < deadline => {}
            Err(_) => panic!("{timeout_message} within 10s"),
        }
    }
}
