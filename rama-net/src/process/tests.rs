use super::*;
use std::{
    io::Read as _,
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
fn reports_owned_endpoints_and_excludes_tcp_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let duplicate = listener.try_clone().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_accepted, _) = listener.accept().unwrap();

    let sockets = listening_sockets(std::process::id()).unwrap();
    let expected = ProcessSocket {
        protocol: TransportProtocol::Tcp,
        local_addr: duplicate.local_addr().unwrap(),
    };
    assert_eq!(
        sockets.iter().filter(|socket| **socket == expected).count(),
        1
    );
    assert!(sockets.contains(&ProcessSocket {
        protocol: TransportProtocol::Udp,
        local_addr: udp.local_addr().unwrap()
    }));
    assert!(!sockets.contains(&ProcessSocket {
        protocol: TransportProtocol::Tcp,
        local_addr: client.local_addr().unwrap()
    }));
    assert_eq!(
        listening_sockets(0).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn reports_wildcard_listeners_and_connected_udp_endpoints() {
    let tcp4 = TcpListener::bind("0.0.0.0:0").unwrap();
    let tcp6 = TcpListener::bind("[::]:0").unwrap();
    let udp6 = UdpSocket::bind("[::]:0").unwrap();
    let udp_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp4 = UdpSocket::bind("0.0.0.0:0").unwrap();
    udp4.connect(udp_peer.local_addr().unwrap()).unwrap();

    let sockets = listening_sockets(std::process::id()).unwrap();
    for (protocol, local_addr) in [
        (TransportProtocol::Tcp, tcp4.local_addr().unwrap()),
        (TransportProtocol::Tcp, tcp6.local_addr().unwrap()),
        (TransportProtocol::Udp, udp4.local_addr().unwrap()),
        (TransportProtocol::Udp, udp6.local_addr().unwrap()),
    ] {
        assert!(
            sockets.contains(&ProcessSocket {
                protocol,
                local_addr
            }),
            "missing {protocol:?} endpoint {local_addr}: {sockets:?}"
        );
    }
}

pub(super) struct ChildGuard(pub(super) Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _reaped = self.0.wait();
    }
}

#[test]
fn discovers_only_the_childs_ipv4_and_ipv6_sockets() {
    let unrelated = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process::tests::socket_child",
                "--ignored",
                "--nocapture",
            ])
            .env("RAMA_PROCESS_SOCKET_TEST_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    let sockets = loop {
        assert!(child.0.try_wait().unwrap().is_none(), "socket child exited");
        let sockets = listening_sockets(child.0.id()).unwrap();
        assert!(child.0.try_wait().unwrap().is_none(), "socket child exited");

        assert!(
            !sockets
                .iter()
                .any(|socket| socket.protocol == TransportProtocol::Tcp
                    && socket.local_addr == unrelated.local_addr().unwrap())
        );

        if sockets.len() == 4 {
            break sockets;
        }

        assert!(
            Instant::now() < deadline,
            "missing child sockets: {sockets:?}"
        );
        thread::sleep(Duration::from_millis(25));
    };

    for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
        for ipv4 in [true, false] {
            assert_eq!(
                sockets
                    .iter()
                    .filter(|socket| socket.protocol == protocol
                        && socket.local_addr.is_ipv4() == ipv4
                        && socket.local_addr.ip().is_loopback())
                    .count(),
                1
            );
        }
    }

    assert!(child.0.try_wait().unwrap().is_none());

    // Closing stdin releases the child; wait explicitly as well as guarding
    // every assertion failure above. No child output carries an address.
    drop(child.0.stdin.take());
    assert!(child.0.wait().unwrap().success());
}

#[test]
#[ignore = "subprocess fixture launched by discovers_only_the_childs_ipv4_and_ipv6_sockets"]
fn socket_child() {
    if std::env::var_os("RAMA_PROCESS_SOCKET_TEST_CHILD").is_none() {
        return;
    }
    thread::sleep(Duration::from_millis(100));
    let _tcp4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let _tcp6 = TcpListener::bind("[::1]:0").unwrap();
    let _udp4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let _udp6 = UdpSocket::bind("[::1]:0").unwrap();
    let _eof = io::stdin().read(&mut [0]).unwrap();
}
