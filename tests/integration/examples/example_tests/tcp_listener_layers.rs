use super::utils;
use rama::{extensions::Extensions, net::address::HostWithPort, tcp::client::default_tcp_connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant, sleep};

#[tokio::test]
#[ignore]
async fn test_tcp_listener_layers() {
    utils::init_tracing();

    let _runner = utils::ExampleRunner::interactive("tcp_listener_layers", None);

    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        let extensions = Extensions::new();
        match default_tcp_connect(&extensions, HostWithPort::local_ipv4(62501)).await {
            Ok((stream, _)) => break stream,
            Err(e) => {
                eprintln!("connect_tcp error: {e}");
                assert!(
                    Instant::now() < deadline,
                    "connect to tcp listener before readiness deadline: {e}"
                );
                sleep(Duration::from_millis(250)).await;
            }
        }
    };

    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}
