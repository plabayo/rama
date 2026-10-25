use super::utils;
use rama::{extensions::Extensions, net::address::HostWithPort, tcp::client::default_tcp_connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, Instant};

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_tcp_listener_layers() {
    utils::init_tracing();

    let mut runner = utils::ExampleRunner::interactive(utils::example!("tcp_listener_layers"));
    runner.wait_for_tcp(([0, 0, 0, 0], 62501)).await;

    let (mut stream, _) = default_tcp_connect(&Extensions::new(), HostWithPort::local_ipv4(62501))
        .await
        .unwrap();

    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");

    // the echo is write-throttled at 8 KiB/s (8 KiB burst): echoing
    // 12 KiB has to pace the 4 KiB beyond the burst (>= 500ms)
    let payload = vec![42u8; 12 * 1024];
    let start = Instant::now();
    stream.write_all(&payload).await.unwrap();
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload);
    assert!(
        start.elapsed() >= Duration::from_millis(400),
        "echo of 12 KiB should be visibly paced, took {:?}",
        start.elapsed()
    );
}
