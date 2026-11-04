use super::utils;
use rama::extensions::Extensions;
use rama::net::address::HostWithPort;
use rama::tcp::client::default_tcp_connect;
use std::time::Duration;
use tokio::io::AsyncReadExt as _;

const LIMIT: Duration = Duration::from_secs(10);

#[tokio::test]
#[ignore = "spawns example processes"]
async fn test_tcp_listener_events() {
    utils::init_tracing();

    let mut runner = utils::ExampleRunner::capturing(
        utils::example!("tcp_listener_events"),
        std::iter::empty::<&str>(),
    );
    runner.wait_for_tcp(([127, 0, 0, 1], 62502)).await;

    let (mut stream, _) =
        default_tcp_connect(&Extensions::default(), HostWithPort::local_ipv4(62502))
            .await
            .unwrap();
    let mut greeting = String::new();
    stream.read_to_string(&mut greeting).await.unwrap();
    assert_eq!(greeting, "hello\n");

    let opened = runner.wait_for_line("connection opened", LIMIT).await;
    assert!(opened.contains("open_connections=1"), "{opened}");

    let closed = runner.wait_for_line("connection closed", LIMIT).await;
    assert!(closed.contains("open_connections=0"), "{closed}");

    let wide = runner.wait_for_line("tcp connection", LIMIT).await;
    for field in [
        "connection=",
        "local=127.0.0.1:62502",
        "peer=127.0.0.1:",
        "duration_us=",
        "busy_us=",
    ] {
        assert!(wide.contains(field), "{field} missing in: {wide}");
    }
}
