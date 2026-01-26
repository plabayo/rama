use super::utils;
use rama::{extensions::Extensions, rt::Executor, tcp::client::default_tcp_connect};
use rama_net::address::HostWithPort;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore]
async fn test_tcp_listener_layers() {
    utils::init_tracing();

    let _runner = utils::ExampleRunner::interactive("tcp_listener_layers", None);

    let mut stream = None;
    for i in 0..5 {
        let extensions = Extensions::new();
        match default_tcp_connect(
            &extensions,
            HostWithPort::local_ipv4(62501),
            Executor::default(),
        )
        .await
        {
            Ok((s, _)) => {
                stream = Some(s);
                break;
            }
            Err(e) => {
                eprintln!("connect_tcp error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
            }
        }
    }

    let mut stream = stream.expect("connect to tcp listener");
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}
