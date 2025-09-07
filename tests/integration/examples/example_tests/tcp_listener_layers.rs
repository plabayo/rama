use super::utils;
use rama::{Context, tcp::client::default_tcp_connect};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore]
async fn test_tcp_listener_layers() {
    utils::init_tracing();

    let _runner = utils::ExampleRunner::interactive("tcp_listener_layers", None);

    let mut stream = None;
    let ctx = Context::default();
    for i in 0..5 {
        match default_tcp_connect(&ctx, ([127, 0, 0, 1], 62501).into()).await {
            Ok((s, _)) => stream = Some(s),
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
