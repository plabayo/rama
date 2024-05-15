use super::utils;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore]
async fn test_tcp_listener_layers() {
    utils::init_tracing();

    let runner = utils::ExampleRunner::interactive("tcp_listener_layers");

    let mut stream = None;
    for i in 0..5 {
        match runner.connect_tcp("127.0.0.1:62501").await {
            Ok(s) => stream = Some(s),
            Err(e) => {
                eprintln!("connect_tcp error: {}", e);
                tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
                continue;
            }
        }
    }

    let mut stream = stream.expect("connect to tcp listener");
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
}
