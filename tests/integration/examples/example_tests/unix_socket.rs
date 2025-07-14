use super::utils;
use rama::{
    Context,
    net::client::{ConnectorService, EstablishedClientConnection},
    unix::client::UnixConnector,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[ignore]
async fn test_unix_socket() {
    utils::init_tracing();

    let _runner = utils::ExampleRunner::<()>::interactive("unix_socket", None);

    let mut stream = None;
    for i in 0..5 {
        match UnixConnector::fixed("/tmp/rama_example_unix.socket")
            .connect(Context::default(), ())
            .await
        {
            Ok(EstablishedClientConnection { conn, .. }) => stream = Some(conn),
            Err(e) => {
                eprintln!("unix connect error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(500 + 250 * i)).await;
            }
        }
    }

    let mut stream = stream.expect("connect to unix socket");
    stream.write_all(b"hello").await.unwrap();
    let mut buf = [0; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"olleh");
}
