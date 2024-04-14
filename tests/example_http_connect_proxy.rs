mod test_server;
use rama::error::Error;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const ADDR: &str = "127.0.0.1:40001";
#[tokio::test]
async fn test_http_connect_proxy() -> Result<(), Error> {
    let _example = test_server::run_example_server("http_connect_proxy");

    let mut stream = TcpStream::connect(ADDR).await.expect("connect tcp 127.0.0.1:40001");
    let connect_write_buf = "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\nProxy-Authorization: basic am9objpzZWNyZXQ=\r\n\r\n";

    let get_write_buf = "GET / HTTP/1.1\r\nHOST: example.com:80\r\nConnection: close\r\n\r\n";

    let mut read_buf = String::new();
    stream.write(connect_write_buf.as_bytes()).await.expect("connect with proxy");
    stream.write(get_write_buf.as_bytes()).await.expect("GET to example.com:80");
    stream.read_to_string(&mut read_buf).await.expect("read example.com:80");

    assert!(read_buf.contains("<title>Example Domain</title>"));

    Ok(())
}
