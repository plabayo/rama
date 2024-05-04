pub mod test_server;

use std::error::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const ADDRESS: &str = "127.0.0.1:49001";

#[tokio::test]
#[ignore]
async fn test_tcp_listener_layers() -> Result<(), Box<dyn Error>> {
    let _example = test_server::run_example_server("tcp_listener_layers");
    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut stream = TcpStream::connect(ADDRESS).await?;
    let write_buf = b"tcp_listener_layers";
    let mut read_buf = [0_u8; 19];
    let _ = stream.write(write_buf).await;
    let _ = stream.read(&mut read_buf).await;
    assert_eq!(*write_buf, read_buf);

    Ok(())
}
