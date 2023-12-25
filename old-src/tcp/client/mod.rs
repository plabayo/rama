use super::TcpStream;

use crate::rt::net::{TcpStream as AsyncTcpStream, ToSocketAddrs};

pub async fn connect(
    address: impl ToSocketAddrs,
) -> Result<TcpStream<AsyncTcpStream>, std::io::Error> {
    let stream = AsyncTcpStream::connect(address).await?;
    Ok(TcpStream::new(stream))
}
