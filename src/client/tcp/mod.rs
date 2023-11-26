use crate::net::{TcpStream, ToSocketAddrs};

use tokio::net::TcpStream as TokioTcpStream;

pub async fn connect(
    address: impl ToSocketAddrs,
) -> Result<TcpStream<TokioTcpStream>, std::io::Error> {
    let stream = TokioTcpStream::connect(address).await?;
    Ok(TcpStream::new(stream))
}
