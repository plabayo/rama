use tokio::{io, net::TcpStream};
use tower::util::service_fn;

use llama::{runtime::Runtime, tcp::Server, Result};

async fn handle(stream: TcpStream) -> Result<()> {
    let (mut reader, mut writer) = io::split(stream);
    io::copy(&mut reader, &mut writer).await?;
    Ok(())
}

pub fn main() -> Result<()> {
    let service = service_fn(handle);
    Runtime::new(Server::new(service).listen_addr("127.0.0.1:20018")).run()
}
