use tokio::{io, net::TcpStream};
use tokio_task_manager::Task;

use llama::{error::Result, runtime::Runtime, tcp::Server};

async fn handle(_task: Task, stream: TcpStream) -> Result<()> {
    let (mut reader, mut writer) = io::split(stream);
    io::copy(&mut reader, &mut writer).await?;
    Ok(())
}

pub fn main() -> Result<()> {
    Runtime::new(Server::new(handle)).run()
}
