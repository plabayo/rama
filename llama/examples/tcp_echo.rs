use std::task::{Context, Poll};

use tokio::{io, net::TcpStream};
use tower::{
    util::service_fn,
    limit::ConcurrencyLimit,
};

use llama::{runtime::Runtime, service::Service, tcp::Server, Result};

async fn handle(stream: TcpStream) -> Result<()> {
    let (mut reader, mut writer) = io::split(stream);
    io::copy(&mut reader, &mut writer).await?;
    Ok(())
}

#[derive(Clone)]
pub struct LogService<S> {
    target: &'static str,
    service: S,
}

impl<S> LogService<S> {
    pub fn new(target: &'static str, service: S) -> Self {
        Self { target, service }
    }
}

impl<S> Service<TcpStream> for LogService<S>
where
    S: Service<TcpStream>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, stream: TcpStream) -> Self::Future {
        // Insert log statement here or other functionality
        println!(
            "incoming TCP Stream = {:?}, target = {:?}",
            stream.peer_addr(),
            self.target
        );
        self.service.call(stream)
    }
}

pub fn main() -> Result<()> {
    let service = service_fn(handle);
    let service = LogService::new("TCP Echo Example", service);
    let service = ConcurrencyLimit::new(service, 1);
    Runtime::new(Server::new(service).listen_addr("127.0.0.1:20018")).run()
}
