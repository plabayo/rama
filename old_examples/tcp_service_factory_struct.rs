use std::{future, task};

use anyhow::Context;
use tokio::net::TcpStream;
use tracing::Level;

use rama::core::transport::tcp::server::{Listener, Result, Service, ServiceFactory};

#[derive(Debug, Default)]
struct HelloServiceFactory {
    counter: usize,
}

impl ServiceFactory<TcpStream> for HelloServiceFactory {
    type Service = HelloService;

    fn new_service(&mut self) -> Result<Self::Service> {
        let id = self.counter;
        self.counter += 1;
        Ok(HelloService { id })
    }
}

#[derive(Debug)]
struct HelloService {
    id: usize,
}

impl Service<TcpStream> for HelloService {
    type Future = future::Ready<Result<()>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> task::Poll<Result<()>> {
        task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, stream: TcpStream) -> Self::Future {
        tracing::info!("Hello {:?}! (id = {})", stream.peer_addr(), self.id);
        future::ready(Ok(()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).context("set global tracing subscriber")?;

    Listener::bind("127.0.0.1:20018")
        .serve(HelloServiceFactory::default())
        .await
}
