use std::{
    sync::{atomic::AtomicUsize, Arc},
    task::Poll,
};

use rama_core::error::OpaqueError;

use super::TcpStreamConnector;

#[derive(Debug, Clone)]
enum PoolMode {
    RoundRobin(Arc<AtomicUsize>),
    Random,
}

#[derive(Debug, Clone)]
pub struct TcpStreamConnectorPool<C> {
    mode: PoolMode,
    connectors: Vec<C>,
}

impl<C: TcpStreamConnector> TcpStreamConnectorPool<C> {
    pub fn new_random(connectors: Vec<C>) -> Self {
        Self {
            mode: PoolMode::Random,
            connectors,
        }
    }

    pub fn new_round_robin(connectors: Vec<C>) -> Self {
        Self {
            mode: PoolMode::RoundRobin(Arc::new(AtomicUsize::new(0))),
            connectors,
        }
    }
}

impl<C: TcpStreamConnector> TcpStreamConnector for TcpStreamConnectorPool<C> {
    type Error = <C as TcpStreamConnector>::Error;

    async fn connect(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<tokio::net::TcpStream, Self::Error> {
        todo!("Implement connection pooling logic")
    }
}

#[cfg(test)]
mod tests {}
