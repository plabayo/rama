use std::sync::{atomic::AtomicUsize, Arc};

use rama_core::error::OpaqueError;
use rand::{rng, seq::IndexedRandom};

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
        let connector: C = match &self.mode {
            PoolMode::RoundRobin(idx) => {
                let next = idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let connector_idx = next % self.connectors.len();
                self.connectors[connector_idx].clone()
            }
            PoolMode::Random => self.connectors.choose(&mut rng()).unwrap().clone(),
        };
        connector.connect(addr).await
    }
}

#[cfg(test)]
mod tests {}
