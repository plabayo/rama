use std::sync::{atomic::AtomicUsize, Arc};

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

    pub fn get_next_connector(&self) -> C {
        match &self.mode {
            PoolMode::RoundRobin(idx) => {
                let next = idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let connector_idx = next % self.connectors.len();
                self.connectors[connector_idx].clone()
            }
            PoolMode::Random => self.connectors.choose(&mut rng()).unwrap().clone(),
        }
    }
}

impl<C: TcpStreamConnector> TcpStreamConnector for TcpStreamConnectorPool<C> {
    type Error = <C as TcpStreamConnector>::Error;

    async fn connect(
        &self,
        addr: std::net::SocketAddr,
    ) -> Result<tokio::net::TcpStream, Self::Error> {
        let connector = self.get_next_connector();
        connector.connect(addr).await
    }
}

#[cfg(test)]
mod tests {
    use rama_net::address::SocketAddress;

    use crate::client::TcpStreamConnector;

    use super::TcpStreamConnectorPool;

    #[derive(Debug, Clone)]
    struct MockConnector;

    impl TcpStreamConnector for MockConnector {
        type Error = String;

        async fn connect(
            &self,
            _addr: std::net::SocketAddr,
        ) -> Result<tokio::net::TcpStream, Self::Error> {
            unimplemented!()
        }
    }

    #[tokio::test]
    async fn test_get_next_connection_round_robin() {
        let expected_connectors = vec![
            SocketAddress::local_ipv4(8080),
            SocketAddress::local_ipv4(8081),
            SocketAddress::local_ipv4(8082),
        ];
        let round_robin_connector =
            TcpStreamConnectorPool::new_round_robin(expected_connectors.clone());

        let mut results = Vec::new();
        for _ in 0..3 {
            results.push(round_robin_connector.get_next_connector());
        }

        assert_eq!(results, expected_connectors);
    }
}
