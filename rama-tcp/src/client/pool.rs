use std::sync::{atomic::AtomicUsize, Arc};

use rand::seq::SliceRandom;

use super::TcpStreamConnector;

#[derive(Debug, Clone)]
pub struct TcpStreamConnectorPool<C> {
    idx: Arc<AtomicUsize>,
    connectors: Vec<C>,
}

impl<C: TcpStreamConnector> TcpStreamConnectorPool<C> {
    pub fn new_random(connectors: Vec<C>) -> Self {
        let mut rng = rand::rng();
        Self::new_round_robin_with_rng(connectors, &mut rng)
    }

    pub fn new_round_robin_with_rng<Rng: rand::Rng>(connectors: Vec<C>, rng: &mut Rng) -> Self {
        let mut connectors = connectors;
        connectors.shuffle(rng);
        Self {
            idx: Arc::new(AtomicUsize::default()),
            connectors,
        }
    }

    pub fn new_round_robin(connectors: Vec<C>) -> Self {
        Self {
            idx: Arc::new(AtomicUsize::default()),
            connectors,
        }
    }

    pub fn get_next_connector(&self) -> C {
        assert!(!self.connectors.is_empty(), "No connectors available");

        let next = self.idx.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let next_idx = next % self.connectors.len();
        self.connectors[next_idx].clone()
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
            SocketAddress::local_ipv4(8083),
            SocketAddress::local_ipv4(8084),
        ];
        let round_robin_connector =
            TcpStreamConnectorPool::new_round_robin(expected_connectors.clone());

        let mut results = Vec::new();
        for _ in 0..expected_connectors.len() {
            results.push(round_robin_connector.get_next_connector());
        }

        assert_eq!(results, expected_connectors);
    }
}
