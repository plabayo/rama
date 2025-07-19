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
        Self::new_random_with_rng(connectors, rand::rng())
    }

    fn shuffle_connectors<Rng: rand::Rng>(mut connectors: Vec<C>, mut rng: Rng) -> Vec<C> {
        connectors.shuffle(&mut rng);
        connectors
    }

    pub fn new_random_with_rng<Rng: rand::Rng>(connectors: Vec<C>, rng: Rng) -> Self {
        Self {
            idx: Arc::new(AtomicUsize::default()),
            connectors: Self::shuffle_connectors(connectors, rng),
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
    use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};

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
        let connectors = vec![
            SocketAddress::local_ipv4(8080),
            SocketAddress::local_ipv4(8081),
            SocketAddress::local_ipv4(8082),
            SocketAddress::local_ipv4(8083),
            SocketAddress::local_ipv4(8084),
        ];

        let number_of_sample = connectors.len() * 2;

        let round_robin_connector = TcpStreamConnectorPool::new_round_robin(connectors.clone());

        let expected: Vec<_> = connectors
            .clone()
            .into_iter()
            .cycle()
            .take(number_of_sample)
            .collect();
        let results: Vec<_> = (0..number_of_sample)
            .map(|_| round_robin_connector.get_next_connector())
            .collect();

        assert_eq!(results, expected);
    }

    #[tokio::test]
    async fn test_get_next_connection_random() {
        let connectors = vec![
            SocketAddress::local_ipv4(8080),
            SocketAddress::local_ipv4(8081),
            SocketAddress::local_ipv4(8082),
            SocketAddress::local_ipv4(8083),
            SocketAddress::local_ipv4(8084),
            SocketAddress::local_ipv4(8085),
            SocketAddress::local_ipv4(8086),
            SocketAddress::local_ipv4(8087),
            SocketAddress::local_ipv4(8088),
            SocketAddress::local_ipv4(8089),
        ];

        let number_of_samples = connectors.len() * 2;
        let seed = 9999;

        let mut rng = StdRng::seed_from_u64(seed);
        let random_connector_pool =
            TcpStreamConnectorPool::new_random_with_rng(connectors.clone(), &mut rng);

        let mut expected_rng = StdRng::seed_from_u64(seed);
        let mut shuffled_connectors = connectors.clone();
        shuffled_connectors.shuffle(&mut expected_rng);

        let expected_connectors: Vec<_> = (0..number_of_samples)
            .map(|i| shuffled_connectors[i % shuffled_connectors.len()])
            .collect();

        let results = (0..number_of_samples)
            .map(|_| random_connector_pool.get_next_connector())
            .collect::<Vec<_>>();

        assert_eq!(results, expected_connectors);
    }
}
