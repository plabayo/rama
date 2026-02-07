use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use rama_core::error::BoxError;
use rand::RngCore;

use crate::{TcpStream, client::TcpStreamConnector};

/// Selection algorithms
#[derive(Debug, Clone)]
enum Selector {
    RoundRobin(Arc<AtomicUsize>),
    Random,
}

impl Selector {
    fn new_random() -> Self {
        Self::Random
    }

    fn new_round_robin() -> Self {
        Self::RoundRobin(Arc::new(AtomicUsize::default()))
    }

    fn next<'a, C: Clone>(&self, connectors: &'a [C]) -> Option<&'a C> {
        if connectors.is_empty() {
            return None;
        }
        let selection = match self {
            Self::RoundRobin(atomic_usize) => atomic_usize.fetch_add(1, Ordering::Relaxed),
            Self::Random => rand::rng().next_u64() as usize,
        };
        let idx = selection % connectors.len();
        Some(&connectors[idx])
    }
}

/// A pool of TcpConnectors
#[derive(Debug, Clone)]
pub struct TcpStreamConnectorPool<C> {
    selector: Selector,
    connectors: Vec<C>,
}

impl<C: TcpStreamConnector> TcpStreamConnectorPool<C> {
    /// A `TcpStreamConnector` where each connection is chosed randomly from a pool of
    /// `TcpStreamConnector`s
    #[must_use]
    pub fn new_random(connectors: Vec<C>) -> Self {
        Self {
            selector: Selector::new_random(),
            connectors,
        }
    }

    /// New 'Round Robin' `TcpStreamConnector`
    #[must_use]
    pub fn new_round_robin(connectors: Vec<C>) -> Self {
        Self {
            selector: Selector::new_round_robin(),
            connectors,
        }
    }
}

impl<C: TcpStreamConnector> TcpStreamConnector for TcpStreamConnectorPool<C>
where
    <C as TcpStreamConnector>::Error: From<BoxError>,
{
    type Error = <C as TcpStreamConnector>::Error;

    async fn connect(&self, addr: std::net::SocketAddr) -> Result<TcpStream, Self::Error> {
        let connector = self.selector.next(&self.connectors).ok_or_else(|| {
            BoxError::from("TcpStreamConnectorPool has empty connectors collection")
        })?;
        connector.connect(addr).await
    }
}

#[cfg(test)]
mod tests {
    use ahash::{HashSet, HashSetExt as _};

    use rama_net::address::SocketAddress;

    use crate::{
        client::TcpStreamConnector,
        pool::{Selector, TcpStreamConnectorPool},
    };

    #[test]
    fn test_selector_round_robin() {
        let connectors = vec![
            SocketAddress::local_ipv4(8080),
            SocketAddress::local_ipv4(8081),
            SocketAddress::local_ipv4(8082),
            SocketAddress::local_ipv4(8083),
            SocketAddress::local_ipv4(8084),
        ];

        let number_of_sample = connectors.len() * 2;

        let selector = Selector::new_round_robin();

        let expected: Vec<_> = connectors.iter().cycle().take(number_of_sample).collect();
        let results: Vec<_> = (0..number_of_sample)
            .map(|_| {
                selector
                    .next(connectors.as_slice())
                    .expect("Selector could not select from empty Connections collection")
            })
            .collect();

        assert_eq!(results, expected, "Selector returned unexpected order");
    }

    #[test]
    fn test_selector_random() {
        let connectors = vec![
            SocketAddress::local_ipv4(8080),
            SocketAddress::local_ipv4(8081),
            SocketAddress::local_ipv4(8082),
        ];

        let number_of_sample = connectors.len() * 2;

        let selector = Selector::new_random();

        let results: Vec<_> = (0..number_of_sample)
            .map(|_| selector.next(connectors.as_slice()))
            .collect();

        assert!(
            results.iter().all(|connector_opt| connector_opt.is_some()),
            "Unexpected got None from selector",
        );
    }

    #[test]
    fn test_selector_random_selection_coverage() {
        let connectors = vec![
            SocketAddress::local_ipv4(8080),
            SocketAddress::local_ipv4(8081),
            SocketAddress::local_ipv4(8082),
        ];

        let selector = Selector::new_random();
        let mut seen = HashSet::new();

        for _ in 0..1000 {
            seen.insert(selector.next(connectors.as_slice()));
            if seen.len() == connectors.len() {
                break;
            }
        }

        assert_eq!(
            seen.len(),
            connectors.len(),
            "Random selector should be able to select all available connectors"
        );
    }

    #[test]
    fn test_empty_selectors() {
        let connectors: Vec<SocketAddress> = vec![];
        let selectors = vec![Selector::new_round_robin(), Selector::new_random()];
        for selector in selectors {
            let next = selector.next(connectors.as_slice());
            assert!(
                next.is_none(),
                "Empty selector should return None. Selector: {selector:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_error_returned_from_empty_tcp_stream_connector_pool() {
        let connectors: Vec<SocketAddress> = vec![];
        let random_connector_pool = TcpStreamConnectorPool::new_round_robin(connectors.clone());
        let connect_res = random_connector_pool
            .connect("127.0.0.1:8080".parse().expect("failed to parse address"))
            .await;
        assert!(connect_res.is_err(), "Expected error from connect");
    }
}
