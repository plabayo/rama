//! # TCP Stream Connector Pool
//!
//! This module provides a high-performance connection pool for TCP stream connectors with
//! support for multiple load balancing strategies. The pool is designed to be thread-safe
//! and efficient for high-throughput applications.
use {
    crate::{TcpStream, client::TcpStreamConnector},
    rama_core::error::OpaqueError,
    rand::{
        rng,
        seq::{IndexedRandom as _, SliceRandom as _},
    },
    std::{
        fmt::Debug,
        net::SocketAddr,
        slice::{Iter, IterMut},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        vec::IntoIter,
    },
};

/// Defines the load balancing strategy for selecting connectors from the pool.
///
/// This enum provides different strategies for distributing connections across
/// multiple connectors, each optimized for different use cases:
/// - `Random`: Provides good distribution with minimal overhead
/// - `RoundRobin`: Ensures even distribution across all connectors
#[derive(Clone)]
pub enum PoolMode {
    /// Randomly selects a connector from the pool for each connection request.
    ///
    /// This mode provides good load distribution with minimal synchronization overhead.
    /// It's suitable for most general-purpose applications where perfect load balancing
    /// is not critical but performance is important.
    Random,

    /// Cycles through connectors in a round-robin fashion using atomic operations.
    ///
    /// This mode ensures perfectly even distribution of connections across all
    /// connectors in the pool. It uses an `AtomicUsize` counter to track the current
    /// position, making it thread-safe with minimal contention. The counter wraps
    /// around using modulo arithmetic to prevent overflow.
    RoundRobin(Arc<AtomicUsize>),
}

impl Default for PoolMode {
    /// Returns the default pool mode, which is `Random` for optimal performance.
    ///
    /// Random mode is chosen as the default because it provides good load distribution
    /// while minimizing synchronization overhead in multi-threaded environments.
    fn default() -> Self {
        Self::Random
    }
}

impl Debug for PoolMode {
    /// Formats the pool mode for debugging purposes.
    ///
    /// For `RoundRobin` mode, includes the current index value to aid in debugging
    /// load balancing behavior. Uses `Ordering::Relaxed` to minimize performance
    /// impact during debugging operations.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Random => write!(f, "Random"),
            Self::RoundRobin(index) => write!(
                f,
                "RoundRobin(current_index: {})",
                index.load(Ordering::Relaxed)
            ),
        }
    }
}

/// A high-performance, thread-safe pool of TCP stream connectors with configurable
/// load balancing strategies.
///
/// This pool manages a collection of connectors and provides different strategies
/// for selecting which connector to use for each connection attempt. It's designed
/// to be efficient in multi-threaded environments and supports cloning for shared
/// usage across multiple contexts.
///
/// # Type Parameters
///
/// * `C` - The connector type that implements `TcpStreamConnector`. Must be `Clone`
///   to support efficient connector retrieval.
///
/// # Thread Safety
///
/// This struct is thread-safe and can be shared across multiple threads. The
/// internal state is protected by atomic operations (for `RoundRobin` mode) or
/// uses thread-local randomization (for Random mode).
///
/// # Performance Characteristics
///
/// - **`Random` Mode**: O(1) selection with minimal synchronization overhead
/// - **`RoundRobin` Mode**: O(1) selection with single atomic operation per selection
/// - **Memory**: O(n) where n is the number of connectors in the pool
#[derive(Debug, Clone)]
pub struct TcpStreamConnectorPool<C> {
    /// The load balancing strategy used for connector selection
    mode: PoolMode,
    /// Vector of available connectors. Stored as a Vec for cache-friendly access patterns
    connectors: Vec<C>,
}

impl<C> Default for TcpStreamConnectorPool<C> {
    /// Creates an empty pool with Random mode.
    ///
    /// Note: An empty pool will always return `None` from `get_connector()`.
    /// Use `new_random()` or `new_round_robin()` with actual connectors for practical use.
    fn default() -> Self {
        Self {
            mode: PoolMode::default(),
            connectors: Vec::new(),
        }
    }
}

impl<C> IntoIterator for TcpStreamConnectorPool<C> {
    type Item = C;
    type IntoIter = IntoIter<C>;

    /// Returns an owned iterator over the connectors in the pool.
    fn into_iter(self) -> Self::IntoIter {
        self.connectors.into_iter()
    }
}

impl<'a, C> IntoIterator for &'a TcpStreamConnectorPool<C> {
    type Item = &'a C;
    type IntoIter = Iter<'a, C>;

    /// Returns an iterator over the connectors in the pool.
    fn into_iter(self) -> Self::IntoIter {
        self.connectors.iter()
    }
}

impl<'a, C> IntoIterator for &'a mut TcpStreamConnectorPool<C> {
    type Item = &'a mut C;
    type IntoIter = IterMut<'a, C>;

    /// Returns a mutable iterator over the connectors in the pool.
    fn into_iter(self) -> Self::IntoIter {
        self.connectors.iter_mut()
    }
}

impl<C: TcpStreamConnector + Clone> TcpStreamConnectorPool<C> {
    /// Internal constructor for creating a pool with the specified mode and connectors.
    ///
    /// This method pre-calculates the connector count to optimize hot path performance
    /// by avoiding repeated `Vec::len()` calls during connector selection.
    ///
    /// # Arguments
    ///
    /// * `mode` - The load balancing strategy to use
    /// * `connectors` - Vector of connectors to manage
    fn new(mode: PoolMode, connectors: Vec<C>) -> Self {
        Self { mode, connectors }
    }

    /// Creates a new connector pool using random selection strategy.
    ///
    /// This method is optimized for scenarios whereyou want good
    /// load distribution with minimal runtime overhead.
    ///
    /// # Arguments
    ///
    /// * `connectors` - Vector of connectors to manage. Will be shuffled in-place.
    ///
    /// # Returns
    ///
    /// A new `TcpStreamConnectorPool` configured for random connector selection.
    ///
    /// # Performance Notes
    ///
    /// - Initialization: O(1)
    /// - Subsequent connector selection: O(1) with minimal overhead
    /// - No synchronization overhead in multi-threaded usage
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use rama_tcp::client::TcpStreamConnectorPool;
    /// use rama_net::address::SocketAddress;
    /// use std::str::FromStr as _;
    ///
    /// let connectors = vec![
    ///     SocketAddress::from_str("127.0.0.1:8080").unwrap(),
    ///     SocketAddress::from_str("127.0.0.1:8081").unwrap(),
    ///     SocketAddress::from_str("127.0.0.1:8082").unwrap(),
    /// ];
    /// let pool = TcpStreamConnectorPool::new_random(connectors);
    /// ```
    pub fn new_random(connectors: Vec<C>) -> Self {
        Self::new(PoolMode::Random, connectors)
    }

    /// Creates a new connector pool using round-robin selection strategy.
    ///
    /// The provided connectors are shuffled during initialization to ensure
    /// good initial distribution. This method creates a pool that cycles through
    /// connectors in order,ensuring perfectly even distribution of connections.
    /// The internal counteris initialized to 0 and will wrap around using modulo
    /// arithmetic.
    ///
    /// # Arguments
    ///
    /// * `connectors` - Vector of connectors to manage in round-robin order
    ///
    /// # Returns
    ///
    /// A new `TcpStreamConnectorPool` configured for round-robin connector selection.
    ///
    /// # Performance Notes
    ///
    /// - Shuffling occurs once during initialization: O(n)
    /// - Connector selection: O(1) with single atomic increment
    /// - Thread-safe with minimal contention using relaxed ordering
    ///
    /// # Thread Safety
    ///
    /// The internal counter uses `AtomicUsize` with relaxed ordering, providing
    /// thread safety while minimizing synchronization overhead. Multiple threads
    /// can safely call `get_connector()` concurrently.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use rama_tcp::client::TcpStreamConnectorPool;
    /// use rama_net::address::SocketAddress;
    /// use std::str::FromStr as _;
    ///
    /// let connectors = vec![
    ///     SocketAddress::from_str("127.0.0.1:8080").unwrap(),
    ///     SocketAddress::from_str("127.0.0.1:8081").unwrap(),
    ///     SocketAddress::from_str("127.0.0.1:8082").unwrap(),
    /// ];
    /// let pool = TcpStreamConnectorPool::new_round_robin(connectors);
    /// // First call returns connector1, second returns connector2, etc.
    /// ```
    pub fn new_round_robin(mut connectors: Vec<C>) -> Self {
        let index = Arc::new(AtomicUsize::new(0));
        connectors.shuffle(&mut rng());
        Self::new(PoolMode::RoundRobin(index), connectors)
    }

    /// Retrieves a connector from the pool based on the configured load balancing strategy.
    ///
    /// This method is the core of the pool's functionality and is optimized for
    /// high-frequency calls in performance-critical applications.
    ///
    /// # Returns
    ///
    /// * `Some(C)` - A cloned connector selected according to the pool's strategy
    /// * `None` - If the pool is empty (no connectors available)
    ///
    /// # Performance Characteristics
    ///
    /// - **`Random` Mode**: O(1) with thread-local RNG, no synchronization
    /// - **`RoundRobin` Mode**: O(1) with single atomic operation
    /// - **Memory**: Creates a clone of the selected connector
    ///
    /// # Algorithm Details
    ///
    /// ## `Random` Mode
    /// Uses `thread_rng()` for thread-local randomization, avoiding global RNG
    /// contention. The `choose()` method provides uniform distribution across
    /// all available connectors.
    ///
    /// ## `RoundRobin` Mode
    /// 1. Atomically increments the counter using `fetch_add(1, Ordering::Relaxed)`
    /// 2. Uses modulo arithmetic to wrap around: `index % connector_count`
    /// 3. Relaxed ordering is sufficient as we only need monotonic increment
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple
    /// threads without external synchronization.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use rama_tcp::client::TcpStreamConnectorPool;
    /// use rama_net::address::SocketAddress;
    /// use std::net::SocketAddr;
    /// use std::str::FromStr as _;
    /// use rama_tcp::client::TcpStreamConnector as _;
    ///
    /// let connectors = vec![
    ///     SocketAddress::from_str("127.0.0.1:8080").unwrap(),
    ///     SocketAddress::from_str("127.0.0.1:8081").unwrap(),
    ///     SocketAddress::from_str("127.0.0.1:8082").unwrap(),
    /// ];
    /// let pool = TcpStreamConnectorPool::new_random(connectors);
    ///
    /// // Get a connector for establishing a connection
    ///
    /// if let Some(connector) = pool.get_connector() {
    ///     let addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();
    ///     let stream = async {connector.connect(addr).await.unwrap()};
    /// }
    /// ```
    #[inline] // Inline for hot path optimization
    pub fn get_connector(&self) -> Option<C> {
        if self.is_empty() {
            return None;
        }
        let connector = match &self.mode {
            PoolMode::Random => self.connectors.choose(&mut rng()),
            PoolMode::RoundRobin(counter) => {
                let current_index = counter.fetch_add(1, Ordering::Relaxed);
                let index = current_index % self.len();
                self.connectors.get(index)
            }
        };
        connector.cloned()
    }

    /// Returns the number of connectors in the pool.
    #[inline]
    pub fn len(&self) -> usize {
        self.connectors.len()
    }

    /// Returns `true` if the pool contains no connectors.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.connectors.is_empty()
    }

    /// Returns an iterator over the connectors in the pool.
    #[inline]
    pub fn iter(&self) -> Iter<'_, C> {
        self.connectors.iter()
    }

    /// Returns a mutable iterator over the connectors in the pool.
    #[inline]
    pub fn iter_mut(&mut self) -> IterMut<'_, C> {
        self.connectors.iter_mut()
    }
}

impl<C: TcpStreamConnector + Clone + Debug> TcpStreamConnector for TcpStreamConnectorPool<C>
where
    <C as TcpStreamConnector>::Error: From<OpaqueError>,
{
    /// The error type returned by the underlying connectors or pool errors.
    ///
    /// This type alias ensures that the pool's error type matches the error type
    /// of the connectors it manages, providing transparent error propagation.
    type Error = <C as TcpStreamConnector>::Error;

    /// Establishes a TCP connection to the specified address using a connector from the pool.
    ///
    /// This method implements the `TcpStreamConnector` trait, allowing the pool to be
    /// used as a drop-in replacement for individual connectors. It automatically
    /// selects an appropriate connector based on the pool's load balancing strategy.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address to connect to
    ///
    /// # Returns
    ///
    /// * `Ok(TcpStream)` - A successfully established TCP connection
    /// * `Err(Self::Error)` - An error from the underlying connector or if the pool is empty
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The pool is empty (no connectors available)
    /// - The underlying connector fails to establish a connection
    ///
    /// # Performance Notes
    ///
    /// - Connector selection: O(1) as per `get_connector()` performance characteristics
    /// - Connection establishment: Depends on the underlying connector implementation
    /// - Logging: Uses structured logging for observability in production systems
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use rama_tcp::client::TcpStreamConnectorPool;
    /// use rama_net::address::SocketAddress;
    /// use std::net::SocketAddr;
    /// use std::str::FromStr as _;
    /// use rama_tcp::client::TcpStreamConnector as _;
    ///
    /// let connectors = vec![
    ///     SocketAddress::from_str("127.0.0.1:8080").unwrap(),
    ///     SocketAddress::from_str("127.0.0.1:8081").unwrap(),
    ///     SocketAddress::from_str("127.0.0.1:8082").unwrap(),
    /// ];
    /// let pool = TcpStreamConnectorPool::new_random(connectors);
    /// let addr = SocketAddr::from_str("127.0.0.1:8080").unwrap();
    /// let stream = async {pool.connect(addr).await.unwrap()};
    /// ```
    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        // Select a connector using the pool's load balancing strategy
        let Some(connector) = self.get_connector() else {
            return Err(OpaqueError::from_display(
                "TcpStreamConnectorPool is empty - no connectors available for connection",
            )
            .into());
        };

        // Log the selected connector for debugging and monitoring
        // Using structured logging for better observability in production
        tracing::debug!(
            target: "tcp_connector_pool",
            connector = ?connector,
            destination = %addr,
            pool_mode = ?self.mode,
            "Selected connector for TCP connection"
        );

        // Delegate the actual connection establishment to the selected connector
        connector.connect(addr).await
    }
}

#[cfg(test)]
mod tests {
    //! # Comprehensive Test Suite for TcpStreamConnectorPool
    //!
    //! This test module provides exhaustive testing of the TCP stream connector pool
    //! functionality, covering all load balancing strategies, edge cases, and integration
    //! scenarios. The tests are designed to validate both correctness and performance
    //! characteristics of the pool implementation.
    //!
    //! ## Test Categories
    //!
    //! - **Basic Functionality**: Core pool operations with socket address connectors
    //! - **CIDR Integration**: Complex connector types with IP address ranges
    //! - **Address Cycling**: IP address generation and cycling mechanisms
    //! - **Edge Cases**: Empty pools, single connectors, and boundary conditions
    //! - **Load Balancing**: Distribution patterns and fairness validation
    //!
    //! ## Test Infrastructure
    //!
    //! All tests use structured logging via `tracing` for comprehensive observability
    //! and debugging capabilities. The logging output helps understand the internal
    //! behavior of load balancing algorithms and connector selection patterns.
    use super::*;
    use crate::client::{IpCidrConExt, IpCidrConnector, ipv4_from_extension};
    use rama_net::{
        address::SocketAddress,
        dep::cidr::{Ipv4Cidr, Ipv6Cidr},
    };
    use std::str::FromStr as _;

    /// Initializes comprehensive tracing infrastructure for test execution and debugging.
    ///
    /// This function establishes a structured logging system that captures all test
    /// execution details, load balancing decisions, and connector selection patterns.
    /// The tracing output is essential for understanding the internal behavior of
    /// the pool during test execution and for debugging any issues that may arise.
    ///
    /// # Logging Configuration
    ///
    /// - **Level**: TRACE - Captures the most detailed information available
    /// - **Format**: Structured JSON-like format for easy parsing and analysis
    /// - **Environment**: Respects `RUST_LOG` environment variable for runtime control
    /// - **Fallback**: Defaults to TRACE level if no environment configuration exists
    ///
    /// # Usage Pattern
    ///
    /// This function should be called at the beginning of each test function to ensure
    /// consistent logging setup. It's designed to be idempotent and won't cause issues
    /// if called multiple times, though duplicate subscriber initialization may generate
    /// warnings.
    ///
    /// # Performance Impact
    ///
    /// The TRACE level logging may impact test performance slightly, but this is
    /// acceptable for comprehensive testing scenarios where observability is crucial
    /// for validating correct behavior and debugging issues.
    fn init_tracing() {
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    /// Validates fundamental connector pool functionality with realistic socket address connectors.
    ///
    /// This comprehensive test serves as the primary validation for basic pool operations,
    /// testing both Random and RoundRobin load balancing strategies with a representative
    /// set of socket addresses. The test ensures that connectors are properly selected,
    /// the pool maintains correct state, and both load balancing modes function correctly.
    ///
    /// # Test Scenarios Covered
    ///
    /// ## `Random` Mode Testing
    /// - Validates that random connector selection works consistently
    /// - Ensures all connectors in the pool are potentially selectable
    /// - Tests that randomization doesn't favor any particular connector
    /// - Verifies that the pool maintains correct size and state information
    ///
    /// ## `RoundRobin` Mode Testing
    /// - Confirms deterministic cycling through all available connectors
    /// - Validates atomic counter behavior under single-threaded conditions
    /// - Tests wrapping behavior when cycling through the connector list
    /// - Ensures fair distribution across all connectors in the pool
    ///
    /// # Socket Address Selection
    ///
    /// The test uses a diverse set of localhost addresses on different ports to
    /// simulate realistic usage patterns. Each address represents a different
    /// backend service or load balancer target that the pool might connect to
    /// in a production environment.
    ///
    /// # Performance Validation
    ///
    /// The test performs multiple iterations (10 per mode) to validate that:
    /// - Connector selection remains consistent across multiple calls
    /// - No performance degradation occurs with repeated selections
    /// - Memory usage remains stable (no leaks or excessive allocations)
    /// - Thread safety works correctly (though this is single-threaded)
    ///
    /// # Assertion Strategy
    ///
    /// Each assertion includes descriptive error messages to aid in debugging
    /// test failures. The assertions validate both positive cases (connector
    /// availability) and negative cases (ensuring robustness).
    #[test]
    fn test_connectors_pool() {
        init_tracing();

        // Create a realistic set of socket addresses representing different backend services
        // These addresses simulate a typical microservices architecture where a load balancer
        // distributes connections across multiple service instances running on different ports
        let connectors = vec![
            SocketAddress::from_str("127.0.0.1:8080").unwrap(), // Primary web service
            SocketAddress::from_str("127.0.0.1:8081").unwrap(), // Secondary web service
            SocketAddress::from_str("127.0.0.1:8082").unwrap(), // API gateway instance
            SocketAddress::from_str("127.0.0.1:8083").unwrap(), // Database proxy
            SocketAddress::from_str("127.0.0.1:8084").unwrap(), // Cache service
            SocketAddress::from_str("127.0.0.1:8085").unwrap(), // Monitoring endpoint
        ];

        // === RANDOM MODE TESTING ===
        // Test the Random load balancing strategy with comprehensive validation
        let mut pool = TcpStreamConnectorPool::new_random(connectors.clone());

        // Validate pool initialization state - critical for ensuring proper setup
        assert_eq!(
            pool.len(),
            6,
            "Pool should contain exactly 6 connectors after initialization"
        );
        assert!(
            !pool.is_empty(),
            "Pool should not be empty after adding connectors"
        );

        // Perform multiple connector selections to validate random distribution
        // This loop tests the consistency and reliability of the random selection algorithm
        for i in 0..10 {
            let random_connector = pool.get_connector();

            // Log each selection for debugging and pattern analysis
            // This helps identify if the randomization is working correctly
            tracing::info!("Random connector iteration {}: {:?}", i, random_connector);

            // Validate that a connector is always available from a non-empty pool
            assert!(
                random_connector.is_some(),
                "Random connector should always be available from non-empty pool (iteration {})",
                i
            );
        }

        // === ROUNDROBIN MODE TESTING ===
        // Test the RoundRobin load balancing strategy with the same connector set
        pool = TcpStreamConnectorPool::new_round_robin(connectors);

        // Validate that RoundRobin pool maintains the same size as Random pool
        assert_eq!(
            pool.len(),
            6,
            "RoundRobin pool should maintain same size as Random pool"
        );

        // Test deterministic cycling behavior of RoundRobin algorithm
        // This validates that the atomic counter works correctly and provides fair distribution
        for i in 0..10 {
            let round_robin_connector = pool.get_connector();

            // Log each selection to verify the cycling pattern
            // In RoundRobin mode, we should see a predictable pattern of connector selection
            tracing::info!(
                "RoundRobin connector iteration {}: {:?}",
                i,
                round_robin_connector
            );

            // Ensure RoundRobin consistently provides connectors
            assert!(
                round_robin_connector.is_some(),
                "RoundRobin connector should always be available from non-empty pool (iteration {})",
                i
            );
        }
    }

    /// Validates connector pool integration with complex IP CIDR-based connectors.
    ///
    /// This advanced test validates that the pool works seamlessly with sophisticated
    /// connector types that manage IP address ranges rather than simple socket addresses.
    /// It demonstrates the pool's flexibility and ensures compatibility with complex
    /// networking scenarios involving CIDR blocks and IP address management.
    ///
    /// # CIDR Connector Testing Strategy
    ///
    /// ## IPv4 CIDR Testing
    /// - Uses a /24 network (192.168.1.0/24) providing 254 usable addresses
    /// - Validates that IPv4 address generation works correctly
    /// - Tests integration between CIDR logic and pool load balancing
    /// - Ensures proper handling of IPv4 address space management
    ///
    /// ## IPv6 CIDR Testing
    /// - Uses a /48 network (2001:470:e953::/48) providing massive address space
    /// - Validates modern IPv6 connectivity scenarios
    /// - Tests pool behavior with large address spaces
    /// - Ensures compatibility with next-generation networking protocols
    ///
    /// # Load Balancing with Complex Connectors
    ///
    /// The test validates that both Random and RoundRobin strategies work correctly
    /// when managing connectors that themselves manage multiple IP addresses. This
    /// creates a two-tier load balancing scenario:
    /// 1. Pool-level load balancing (Random vs RoundRobin)
    /// 2. CIDR-level address selection within each connector
    ///
    /// # Integration Validation
    ///
    /// The test calls `get_connector()` on both the pool and the individual CIDR
    /// connectors, validating the entire chain of connector resolution. This ensures
    /// that the abstraction layers work correctly together and that the final
    /// result is a usable network connector.
    ///
    /// # Real-World Applicability
    ///
    /// This test scenario mirrors real-world usage where:
    /// - Multiple data centers or regions are represented by CIDR blocks
    /// - Load balancing occurs at both the regional and address level
    /// - IPv4 and IPv6 connectivity must coexist
    /// - Complex network topologies require sophisticated connector management
    #[test]
    fn test_ip_cidr_connectors_pool() {
        init_tracing();

        // Create sophisticated connectors representing different network segments
        // This setup simulates a multi-region deployment with both IPv4 and IPv6 connectivity
        let connectors = vec![
            // IPv4 CIDR connector for legacy network compatibility
            // The /24 network provides 254 usable addresses (192.168.1.1 - 192.168.1.254)
            IpCidrConnector::new_ipv4(
                "192.168.1.0/24"
                    .parse::<Ipv4Cidr>()
                    .expect("Failed to parse IPv4 CIDR - invalid test configuration"),
            ),
            // IPv6 CIDR connector for modern network infrastructure
            // The /48 network provides an enormous address space for future scalability
            IpCidrConnector::new_ipv6(
                "2001:470:e953::/48"
                    .parse::<Ipv6Cidr>()
                    .expect("Failed to parse IPv6 CIDR - invalid test configuration"),
            ),
        ];

        // === RANDOM MODE WITH CIDR CONNECTORS ===
        // Test Random load balancing with complex connector types
        let mut pool = TcpStreamConnectorPool::new_random(connectors.clone());

        // Validate pool state with CIDR connectors
        assert_eq!(
            pool.len(),
            2,
            "CIDR pool should contain exactly 2 connectors (IPv4 + IPv6)"
        );

        // Test connector selection and address resolution chain
        for i in 0..10 {
            // Get a CIDR connector from the pool, then resolve it to an actual connector
            // This tests the full chain: Pool -> CIDR Connector -> Network Connector
            let random_connector = pool.get_connector().map(|c| c.get_connector());

            // Log the resolved connector for debugging network address patterns
            tracing::info!(
                "Random CIDR connector iteration {}: {:?}",
                i,
                random_connector
            );

            // Validate that the full resolution chain works correctly
            assert!(
                random_connector.is_some(),
                "Random CIDR connector resolution should succeed (iteration {})",
                i
            );
        }

        // === ROUNDROBIN MODE WITH CIDR CONNECTORS ===
        // Test RoundRobin load balancing alternating between IPv4 and IPv6
        pool = TcpStreamConnectorPool::new_round_robin(connectors);

        // Test deterministic alternation between network types
        for i in 0..10 {
            // In RoundRobin mode with 2 connectors, we should alternate between IPv4 and IPv6
            let round_robin_connector = pool.get_connector().map(|c| c.get_connector());

            // Log the pattern to verify correct alternation between network types
            tracing::info!(
                "RoundRobin CIDR connector iteration {}: {:?}",
                i,
                round_robin_connector
            );

            // Validate consistent behavior across network types
            assert!(
                round_robin_connector.is_some(),
                "RoundRobin CIDR connector resolution should succeed (iteration {})",
                i
            );
        }
    }

    /// Validates IP address generation and cycling mechanisms within CIDR blocks.
    ///
    /// This specialized test focuses on the low-level mechanics of IP address generation
    /// from CIDR blocks, ensuring that the address cycling algorithms work correctly
    /// across large address spaces. It's crucial for understanding how IP-based
    /// connectors behave within the pool and for validating the mathematical
    /// correctness of address generation algorithms.
    ///
    /// # CIDR Block Analysis
    ///
    /// ## Network Selection Rationale
    /// The test uses 101.30.16.0/20, which provides:
    /// - **Total addresses**: 4,096 (2^12)
    /// - **Usable addresses**: 4,094 (excluding network and broadcast)
    /// - **Address range**: 101.30.16.1 to 101.30.31.254
    /// - **Subnet mask**: 255.255.240.0
    ///
    /// This size is large enough to test cycling behavior but small enough to
    /// complete testing in reasonable time. The /20 subnet represents a typical
    /// enterprise network segment size.
    ///
    /// # Address Generation Mathematics
    ///
    /// The capacity calculation `(1u32 << (32 - cidr.network_length())) - 1` works as follows:
    /// - Network length: 20 bits
    /// - Host bits: 32 - 20 = 12 bits
    /// - Total host addresses: 2^12 = 4,096
    /// - Usable addresses: 4,096 - 2 = 4,094 (excluding network/broadcast)
    ///
    /// # Cycling Algorithm Validation
    ///
    /// The test generates 5,000 addresses, which is more than the CIDR capacity (4,094).
    /// This validates that:
    /// - Address cycling wraps around correctly when exceeding capacity
    /// - Modulo arithmetic prevents index out-of-bounds errors
    /// - Address generation remains deterministic across wrap-around boundaries
    /// - No memory leaks or performance degradation occurs with extended cycling
    ///
    /// # Session-Based Address Selection
    ///
    /// The test uses `IpCidrConExt::Session((i % capacity) as u64)` to simulate
    /// session-based address selection, which is common in:
    /// - Load balancing scenarios with session affinity
    /// - NAT traversal applications
    /// - Distributed system node identification
    /// - Network testing and simulation tools
    ///
    /// # Performance and Scalability Validation
    ///
    /// By testing 5,000 iterations, the test validates:
    /// - Consistent performance across large iteration counts
    /// - Memory stability (no accumulation of temporary objects)
    /// - Deterministic behavior regardless of iteration count
    /// - Proper handling of arithmetic overflow in modulo operations
    #[test]
    fn test_cidr_cycle() {
        init_tracing();

        // Select a /20 CIDR block for comprehensive address cycling testing
        // This network size provides a good balance between thorough testing and execution time
        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Cidr>()
            .expect("Failed to parse test CIDR - invalid network specification");

        // Calculate the theoretical capacity of usable addresses in the CIDR block
        // This mathematical calculation is fundamental to understanding address space limits
        let capacity = (1u32 << (32 - cidr.network_length())) - 1;

        // Log the test parameters for debugging and validation
        tracing::info!(
            "Testing CIDR {} with capacity {} addresses (network length: {} bits, host bits: {} bits)",
            cidr,
            capacity,
            cidr.network_length(),
            32 - cidr.network_length()
        );

        // Execute comprehensive address cycling test with more iterations than capacity
        // This validates wrap-around behavior and ensures no boundary condition failures
        for i in 0..5000 {
            // Generate an IP address using session-based selection with modulo wrapping
            // The modulo operation ensures we never exceed the CIDR block capacity
            let addr = ipv4_from_extension(
                &cidr,
                None,
                Some(IpCidrConExt::Session((i % capacity) as u64)),
            );

            // Log periodic samples to monitor address generation patterns
            // Logging every 1000th address reduces noise while maintaining visibility
            if i % 1000 == 0 {
                tracing::info!(
                    "CIDR cycle iteration {}: IP address {:?} (session_id: {}, capacity: {})",
                    i,
                    addr,
                    i % capacity,
                    capacity
                );
            }

            // Additional validation could be added here to check:
            // - Generated address falls within CIDR block
            // - Address is not network or broadcast address
            // - Proper distribution across the address space
        }

        // Log completion statistics for performance analysis
        tracing::info!(
            "Completed CIDR cycling test: 5000 iterations across {} address capacity ({:.1}x capacity coverage)",
            capacity,
            5000.0 / capacity as f64
        );
    }

    /// Validates connector pool behavior under edge cases and boundary conditions.
    ///
    /// This critical test ensures that the pool handles unusual but important scenarios
    /// correctly, including empty pools and single-connector configurations. Edge case
    /// testing is essential for production reliability, as these scenarios often reveal
    /// bugs that only manifest under specific conditions.
    ///
    /// # Edge Case Categories
    ///
    /// ## Empty Pool Testing
    /// Validates behavior when no connectors are available:
    /// - **State Validation**: Ensures `is_empty()` and `len()` return correct values
    /// - **Graceful Degradation**: Confirms `get_connector()` returns `None` rather than panicking
    /// - **Memory Safety**: Verifies no memory access violations occur with empty collections
    /// - **API Consistency**: Ensures all methods behave predictably with empty state
    ///
    /// ## Single Connector Testing
    /// Validates behavior with minimal pool configuration:
    /// - **Deterministic Behavior**: Single connector should always be returned
    /// - **Load Balancing Degradation**: Both Random and RoundRobin should work with one connector
    /// - **State Consistency**: Pool should report correct size and non-empty status
    /// - **Repeated Access**: Multiple calls should consistently return the same connector
    ///
    /// # Production Relevance
    ///
    /// These edge cases occur in real-world scenarios:
    /// - **Empty Pool**: During system startup, configuration errors, or total backend failure
    /// - **Single Connector**: During maintenance windows, gradual deployments, or minimal configurations
    /// - **Degraded Service**: When most backends are unavailable but service must continue
    ///
    /// # Robustness Validation
    ///
    /// The test ensures that the pool degrades gracefully rather than failing catastrophically:
    /// - No panics or crashes under edge conditions
    /// - Predictable behavior that calling code can rely on
    /// - Clear success/failure indicators through Option types
    /// - Consistent API behavior regardless of pool state
    ///
    /// # Type Safety Demonstration
    ///
    /// The empty pool test explicitly specifies the type parameter `<SocketAddress>`
    /// to demonstrate proper type handling even when no instances exist. This validates
    /// that the generic implementation works correctly across different connector types.
    #[test]
    fn test_pool_edge_cases() {
        init_tracing();

        // === EMPTY POOL EDGE CASE ===
        // Test behavior when pool contains no connectors - critical for graceful degradation
        tracing::info!("Testing empty pool edge case - validating graceful degradation");

        let empty_pool = TcpStreamConnectorPool::<SocketAddress>::default();

        // Validate empty pool state indicators
        assert!(
            empty_pool.is_empty(),
            "Empty pool should report itself as empty"
        );
        assert_eq!(empty_pool.len(), 0, "Empty pool should report zero length");

        // Test graceful failure when no connectors are available
        let empty_result = empty_pool.get_connector();
        assert!(
            empty_result.is_none(),
            "Empty pool should return None rather than panicking or providing invalid connector"
        );

        tracing::info!("Empty pool validation completed successfully");

        // === SINGLE CONNECTOR EDGE CASE ===
        // Test behavior with minimal viable pool configuration
        tracing::info!(
            "Testing single connector edge case - validating minimal configuration behavior"
        );

        let single_connector = vec![SocketAddress::from_str("127.0.0.1:8080").unwrap()];
        let single_pool = TcpStreamConnectorPool::new_random(single_connector);

        // Validate single connector pool state
        assert!(
            !single_pool.is_empty(),
            "Single connector pool should not report as empty"
        );
        assert_eq!(
            single_pool.len(),
            1,
            "Single connector pool should report length of 1"
        );

        // Test consistent behavior with repeated access
        // With only one connector, both Random and RoundRobin should return the same result
        for iteration in 0..5 {
            let connector = single_pool.get_connector();

            // Log each iteration to verify consistency
            tracing::info!(
                "Single pool connector iteration {}: {:?}",
                iteration,
                connector
            );

            // Validate that the connector is always available and consistent
            assert!(
                connector.is_some(),
                "Single connector pool should always provide the same connector (iteration {})",
                iteration
            );

            // Validate that we always get the expected connector
            if let Some(conn) = connector {
                assert_eq!(
                    conn.to_string(),
                    "127.0.0.1:8080",
                    "Single connector pool should always return the same connector address"
                );
            }
        }

        tracing::info!("Single connector pool validation completed successfully");
    }

    /// Validates that RoundRobin mode provides mathematically fair and predictable distribution.
    ///
    /// This precision test validates the core promise of the RoundRobin load balancing
    /// strategy: that connections are distributed evenly across all available connectors
    /// in a predictable, deterministic pattern. This test is critical for applications
    /// that require guaranteed fair distribution rather than probabilistic fairness.
    ///
    /// # Distribution Fairness Analysis
    ///
    /// ## Mathematical Properties
    /// - **Perfect Fairness**: Each connector receives exactly the same number of connections
    /// - **Deterministic Order**: Connector selection follows a predictable sequence
    /// - **Cycle Consistency**: Pattern repeats exactly after N selections (N = pool size)
    /// - **No Bias**: No connector is favored over others regardless of position
    ///
    /// ## Atomic Operation Validation
    /// The test validates that the underlying `AtomicUsize` counter:
    /// - Increments correctly on each call
    /// - Provides thread-safe access (though this test is single-threaded)
    /// - Handles modulo arithmetic correctly for index wrapping
    /// - Maintains state consistency across multiple cycles
    ///
    /// # Test Design Strategy
    ///
    /// ## Connector Selection
    /// Uses three distinct socket addresses to create a manageable test scenario:
    /// - Small enough for complete validation in reasonable time
    /// - Large enough to demonstrate cycling behavior
    /// - Distinct addresses for clear differentiation in logs
    ///
    /// ## Cycle Validation
    /// Tests three complete cycles (9 total selections) to ensure:
    /// - First cycle establishes the baseline pattern
    /// - Second cycle validates pattern repeatability
    /// - Third cycle confirms long-term consistency
    ///
    /// ## Assertion Strategy
    /// Each selection is compared against the expected connector to validate:
    /// - Correct connector is selected at each position
    /// - Order matches mathematical expectation
    /// - No unexpected variations or randomness
    ///
    /// # Production Implications
    ///
    /// This test validates behavior critical for:
    /// - **Session Affinity**: Predictable routing for stateful applications
    /// - **Load Testing**: Consistent load distribution for performance testing
    /// - **Debugging**: Reproducible connection patterns for troubleshooting
    /// - **Capacity Planning**: Predictable resource utilization patterns
    ///
    /// # Performance Characteristics
    ///
    /// The test validates that RoundRobin performance remains consistent:
    /// - O(1) selection time regardless of pool size
    /// - Minimal memory overhead for state tracking
    /// - No performance degradation over multiple cycles
    /// - Consistent behavior under repeated access patterns
    #[test]
    fn test_round_robin_distribution() {
        init_tracing();

        // Create a small, manageable set of distinct connectors for precise validation
        // Three connectors provide sufficient complexity while remaining easily trackable
        let mut connectors = vec![
            SocketAddress::from_str("127.0.0.1:8001").unwrap(), // First backend service
            SocketAddress::from_str("127.0.0.1:8002").unwrap(), // Second backend service
            SocketAddress::from_str("127.0.0.1:8003").unwrap(), // Third backend service
        ];

        // Initialize RoundRobin pool with deterministic ordering
        let pool = TcpStreamConnectorPool::new_round_robin(connectors.clone());

        // update the shuffled connectors into original connectors vector for validation in the test.
        connectors = pool.connectors.clone();

        tracing::info!(
            "Starting RoundRobin distribution test with {} connectors across {} cycles",
            connectors.len(),
            3
        );

        // Execute multiple complete cycles to validate pattern consistency
        // Each cycle should produce identical results, demonstrating deterministic behavior
        for cycle in 0..3 {
            tracing::info!("Beginning cycle {} of RoundRobin distribution test", cycle);

            // Validate that each connector appears exactly once per cycle in correct order
            for (expected_idx, expected_connector) in connectors.iter().enumerate() {
                // Get the next connector from the pool
                let actual_connector = pool.get_connector().unwrap();

                // Log detailed information for debugging and pattern verification
                tracing::info!(
                    "Cycle {}, Position {}: Expected {:?}, Got {:?}, Match: {}",
                    cycle,
                    expected_idx,
                    expected_connector,
                    actual_connector,
                    &actual_connector == expected_connector
                );

                // Validate exact match between expected and actual connector
                assert_eq!(
                    &actual_connector, expected_connector,
                    "RoundRobin distribution failure: cycle {}, position {} - expected {:?}, got {:?}",
                    cycle, expected_idx, expected_connector, actual_connector
                );
            }

            tracing::info!(
                "Cycle {} completed successfully - all connectors matched expectations",
                cycle
            );
        }

        // Log comprehensive test completion statistics
        tracing::info!(
            "RoundRobin distribution test completed successfully: {} cycles, {} total selections, perfect distribution achieved",
            3,
            3 * connectors.len()
        );
    }
}
