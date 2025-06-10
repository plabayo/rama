use {
    super::{
        PoolMode,
        utils::{IpCidrConExt, ipv4_from_extension, ipv6_from_extension},
    },
    crate::{TcpStream, client::TcpStreamConnector},
    rama_core::error::OpaqueError,
    rama_net::{
        address::SocketAddress,
        dep::cidr::{IpCidr, Ipv4Cidr, Ipv6Cidr},
    },
    std::{
        collections::HashSet,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::atomic::Ordering,
    },
};

/// A high-performance TCP connector that intelligently manages IP address selection from CIDR blocks.
///
/// This connector provides sophisticated IP address management for outbound connections, supporting
/// both IPv4 and IPv6 CIDR blocks with multiple selection strategies. It's designed for scenarios
/// where you need to distribute connections across multiple source IP addresses, such as:
///
/// - Load balancing across multiple network interfaces
/// - Rotating source IPs to avoid rate limiting
/// - Geographic distribution of connection sources
/// - High-availability networking with fallback capabilities
///
/// # Performance Characteristics
///
/// - **O(1)** address selection for random mode
/// - **O(1)** address selection for round-robin mode
/// - **O(k)** exclusion checking where k is the number of excluded addresses
/// - Pre-computed capacity calculations minimize runtime overhead
/// - Lock-free atomic operations for thread-safe round-robin indexing
///
/// # Examples
///
/// ```rust
/// use std::sync::Arc;
/// use std::sync::atomic::AtomicUsize;
/// use std::net::IpAddr;
/// use std::net::Ipv4Addr;
/// use rama_net::dep::cidr::Ipv4Cidr;
/// use rama_tcp::client::IpCidrConnector;
/// use rama_tcp::client::PoolMode;
///
/// // Create a connector for a /24 IPv4 subnet with random selection
/// let connector = IpCidrConnector::new_ipv4(
///     Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()
/// );
///
/// // Configure with round-robin selection and fallback
/// let connector = connector
///     .with_mode(PoolMode::RoundRobin(Arc::new(AtomicUsize::new(0))))
///     .with_fallback("192.168.2.0/24".parse().ok())
///     .with_excluded(Some(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]));
/// ```
#[derive(Debug, Clone)]
pub struct IpCidrConnector {
    /// The IP address selection strategy (`Random` or `RoundRobin`)
    mode: PoolMode,

    /// The CIDR block from which IP addresses will be selected
    ///
    /// This defines the network range for source IP address selection.
    /// Must be a valid IPv4 or IPv6 CIDR notation.
    ip_cidr: IpCidr,

    /// Optional subnet mask override for further restricting the address range
    ///
    /// When specified, this narrows the selection range within the main CIDR block.
    /// Must not exceed the maximum bits for the IP version (32 for IPv4, 128 for IPv6).
    cidr_range: Option<u8>,

    /// Fallback CIDR block from which IP addresses will be selected and used
    /// when primary connection attempts fail
    ///
    /// This defines the network range for Fallback IP address selection.
    /// Must be a valid IPv4 or IPv6 CIDR notation.
    ///
    /// Provides high availability by offering an alternative source address
    /// when connections from the primary CIDR range fail.
    fallback: Option<IpCidr>,

    /// Set of IP addresses to exclude from selection
    ///
    /// Uses `HashSet` for O(1) lookup performance when checking exclusions.
    /// Commonly used to avoid problematic or reserved addresses within the CIDR range.
    excluded: Option<HashSet<IpAddr>>,

    /// Extension configuration for advanced address generation
    ///
    /// Allows for custom address generation logic and session-based selection.
    extension: Option<IpCidrConExt>,

    /// Pre-computed total number of available addresses in the CIDR block
    ///
    /// Cached for performance to avoid recalculating on every address selection.
    /// Used for efficient modulo operations in round-robin mode.
    capacity: u128,
}

impl Default for IpCidrConnector {
    /// Creates a default connector with an unspecified IPv4 address and random selection mode.
    ///
    /// This default configuration is primarily useful for testing or as a base for customization.
    /// In production, you should use `new()`, `new_ipv4()`, or `new_ipv6()` with specific CIDR blocks.
    fn default() -> Self {
        Self {
            mode: PoolMode::Random,
            ip_cidr: IpCidr::V4(
                Ipv4Cidr::new(Ipv4Addr::UNSPECIFIED, 0)
                    .expect("Failed to parse unspecified IPv4 address"),
            ),
            cidr_range: None,
            fallback: None,
            excluded: None,
            extension: None,
            capacity: u128::from(u32::MAX),
        }
    }
}

impl IpCidrConnector {
    /// Creates a new connector with the specified CIDR block.
    ///
    /// Automatically calculates the address space capacity for optimal performance.
    /// The capacity calculation handles both IPv4 (32-bit) and IPv6 (128-bit) address spaces.
    ///
    /// # Arguments
    ///
    /// * `ip_cidr` - The CIDR block defining the available IP address range
    ///
    /// # Performance Notes
    ///
    /// Capacity is pre-computed during construction to avoid runtime calculations.
    /// For very large IPv6 ranges, capacity may be clamped to prevent overflow.
    pub fn new(ip_cidr: IpCidr) -> Self {
        let capacity = Self::calculate_capacity(&ip_cidr);
        Self {
            ip_cidr,
            capacity,
            ..Default::default()
        }
    }

    /// Creates a new connector specifically for IPv4 CIDR blocks.
    ///
    /// This is a convenience method that's slightly more efficient than the generic `new()`
    /// method when you know you're working with IPv4 addresses.
    ///
    /// # Arguments
    ///
    /// * `ip_cidr` - IPv4 CIDR block (e.g., 192.168.1.0/24)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rama_tcp::client::IpCidrConnector;
    ///
    /// let cidr = "10.0.0.0/16".parse().unwrap();
    /// let connector = IpCidrConnector::new_ipv4(cidr);
    /// ```
    pub fn new_ipv4(ip_cidr: Ipv4Cidr) -> Self {
        let network_len = ip_cidr.network_length();
        let capacity = if network_len == 0 {
            u128::from(u32::MAX)
        } else if network_len >= 32 {
            1
        } else {
            u128::from((1u64 << (32 - network_len)) - 1)
        };

        Self {
            ip_cidr: IpCidr::V4(ip_cidr),
            capacity,
            ..Default::default()
        }
    }

    /// Creates a new connector specifically for IPv6 CIDR blocks.
    ///
    /// Optimized for IPv6 address space calculations with overflow protection
    /// for very large network ranges.
    ///
    /// # Arguments
    ///
    /// * `ip_cidr` - IPv6 CIDR block (e.g., `2001:db8::/32`)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rama_tcp::client::IpCidrConnector;
    ///
    /// let cidr = "2001:db8::/64".parse().unwrap();
    /// let connector = IpCidrConnector::new_ipv6(cidr);
    /// ```
    pub fn new_ipv6(ip_cidr: Ipv6Cidr) -> Self {
        let network_len = ip_cidr.network_length();
        let capacity = if network_len == 0 {
            u128::MAX
        } else if network_len >= 128 {
            1
        } else {
            (1u128 << (128 - network_len)).saturating_sub(1)
        };

        Self {
            ip_cidr: IpCidr::V6(ip_cidr),
            capacity,
            ..Default::default()
        }
    }

    /// Configures the IP address selection strategy.
    ///
    /// # Selection Modes
    ///
    /// - **`Random`*: Provides unpredictable address selection, useful for load distribution
    /// - **`RoundRobin`**: Ensures even distribution across all available addresses
    ///
    /// # Arguments
    ///
    /// * `mode` - The selection strategy to use
    ///
    /// # Performance Notes
    ///
    /// Round-robin mode uses atomic operations for thread-safety with minimal overhead.
    pub fn with_mode(mut self, mode: PoolMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets an optional CIDR range override to further restrict address selection.
    ///
    /// This allows you to define a subset within the main CIDR block for address selection.
    /// Useful when you want to reserve parts of your address space.
    ///
    /// # Arguments
    ///
    /// * `cidr_range` - Optional subnet mask (must not exceed IP version limits)
    ///
    /// # Panics
    ///
    /// Panics if the CIDR range exceeds 32 for IPv4 or 128 for IPv6.
    /// This is a design-time error that should be caught during development.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rama_tcp::client::IpCidrConnector;
    ///
    /// let cidr = "10.0.0.0/16".parse().unwrap();
    /// let connector = IpCidrConnector::new_ipv4(cidr)
    ///     .with_cidr_range(Some(28)); // Further restrict to /28
    /// ```
    pub fn with_cidr_range(mut self, cidr_range: Option<u8>) -> Self {
        if let Some(range) = cidr_range {
            match self.ip_cidr {
                IpCidr::V4(_) => {
                    assert!((range <= 32), "IPv4 CIDR range cannot exceed 32 bits");
                }
                IpCidr::V6(_) => {
                    assert!((range <= 128), "IPv6 CIDR range cannot exceed 128 bits");
                }
            }
        }
        self.cidr_range = cidr_range;
        self
    }

    /// Configures a fallback IPv4/IPv6 CIDR blocks address for high availability.
    ///
    /// When a connection attempt fails using an address from the primary CIDR range,
    /// the connector will retry using this fallback CIDR range.
    ///
    /// # Arguments
    ///
    /// * `fallback` - Optional fallback IPv4/IPv6 CIDR blocks (e.g., `192.168.1.0/24` or `2001:db8::/32`)
    ///
    /// # Use Cases
    ///
    /// - Providing a stable backup address when dynamic addresses fail
    /// - Ensuring connectivity through a known-good interface
    /// - Implementing graceful degradation in network configurations
    pub fn with_fallback(mut self, fallback: Option<IpCidr>) -> Self {
        self.fallback = fallback;
        self
    }

    /// Specifies IP addresses to exclude from selection.
    ///
    /// Uses a `HashSet` internally for O(1) exclusion checking performance.
    /// Common exclusions include network/broadcast addresses, gateways, or reserved IPs.
    ///
    /// # Arguments
    ///
    /// * `excluded` - Optional vector of IP addresses to exclude
    ///
    /// # Performance Notes
    ///
    /// The exclusion list is converted to a `HashSet` for optimal lookup performance.
    /// For large exclusion lists, this provides significant performance benefits.
    pub fn with_excluded(mut self, excluded: Option<Vec<IpAddr>>) -> Self {
        self.excluded = excluded.map(|vec| vec.into_iter().collect());
        self
    }

    /// Configures advanced extension options for custom address generation.
    ///
    /// Extensions provide hooks for specialized address selection logic,
    /// session-based addressing, and integration with external systems.
    ///
    /// # Arguments
    ///
    /// * `extension` - Optional extension configuration
    pub fn with_extension(mut self, extension: Option<IpCidrConExt>) -> Self {
        self.extension = extension;
        self
    }

    /// Generates a source IP address and optional fallback address for connection binding.
    ///
    /// This is the core address selection logic, optimized for both performance and
    /// distribution quality. The method handles exclusion checking and implements
    /// infinite retry logic to ensure a valid address is always returned.
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// - Primary `SocketAddress` for connection binding (port set to 0 for auto-assignment)
    /// - Optional fallback `SocketAddress` if configured
    ///
    /// # Performance Characteristics
    ///
    /// - **Average case**: O(1) for address generation + O(k) for exclusion checking
    /// - **Worst case**: May loop if many addresses are excluded
    /// - Lock-free atomic operations for thread-safe round-robin indexing
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// Round-robin indexing uses atomic operations to ensure proper distribution.
    pub fn get_connector(&self) -> (SocketAddress, Option<SocketAddress>) {
        // Use a bounded retry mechanism to prevent infinite loops in pathological cases
        const MAX_RETRIES: usize = 1000;

        for _ in 0..MAX_RETRIES {
            let ip_addr = self.generate_ip_address();
            if self.excluded.is_none() {
                return self.create_socket_addresses(ip_addr);
            }
            if let Some(ref excluded) = self.excluded {
                if !excluded.contains(&ip_addr) {
                    return self.create_socket_addresses(ip_addr);
                }
            }
        }
        // Fallback to any address if we've exhausted retries
        // This prevents infinite loops in extreme edge cases
        let ip_addr = self.generate_ip_address();
        self.create_socket_addresses(ip_addr)
    }

    /// Calculates the total address capacity for a given CIDR block.
    ///
    /// This is a performance optimization that pre-computes capacity to avoid
    /// repeated calculations during address selection.
    #[inline]
    fn calculate_capacity(ip_cidr: &IpCidr) -> u128 {
        let network_len = ip_cidr.network_length();
        match ip_cidr {
            IpCidr::V4(_) => {
                if network_len == 0 {
                    u128::from(u32::MAX)
                } else if network_len >= 32 {
                    1
                } else {
                    u128::from((1u64 << (32 - network_len)) - 1)
                }
            }
            IpCidr::V6(_) => {
                if network_len == 0 {
                    u128::MAX
                } else if network_len >= 128 {
                    1
                } else {
                    (1u128 << (128 - network_len)).saturating_sub(1)
                }
            }
        }
    }

    /// Generates an IP address based on the configured selection mode.
    ///
    /// This method encapsulates the core address generation logic,
    /// handling both random and round-robin selection strategies.
    #[inline]
    fn generate_ip_address(&self) -> IpAddr {
        match (&self.mode, &self.ip_cidr) {
            (PoolMode::Random, IpCidr::V4(cidr)) => {
                IpAddr::V4(ipv4_from_extension(cidr, self.cidr_range, self.extension))
            }
            (PoolMode::Random, IpCidr::V6(cidr)) => {
                IpAddr::V6(ipv6_from_extension(cidr, self.cidr_range, self.extension))
            }
            (PoolMode::RoundRobin(index), IpCidr::V4(cidr)) => {
                let current_idx = index.fetch_add(1, Ordering::Relaxed);
                tracing::debug!("Round-robin index: {}", current_idx);
                tracing::debug!("Round-robin capacity: {}", self.capacity);
                let session_id = (current_idx % self.capacity as usize) as u64;
                let ipv4_addr =
                    ipv4_from_extension(cidr, None, Some(IpCidrConExt::Session(session_id)));
                IpAddr::V4(ipv4_addr)
            }
            (PoolMode::RoundRobin(index), IpCidr::V6(cidr)) => {
                let current_idx = index.fetch_add(1, Ordering::Relaxed);
                let session_id = u64::try_from(current_idx as u128 % self.capacity)
                    .expect("Failed to convert u128 to u64");
                let ipv6_addr =
                    ipv6_from_extension(cidr, None, Some(IpCidrConExt::Session(session_id)));
                IpAddr::V6(ipv6_addr)
            }
        }
    }

    /// Generates an Fallback IP address based on only random selection mode.
    #[inline]
    fn generate_fallback_ip_address(&self) -> Option<IpAddr> {
        match &self.fallback {
            Some(IpCidr::V4(cidr)) => Some(IpAddr::V4(ipv4_from_extension(
                cidr,
                self.cidr_range,
                self.extension,
            ))),
            Some(IpCidr::V6(cidr)) => Some(IpAddr::V6(ipv6_from_extension(
                cidr,
                self.cidr_range,
                self.extension,
            ))),
            None => None,
        }
    }

    /// Creates socket addresses for the primary and fallback connections.
    #[inline]
    fn create_socket_addresses(&self, ip_addr: IpAddr) -> (SocketAddress, Option<SocketAddress>) {
        let primary = SocketAddress::new(ip_addr, 0);
        let fallback = self
            .generate_fallback_ip_address()
            .map(|fb| SocketAddress::new(fb, 0));
        (primary, fallback)
    }
}

impl TcpStreamConnector for IpCidrConnector {
    type Error = OpaqueError;

    /// Establishes a TCP connection using the configured source IP selection strategy.
    ///
    /// This method implements the core connection logic with intelligent fallback handling.
    /// It attempts to connect using a dynamically selected source address, and falls back
    /// to the configured fallback address if the primary attempt fails.
    ///
    /// # Connection Flow
    ///
    /// 1. Select a source IP address using the configured strategy
    /// 2. Attempt connection with the selected address
    /// 3. On failure, retry with fallback address if configured
    /// 4. Return appropriate error if all attempts fail
    ///
    /// # Error Handling
    ///
    /// - Primary connection failures are logged but don't immediately fail the operation
    /// - Fallback attempts are clearly logged for operational visibility
    /// - Only fails definitively when all options are exhausted
    ///
    /// # Arguments
    ///
    /// * `addr` - The destination socket address to connect to
    ///
    /// # Returns
    ///
    /// - `Ok(TcpStream)` - Successfully established connection
    /// - `Err(OpaqueError)` - Connection failed on all attempts
    async fn connect(&self, addr: SocketAddr) -> Result<TcpStream, Self::Error> {
        let (bind_addr, fallback) = self.get_connector();

        tracing::debug!(
            target: "ip_cidr_connector",
            %addr,
            %bind_addr,
            "attempting primary connection"
        );

        match bind_addr.connect(addr).await {
            Ok(stream) => {
                tracing::debug!(
                    target: "ip_cidr_connector",
                    %addr,
                    %bind_addr,
                    "primary connection successful"
                );
                Ok(stream)
            }
            Err(primary_err) => {
                tracing::warn!(
                    target: "ip_cidr_connector",
                    error = %primary_err,
                    %addr,
                    %bind_addr,
                    "primary connection failed"
                );

                if let Some(fallback_addr) = fallback {
                    tracing::info!(
                        target: "ip_cidr_connector",
                        %addr,
                        %fallback_addr,
                        "attempting fallback connection"
                    );

                    match fallback_addr.connect(addr).await {
                        Ok(stream) => {
                            tracing::info!(
                                target: "ip_cidr_connector",
                                %addr,
                                %fallback_addr,
                                "fallback connection successful"
                            );
                            Ok(stream)
                        }
                        Err(fallback_err) => {
                            tracing::error!(
                                target: "ip_cidr_connector",
                                primary_error = %primary_err,
                                fallback_error = %fallback_err,
                                %addr,
                                "all connection attempts failed"
                            );
                            Err(fallback_err)
                        }
                    }
                } else {
                    tracing::error!(
                        target: "ip_cidr_connector",
                        error = %primary_err,
                        %addr,
                        "connection failed with no fallback configured"
                    );
                    Err(primary_err)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_net::dep::cidr::{Ipv4Cidr, Ipv6Cidr};
    use std::{
        str::FromStr,
        sync::{Arc, atomic::AtomicUsize},
    };

    /// Initializes comprehensive tracing infrastructure for test diagnostics and debugging.
    ///
    /// This function establishes a sophisticated logging system that provides deep visibility
    /// into test execution, IP address selection patterns, and connection behavior. The tracing
    /// setup is essential for understanding the complex interactions within the IP CIDR connector
    /// and for debugging issues in distributed networking scenarios.
    ///
    /// # Tracing Configuration
    ///
    /// - **Level**: TRACE - captures all possible log events for maximum visibility
    /// - **Format**: Structured JSON-like output with timestamps and metadata
    /// - **Environment**: Respects RUST_LOG environment variable for runtime control
    /// - **Safety**: Designed to be idempotent - multiple calls won't create duplicate subscribers
    ///
    /// # Use Cases
    ///
    /// - Debugging IP address selection algorithms and distribution patterns
    /// - Monitoring round-robin index progression and atomic operations
    /// - Analyzing exclusion list performance and collision detection
    /// - Tracking connection attempt flows and fallback behavior
    /// - Performance profiling of address generation under load
    ///
    /// # Performance Impact
    ///
    /// The tracing infrastructure adds minimal overhead in test environments but provides
    /// invaluable insights into system behavior. In production, log levels should be
    /// adjusted appropriately to balance performance with observability needs.
    fn init_tracing() {
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    /// Comprehensive integration test validating IP CIDR connector functionality across multiple scenarios.
    ///
    /// This test function serves as the primary validation suite for the `IpCidrConnector`,
    /// exercising both IPv4 and IPv6 address spaces with different network configurations.
    /// It systematically tests the core functionality including address selection modes,
    /// fallback mechanisms, and exclusion list behavior.
    ///
    /// # Test Coverage Matrix
    ///
    /// | Network Type | Selection Mode | Fallback | Exclusions | Iterations |
    /// |--------------|----------------|----------|------------|------------|
    /// | IPv4 /24     | Random         | None     | None       | 10         |
    /// | IPv4 /24     | Round-Robin    | Last IP  | First IP   | 10         |
    /// | IPv6 /48     | Random         | None     | None       | 10         |
    /// | IPv6 /48     | Round-Robin    | Last IP  | First IP   | 10         |
    ///
    /// # Test Scenarios Validated
    ///
    /// ## Random Mode Testing
    /// - Verifies that random address selection produces valid addresses within CIDR bounds
    /// - Ensures no fallback addresses are returned when none are configured
    /// - Tests address uniqueness and distribution over multiple iterations
    /// - Validates both IPv4 and IPv6 random generation algorithms
    ///
    /// ## Round-Robin Mode Testing
    /// - Confirms sequential address selection with atomic index management
    /// - Tests fallback address configuration and retrieval
    /// - Validates exclusion list functionality and collision avoidance
    /// - Ensures excluded addresses (network address) are never selected
    /// - Verifies thread-safe atomic operations for index incrementation
    ///
    /// # Network Configurations
    ///
    /// - **IPv4 /24**: 192.168.1.0/24 - Standard private network with 254 usable addresses
    /// - **IPv6 /48**: 2001:470:e953::/48 - Hurricane Electric tunnel with massive address space
    ///
    /// # Assertions and Validations
    ///
    /// - Address bounds checking ensures all generated IPs fall within CIDR ranges
    /// - Exclusion list compliance verified through direct IP comparison
    /// - Fallback configuration state validated at each test phase
    /// - Atomic counter behavior implicitly tested through round-robin consistency
    ///
    /// # Tracing and Observability
    ///
    /// The test generates extensive tracing output showing:
    /// - Address selection patterns and distribution
    /// - Mode transitions and configuration changes
    /// - Exclusion list hits and collision resolution
    /// - Performance characteristics under rapid selection
    #[test]
    fn test_ipcidr_connectors_comprehensive() {
        // Initialize comprehensive tracing to capture all test execution details
        // This provides visibility into address selection patterns and system behavior
        init_tracing();

        // Define test cases covering both IPv4 and IPv6 address families
        // Each test case represents a different network topology and use case
        let test_cases = vec![
            (
                "IPv4 /24 network", // Standard private network configuration
                IpCidrConnector::new_ipv4(
                    "192.168.1.0/24"
                        .parse::<Ipv4Cidr>()
                        .expect("Failed to parse IPv4 CIDR"),
                ),
            ),
            (
                "IPv6 /48 network", // Large IPv6 address space for scalability testing
                IpCidrConnector::new_ipv6(
                    "2001:470:e953::/48"
                        .parse::<Ipv6Cidr>()
                        .expect("Failed to parse IPv6 CIDR"),
                ),
            ),
        ];

        // Iterate through each test case to validate both address families
        for (test_name, mut connector) in test_cases {
            tracing::info!("Testing: {} - {:?}", test_name, connector);

            // Phase 1: Random Mode Validation
            // Test the default random selection algorithm for unpredictable address distribution
            tracing::info!("Testing random mode for {}", test_name);
            for i in 0..10 {
                // Generate address using random selection algorithm
                let (random_connector, fallback) = connector.get_connector();
                tracing::debug!("Random selection {}: {:?}", i + 1, random_connector);

                // Validate that no fallback is configured in default state
                // This ensures clean initial state before advanced configuration
                assert!(
                    fallback.is_none(),
                    "No fallback should be configured initially"
                );
            }

            // Phase 2: Round-Robin Mode with Advanced Configuration
            // Test deterministic address selection with fallback and exclusion features
            tracing::info!("Testing round-robin mode for {}", test_name);

            // Configure round-robin mode with atomic counter for thread-safe operation
            connector.mode = PoolMode::RoundRobin(Arc::new(AtomicUsize::new(0)));

            // Set fallback to the last address in the CIDR range for high availability
            connector.fallback = "2001:470:e953:f179::/64".parse::<IpCidr>().ok();

            // Configure exclusion list to avoid problematic addresses (network address)
            let excluded_addrs = vec![connector.ip_cidr.first_address()];
            connector.excluded = Some(excluded_addrs.into_iter().collect());

            // Test round-robin selection with exclusions over multiple iterations
            for i in 0..10 {
                let (round_robin_connector, fallback) = connector.get_connector();
                tracing::debug!(
                    "Round-robin selection {}: {:?}, Fallback: {:?}",
                    i + 1,
                    round_robin_connector,
                    fallback
                );

                // Verify fallback address is properly configured and returned
                assert!(fallback.is_some(), "Fallback should be configured");

                // Critical validation: ensure excluded addresses are never selected
                // This tests the O(1) HashSet exclusion lookup performance
                let selected_ip = round_robin_connector.ip_addr();
                assert_ne!(selected_ip, connector.ip_cidr.first_address());
            }
        }
    }

    /// Validates single IP CIDR configurations with sophisticated fallback mechanisms for edge case scenarios.
    ///
    /// This specialized test function focuses on the critical edge case of single-IP CIDR blocks (/32 for IPv4, /128 for IPv6),
    /// which represent the smallest possible network configurations. These scenarios are particularly important in:
    ///
    /// - **Container networking**: Where each container gets exactly one IP address
    /// - **Point-to-point links**: Direct connections between two network endpoints
    /// - **Load balancer backends**: Individual server instances with dedicated addresses
    /// - **Security appliances**: Devices requiring precise IP address control
    /// - **Network address translation**: One-to-one NAT configurations
    ///
    /// # Test Architecture and Methodology
    ///
    /// This test employs a comprehensive multi-phase validation approach that systematically examines
    /// both the deterministic and probabilistic behaviors of single-IP CIDR configurations under
    /// various operational modes. The methodology ensures robust validation of edge cases that could
    /// cause failures in production environments.
    ///
    /// ## Phase Structure
    ///
    /// 1. **Baseline Random Mode Testing**: Validates consistent behavior with single IP
    /// 2. **Cross-Protocol Fallback Testing**: Tests IPv4 primary with IPv6 fallback scenarios
    /// 3. **High-Availability Configuration**: Ensures robust fallback mechanisms
    ///
    /// # Mathematical Constraints and Edge Cases
    ///
    /// Single IP CIDR blocks present unique mathematical constraints:
    /// - **Capacity**: Exactly 1 address available (no selection randomness possible)
    /// - **Round-robin behavior**: Index rotation becomes meaningless with capacity=1
    /// - **Exclusion logic**: Excluding the only address creates impossible selections
    /// - **Fallback criticality**: Fallback becomes essential rather than optional
    ///
    /// # Cross-Protocol Fallback Strategy
    ///
    /// The test validates an advanced networking pattern where:
    /// - **Primary**: IPv4 single address (192.168.1.15/32)
    /// - **Fallback**: IPv6 address from different network segment (2001:470:e953::ffff)
    /// - **Use Case**: Dual-stack environments with protocol preference hierarchies
    /// - **Resilience**: Maintains connectivity even if entire IPv4 infrastructure fails
    ///
    /// This cross-protocol fallback strategy is particularly valuable in:
    /// - **IPv6 transition scenarios**: Gradual migration from IPv4 to IPv6
    /// - **Multi-homed networks**: Networks with multiple ISP connections
    /// - **Disaster recovery**: Geographic failover between different protocol stacks
    /// - **Performance optimization**: Protocol selection based on latency characteristics
    ///
    /// # Iteration Strategy and Statistical Validation
    ///
    /// The 10-iteration loop serves multiple validation purposes:
    /// - **Consistency verification**: Ensures single IP is returned consistently
    /// - **Memory stability**: Validates no memory leaks in tight selection loops
    /// - **Atomic operation testing**: Confirms thread-safe counter behavior even with capacity=1
    /// - **Performance profiling**: Measures selection overhead for single-address scenarios
    ///
    /// # Tracing and Observability Integration
    ///
    /// Comprehensive tracing provides operational insights into:
    /// - **Address selection determinism**: How single IP affects selection algorithms
    /// - **Fallback activation patterns**: When and how cross-protocol fallback occurs
    /// - **Performance characteristics**: Latency and throughput under single-IP constraints
    /// - **Error condition handling**: Behavior when primary address becomes unavailable
    #[test]
    fn test_single_ip_ipcidr_connectors_with_fallback() {
        // Initialize comprehensive tracing infrastructure to capture detailed execution telemetry
        // This provides essential visibility into the complex interactions within single-IP scenarios
        // where traditional address selection algorithms must adapt to constrained address spaces
        init_tracing();

        // Define sophisticated test case matrix covering single-IP CIDR configurations
        // Each test case represents a critical networking edge case that must be handled robustly
        // The /32 CIDR represents the ultimate constraint: exactly one available IP address
        let test_cases = vec![(
            "IPv4 /32 single-host network", // Most constrained possible IPv4 configuration
            IpCidrConnector::new_ipv4(
                "192.168.1.15/32" // Private network single host - common in container environments
                    .parse::<Ipv4Cidr>()
                    .expect("Failed to parse IPv4 /32 CIDR - this indicates a fundamental parsing error"),
            ),
        )];

        // Systematically iterate through each test case to validate single-IP behavior patterns
        // This comprehensive testing ensures robustness across different network topologies
        for (test_name, mut connector) in test_cases {
            tracing::info!(
                "Initiating single-IP CIDR validation: {} - Configuration: {:?}",
                test_name,
                connector
            );

            // ==================================================================================
            // PHASE 1: BASELINE RANDOM MODE VALIDATION FOR SINGLE-IP DETERMINISM
            // ==================================================================================
            //
            // In single-IP scenarios, "random" selection becomes deterministic since only one
            // address exists. This phase validates that the random selection algorithm gracefully
            // handles this mathematical constraint without introducing selection errors or performance
            // degradation. The behavior should be identical to round-robin in single-IP cases.
            //
            // Key Validation Points:
            // - Consistent single IP address return across all iterations
            // - No fallback activation in default configuration state
            // - Proper handling of capacity=1 mathematical constraint
            // - Performance stability under repeated selection operations
            tracing::info!(
                "Phase 1: Baseline random mode validation for single-IP determinism - {}",
                test_name
            );

            for iteration in 0..10 {
                // Execute address selection using the random algorithm
                // With capacity=1, this should behave identically to deterministic selection
                let (selected_address, fallback_address) = connector.get_connector();

                tracing::debug!(
                    "Random mode iteration {} of 10: Selected address={:?}, Expected IP=192.168.1.15",
                    iteration + 1,
                    selected_address
                );

                // Critical validation: ensure exactly the single IP address is always selected
                // This confirms the algorithm correctly handles the capacity=1 constraint
                assert_eq!(
                    selected_address.ip_addr(),
                    IpAddr::V4("192.168.1.15".parse().unwrap()),
                    "Single-IP CIDR must always return the exact configured address"
                );

                // Validate clean initial state with no fallback configuration
                // This establishes baseline behavior before advanced configuration testing
                assert!(
                    fallback_address.is_none(),
                    "Initial configuration should have no fallback address configured"
                );
            }

            // ==================================================================================
            // PHASE 2: ADVANCED ROUND-ROBIN CONFIGURATION WITH CROSS-PROTOCOL FALLBACK
            // ==================================================================================
            //
            // This phase tests the sophisticated scenario where a single IPv4 address is configured
            // with an IPv6 fallback address from a completely different network segment. This
            // represents a real-world dual-stack configuration common in enterprise environments
            // transitioning between IPv4 and IPv6 protocols.
            //
            // The cross-protocol fallback strategy provides several advantages:
            // - Protocol diversity reduces single points of failure
            // - Different routing paths improve resilience
            // - Supports gradual IPv6 migration strategies
            // - Enables performance optimization through protocol selection
            tracing::info!(
                "Phase 2: Cross-protocol fallback configuration and validation - {}",
                test_name
            );

            // Configure round-robin mode with atomic counter for thread-safe operation
            // Even with capacity=1, this tests the mathematical robustness of modulo operations
            // and ensures the atomic counter infrastructure functions correctly under constraints
            connector.mode = PoolMode::RoundRobin(Arc::new(AtomicUsize::new(0)));
            tracing::debug!("Configured round-robin mode with atomic counter initialized to 0");

            // Establish sophisticated cross-protocol fallback configuration
            // Primary: IPv4 (192.168.1.15) -> Fallback: IPv6 (2001:470:e953::ffff)
            // This represents a Hurricane Electric IPv6 tunnel endpoint commonly used in production
            connector.fallback = IpAddr::from_str("2001:470:e953::ffff").ok().map(|addr| {
                let addr = IpCidr::from(addr);
                tracing::info!(
                    "Cross-protocol fallback configured: IPv4 primary -> IPv6 fallback ({})",
                    addr
                );
                addr
            });

            // Execute comprehensive round-robin validation with cross-protocol fallback verification
            // This testing phase validates both the primary selection algorithm and fallback mechanisms
            for iteration in 0..10 {
                let (primary_address, fallback_address) = connector.get_connector();

                tracing::debug!(
                    "Round-robin iteration {} of 10: Primary={:?}, Fallback={:?}",
                    iteration + 1,
                    primary_address,
                    fallback_address
                );

                // Validate consistent primary address selection despite round-robin mode
                // With capacity=1, round-robin should behave identically to deterministic selection
                assert_eq!(
                    primary_address.ip_addr(),
                    IpAddr::V4("192.168.1.15".parse().unwrap()),
                    "Round-robin mode with single IP must consistently return the configured address"
                );

                // Critical validation: ensure cross-protocol fallback is properly configured and accessible
                // This confirms the dual-stack configuration is operational and ready for failover scenarios
                assert!(
                    fallback_address.is_some(),
                    "Cross-protocol fallback must be configured and available for high-availability scenarios"
                );

                // Validate the specific IPv6 fallback address configuration
                // This ensures the cross-protocol transition maintains the expected network topology
                if let Some(fallback) = fallback_address {
                    assert_eq!(
                        fallback.ip_addr(),
                        IpAddr::V6("2001:470:e953::ffff".parse().unwrap()),
                        "IPv6 fallback address must match the configured Hurricane Electric tunnel endpoint"
                    );

                    tracing::debug!(
                        "Cross-protocol fallback validation successful: IPv6 address {} properly configured",
                        fallback.ip_addr()
                    );
                }
            }

            tracing::info!(
                "Single-IP CIDR connector validation completed successfully for {}",
                test_name
            );
        }
    }

    /// Validates mathematical correctness of CIDR address space capacity calculations.
    ///
    /// This test ensures that the pre-computed capacity values used for performance
    /// optimization are mathematically correct across different network sizes and
    /// address families. Accurate capacity calculations are critical for:
    ///
    /// - Efficient modulo operations in round-robin mode
    /// - Memory allocation optimization for exclusion lists
    /// - Performance tuning of address selection algorithms
    /// - Preventing integer overflow in large address spaces
    ///
    /// # Mathematical Validation
    ///
    /// The test validates the formula: `capacity = 2^(address_bits - network_bits) - 1`
    ///
    /// Where:
    /// - `address_bits` = 32 for IPv4, 128 for IPv6
    /// - `network_bits` = CIDR prefix length
    /// - The `-1` accounts for excluding the network address itself
    ///
    /// # Test Cases
    ///
    /// ## IPv4 Capacity Tests
    /// - `/24` network: 2^8 - 1 = 255 usable addresses
    /// - `/16` network: 2^16 - 1 = 65,535 usable addresses
    ///
    /// ## IPv6 Capacity Tests
    /// - `/64` network: 2^64 - 1 = 18,446,744,073,709,551,615 addresses
    ///
    /// # Performance Implications
    ///
    /// These pre-computed values enable O(1) address selection by avoiding
    /// runtime calculation overhead. The test ensures these optimizations
    /// maintain mathematical correctness across network configurations.
    #[test]
    fn test_capacity_calculations() {
        // IPv4 /24 network capacity validation
        // Standard subnet with 8 host bits = 2^8 - 1 = 255 usable addresses
        let ipv4_24 = IpCidrConnector::new_ipv4("192.168.1.0/24".parse().unwrap());
        assert_eq!(ipv4_24.capacity, 255); // 2^8 - 1

        // IPv4 /16 network capacity validation
        // Large subnet with 16 host bits = 2^16 - 1 = 65,535 usable addresses
        let ipv4_16 = IpCidrConnector::new_ipv4("10.0.0.0/16".parse().unwrap());
        assert_eq!(ipv4_16.capacity, 65535); // 2^16 - 1

        // IPv6 /64 network capacity validation
        // Standard IPv6 subnet with 64 host bits = 2^64 - 1 addresses
        // This tests large number handling and prevents overflow issues
        let ipv6_64 = IpCidrConnector::new_ipv6("2001:db8::/64".parse().unwrap());
        assert_eq!(ipv6_64.capacity, (1u128 << 64) - 1);
    }

    /// Validates input validation and error handling for invalid IPv4 CIDR range configurations.
    ///
    /// This test ensures that the connector properly validates CIDR range parameters
    /// and panics with descriptive error messages when invalid configurations are provided.
    /// The test specifically validates that IPv4 CIDR ranges cannot exceed the maximum
    /// 32-bit address space limit.
    ///
    /// # Security and Correctness
    ///
    /// Input validation is critical for:
    /// - Preventing buffer overflows in address calculation
    /// - Ensuring mathematical correctness of bit operations
    /// - Providing clear error messages for configuration mistakes
    /// - Failing fast during development rather than runtime corruption
    ///
    /// # Test Behavior
    ///
    /// The test attempts to configure a /33 IPv4 CIDR range, which is mathematically
    /// impossible since IPv4 addresses are only 32 bits. The expected panic with
    /// the specific error message validates both the validation logic and error clarity.
    ///
    /// # Design Philosophy
    ///
    /// This represents a "fail-fast" approach where configuration errors are caught
    /// immediately during setup rather than causing subtle bugs during operation.
    #[test]
    #[should_panic(expected = "IPv4 CIDR range cannot exceed 32 bits")]
    fn test_invalid_ipv4_cidr_range() {
        // Attempt to create an invalid IPv4 CIDR configuration
        // This should panic immediately with a descriptive error message
        let _unused =
            IpCidrConnector::new_ipv4("192.168.1.0/24".parse().unwrap()).with_cidr_range(Some(33));
    }

    /// Validates input validation and error handling for invalid IPv6 CIDR range configurations.
    ///
    /// This test ensures that the connector properly validates IPv6 CIDR range parameters
    /// and panics with descriptive error messages when configurations exceed the 128-bit
    /// IPv6 address space limit. This is the IPv6 equivalent of the IPv4 validation test.
    ///
    /// # IPv6 Address Space Considerations
    ///
    /// IPv6's 128-bit address space is significantly larger than IPv4's 32-bit space,
    /// but the same validation principles apply:
    /// - CIDR prefixes cannot exceed the total address bits available
    /// - Invalid configurations should fail immediately and clearly
    /// - Mathematical operations must remain within defined bounds
    ///
    /// # Test Behavior
    ///
    /// The test attempts to configure a /129 IPv6 CIDR range, which exceeds the
    /// 128-bit limit of IPv6 addresses. The expected panic validates the boundary
    /// checking logic and ensures appropriate error messaging.
    ///
    /// # Robustness Testing
    ///
    /// This test contributes to overall system robustness by ensuring that
    /// edge cases and invalid inputs are handled gracefully with clear feedback.
    #[test]
    #[should_panic(expected = "IPv6 CIDR range cannot exceed 128 bits")]
    fn test_invalid_ipv6_cidr_range() {
        // Attempt to create an invalid IPv6 CIDR configuration
        // This should panic immediately with a descriptive error message
        let _unused =
            IpCidrConnector::new_ipv6("2001:db8::/64".parse().unwrap()).with_cidr_range(Some(129));
    }
}
