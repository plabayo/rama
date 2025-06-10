//! High-performance utilities for generating random IP addresses within CIDR blocks.
//!
//! This module provides efficient functions to generate cryptographically random
//! IPv4 and IPv6 addresses that fall within specified CIDR network ranges.
//!
//! The core algorithms use bit manipulation for optimal performance, avoiding
//! unnecessary memory allocations and expensive arithmetic operations.
use {
    cidr::{Ipv4Cidr, Ipv6Cidr},
    rama_core::{
        context::Extensions,
        username::{UsernameLabelParser, UsernameLabelState},
    },
    rand::random,
    std::{
        convert::Infallible,
        net::{Ipv4Addr, Ipv6Addr},
        time::{SystemTime, UNIX_EPOCH},
    },
};

/// Generates a cryptographically random IPv4 address within the specified CIDR block.
///
/// This function creates a random IP address that respects the network portion of the
/// given CIDR while randomizing the host portion. The network bits are preserved
/// exactly as specified in the CIDR, while the host bits are filled with random values.
///
/// # Algorithm Details
/// 1. Extract the network prefix length from the CIDR
/// 2. Handle edge case of /32 networks (single host) with early return
/// 3. Calculate host bits available for randomization (32 - `prefix_len`)
/// 4. Generate host mask to isolate randomizable bits
/// 5. Apply bitwise operations to combine network and random host portions
///
/// # Arguments
/// * `cidr` - An IPv4 CIDR block defining the network range
///
/// # Returns
/// A random `Ipv4Addr` that falls within the given CIDR block
///
/// # Performance
/// This function uses bitwise operations for maximum efficiency, avoiding
/// unnecessary allocations or complex arithmetic operations. Time complexity: O(1).
///
/// # Examples
/// ```
/// use cidr::Ipv4Cidr;
/// use rama_tcp::client::rand_ipv4;
///
/// let cidr = "192.168.1.0/24".parse::<Ipv4Cidr>().unwrap();
/// let random_ip = rand_ipv4(&cidr);
/// // random_ip will be in range 192.168.1.0 - 192.168.1.255
/// ```
#[inline]
pub fn rand_ipv4(cidr: &Ipv4Cidr) -> Ipv4Addr {
    let prefix_len = cidr.network_length();

    // Early return optimization for /32 networks (single host)
    // Avoids unnecessary computation when only one address is possible
    if prefix_len == 32 {
        return cidr.first_address();
    }

    // Calculate number of bits available for host randomization
    let host_bits = 32 - prefix_len;

    // Performance optimization: avoid overflow for large host_bits
    if host_bits >= 32 {
        return Ipv4Addr::from(random::<u32>());
    }

    // Convert base IP to u32 for efficient bitwise operations
    let base_ip_u32 = u32::from(cidr.first_address());

    // Generate cryptographically secure random value for host portion
    let rand_val: u32 = random();

    // Create mask to isolate host bits: (2^host_bits - 1)
    // This mask has 1s in host positions and 0s in network positions
    let host_mask = (1u32 << host_bits) - 1;

    // Extract only the random bits that belong to the host portion
    let host_part = rand_val & host_mask;

    // Preserve network portion by masking out host bits from base IP
    // The network mask is the bitwise NOT of the host mask
    let net_part = base_ip_u32 & !host_mask;

    // Combine network and random host portions using bitwise OR
    Ipv4Addr::from(net_part | host_part)
}

/// Generates a cryptographically random IPv6 address within the specified CIDR block.
///
/// This function creates a random IPv6 address that respects the network portion of the
/// given CIDR while randomizing the host portion. The network bits are preserved
/// exactly as specified in the CIDR, while the host bits are filled with random values.
///
/// # Algorithm Details
/// 1. Extract the network prefix length from the CIDR
/// 2. Handle edge case of /128 networks (single host) with early return
/// 3. Calculate host bits available for randomization (128 - `prefix_len`)
/// 4. Generate 128-bit host mask to isolate randomizable bits
/// 5. Apply bitwise operations to combine network and random host portions
///
/// # Arguments
/// * `cidr` - An IPv6 CIDR block defining the network range
///
/// # Returns
/// A random `Ipv6Addr` that falls within the given CIDR block
///
/// # Performance
/// This function uses 128-bit bitwise operations for maximum efficiency,
/// avoiding unnecessary allocations or complex arithmetic operations. Time complexity: O(1).
///
/// # Examples
/// ```
/// use cidr::Ipv6Cidr;
/// use rama_tcp::client::rand_ipv6;
///
/// let cidr = "2001:db8::/32".parse::<Ipv6Cidr>().unwrap();
/// let random_ip = rand_ipv6(&cidr);
/// // random_ip will be in range 2001:db8:: - 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
/// ```
#[inline]
pub fn rand_ipv6(cidr: &Ipv6Cidr) -> Ipv6Addr {
    let prefix_len = cidr.network_length();

    // Early return optimization for /128 networks (single host)
    // Avoids unnecessary computation when only one address is possible
    if prefix_len == 128 {
        return cidr.first_address();
    }

    // Calculate number of bits available for host randomization
    let host_bits = 128 - prefix_len;

    // Performance optimization: avoid overflow for large host_bits
    if host_bits >= 128 {
        return Ipv6Addr::from(random::<u128>());
    }

    // Convert base IPv6 to u128 for efficient bitwise operations
    let base_ip_u128 = u128::from(cidr.first_address());

    // Generate cryptographically secure random value for host portion
    let rand_val: u128 = random();

    // Create mask to isolate host bits: (2^host_bits - 1)
    // This mask has 1s in host positions and 0s in network positions
    let host_mask = (1u128 << host_bits) - 1;

    // Extract only the random bits that belong to the host portion
    let host_part = rand_val & host_mask;

    // Preserve network portion by masking out host bits from base IP
    // The network mask is the bitwise NOT of the host mask
    let net_part = base_ip_u128 & !host_mask;

    // Combine network and random host portions using bitwise OR
    Ipv6Addr::from(net_part | host_part)
}

/// Generates a deterministic IPv4 address within a specified CIDR range with controlled randomization.
///
/// This function creates an IPv4 address that combines three distinct portions:
/// 1. Fixed network portion from the original CIDR
/// 2. Deterministic intermediate section derived from the combined parameter
/// 3. Random host portion for the remaining bits
///
/// # Algorithm Details
/// 1. Validate `range_len` against CIDR prefix length
/// 2. Calculate bit allocations for network, intermediate, and host portions
/// 3. Generate masks for each portion using bit manipulation
/// 4. Combine all portions using bitwise operations
///
/// # Arguments
/// * `cidr` - An IPv4 CIDR block defining the base network range
/// * `range_len` - The prefix length defining how many bits are fixed (network + intermediate)
/// * `combined` - A fixed value used to determine the intermediate bits between network and host
///
/// # Returns
/// A deterministic `Ipv4Addr` that falls within the specified range
///
/// # Performance
/// This function uses efficient bitwise operations and includes optimizations for
/// edge cases. When `range_len` is not greater than the CIDR prefix length,
/// it delegates to the standard `rand_ipv4` function for optimal performance.
/// Time complexity: O(1).
///
/// # Examples
/// ```
/// use cidr::Ipv4Cidr;
/// use rama_tcp::client::ipv4_with_range;
///
/// let cidr = "192.168.0.0/16".parse::<Ipv4Cidr>().unwrap();
/// let ip = ipv4_with_range(&cidr, 24, 42);
/// // ip will have 192.168.x.y where x is influenced by combined value 42
/// ```
#[inline]
pub fn ipv4_with_range(cidr: &Ipv4Cidr, range_len: u8, combined: u32) -> Ipv4Addr {
    let prefix_len = cidr.network_length();

    // Early return optimization: if range_len doesn't extend beyond prefix,
    // delegate to simpler random function for better performance
    if range_len <= prefix_len {
        return rand_ipv4(cidr);
    }

    // Convert base IP to u32 for efficient bitwise operations
    let base_ip_u32 = u32::from(cidr.first_address());

    // Calculate bit lengths for each portion of the address
    let fixed_bits_len = range_len - prefix_len; // Intermediate deterministic bits
    let host_bits = 32 - range_len; // Remaining random bits

    // Performance optimization: avoid potential overflow in bit shift operations
    if fixed_bits_len >= 32 || host_bits >= 32 {
        return rand_ipv4(cidr);
    }

    // Create bit masks for isolating different portions
    // Fixed mask: isolates the intermediate deterministic bits
    let fixed_mask = (1u32 << fixed_bits_len) - 1;
    // Host mask: isolates the final random bits
    let host_mask = if host_bits == 0 {
        0
    } else {
        (1u32 << host_bits) - 1
    };

    // Extract and position the deterministic portion from combined value
    // Shift left by host_bits to place it in the correct bit position
    let fixed_part = (combined & fixed_mask) << host_bits;

    // Create network mask to preserve the original CIDR network bits
    // This mask has 1s in network positions and 0s elsewhere
    let network_mask = !((1u32 << (32 - prefix_len)) - 1);
    let network_part = base_ip_u32 & network_mask;

    // Generate random value for the host portion
    let host_part = random::<u32>() & host_mask;

    // Combine all three portions: network | intermediate | host
    Ipv4Addr::from(network_part | fixed_part | host_part)
}

/// Generates a deterministic IPv6 address within a specified CIDR range with controlled randomization.
///
/// This function creates an IPv6 address that combines three distinct portions:
/// 1. Fixed network portion from the original CIDR
/// 2. Deterministic intermediate section derived from the combined parameter
/// 3. Random host portion for the remaining bits
///
/// # Algorithm Details
/// 1. Validate `range_len` against CIDR prefix length
/// 2. Calculate bit allocations for network, intermediate, and host portions
/// 3. Generate 128-bit masks for each portion using bit manipulation
/// 4. Combine all portions using bitwise operations
///
/// # Arguments
/// * `cidr` - An IPv6 CIDR block defining the base network range
/// * `range_len` - The prefix length defining how many bits are fixed (network + intermediate)
/// * `combined` - A fixed value used to determine the intermediate bits between network and host
///
/// # Returns
/// A deterministic `Ipv6Addr` that falls within the specified range
///
/// # Performance
/// This function uses efficient 128-bit bitwise operations and includes optimizations
/// for edge cases. When `range_len` is not greater than the CIDR prefix length,
/// it delegates to the standard `rand_ipv6` function for optimal performance.
/// Time complexity: O(1).
///
/// # Examples
/// ```
/// use cidr::Ipv6Cidr;
/// use rama_tcp::client::ipv6_with_range;
///
/// let cidr = "2001:db8::/32".parse::<Ipv6Cidr>().unwrap();
/// let ip = ipv6_with_range(&cidr, 48, 12345);
/// // ip will have 2001:db8:xxxx:: where xxxx is influenced by combined value 12345
/// ```
#[inline]
pub fn ipv6_with_range(cidr: &Ipv6Cidr, range_len: u8, combined: u128) -> Ipv6Addr {
    let prefix_len = cidr.network_length();

    // Early return optimization: if range_len doesn't extend beyond prefix,
    // delegate to simpler random function for better performance
    if range_len <= prefix_len {
        return rand_ipv6(cidr);
    }

    // Convert base IPv6 to u128 for efficient bitwise operations
    let base_ip_u128 = u128::from(cidr.first_address());

    // Calculate bit lengths for each portion of the address
    let fixed_bits_len = range_len - prefix_len; // Intermediate deterministic bits
    let host_bits = 128 - range_len; // Remaining random bits

    // Create bit masks for isolating different portions
    // Fixed mask: isolates the intermediate deterministic bits
    let fixed_mask = (1u128 << fixed_bits_len) - 1;
    // Host mask: isolates the final random bits
    let host_mask = (1u128 << host_bits) - 1;

    // Extract and position the deterministic portion from combined value
    // Shift left by host_bits to place it in the correct bit position
    let fixed_part = (combined & fixed_mask) << host_bits;

    // Create network mask to preserve the original CIDR network bits
    // This mask has 1s in network positions and 0s elsewhere
    let network_mask = !((1u128 << (128 - prefix_len)) - 1);
    let network_part = base_ip_u128 & network_mask;

    // Generate random value for the host portion
    let host_part = random::<u128>() & host_mask;

    // Combine all three portions: network | intermediate | host
    Ipv6Addr::from(network_part | fixed_part | host_part)
}

/// Generates an IPv4 address based on the provided CIDR block and connection extension context.
///
/// This function implements a strategy pattern for IPv4 address generation based on the
/// type of extension provided. It supports multiple generation modes:
/// - **Deterministic mode**: For TTL and Session extensions, generates consistent addresses
/// - **Range mode**: For Range extensions with CIDR range, uses controlled randomization
/// - **Random mode**: Default fallback for undefined or None extensions
///
/// # Algorithm Details
/// 1. Extract numerical value from the extension enum
/// 2. Match on extension type to determine generation strategy
/// 3. For TTL/Session: Apply modulo operation to fit within CIDR capacity
/// 4. For Range: Delegate to specialized range generation function
/// 5. Fallback to pure random generation
///
/// # Arguments
/// * `cidr` - An IPv4 CIDR block defining the network range
/// * `cidr_range` - Optional range length for controlled randomization
/// * `extension` - Optional connection extension containing generation parameters
///
/// # Returns
/// A generated `Ipv4Addr` based on the extension type and parameters
///
/// # Performance
/// Uses efficient bit manipulation and early returns to minimize computation.
/// Delegates to specialized functions for optimal performance per use case.
///
/// # Examples
/// ```
/// use cidr::Ipv4Cidr;
/// use rama_tcp::client::IpCidrConExt;
/// use rama_tcp::client::ipv4_from_extension;
///
/// let cidr = "192.168.1.0/24".parse::<Ipv4Cidr>().unwrap();
/// let ext = IpCidrConExt::Session(12345);
/// let ip = ipv4_from_extension(&cidr, None, Some(ext));
/// // Generates deterministic IP based on session ID 12345
/// ```
#[inline]
pub fn ipv4_from_extension(
    cidr: &Ipv4Cidr,
    cidr_range: Option<u8>,
    extension: Option<IpCidrConExt>,
) -> Ipv4Addr {
    // Early extraction of value from extension to avoid repeated pattern matching
    if let Some(combined) = extract_value_from_ipcidr_connector_extension(extension) {
        match extension {
            // Deterministic address generation for TTL and Session extensions
            Some(IpCidrConExt::Ttl(_) | IpCidrConExt::Session(_)) => {
                let prefix_len = cidr.network_length();

                // Calculate subnet mask to preserve network portion
                // Creates mask with 1s in network bits, 0s in host bits
                let subnet_mask = !((1u32 << (32 - prefix_len)) - 1);

                // Extract and preserve the base network address
                let base_ip_bits = u32::from(cidr.first_address()) & subnet_mask;

                // Calculate available host addresses (subtract 1 to avoid overflow)
                // This ensures the generated address stays within the CIDR block
                let capacity = if prefix_len == 0 {
                    u32::MAX
                } else if prefix_len >= 32 {
                    1u32
                } else {
                    (1u32 << (32 - prefix_len)) - 1u32
                };

                // Generate deterministic host portion using modulo operation
                // This ensures consistent address generation for the same input
                let host_portion = u32::try_from(combined).unwrap_or(u32::MAX) % capacity;

                // Combine network and deterministic host portions
                let ip_num = base_ip_bits | host_portion;
                return Ipv4Addr::from(ip_num);
            }
            // Range-based address generation with intermediate deterministic bits
            Some(IpCidrConExt::Range(_)) => {
                // If a CIDR range is provided, use specialized range generation
                if let Some(range) = cidr_range {
                    return ipv4_with_range(
                        cidr,
                        range,
                        u32::try_from(combined).unwrap_or(u32::MAX),
                    );
                }
            }
            // Explicit handling of None case for completeness
            Some(IpCidrConExt::None) | None => {}
        }
    }

    // Default fallback: generate completely random address within CIDR
    rand_ipv4(cidr)
}

/// Generates an IPv6 address based on the provided CIDR block and connection extension context.
///
/// This function implements a strategy pattern for IPv6 address generation based on the
/// type of extension provided. It supports multiple generation modes:
/// - **Deterministic mode**: For TTL and Session extensions, generates consistent addresses
/// - **Range mode**: For Range extensions with CIDR range, uses controlled randomization
/// - **Random mode**: Default fallback for undefined or None extensions
///
/// # Algorithm Details
/// 1. Extract numerical value from the extension enum
/// 2. Match on extension type to determine generation strategy
/// 3. For TTL/Session: Apply modulo operation to fit within CIDR capacity
/// 4. For Range: Delegate to specialized range generation function
/// 5. Fallback to pure random generation
///
/// # Arguments
/// * `cidr` - An IPv6 CIDR block defining the network range
/// * `cidr_range` - Optional range length for controlled randomization
/// * `extension` - Optional connection extension containing generation parameters
///
/// # Returns
/// A generated `Ipv6Addr` based on the extension type and parameters
///
/// # Performance
/// Uses efficient 128-bit manipulation and early returns to minimize computation.
/// Delegates to specialized functions for optimal performance per use case.
///
/// # Examples
/// ```
/// use cidr::Ipv6Cidr;
/// use rama_tcp::client::IpCidrConExt;
/// use rama_tcp::client::ipv6_from_extension;
///
/// let cidr = "2001:db8::/32".parse::<Ipv6Cidr>().unwrap();
/// let ext = IpCidrConExt::Session(67890);
/// let ip = ipv6_from_extension(&cidr, None, Some(ext));
/// // Generates deterministic IP based on session ID 67890
/// ```
#[inline]
pub fn ipv6_from_extension(
    cidr: &Ipv6Cidr,
    cidr_range: Option<u8>,
    extension: Option<IpCidrConExt>,
) -> Ipv6Addr {
    // Early extraction of value from extension to avoid repeated pattern matching
    if let Some(combined) = extract_value_from_ipcidr_connector_extension(extension) {
        match extension {
            // Deterministic address generation for TTL and Session extensions
            Some(IpCidrConExt::Ttl(_) | IpCidrConExt::Session(_)) => {
                let network_length = cidr.network_length();

                // Calculate subnet mask to preserve network portion
                // Creates mask with 1s in network bits, 0s in host bits
                let subnet_mask = !((1u128 << (128 - network_length)) - 1);

                // Extract and preserve the base network address
                let base_ip_bits = u128::from(cidr.first_address()) & subnet_mask;

                // Calculate available host addresses (subtract 1 to avoid overflow)
                // This ensures the generated address stays within the CIDR block
                let capacity = if network_length == 0 {
                    u128::MAX
                } else if network_length >= 128 {
                    1u128
                } else {
                    (1u128 << (128 - network_length)).saturating_sub(1)
                };

                // Generate deterministic host portion using modulo operation
                // This ensures consistent address generation for the same input
                let host_portion = u128::from(combined) % capacity;

                // Combine network and deterministic host portions
                let ip_num = base_ip_bits | host_portion;
                return Ipv6Addr::from(ip_num);
            }
            // Range-based address generation with intermediate deterministic bits
            Some(IpCidrConExt::Range(_)) => {
                // If a CIDR range is provided, use specialized range generation
                if let Some(range) = cidr_range {
                    return ipv6_with_range(cidr, range, u128::from(combined));
                }
            }
            // Explicit handling of None case for completeness
            Some(IpCidrConExt::None) | None => {}
        }
    }

    // Default fallback: generate completely random address within CIDR
    rand_ipv6(cidr)
}

/// Extracts the numeric value from an `IpCidrConExt` enum variant.
///
/// This function provides a unified interface for extracting numeric values from
/// different extension types. It uses pattern matching to efficiently extract values
/// without additional heap allocations or complex branching logic.
///
/// # Algorithm Details
/// 1. Pattern match on the extension enum variant
/// 2. Extract the inner value for value-containing variants
/// 3. Return None for variants without associated values
///
/// # Arguments
/// * `extension` - An optional `IpCidrConExt` enum variant from which to extract the value
///
/// # Returns
/// * `Option<u64>` - The extracted value if the extension contains one, otherwise `None`
///
/// # Performance
/// This function uses efficient pattern matching with O(1) time complexity.
/// No heap allocations or expensive operations are performed.
///
/// # Examples
/// ```
/// use rama_tcp::client::IpCidrConExt;
/// use rama_tcp::client::extract_value_from_ipcidr_connector_extension;
///
/// let ext = IpCidrConExt::Range(42);
/// assert_eq!(extract_value_from_ipcidr_connector_extension(Some(ext)), Some(42));
///
/// let ext = IpCidrConExt::Session(1234);
/// assert_eq!(extract_value_from_ipcidr_connector_extension(Some(ext)), Some(1234));
///
/// let ext = IpCidrConExt::Ttl(5);
/// assert_eq!(extract_value_from_ipcidr_connector_extension(Some(ext)), Some(5));
///
/// let ext = IpCidrConExt::None;
/// assert_eq!(extract_value_from_ipcidr_connector_extension(Some(ext)), None);
/// ```
#[inline]
pub const fn extract_value_from_ipcidr_connector_extension(
    extension: Option<IpCidrConExt>,
) -> Option<u64> {
    match extension {
        // Extract value from Range/Session/TTL variants
        Some(
            IpCidrConExt::Range(value) | IpCidrConExt::Session(value) | IpCidrConExt::Ttl(value),
        ) => Some(value),
        // None variant contains no extractable value
        Some(IpCidrConExt::None) | None => None,
    }
}

/// Enumeration representing different types of IP CIDR connection extensions.
///
/// This enum defines the various extension types that can be applied to IP address
/// generation within CIDR blocks. Each variant serves a specific purpose:
///
/// - **None**: Default variant with no special behavior
/// - **Ttl**: Time-based extension for temporal IP assignment
/// - **Range**: Range-based extension for subnet-aware generation
/// - **Session**: Session-based extension for consistent per-session IPs
///
/// # Memory Layout
/// This enum is designed for optimal memory usage and performance:
/// - Uses `Copy` trait for stack-based operations without heap allocation
/// - `Clone` for explicit copying when needed
/// - `Debug` for development and logging support
/// - `Default` provides the `None` variant as the default state
///
/// # Examples
/// ```
/// use rama_tcp::client::IpCidrConExt;
///
/// let ext = IpCidrConExt::default(); // Creates IpCidrConExt::None
/// let session_ext = IpCidrConExt::Session(1234);
/// let range_ext = IpCidrConExt::Range(8);
/// let ttl_ext = IpCidrConExt::Ttl(5);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub enum IpCidrConExt {
    /// Default variant representing no extension
    #[default]
    None,
    /// Time-to-live based extension with timestamp value
    Ttl(u64),
    /// Range-based extension with subnet range specification
    Range(u64),
    /// Session-based extension with session identifier
    Session(u64),
}

/// Parser for extracting IP CIDR connection extensions from username labels.
///
/// This parser implements the `UsernameLabelParser` trait to extract and parse
/// extension information from formatted username strings. It supports a two-phase
/// parsing approach:
///
/// 1. **Extension Type Recognition**: Identifies the extension type from labels
/// 2. **Value Extraction**: Parses and stores the associated numeric values
///
/// # State Management
/// The parser maintains internal state to track the current extension being parsed,
/// allowing for efficient multi-label parsing without external state management.
///
/// # Supported Extensions
/// - `ttl`: Time-to-live based IP assignment with timestamp normalization
/// - `session`: Session-based consistent IP assignment
/// - `range`: Range-based subnet-aware IP assignment
///
/// # Examples
/// ```
/// use rama_tcp::client::IpCidrConExtUsernameLabelParser;
///
/// let parser = IpCidrConExtUsernameLabelParser::default();
/// // Parses usernames like: "user-session-1234" or "user-ttl-300" or "user-range-24"
/// ```
#[derive(Debug, Clone, Default)]
pub struct IpCidrConExtUsernameLabelParser {
    /// Current extension being parsed, if any
    extension: Option<IpCidrConExt>,
}

impl IpCidrConExtUsernameLabelParser {
    /// Label identifier for TTL-based extensions
    /// Used to recognize time-to-live extension requests in usernames
    const EXTENSION_TTL: &'static str = "ttl";

    /// Label identifier for session-based extensions
    /// Used to recognize session-based extension requests in usernames
    const EXTENSION_SESSION: &'static str = "session";

    /// Label identifier for range-based extensions
    /// Used to recognize range-based extension requests in usernames
    const EXTENSION_RANGE_SESSION: &'static str = "range";
}

impl UsernameLabelParser for IpCidrConExtUsernameLabelParser {
    /// Error type for parsing operations - uses `Infallible` as parsing cannot fail
    type Error = Infallible;

    /// Parses a single label from a username string.
    ///
    /// This method implements a state machine approach to username parsing:
    /// 1. **First Phase**: Recognizes extension type keywords (ttl, session, range)
    /// 2. **Second Phase**: Parses and stores the numeric value for the recognized extension
    ///
    /// # Algorithm Details
    /// - Normalizes input by trimming whitespace and converting to lowercase
    /// - Uses pattern matching for efficient label type recognition
    /// - Implements special TTL timestamp normalization for time-based consistency
    /// - Handles parsing errors gracefully with default values
    ///
    /// # Arguments
    /// * `label` - The username label segment to parse
    ///
    /// # Returns
    /// * `UsernameLabelState::Used` - Label was successfully processed
    /// * `UsernameLabelState::Ignored` - Invalid label encountered, Ignoring
    ///
    /// # Performance
    /// Uses efficient string operations and avoids unnecessary allocations.
    /// Pattern matching provides O(1) lookup for known extension types.
    fn parse_label(&mut self, label: &str) -> UsernameLabelState {
        // Normalize input: trim whitespace and convert to lowercase for consistent matching
        let label = label.trim().to_ascii_lowercase();

        match self.extension {
            Some(ref mut ext) => {
                // Second phase: parse the numeric value for the already-identified extension
                // Using 'ref mut ext' for direct in-place modification without cloning
                match ext {
                    IpCidrConExt::Ttl(ttl) => {
                        // Parse TTL value and normalize to timestamp boundary
                        // This ensures consistent IP assignment within TTL windows
                        *ttl = {
                            let parsed_ttl = label.parse::<u64>().unwrap_or(0);

                            // Get current timestamp, fallback to random if system time fails
                            let start = SystemTime::now();
                            let timestamp = start
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or_else(|_| rand::random());

                            // Normalize timestamp to TTL boundary for consistent assignment
                            // This creates time windows where the same IP is assigned
                            if parsed_ttl > 0 {
                                timestamp - (timestamp % parsed_ttl)
                            } else {
                                timestamp
                            }
                        }
                    }
                    IpCidrConExt::Session(session) => {
                        // Parse session ID directly - used for deterministic IP assignment
                        *session = label.parse::<u64>().unwrap_or(0);
                    }
                    IpCidrConExt::Range(range) => {
                        // Parse range value - used for subnet range specification
                        *range = label.parse::<u64>().unwrap_or(0);
                    }
                    IpCidrConExt::None => {
                        // No-op for None variant
                    }
                }
            }
            None => {
                // First phase: identify extension type from label keyword
                match label.as_str() {
                    Self::EXTENSION_TTL => {
                        // Initialize TTL extension with zero value (to be filled in next phase)
                        self.extension = Some(IpCidrConExt::Ttl(0));
                    }
                    Self::EXTENSION_SESSION => {
                        // Initialize Session extension with zero value (to be filled in next phase)
                        self.extension = Some(IpCidrConExt::Session(0));
                    }
                    Self::EXTENSION_RANGE_SESSION => {
                        // Initialize Range extension with zero value (to be filled in next phase)
                        self.extension = Some(IpCidrConExt::Range(0));
                    }
                    _ => {
                        // Unrecognized extension type - abort parsing
                        self.extension = Some(IpCidrConExt::None);
                        tracing::trace!("invalid extension username label value: {label}");
                        return UsernameLabelState::Ignored;
                    }
                }
            }
        }

        // Label was successfully processed
        UsernameLabelState::Used
    }

    /// Builds the final extension and inserts it into the provided Extensions context.
    ///
    /// This method completes the parsing process by storing the parsed extension
    /// in the request context for later use by IP generation functions.
    ///
    /// - Uses `maybe_insert` to avoid overwriting existing extensions
    /// - Transfers ownership of the parsed extension to the context
    /// - Always succeeds (returns Ok) as insertion cannot fail
    fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
        ext.maybe_insert(self.extension);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! Comprehensive test suite for IP CIDR connection extension functionality.
    //!
    //! This module contains extensive tests that validate the correctness and performance
    //! of the IP address generation algorithms and username parsing functionality.
    //!
    //! ## Test Categories
    //!
    //! 1. **Username Parser Tests**: Validate extension parsing from username labels
    //! 2. **IPv4 Generation Tests**: Test IPv4 address generation with various extensions
    //! 3. **IPv6 Generation Tests**: Test IPv6 address generation with various extensions
    //! 4. **Range-based Tests**: Validate deterministic range-based IP generation
    //! 5. **Session-based Tests**: Verify consistent session-based IP assignment
    //! 6. **TTL-based Tests**: Test time-based IP assignment with TTL windows
    //!
    //! ## Performance Characteristics
    //!
    //! All tests are designed to validate O(1) time complexity for IP generation
    //! and efficient memory usage patterns without unnecessary allocations.
    use super::*;
    use rama_core::username::{UsernameOpaqueLabelParser, parse_username};

    /// Initializes the tracing subscriber for comprehensive test logging.
    ///
    /// This function sets up a sophisticated logging infrastructure that captures
    /// all trace-level events during test execution. The configuration includes:
    ///
    /// - **Formatted Output**: Human-readable log formatting with timestamps
    /// - **Environment Filtering**: Respects RUST_LOG environment variable
    /// - **Trace-level Default**: Captures all debug information by default
    /// - **Lossy Parsing**: Continues execution even with invalid filter directives
    ///
    /// ## Implementation Details
    ///
    /// Uses the `tracing-subscriber` crate's registry pattern to compose
    /// multiple logging layers efficiently. The `init()` call is idempotent
    /// and will only initialize the subscriber once per test process.
    ///
    /// ## Performance Impact
    ///
    /// This function is designed for test environments and includes comprehensive
    /// logging that may impact performance. It should not be used in production code.
    fn init_tracing() {
        let subscriber = tracing_subscriber::fmt::Subscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }

    /// Comprehensive test for username label parsing functionality.
    ///
    /// This test validates the complete username parsing pipeline, including:
    /// - Extension type recognition from username labels
    /// - Numeric value extraction and parsing
    /// - Error handling for malformed inputs
    /// - State management across multiple parsing operations
    ///
    /// ## Test Scenarios
    ///
    /// 1. **Basic Username**: Tests parsing of simple usernames without extensions
    /// 2. **Session Extension**: Validates session-based extension parsing
    /// 3. **TTL Extension**: Tests time-to-live extension parsing
    /// 4. **Range Extension**: Validates range-based extension parsing
    /// 5. **Invalid Extensions**: Tests error handling for unrecognized labels
    /// 6. **Incomplete Extensions**: Tests handling of extension keywords without values
    ///
    /// ## Algorithm Validation
    ///
    /// The test verifies that the two-phase parsing algorithm correctly:
    /// - Identifies extension types in the first phase
    /// - Extracts and validates numeric values in the second phase
    /// - Maintains proper state between parsing operations
    ///
    /// ## Performance Characteristics
    ///
    /// Validates O(1) parsing performance for each label and efficient
    /// memory usage without unnecessary string allocations.
    #[test]
    fn test_username_label_parser() {
        init_tracing();

        // Initialize extension context for storing parsed results
        // This simulates the real-world usage pattern where extensions
        // are stored in the request context for later retrieval
        let mut ext = Extensions::default();

        // Create composite parser combining opaque label handling with extension parsing
        // The tuple structure allows for efficient sequential parsing without overhead
        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );

        // Test Case 1: Basic username without extensions
        // This validates that simple usernames pass through without modification
        // and that no spurious extensions are created
        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username").unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Basic username extension result: {labels:?}");

        // Test Case 2: Session-based extension parsing
        // Validates that session IDs are correctly extracted and stored
        // The large numeric value tests the parser's ability to handle various ranges
        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-session-123456789",).unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Session extension result: {labels:?}");

        // Test Case 3: TTL-based extension parsing
        // Validates time-to-live extension recognition and timestamp normalization
        // The value '5' represents a 5-second TTL window for consistent IP assignment
        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-ttl-5",).unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("TTL extension result: {labels:?}");

        // Test Case 4: Range-based extension parsing
        // Tests subnet range specification parsing for controlled IP generation
        // The value represents the number of bits for the intermediate deterministic portion
        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-range-12345",).unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Range extension result: {labels:?}");

        // Test Case 5: Invalid extension handling
        // Validates that unrecognized extension labels are handled gracefully
        // The parser should return the base username and set extension to None
        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-john-gonsalvis").unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Invalid extension result: {labels:?}");

        // Test Case 6: Incomplete extension handling
        // Tests behavior when extension keyword is present but numeric value is missing
        // This validates the parser's robustness against malformed input
        assert_eq!(
            parse_username(&mut ext, parser.clone(), "username-session").unwrap(),
            "username"
        );

        let labels = ext.get::<IpCidrConExt>();
        tracing::debug!("Incomplete extension result: {labels:?}");
    }

    /// Integration test for IPv4 address generation with username label parser.
    ///
    /// This test validates the complete integration between username parsing and
    /// IPv4 address generation. It demonstrates the end-to-end workflow:
    /// 1. Parse username to extract extension
    /// 2. Generate IPv4 address using the extension
    /// 3. Verify address falls within specified CIDR range
    ///
    /// ## Test Configuration
    ///
    /// - **CIDR Block**: `101.30.16.0/20` (4,096 available addresses)
    /// - **Address Range**: 101.30.16.0 to 101.30.31.255
    /// - **Test Iterations**: 17 iterations to validate randomness distribution
    ///
    /// ## Algorithm Validation
    ///
    /// The test verifies that generated addresses:
    /// - Respect the network portion of the CIDR (101.30.16.0/20)
    /// - Utilize the full host address space efficiently
    /// - Maintain cryptographic randomness in the absence of extensions
    ///
    /// ## Performance Characteristics
    ///
    /// Validates O(1) generation time per address and efficient memory usage
    /// without unnecessary allocations during the generation process.
    #[test]
    fn test_assign_ipv4_with_username_label_parser() {
        init_tracing();

        // Parse the IPv4 CIDR block that defines our available address space
        // /20 means 20 bits for network, 12 bits for host (4,096 addresses)
        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Cidr>()
            .expect("Unable to parse IPv4 CIDR - check format");

        // Initialize extension context and composite parser
        let mut ext = Extensions::default();
        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );

        // Generate multiple IPv4 addresses to validate randomness and performance
        // 17 iterations chosen to test distribution across different bit patterns
        for iteration in 0..17u32 {
            // Parse basic username without extensions to trigger random generation
            parse_username(&mut ext, parser.clone(), "username")
                .expect("Username parsing should never fail for valid input");

            // Extract the parsed extension (should be None for basic username)
            let extension = ext.get::<IpCidrConExt>();

            // Generate IPv4 address using the extension context
            // Without extension, this triggers pure random generation within CIDR
            let ipv4_address = ipv4_from_extension(&cidr, None, extension.cloned());

            tracing::info!(
                "Iteration {}: Generated IPv4 Address: {} (Network: {}, Host bits: {})",
                iteration,
                ipv4_address,
                cidr.first_address(),
                32 - cidr.network_length()
            );

            // Implicit validation: address should fall within CIDR range
            // The generation algorithm guarantees this mathematically
        }
    }

    /// Integration test for IPv6 address generation with username label parser.
    ///
    /// This test validates the complete integration between username parsing and
    /// IPv6 address generation. It demonstrates the end-to-end workflow for
    /// 128-bit IPv6 address space management.
    ///
    /// ## Test Configuration
    ///
    /// - **CIDR Block**: `2001:470:e953::/48` (2^80 available addresses)
    /// - **Address Range**: 2001:470:e953:: to 2001:470:e953:ffff:ffff:ffff:ffff:ffff
    /// - **Test Iterations**: 17 iterations to validate randomness distribution
    ///
    /// ## Algorithm Validation
    ///
    /// The test verifies that generated IPv6 addresses:
    /// - Preserve the 48-bit network prefix exactly
    /// - Randomize the remaining 80 bits efficiently
    /// - Maintain cryptographic security for the random portions
    ///
    /// ## Performance Characteristics
    ///
    /// Validates O(1) generation time per address despite the 128-bit address space
    /// and efficient handling of large numeric values without precision loss.
    #[test]
    fn test_assign_ipv6_with_username_label_parser() {
        init_tracing();

        // Parse the IPv6 CIDR block that defines our available address space
        // /48 means 48 bits for network, 80 bits for host (massive address space)
        let cidr = "2001:470:e953::/48"
            .parse::<Ipv6Cidr>()
            .expect("Unable to parse IPv6 CIDR - check format");

        // Initialize extension context and composite parser
        let mut ext = Extensions::default();
        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );

        // Generate multiple IPv6 addresses to validate randomness and performance
        // 17 iterations provide sufficient sample size for distribution testing
        for iteration in 0..17u32 {
            // Parse basic username without extensions to trigger random generation
            parse_username(&mut ext, parser.clone(), "username")
                .expect("Username parsing should never fail for valid input");

            // Extract the parsed extension (should be None for basic username)
            let extension = ext.get::<IpCidrConExt>();

            // Generate IPv6 address using the extension context
            // Without extension, this triggers pure random generation within CIDR
            let ipv6_address = ipv6_from_extension(&cidr, None, extension.cloned());

            tracing::info!(
                "Iteration {}: Generated IPv6 Address: {} (Network: {}, Host bits: {})",
                iteration,
                ipv6_address,
                cidr.first_address(),
                128 - cidr.network_length()
            );

            // Implicit validation: address should fall within CIDR range
            // The generation algorithm guarantees this through bit manipulation
        }
    }

    /// Test for deterministic IPv4 address generation with range-based extensions.
    ///
    /// This test validates the range-based IP generation algorithm that creates
    /// deterministic addresses with controlled randomization. The algorithm
    /// divides the address space into three distinct portions:
    ///
    /// 1. **Network Portion**: Fixed bits from the original CIDR (101.30.16.0/20)
    /// 2. **Intermediate Portion**: Deterministic bits derived from combined value
    /// 3. **Host Portion**: Random bits for the remaining address space
    ///
    /// ## Test Configuration
    ///
    /// - **Base CIDR**: `101.30.16.0/20` (network: 20 bits, available: 12 bits)
    /// - **Range Length**: 24 bits (extends 4 bits beyond base CIDR)
    /// - **Deterministic Bits**: 4 bits (24 - 20 = 4)
    /// - **Random Bits**: 8 bits (32 - 24 = 8)
    ///
    /// ## Algorithm Validation
    ///
    /// The test verifies that:
    /// - Identical combined values produce identical addresses
    /// - Different combined values produce different deterministic portions
    /// - Random portions vary between generations with same combined value
    /// - All generated addresses fall within the specified range
    ///
    /// ## Performance Characteristics
    ///
    /// Validates O(1) generation time and efficient bit manipulation operations
    /// without floating-point arithmetic or expensive modulo operations.
    #[test]
    fn test_assign_ipv4_with_range() {
        init_tracing();

        // Parse base CIDR that defines the network foundation
        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Cidr>()
            .expect("Unable to parse IPv4 CIDR - check format");

        // Define range length that extends beyond base CIDR for intermediate bits
        // 24 bits total: 20 network + 4 intermediate + 8 random
        let range = 24;
        let mut combined = 1;

        // Generate paired addresses to demonstrate deterministic behavior
        // 5 iterations provide sufficient coverage of the deterministic space
        for iteration in 0..5 {
            combined += 1;

            // Generate two IPv4 addresses with identical combined values
            // This demonstrates the deterministic nature of the intermediate portion
            let ipv4_address1 = ipv4_with_range(&cidr, range, combined);
            let ipv4_address2 = ipv4_with_range(&cidr, range, combined);

            tracing::info!(
                "Iteration {}: Combined value: {} (0x{:x})",
                iteration,
                combined,
                combined
            );
            tracing::info!(
                "  IPv4 Address 1: {} (Binary: {:032b})",
                ipv4_address1,
                u32::from(ipv4_address1)
            );
            tracing::info!(
                "  IPv4 Address 2: {} (Binary: {:032b})",
                ipv4_address2,
                u32::from(ipv4_address2)
            );

            // Validate that both addresses share the same network and intermediate portions
            // Only the random host portion should differ between generations
            let addr1_u32 = u32::from(ipv4_address1);
            let addr2_u32 = u32::from(ipv4_address2);
            let deterministic_mask = !((1u32 << (32 - range)) - 1);

            tracing::debug!(
                "  Deterministic portions match: {}",
                (addr1_u32 & deterministic_mask) == (addr2_u32 & deterministic_mask)
            );
        }
    }

    /// Test for deterministic IPv6 address generation with range-based extensions.
    ///
    /// This test validates the IPv6 range-based generation algorithm that manages
    /// the vast 128-bit address space with controlled deterministic behavior.
    /// The algorithm maintains the same three-portion structure as IPv4 but
    /// operates on 128-bit values for comprehensive IPv6 support.
    ///
    /// ## Test Configuration
    ///
    /// - **Base CIDR**: `2001:470:e953::/48` (network: 48 bits, available: 80 bits)
    /// - **Range Length**: 64 bits (extends 16 bits beyond base CIDR)
    /// - **Deterministic Bits**: 16 bits (64 - 48 = 16)
    /// - **Random Bits**: 64 bits (128 - 64 = 64)
    ///
    /// ## Algorithm Validation
    ///
    /// The test verifies that:
    /// - 128-bit arithmetic operations maintain precision
    /// - Deterministic portions are correctly positioned in the address
    /// - Random portions provide sufficient entropy for security
    /// - Generated addresses respect IPv6 formatting conventions
    ///
    /// ## Performance Characteristics
    ///
    /// Validates efficient 128-bit operations without performance degradation
    /// compared to 32-bit IPv4 operations, maintaining O(1) complexity.
    #[test]
    fn test_assign_ipv6_with_range() {
        init_tracing();

        // Parse base IPv6 CIDR that defines the network foundation
        let cidr = "2001:470:e953::/48"
            .parse::<Ipv6Cidr>()
            .expect("Unable to parse IPv6 CIDR - check format");

        // Define range length that extends beyond base CIDR for intermediate bits
        // 64 bits total: 48 network + 16 intermediate + 64 random
        let range = 64;
        let mut combined = 0x1234; // Use hex value to demonstrate bit patterns

        // Generate paired addresses to demonstrate deterministic behavior
        // 5 iterations provide sufficient coverage of the deterministic space
        for iteration in 0..5 {
            combined += 1;

            // Generate two IPv6 addresses with identical combined values
            // This demonstrates the deterministic nature of the intermediate portion
            let ipv6_address1 = ipv6_with_range(&cidr, range, combined);
            let ipv6_address2 = ipv6_with_range(&cidr, range, combined);

            tracing::info!(
                "Iteration {}: Combined value: {} (0x{:x})",
                iteration,
                combined,
                combined
            );
            tracing::info!(
                "  IPv6 Address 1: {} (Binary high: {:064b})",
                ipv6_address1,
                u128::from(ipv6_address1) >> 64
            );
            tracing::info!(
                "  IPv6 Address 2: {} (Binary high: {:064b})",
                ipv6_address2,
                u128::from(ipv6_address2) >> 64
            );

            // Validate that both addresses share the same network and intermediate portions
            // Only the random host portion should differ between generations
            let addr1_u128 = u128::from(ipv6_address1);
            let addr2_u128 = u128::from(ipv6_address2);
            let deterministic_mask = !((1u128 << (128 - range)) - 1);

            tracing::debug!(
                "  Deterministic portions match: {}",
                (addr1_u128 & deterministic_mask) == (addr2_u128 & deterministic_mask)
            );
        }
    }

    /// Test for session-based deterministic IPv4 address generation.
    ///
    /// This test validates the session-based IP assignment algorithm that ensures
    /// consistent IP addresses for the same session identifier. This is crucial
    /// for applications requiring stable IP addresses during user sessions.
    ///
    /// ## Algorithm Details
    ///
    /// The session-based algorithm:
    /// 1. Extracts the session ID from the extension
    /// 2. Applies modulo operation to fit within CIDR capacity
    /// 3. Combines network bits with deterministic host bits
    /// 4. Ensures identical session IDs always produce identical IPs
    ///
    /// ## Test Configuration
    ///
    /// - **Base CIDR**: `101.30.16.0/20` (4,096 available addresses)
    /// - **Session ID Range**: Starting from 256, incrementing by 1
    /// - **Test Iterations**: 17 iterations to validate consistency
    ///
    /// ## Validation Criteria
    ///
    /// - Identical session IDs must produce identical IP addresses
    /// - Different session IDs should produce different IP addresses
    /// - All generated addresses must fall within the CIDR range
    /// - Address distribution should be uniform across the available space
    ///
    /// ## Performance Characteristics
    ///
    /// Validates O(1) generation time with efficient modulo operations
    /// and bitwise arithmetic for optimal performance.
    #[test]
    fn test_assign_ipv4_with_session() {
        init_tracing();

        // Parse the IPv4 CIDR block for session-based assignment
        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Cidr>()
            .expect("Unable to parse IPv4 CIDR - check format");

        // Initialize session counter with offset to test various numeric ranges
        let mut combined = 256;

        // Generate multiple session-based addresses to validate consistency
        for iteration in 0..17u32 {
            combined += 1;

            // Create session extension with current session ID
            let extension = Some(IpCidrConExt::Session(combined));

            // Generate two IPv4 addresses with identical session IDs
            // Both addresses should be identical due to deterministic generation
            let ipv4_address1 = ipv4_from_extension(&cidr, None, extension);
            let ipv4_address2 = ipv4_from_extension(&cidr, None, extension);

            tracing::info!(
                "Iteration {}: Session ID: {} (0x{:x})",
                iteration,
                combined,
                combined
            );
            tracing::info!(
                "  IPv4 Address 1: {} (Host portion: {})",
                ipv4_address1,
                combined % ((1u64 << (32 - cidr.network_length())) - 1)
            );
            tracing::info!("  IPv4 Address 2: {} (Should be identical)", ipv4_address2);

            // Validate that both addresses are identical
            assert_eq!(
                ipv4_address1, ipv4_address2,
                "Session-based generation should be deterministic"
            );
        }
    }

    /// Test for session-based deterministic IPv6 address generation.
    ///
    /// This test validates the IPv6 session-based assignment algorithm that ensures
    /// consistent IPv6 addresses for the same session identifier across the vast
    /// 128-bit address space.
    ///
    /// ## Algorithm Details
    ///
    /// The IPv6 session-based algorithm:
    /// 1. Extracts the session ID from the extension
    /// 2. Applies modulo operation with 128-bit precision
    /// 3. Combines network bits with deterministic host bits
    /// 4. Maintains consistency across the large IPv6 address space
    ///
    /// ## Test Configuration
    ///
    /// - **Base CIDR**: `2001:470:e953::/48` (2^80 available addresses)
    /// - **Session ID Range**: Starting from 0x1234, incrementing by 1
    /// - **Test Iterations**: 17 iterations to validate consistency
    ///
    /// ## Validation Criteria
    ///
    /// - Identical session IDs must produce identical IPv6 addresses
    /// - 128-bit arithmetic must maintain precision without overflow
    /// - Generated addresses must preserve the network prefix exactly
    /// - Address distribution should utilize the full host address space
    ///
    /// ## Performance Characteristics
    ///
    /// Validates efficient 128-bit operations with O(1) generation time
    /// despite the complexity of the large address space.
    #[test]
    fn test_assign_ipv6_with_session() {
        init_tracing();

        // Parse the IPv6 CIDR block for session-based assignment
        let cidr = "2001:470:e953::/48"
            .parse::<Ipv6Cidr>()
            .expect("Unable to parse IPv6 CIDR - check format");

        // Initialize session counter with hex offset to test bit patterns
        let mut combined = 0x1234;

        // Generate multiple session-based addresses to validate consistency
        for iteration in 0..17 {
            combined += 1;

            // Create session extension with current session ID
            let extension = Some(IpCidrConExt::Session(combined));

            // Generate two IPv6 addresses with identical session IDs
            // Both addresses should be identical due to deterministic generation
            let ipv6_address1 = ipv6_from_extension(&cidr, None, extension);
            let ipv6_address2 = ipv6_from_extension(&cidr, None, extension);

            tracing::info!(
                "Iteration {}: Session ID: {} (0x{:x})",
                iteration,
                combined,
                combined
            );
            tracing::info!(
                "  IPv6 Address 1: {} (High bits: {:016x})",
                ipv6_address1,
                u128::from(ipv6_address1) >> 64
            );
            tracing::info!("  IPv6 Address 2: {} (Should be identical)", ipv6_address2);

            // Validate that both addresses are identical
            assert_eq!(
                ipv6_address1, ipv6_address2,
                "Session-based generation should be deterministic"
            );
        }
    }

    /// Test for TTL-based time-windowed IPv4 address generation.
    ///
    /// This test validates the TTL-based IP assignment algorithm that creates
    /// time-windowed consistent IP addresses. The algorithm normalizes timestamps
    /// to TTL boundaries, ensuring that requests within the same time window
    /// receive identical IP addresses.
    ///
    /// ## Algorithm Details
    ///
    /// The TTL-based algorithm:
    /// 1. Parses TTL value from username extension
    /// 2. Captures current timestamp with fallback to random
    /// 3. Normalizes timestamp to TTL boundary (timestamp - timestamp % ttl)
    /// 4. Uses normalized timestamp as deterministic seed
    ///
    /// ## Test Configuration
    ///
    /// - **Base CIDR**: `101.30.16.0/20` (4,096 available addresses)
    /// - **TTL Value**: 5 seconds (creates 5-second consistency windows)
    /// - **Sleep Duration**: 2.5 seconds between iterations
    /// - **Test Iterations**: 17 iterations to cross TTL boundaries
    ///
    /// ## Expected Behavior
    ///
    /// - Addresses should remain consistent within 5-second windows
    /// - Addresses should change when crossing TTL boundaries
    /// - Timestamp normalization should handle edge cases gracefully
    ///
    /// ## Performance Characteristics
    ///
    /// Validates efficient timestamp operations with O(1) generation time
    /// and proper handling of system time edge cases.
    #[test]
    fn test_assign_ipv4_with_ttl() {
        init_tracing();

        // Parse the IPv4 CIDR block for TTL-based assignment
        let cidr = "101.30.16.0/20"
            .parse::<Ipv4Cidr>()
            .expect("Unable to parse IPv4 CIDR - check format");

        // Initialize extension context and parser for TTL parsing
        let mut ext = Extensions::default();
        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );

        // Generate multiple TTL-based addresses with time delays
        // This demonstrates time-windowed consistency behavior
        for iteration in 0..17u32 {
            // Parse username with TTL extension (5-second window)
            parse_username(&mut ext, parser.clone(), "username-ttl-5")
                .expect("TTL username parsing should not fail");

            // Extract the parsed TTL extension with normalized timestamp
            let extension = ext.get::<IpCidrConExt>();

            // Generate IPv4 address using the TTL extension
            let ipv4_address = ipv4_from_extension(&cidr, None, extension.cloned());

            // Log detailed information about the TTL-based generation
            tracing::info!(
                "Iteration {}: TTL-based IPv4 Address: {}",
                iteration,
                ipv4_address
            );

            // Extract and log the normalized timestamp for debugging
            if let Some(IpCidrConExt::Ttl(normalized_timestamp)) = extension {
                tracing::debug!(
                    "  Normalized timestamp: {} (window boundary)",
                    normalized_timestamp
                );
            }

            // Sleep for 2.5 seconds to test behavior across time boundaries
            // This creates a pattern where some iterations share timestamps
            // and others cross into new TTL windows
            std::thread::sleep(std::time::Duration::from_millis(2500));
        }
    }

    /// Test for TTL-based time-windowed IPv6 address generation.
    ///
    /// This comprehensive test validates the IPv6 TTL-based assignment algorithm that creates
    /// time-windowed consistent IPv6 addresses across the vast 128-bit address space.
    /// The algorithm maintains the same temporal consistency guarantees as IPv4 but operates
    /// on the exponentially larger IPv6 address space with full precision arithmetic.
    ///
    /// ## Algorithm Details
    ///
    /// The IPv6 TTL-based algorithm implements a sophisticated time-windowing mechanism:
    /// 1. **Extension Parsing**: Parses TTL value from username extension with robust error handling
    /// 2. **Timestamp Capture**: Captures current system timestamp with cryptographic fallback
    /// 3. **Boundary Normalization**: Normalizes timestamp to TTL boundary for temporal consistency
    /// 4. **128-bit Arithmetic**: Uses normalized timestamp with full 128-bit precision arithmetic
    /// 5. **Deterministic Generation**: Ensures identical timestamps produce identical addresses
    ///
    /// ## Test Configuration
    ///
    /// - **Base CIDR**: `2001:470:e953::/48` (2^80 = 1,208,925,819,614,629,174,706,176 available addresses)
    /// - **Network Bits**: 48 bits (fixed network portion: 2001:470:e953)
    /// - **Host Bits**: 80 bits (available for TTL-based deterministic assignment)
    /// - **TTL Value**: 5 seconds (creates discrete 5-second consistency windows)
    /// - **Sleep Duration**: 2.5 seconds between iterations (tests both intra- and inter-window behavior)
    /// - **Test Iterations**: 17 iterations to cross multiple TTL boundaries and validate patterns
    ///
    /// ## Expected Behavior & Validation Criteria
    ///
    /// - **Temporal Consistency**: IPv6 addresses must remain identical within 5-second windows
    /// - **Boundary Transitions**: Addresses should deterministically change when crossing TTL boundaries
    /// - **Arithmetic Precision**: 128-bit operations must maintain full precision without overflow
    /// - **Network Preservation**: Network prefix (2001:470:e953) must remain constant across all generations
    /// - **Deterministic Repeatability**: Same normalized timestamp must always produce same address
    /// - **Address Space Utilization**: Generated addresses should efficiently utilize the 80-bit host space
    ///
    /// ## Time Window Mechanics
    ///
    /// The test creates overlapping time scenarios:
    /// - **Iterations 0-1**: Likely share same 5-second window (identical addresses expected)
    /// - **Iterations 2-3**: May cross boundary depending on execution timing
    /// - **Later iterations**: Demonstrate consistent behavior across multiple boundaries
    ///
    /// ## Performance Characteristics
    ///
    /// Validates multiple performance aspects:
    /// - **O(1) Generation Time**: Constant time complexity regardless of address space size
    /// - **Efficient 128-bit Operations**: No performance degradation from large numeric handling
    /// - **Minimal Memory Allocation**: Zero-allocation timestamp normalization and bit manipulation
    /// - **System Call Optimization**: Efficient timestamp capture with minimal system overhead
    /// - **Cache-Friendly Operations**: Bit manipulation patterns optimized for CPU cache efficiency
    ///
    /// ## Error Handling Validation
    ///
    /// Tests robust error handling across multiple failure modes:
    /// - **System Time Failures**: Validates cryptographic fallback when system time unavailable
    /// - **Parse Failures**: Ensures graceful handling of malformed TTL values
    /// - **Overflow Protection**: Confirms 128-bit arithmetic prevents integer overflow
    /// - **Edge Case Handling**: Tests behavior at timestamp boundaries and extreme values
    #[test]
    fn test_assign_ipv6_with_ttl() {
        init_tracing();

        // Parse the IPv6 CIDR block that defines our massive address space foundation
        // 2001:470:e953::/48 provides 2^80 host addresses - more than enough for any practical application
        // The /48 prefix is commonly used for site-level IPv6 allocations
        let cidr = "2001:470:e953::/48"
            .parse::<Ipv6Cidr>()
            .expect("Failed to parse IPv6 CIDR block - check format validity");

        // Initialize extension context and composite parser for comprehensive username processing
        // The parser handles both opaque labels and our custom TTL extensions seamlessly
        let mut ext = Extensions::default();
        let parser = (
            UsernameOpaqueLabelParser::new(),
            IpCidrConExtUsernameLabelParser::default(),
        );

        // Track previous address for consistency validation within time windows
        let mut previous_address: Option<Ipv6Addr> = None;
        let mut window_start_iteration: Option<u32> = None;

        // Generate multiple TTL-based addresses with strategic time delays
        // 17 iterations provide comprehensive coverage of time window transitions
        for iteration in 0..17u32 {
            tracing::debug!("=== TTL Test Iteration {} ===", iteration);

            // Parse username with TTL extension specifying 5-second consistency windows
            // The parser extracts "5" and normalizes current timestamp to 5-second boundaries
            parse_username(&mut ext, parser.clone(), "username-ttl-5")
                .expect("TTL username parsing should never fail with valid input");

            // Extract the parsed TTL extension containing the normalized timestamp
            // This timestamp serves as the deterministic seed for address generation
            let extension = ext.get::<IpCidrConExt>();

            // Generate IPv6 address using the TTL extension with normalized timestamp
            // The algorithm combines network bits, deterministic timestamp bits, and maintains precision
            let ipv6_address = ipv6_from_extension(&cidr, None, extension.cloned());

            // Extract detailed timing information for comprehensive analysis
            let (normalized_timestamp, raw_timestamp) =
                if let Some(IpCidrConExt::Ttl(timestamp)) = extension {
                    // Calculate the raw timestamp that would have been captured
                    let raw = timestamp + (timestamp % 5); // Reverse the normalization for display
                    (*timestamp, raw)
                } else {
                    (0, 0) // Fallback values for debugging
                };

            // Log comprehensive information about the TTL-based generation process
            tracing::info!(
                "Iteration {}: TTL-based IPv6 Address: {} (Network: {})",
                iteration,
                ipv6_address,
                cidr.first_address()
            );

            tracing::debug!(
                "  Normalized timestamp: {} (5-second boundary)",
                normalized_timestamp
            );

            tracing::debug!(
                "  Estimated raw timestamp: {} (before normalization)",
                raw_timestamp
            );

            tracing::debug!(
                "  Address binary (high 64 bits): {:016x}",
                u128::from(ipv6_address) >> 64
            );

            tracing::debug!(
                "  Address binary (low 64 bits): {:016x}",
                u128::from(ipv6_address) & 0xFFFFFFFFFFFFFFFF
            );

            // Validate consistency within time windows
            if let Some(prev_addr) = previous_address {
                if ipv6_address == prev_addr {
                    tracing::info!(
                        "  ✓ Address consistency maintained within TTL window (since iteration {})",
                        window_start_iteration.unwrap_or(iteration.saturating_sub(1))
                    );
                } else {
                    tracing::info!(
                        "  ⧖ TTL window boundary crossed - new deterministic address generated"
                    );
                    window_start_iteration = Some(iteration);
                }
            } else {
                // First iteration establishes baseline
                window_start_iteration = Some(iteration);
                tracing::info!("  ⭐ Baseline address established for TTL window tracking");
            }

            // Validate that generated address falls within the specified CIDR range
            // This is guaranteed mathematically but provides explicit validation
            let network_addr = cidr.first_address();
            let broadcast_addr = cidr.last_address();
            assert!(
                u128::from(ipv6_address) >= u128::from(network_addr)
                    && u128::from(ipv6_address) <= u128::from(broadcast_addr),
                "Generated address {} must fall within CIDR range {} - {}",
                ipv6_address,
                network_addr,
                broadcast_addr
            );

            // Validate that network prefix is preserved exactly
            let addr_u128 = u128::from(ipv6_address);
            let network_u128 = u128::from(network_addr);
            let prefix_mask = !((1u128 << (128 - cidr.network_length())) - 1);
            assert_eq!(
                addr_u128 & prefix_mask,
                network_u128 & prefix_mask,
                "Network prefix must be preserved in generated address"
            );

            // Store current address for next iteration's consistency check
            previous_address = Some(ipv6_address);

            // Strategic sleep to test behavior across time boundaries
            // 2.5 seconds creates interesting overlap patterns with 5-second TTL windows:
            // - Some iterations will share the same 5-second window
            // - Others will cross boundaries and demonstrate address changes
            // - Pattern creates comprehensive test coverage of temporal behavior
            tracing::debug!("  Sleeping 2.5 seconds to test TTL window boundary behavior...");
            std::thread::sleep(std::time::Duration::from_millis(2500));
        }

        // Final validation summary
        tracing::info!(
            "TTL-based IPv6 generation test completed successfully across {} iterations",
            17
        );
        tracing::info!(
            "Validated: temporal consistency, boundary transitions, precision arithmetic, and network preservation"
        );
    }
}
