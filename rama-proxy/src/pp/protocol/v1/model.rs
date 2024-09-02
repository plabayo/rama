//! The data model to represent the test PROXY protocol header.

use crate::proxy::pp::protocol::ip::{IPv4, IPv6};
use std::borrow::Cow;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// The prefix of the PROXY protocol header.
pub const PROTOCOL_PREFIX: &str = "PROXY";

/// The suffix of the PROXY protocol header.
pub const PROTOCOL_SUFFIX: &str = "\r\n";

/// TCP protocol with IPv4 address family.
pub const TCP4: &str = "TCP4";

/// TCP protocol with IPv6 address family.
pub const TCP6: &str = "TCP6";

/// Unknown protocol and address family. Address portion of the header should be ignored.
pub const UNKNOWN: &str = "UNKNOWN";

/// The separator of the header parts.
pub const SEPARATOR: char = ' ';

/// A text PROXY protocol header that borrows the input string.
///
/// ## Examples
/// ### Worst Case (from bytes)
/// ```rust
/// use rama::proxy::pp::protocol::v1::{Addresses, Header, UNKNOWN};
///
/// let input = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
/// let header = Header::try_from(input.as_bytes()).unwrap();
///
/// assert_eq!(header, Header::new(input, Addresses::Unknown));
/// assert_eq!(header.protocol(), UNKNOWN);
/// assert_eq!(header.addresses_str(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535");
/// ```
///
/// ### UNKNOWN
/// ```rust
/// use rama::proxy::pp::protocol::v1::{Addresses, Header, UNKNOWN};
///
/// let input = "PROXY UNKNOWN\r\nhello";
/// let header = Header::try_from(input).unwrap();
///
/// assert_eq!(header, Header::new("PROXY UNKNOWN\r\n", Addresses::Unknown));
/// assert_eq!(header.protocol(), UNKNOWN);
/// assert_eq!(header.addresses_str(), "");
/// ```
///
/// ### TCP4
/// ```rust
/// use std::net::Ipv4Addr;
/// use rama::proxy::pp::protocol::v1::{Header, Addresses, TCP4};
///
/// let input = "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n";
/// let header = Header::try_from(input).unwrap();
///
/// assert_eq!(header, Header::new(input, Addresses::new_tcp4(Ipv4Addr::new(127, 0, 1, 2), Ipv4Addr::new(192, 168, 1, 101), 80, 443)));
/// assert_eq!(header.protocol(), TCP4);
/// assert_eq!(header.addresses_str(), "127.0.1.2 192.168.1.101 80 443");
/// ```
///
/// ### TCP6
/// ```rust
/// use std::net::Ipv6Addr;
/// use rama::proxy::pp::protocol::v1::{Header, Addresses, TCP6};
///
/// let input = "PROXY TCP6 1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535\r\n";
/// let header = Header::try_from(input).unwrap();
///
/// assert_eq!(
///     header,
///     Header::new(
///         input,
///         Addresses::new_tcp6(
///             Ipv6Addr::from([0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFEDC, 0xBA09, 0x8765, 0x4321]),
///             Ipv6Addr::from([0x4321, 0x8765, 0xBA09, 0xFEDC, 0xCDEF, 0x90AB, 0x5678, 0x01234,]),
///             443,
///             65535
///         )
///     )
/// );
/// assert_eq!(header.protocol(), TCP6);
/// assert_eq!(header.addresses_str(), "1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535");
/// ```
///
/// ### Invalid
/// ```rust
/// use rama::proxy::pp::protocol::v1::{Header, Addresses, ParseError};
///
/// assert_eq!(Err(ParseError::InvalidProtocol), "PROXY tcp4\r\n".parse::<Addresses>());
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Header<'a> {
    /// The original input string.
    pub header: Cow<'a, str>,
    /// The source and destination addresses of the header.
    pub addresses: Addresses,
}

impl<'a> Header<'a> {
    /// Creates a new `Header` with the given addresses and a reference to the original input.
    pub fn new<H: Into<&'a str>, A: Into<Addresses>>(header: H, addresses: A) -> Self {
        Header {
            header: Cow::Borrowed(header.into()),
            addresses: addresses.into(),
        }
    }

    /// Creates an owned clone of this [`Header`].
    pub fn to_owned(&self) -> Header<'static> {
        Header {
            header: Cow::Owned::<'static>(self.header.to_string()),
            addresses: self.addresses,
        }
    }

    /// The protocol portion of this `Header`.
    pub fn protocol(&self) -> &str {
        self.addresses.protocol()
    }

    /// The source and destination addresses portion of this `Header`.
    pub fn addresses_str(&self) -> &str {
        let start = PROTOCOL_PREFIX.len() + SEPARATOR.len_utf8() + self.protocol().len();
        let end = self.header.len() - PROTOCOL_SUFFIX.len();
        let addresses = &self.header[start..end];

        if addresses.starts_with(SEPARATOR) {
            &addresses[SEPARATOR.len_utf8()..]
        } else {
            addresses
        }
    }
}

/// The source and destination of a header.
/// Includes IP (v4 or v6) addresses and TCP ports.
///
/// ## Examples
/// ### Worst Case
/// ```rust
/// use rama::proxy::pp::protocol::v1::{Addresses, Header, UNKNOWN};
///
/// let header = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
/// let addresses = Addresses::Unknown;
///
/// assert_eq!(addresses, header.parse().unwrap());
/// assert_ne!(addresses.to_string().as_str(), header);
/// ```
///
/// ### UNKNOWN
/// ```rust
/// use rama::proxy::pp::protocol::v1::Addresses;
///
/// let header = "PROXY UNKNOWN\r\n";
/// let addresses = Addresses::Unknown;
///
/// assert_eq!(addresses, header.parse().unwrap());
/// assert_eq!(addresses.to_string().as_str(), header);
/// ```
///
/// ### TCP4
/// ```rust
/// use std::net::Ipv4Addr;
/// use rama::proxy::pp::protocol::v1::Addresses;
///
/// let header = "PROXY TCP4 127.0.1.2 192.168.1.101 80 443\r\n";
/// let addresses = Addresses::new_tcp4(Ipv4Addr::new(127, 0, 1, 2), Ipv4Addr::new(192, 168, 1, 101), 80, 443);
///
/// assert_eq!(addresses, header.parse().unwrap());
/// assert_eq!(addresses.to_string().as_str(), header);
/// ```
///
/// ### TCP6
/// ```rust
/// use std::net::Ipv6Addr;
/// use rama::proxy::pp::protocol::v1::Addresses;
///
/// let header = "PROXY TCP6 1234:5678:90ab:cdef:fedc:ba09:8765:4321 4321:8765:ba09:fedc:cdef:90ab:5678:1234 443 65535\r\n";
/// let addresses = Addresses::new_tcp6(
///     Ipv6Addr::from([0x1234, 0x5678, 0x90AB, 0xCDEF, 0xFEDC, 0xBA09, 0x8765, 0x4321]),
///     Ipv6Addr::from([0x4321, 0x8765, 0xBA09, 0xFEDC, 0xCDEF, 0x90AB, 0x5678, 0x01234,]),
///     443,
///     65535
/// );
///
/// assert_eq!(addresses, header.parse().unwrap());
/// assert_eq!(addresses.to_string().as_str(), header);
/// ```
///
/// ### Invalid
/// ```rust
/// use rama::proxy::pp::protocol::v1::{Addresses, ParseError};
///
/// assert_eq!(Err(ParseError::InvalidProtocol), "PROXY tcp4\r\n".parse::<Addresses>());
/// ```
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, Hash)]
pub enum Addresses {
    #[default]
    /// The source and destination addresses of the header are unknown.
    Unknown,
    /// The source and destination addresses of the header are IPv4.
    Tcp4(IPv4),
    /// The source and destination addresses of the header are IPv6.
    Tcp6(IPv6),
}

impl Addresses {
    /// Create a new IPv4 TCP address.
    pub fn new_tcp4<T: Into<Ipv4Addr>>(
        source_address: T,
        destination_address: T,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Addresses::Tcp4(IPv4 {
            source_address: source_address.into(),
            source_port,
            destination_address: destination_address.into(),
            destination_port,
        })
    }

    /// Create a new IPv6 TCP address.
    pub fn new_tcp6<T: Into<Ipv6Addr>>(
        source_address: T,
        destination_address: T,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Addresses::Tcp6(IPv6 {
            source_address: source_address.into(),
            source_port,
            destination_address: destination_address.into(),
            destination_port,
        })
    }

    /// The protocol portion of this `Addresses`.
    pub fn protocol(&self) -> &str {
        match self {
            Addresses::Tcp4(..) => TCP4,
            Addresses::Tcp6(..) => TCP6,
            Addresses::Unknown => UNKNOWN,
        }
    }
}

impl From<(SocketAddr, SocketAddr)> for Addresses {
    fn from(addresses: (SocketAddr, SocketAddr)) -> Self {
        match addresses {
            (SocketAddr::V4(source), SocketAddr::V4(destination)) => Addresses::Tcp4(IPv4::new(
                *source.ip(),
                *destination.ip(),
                source.port(),
                destination.port(),
            )),
            (SocketAddr::V6(source), SocketAddr::V6(destination)) => Addresses::Tcp6(IPv6::new(
                *source.ip(),
                *destination.ip(),
                source.port(),
                destination.port(),
            )),
            _ => Addresses::Unknown,
        }
    }
}

impl From<IPv4> for Addresses {
    fn from(addresses: IPv4) -> Self {
        Addresses::Tcp4(addresses)
    }
}

impl From<IPv6> for Addresses {
    fn from(addresses: IPv6) -> Self {
        Addresses::Tcp6(addresses)
    }
}

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.header.as_ref())
    }
}

impl fmt::Display for Addresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("PROXY UNKNOWN\r\n"),
            Self::Tcp4(a) => write!(
                f,
                "PROXY TCP4 {} {} {} {}\r\n",
                a.source_address, a.destination_address, a.source_port, a.destination_port
            ),
            Self::Tcp6(a) => write!(
                f,
                "PROXY TCP6 {} {} {} {}\r\n",
                a.source_address, a.destination_address, a.source_port, a.destination_port
            ),
        }
    }
}
