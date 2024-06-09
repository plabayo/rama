use crate::proxy::pp::protocol::ip::{IPv4, IPv6};
use crate::proxy::pp::protocol::v2::error::ParseError;
use std::borrow::Cow;
use std::fmt;
use std::net::SocketAddr;
use std::ops::BitOr;

/// The prefix of the PROXY protocol header.
pub const PROTOCOL_PREFIX: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";
/// The minimum length in bytes of a PROXY protocol header.
pub(crate) const MINIMUM_LENGTH: usize = 16;
/// The minimum length in bytes of a Type-Length-Value payload.
pub(crate) const MINIMUM_TLV_LENGTH: usize = 3;

/// The number of bytes for an IPv4 addresses payload.
const IPV4_ADDRESSES_BYTES: usize = 12;
/// The number of bytes for an IPv6 addresses payload.
const IPV6_ADDRESSES_BYTES: usize = 36;
/// The number of bytes for a unix addresses payload.
const UNIX_ADDRESSES_BYTES: usize = 216;

/// A proxy protocol version 2 header.
///
/// ## Examples
/// ```rust
/// use rama::proxy::pp::protocol::v2::{Addresses, AddressFamily, Command, Header, IPv4, ParseError, Protocol, PROTOCOL_PREFIX, Type, TypeLengthValue, Version};
/// let mut header = Vec::from(PROTOCOL_PREFIX);
/// header.extend([
///    0x21, 0x12, 0, 16, 127, 0, 0, 1, 192, 168, 1, 1, 0, 80, 1, 187, 4, 0, 1, 42
/// ]);
///
/// let addresses: Addresses = IPv4::new([127, 0, 0, 1], [192, 168, 1, 1], 80, 443).into();
/// let expected = Header {
///    header: header.as_slice().into(),
///    version: Version::Two,
///    command: Command::Proxy,
///    protocol: Protocol::Datagram,
///    addresses
/// };
/// let actual = Header::try_from(header.as_slice()).unwrap();
///
/// assert_eq!(actual, expected);
/// assert_eq!(actual.tlvs().collect::<Vec<Result<TypeLengthValue<'_>, ParseError>>>(), vec![Ok(TypeLengthValue::new(Type::NoOp, &[42]))]);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Header<'a> {
    /// The underlying byte slice this `Header` is built on.
    pub header: Cow<'a, [u8]>,
    /// The version of the PROXY protocol.
    pub version: Version,
    /// The command of the PROXY protocol.
    pub command: Command,
    /// The protocol of the PROXY protocol.
    pub protocol: Protocol,
    /// The source and destination addresses of the PROXY protocol.
    pub addresses: Addresses,
}

/// The supported `Version`s for binary headers.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Version {
    /// Version two of the PROXY protocol.
    Two = 0x20,
}

/// The supported `Command`s for a PROXY protocol header.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Command {
    /// The connection is a local connection.
    Local = 0,
    /// The connection is a proxy connection.
    Proxy,
}

/// The supported `AddressFamily` for a PROXY protocol header.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AddressFamily {
    /// The address family is unspecified.
    Unspecified = 0x00,
    /// The address family is IPv4.
    IPv4 = 0x10,
    /// The address family is IPv6.
    IPv6 = 0x20,
    /// The address family is Unix.
    Unix = 0x30,
}

/// The supported `Protocol`s for a PROXY protocol header.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// The protocol is unspecified.
    Unspecified = 0,
    /// The protocol is a stream.
    Stream,
    /// The protocol is a datagram.
    Datagram,
}

/// The source and destination address information for a given `AddressFamily`.
///
/// ## Examples
/// ```rust
/// use rama::proxy::pp::protocol::v2::{Addresses, AddressFamily};
/// use std::net::SocketAddr;
///
/// let addresses: Addresses = ("127.0.0.1:80".parse::<SocketAddr>().unwrap(), "192.168.1.1:443".parse::<SocketAddr>().unwrap()).into();
///
/// assert_eq!(addresses.address_family(), AddressFamily::IPv4);
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Addresses {
    /// The source and destination addresses are unspecified.
    Unspecified,
    /// The source and destination addresses are IPv4.
    IPv4(IPv4),
    /// The source and destination addresses are IPv6.
    IPv6(IPv6),
    /// The source and destination addresses are Unix.
    Unix(Unix),
}

/// The source and destination addresses of UNIX sockets.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Unix {
    /// The source address of the UNIX socket.
    pub source: [u8; 108],
    /// The destination address of the UNIX socket.
    pub destination: [u8; 108],
}

/// An `Iterator` of `TypeLengthValue`s stored in a byte slice.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TypeLengthValues<'a> {
    bytes: &'a [u8],
    offset: usize,
}

/// A Type-Length-Value payload.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TypeLengthValue<'a> {
    /// The type of the `TypeLengthValue`.
    pub kind: u8,
    /// The value of the `TypeLengthValue`.
    pub value: Cow<'a, [u8]>,
}

/// Supported types for `TypeLengthValue` payloads.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Type {
    /// The ALPN of the connection.
    ALPN = 0x01,
    /// The authority of the connection.
    Authority,
    /// The CRC32C checksum of the connection.
    CRC32C,
    /// NoOp
    NoOp,
    /// The Unique ID of the connection.
    UniqueId,
    /// The SSL information.
    SSL = 0x20,
    /// The SSL Version.
    SSLVersion,
    /// The SSL common name.
    SSLCommonName,
    /// The SSL cipher.
    SSLCipher,
    /// The SSL Signature Algorithm.
    SSLSignatureAlgorithm,
    /// The SSL Key Algorithm
    SSLKeyAlgorithm,
    /// The SSL Network Namespace.
    NetworkNamespace = 0x30,
}

impl<'a> fmt::Display for Header<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {:#X} {:#X} ({} bytes)",
            PROTOCOL_PREFIX,
            self.version | self.command,
            self.protocol | self.address_family(),
            self.length()
        )
    }
}

impl<'a> Header<'a> {
    /// Creates an owned clone of this [`Header`].
    pub fn to_owned(&self) -> Header<'static> {
        Header {
            header: Cow::Owned(self.header.to_vec()),
            version: self.version,
            command: self.command,
            protocol: self.protocol,
            addresses: self.addresses,
        }
    }

    /// The length of this `Header`'s payload in bytes.
    pub fn length(&self) -> usize {
        self.header[MINIMUM_LENGTH..].len()
    }

    /// The total length of this `Header` in bytes.
    pub fn len(&self) -> usize {
        self.header.len()
    }

    /// Tests whether this `Header`'s underlying byte slice is empty.
    pub fn is_empty(&self) -> bool {
        self.header.is_empty()
    }

    /// The `AddressFamily` of this `Header`.
    pub fn address_family(&self) -> AddressFamily {
        self.addresses.address_family()
    }

    /// The length in bytes of the address portion of the payload.
    fn address_bytes_end(&self) -> usize {
        let length = self.length();
        let address_bytes = self.address_family().byte_length().unwrap_or(length);

        MINIMUM_LENGTH + std::cmp::min(address_bytes, length)
    }

    /// The bytes of the address portion of the payload.
    pub fn address_bytes(&self) -> &[u8] {
        &self.header[MINIMUM_LENGTH..self.address_bytes_end()]
    }

    /// The bytes of the `TypeLengthValue` portion of the payload.
    pub fn tlv_bytes(&self) -> &[u8] {
        &self.header[self.address_bytes_end()..]
    }

    /// An `Iterator` of `TypeLengthValue`s.
    pub fn tlvs(&self) -> TypeLengthValues<'_> {
        TypeLengthValues {
            bytes: self.tlv_bytes(),
            offset: 0,
        }
    }

    /// The underlying byte slice this `Header` is built on.
    pub fn as_bytes(&self) -> &[u8] {
        self.header.as_ref()
    }
}

impl<'a> TypeLengthValues<'a> {
    /// The underlying byte slice of the `TypeLengthValue`s portion of the `Header` payload.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
}

impl<'a> From<&'a [u8]> for TypeLengthValues<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        TypeLengthValues { bytes, offset: 0 }
    }
}

impl<'a> Iterator for TypeLengthValues<'a> {
    type Item = Result<TypeLengthValue<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }

        let remaining = &self.bytes[self.offset..];

        if remaining.len() < MINIMUM_TLV_LENGTH {
            self.offset = self.bytes.len();
            return Some(Err(ParseError::Leftovers(self.bytes.len())));
        }

        let tlv_type = remaining[0];
        let length = u16::from_be_bytes([remaining[1], remaining[2]]);
        let tlv_length = MINIMUM_TLV_LENGTH + length as usize;

        if remaining.len() < tlv_length {
            self.offset = self.bytes.len();
            return Some(Err(ParseError::InvalidTLV(tlv_type, length)));
        }

        self.offset += tlv_length;

        Some(Ok(TypeLengthValue {
            kind: tlv_type,
            value: Cow::Borrowed(&remaining[MINIMUM_TLV_LENGTH..tlv_length]),
        }))
    }
}

impl<'a> TypeLengthValues<'a> {
    /// The number of bytes in the `TypeLengthValue` portion of the `Header`.
    pub fn len(&self) -> u16 {
        self.bytes.len() as u16
    }

    /// Whether there are any bytes to be interpreted as `TypeLengthValue`s.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl BitOr<Command> for Version {
    type Output = u8;

    fn bitor(self, command: Command) -> Self::Output {
        (self as u8) | (command as u8)
    }
}

impl BitOr<Version> for Command {
    type Output = u8;

    fn bitor(self, version: Version) -> Self::Output {
        (self as u8) | (version as u8)
    }
}

impl BitOr<Protocol> for AddressFamily {
    type Output = u8;

    fn bitor(self, protocol: Protocol) -> Self::Output {
        (self as u8) | (protocol as u8)
    }
}

impl AddressFamily {
    /// The length in bytes for this `AddressFamily`.
    /// `AddressFamily::Unspecified` does not require any bytes, and is represented as `None`.
    pub fn byte_length(&self) -> Option<usize> {
        match self {
            AddressFamily::IPv4 => Some(IPV4_ADDRESSES_BYTES),
            AddressFamily::IPv6 => Some(IPV6_ADDRESSES_BYTES),
            AddressFamily::Unix => Some(UNIX_ADDRESSES_BYTES),
            AddressFamily::Unspecified => None,
        }
    }
}

impl From<AddressFamily> for u16 {
    fn from(address_family: AddressFamily) -> Self {
        address_family.byte_length().unwrap_or_default() as u16
    }
}

impl From<(SocketAddr, SocketAddr)> for Addresses {
    fn from(addresses: (SocketAddr, SocketAddr)) -> Self {
        match addresses {
            (SocketAddr::V4(source), SocketAddr::V4(destination)) => Addresses::IPv4(IPv4::new(
                *source.ip(),
                *destination.ip(),
                source.port(),
                destination.port(),
            )),
            (SocketAddr::V6(source), SocketAddr::V6(destination)) => Addresses::IPv6(IPv6::new(
                *source.ip(),
                *destination.ip(),
                source.port(),
                destination.port(),
            )),
            _ => Addresses::Unspecified,
        }
    }
}

impl From<IPv4> for Addresses {
    fn from(addresses: IPv4) -> Self {
        Addresses::IPv4(addresses)
    }
}

impl From<IPv6> for Addresses {
    fn from(addresses: IPv6) -> Self {
        Addresses::IPv6(addresses)
    }
}

impl From<Unix> for Addresses {
    fn from(addresses: Unix) -> Self {
        Addresses::Unix(addresses)
    }
}

impl Addresses {
    /// The `AddressFamily` for this `Addresses`.
    pub fn address_family(&self) -> AddressFamily {
        match self {
            Addresses::Unspecified => AddressFamily::Unspecified,
            Addresses::IPv4(..) => AddressFamily::IPv4,
            Addresses::IPv6(..) => AddressFamily::IPv6,
            Addresses::Unix(..) => AddressFamily::Unix,
        }
    }

    /// The length in bytes of the `Addresses` in the `Header`'s payload.
    pub fn len(&self) -> usize {
        self.address_family().byte_length().unwrap_or_default()
    }

    /// Tests whether the `Addresses` consume any space in the `Header`'s payload.
    /// `AddressFamily::Unspecified` does not require any bytes, and always returns true.
    pub fn is_empty(&self) -> bool {
        self.address_family().byte_length().is_none()
    }
}

impl Unix {
    /// Creates a new instance of a source and destination address pair for Unix sockets.
    pub fn new(source: [u8; 108], destination: [u8; 108]) -> Self {
        Unix {
            source,
            destination,
        }
    }
}

impl BitOr<AddressFamily> for Protocol {
    type Output = u8;

    fn bitor(self, address_family: AddressFamily) -> Self::Output {
        (self as u8) | (address_family as u8)
    }
}

impl<'a, T: Into<u8>> From<(T, &'a [u8])> for TypeLengthValue<'a> {
    fn from((kind, value): (T, &'a [u8])) -> Self {
        TypeLengthValue {
            kind: kind.into(),
            value: value.into(),
        }
    }
}

impl<'a> TypeLengthValue<'a> {
    /// Creates an owned clone of this [`TypeLengthValue`].
    pub fn to_owned(&self) -> TypeLengthValue<'static> {
        TypeLengthValue {
            kind: self.kind,
            value: Cow::Owned(self.value.to_vec()),
        }
    }

    /// Creates a new instance of a `TypeLengthValue`, where the length is determine by the length of the byte slice.
    /// No check is done to ensure the byte slice's length fits in a `u16`.
    pub fn new<T: Into<u8>>(kind: T, value: &'a [u8]) -> Self {
        TypeLengthValue {
            kind: kind.into(),
            value: value.into(),
        }
    }

    /// The length in bytes of this `TypeLengthValue`'s value.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Tests whether the value of this `TypeLengthValue` is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl From<Type> for u8 {
    fn from(kind: Type) -> Self {
        kind as u8
    }
}
