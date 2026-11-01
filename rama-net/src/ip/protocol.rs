use core::fmt;

/// An IP Protocol / IPv6 Next Header number (IANA Internet Protocol Numbers).
///
/// Unknown numbers are preserved. This is independent of URI schemes and socket
/// transport selection. In particular, zero means IPv6 Hop-by-Hop Options, not
/// a wildcard; protocols such as CONNECT-IP define their own wildcard semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IpProtocol(u8);

impl IpProtocol {
    /// IPv6 Hop-by-Hop Options.
    pub const HOP_BY_HOP: Self = Self(0);
    /// Internet Control Message Protocol for IPv4.
    pub const ICMP: Self = Self(1);
    /// Transmission Control Protocol.
    pub const TCP: Self = Self(6);
    /// User Datagram Protocol.
    pub const UDP: Self = Self(17);
    /// IPv6 Routing header.
    pub const ROUTING: Self = Self(43);
    /// IPv6 Fragment header.
    pub const FRAGMENT: Self = Self(44);
    /// Encapsulating Security Payload; its contents are opaque.
    pub const ESP: Self = Self(50);
    /// Authentication Header.
    pub const AH: Self = Self(51);
    /// Internet Control Message Protocol for IPv6.
    pub const ICMPV6: Self = Self(58);
    /// IPv6 No Next Header.
    pub const NO_NEXT_HEADER: Self = Self(59);
    /// IPv6 Destination Options.
    pub const DESTINATION_OPTIONS: Self = Self(60);

    /// Preserve a wire number, including unassigned and experimental numbers.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// The wire number.
    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Whether this identifies an ICMP protocol.
    #[must_use]
    pub const fn is_icmp(self) -> bool {
        matches!(self.0, 1 | 58)
    }
}

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl From<IpProtocol> for u8 {
    fn from(value: IpProtocol) -> Self {
        value.0
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
