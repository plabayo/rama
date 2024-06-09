//! Errors for the binary proxy protocol.

use std::fmt;

/// An error in parsing a binary PROXY protocol header.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ParseError {
    /// Expected header to the protocol prefix plus 4 bytes after the prefix.
    Incomplete(usize),
    /// Expected header to start with a prefix of '\r\n\r\n\0\r\nQUIT\n'.
    Prefix,
    /// Expected version to be equal to 2.
    Version(u8),
    /// Invalid command. Command must be one of: Local, Proxy.
    Command(u8),
    /// Invalid Address Family. Address Family must be one of: Unspecified, IPv4, IPv6, Unix.
    AddressFamily(u8),
    /// Invalid protocol. Protocol must be one of: Unspecified, Stream, or Datagram.
    Protocol(u8),
    /// Header does not contain the advertised length of the address information and TLVs.
    Partial(usize, usize),
    /// Header length of {0} bytes cannot store the {1} bytes required for the address family.
    InvalidAddresses(usize, usize),
    /// Header is not long enough to contain TLV {0} with length {1}.
    InvalidTLV(u8, u16),
    /// Header contains leftover {0} bytes not accounted for by the address family or TLVs.
    Leftovers(usize),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete(len) => write!(f, "Expected header to the protocol prefix plus 4 bytes after the prefix (length {}).", len),
            Self::Prefix => write!(f, "Expected header to start with a prefix of '\\r\\n\\r\\n\\0\\r\\nQUIT\\n'."),
            Self::Version(version) => write!(f, "Expected version {:X} to be equal to 2.", version),
            Self::Command(command) => write!(f, "Invalid command {:X}. Command must be one of: Local, Proxy.", command),
            Self::AddressFamily(af) => write!(f, "Invalid Address Family {:X}. Address Family must be one of: Unspecified, IPv4, IPv6, Unix.", af),
            Self::Protocol(protocol) => write!(f, "Invalid protocol {:X}. Protocol must be one of: Unspecified, Stream, or Datagram.", protocol),
            Self::Partial(len, total) => write!(f, "Header does not contain the advertised length of the address information and TLVs (has {} out of {} bytes).", len, total),
            Self::InvalidAddresses(len, total) => write!(f, "Header length of {} bytes cannot store the {} bytes required for the address family.", len, total),
            Self::InvalidTLV(tlv, len) => write!(f, "Header is not long enough to contain TLV {} with length {}.", tlv, len),
            Self::Leftovers(len) => write!(f, "Header contains leftover {} bytes not accounted for by the address family or TLVs.", len),
        }
    }
}

impl std::error::Error for ParseError {}
