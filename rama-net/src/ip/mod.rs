//! Internet Protocol packets and metadata, independent of sockets and tunnels.
//!
//! Checked packet views borrow their input; header types encode into caller-owned
//! buffers. Unknown protocol numbers are preserved. These primitives also work
//! without the `std` feature.
//!
//! ```
//! use rama_net::ip::{IpPacket, IpProtocol, Ipv4Header, decrement_hop_limit};
//! use core::net::Ipv4Addr;
//!
//! let mut bytes = [0; 128];
//! let header = Ipv4Header::new(
//!     Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2),
//!     IpProtocol::new(253), // experimental protocol, preserved as-is
//! );
//! let n = header.encode(&[], b"payload", &mut bytes)?;
//! decrement_hop_limit(&mut bytes[..n])?;
//! let packet = IpPacket::parse(&bytes[..n])?;
//! assert_eq!(packet.hop_limit(), 63);
//! assert_eq!(packet.protocol(), Some(IpProtocol::new(253)));
//! # Ok::<(), rama_net::ip::IpPacketError>(())
//! ```

pub mod icmp;

mod protocol;
pub use protocol::IpProtocol;
mod checksum;
pub use checksum::{InternetChecksum, internet_checksum};
mod packet;
pub use packet::{
    IpFragment, IpPacket, IpPacketError, Ipv4Header, Ipv4Option, Ipv4Options, Ipv4Packet,
    Ipv6Extension, Ipv6Extensions, Ipv6Header, Ipv6Packet, decrement_hop_limit, set_traffic_class,
};

/// Explicit Congestion Notification codepoint from the low two IP traffic-class bits.
///
/// RFC 8311 permits protocol-specific experimental use of ECT(1), so this type
/// exposes the codepoint without assigning transport behavior to it.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EcnCodepoint {
    /// The sender is not ECN-capable (`00`).
    NotEct = 0b00,
    /// ECN Capable Transport (1) (`01`).
    Ect1 = 0b01,
    /// ECN Capable Transport (0) (`10`).
    Ect0 = 0b10,
    /// Congestion Experienced (`11`).
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Decode the low two bits of an IP traffic-class value.
    #[inline]
    #[must_use]
    pub const fn from_bits(value: u8) -> Self {
        match value & 0b11 {
            0b00 => Self::NotEct,
            0b01 => Self::Ect1,
            0b10 => Self::Ect0,
            _ => Self::Ce,
        }
    }

    /// Return the two wire bits for this codepoint.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests;
