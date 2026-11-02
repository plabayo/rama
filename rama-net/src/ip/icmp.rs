//! ICMP forwarding errors without a socket or routing-table dependency.

use super::{
    InternetChecksum, IpPacket, IpPacketError, IpProtocol, Ipv4Header, Ipv6Header,
    internet_checksum,
};
use core::net::{IpAddr, Ipv6Addr};

/// A forwarding error that can be returned to the source of an IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpErrorKind {
    /// No route to the destination.
    NoRoute,
    /// Local policy forbids forwarding.
    AdministrativelyProhibited,
    /// IPv6 ingress/egress source-address policy failed (IPv4 uses prohibited).
    SourcePolicy,
    /// The outgoing link cannot carry the packet.
    PacketTooBig {
        /// IP MTU, excluding link/tunnel encapsulation.
        mtu: u32,
    },
    /// TTL / Hop Limit expired in transit.
    HopLimitExceeded,
}

/// ICMPv6 checksum including the IPv6 pseudo-header (RFC 4443 §2.3).
///
/// Returns zero for a valid received message including its checksum. This helper
/// supports ordinary IPv6 packets (up to 65535 payload bytes), not jumbograms.
pub fn icmpv6_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    message: &[u8],
) -> Result<u16, IpPacketError> {
    if message.len() > 65535 {
        return Err(IpPacketError::Length);
    }
    let mut sum = InternetChecksum::new();
    sum.update(&source.octets());
    sum.update(&destination.octets());
    sum.update(&(message.len() as u32).to_be_bytes());
    sum.update(&[0, 0, 0, IpProtocol::ICMPV6.value()]);
    sum.update(message);
    Ok(sum.finish())
}

/// Whether a packet carries an ICMP error (rather than an informational message).
/// Returns false if fragmentation prevents inspecting the type.
#[must_use]
pub fn is_icmp_error(packet: IpPacket<'_>) -> bool {
    let Some(payload) = packet.upper_layer_payload() else {
        return false;
    };
    let Some(&kind) = payload.first() else {
        return false;
    };
    match packet {
        IpPacket::V4(p) if p.protocol() == IpProtocol::ICMP => matches!(kind, 3 | 4 | 5 | 11 | 12),
        IpPacket::V6(p) if p.protocol() == Some(IpProtocol::ICMPV6) => kind < 128,
        _ => false,
    }
}

/// Encode an IP packet carrying an ICMP error and a bounded quotation of `invoking`.
///
/// Returns `None` when error generation is suppressed: an error in response to
/// an error, an unusable source, a non-initial IPv4 fragment, or a multicast
/// destination (except IPv6 Packet Too Big). The caller must also suppress errors
/// for link-layer broadcasts and subnet-directed IPv4 broadcasts, which cannot
/// be identified without link configuration, and apply a rate limit.
///
/// Replies are at most 576 bytes for IPv4 and 1280 for IPv6; they do not reflect
/// arbitrary peer-sized payloads. `source` is an address selected by the caller's
/// routing policy, not automatically the invoking packet's destination.
pub fn encode_icmp_error(
    invoking: IpPacket<'_>,
    source: IpAddr,
    kind: IcmpErrorKind,
    output: &mut [u8],
) -> Result<Option<usize>, IpPacketError> {
    let destination = invoking.source();
    if source.is_ipv4() != destination.is_ipv4() {
        return Err(IpPacketError::Field);
    }
    if source.is_unspecified() || source.is_multicast() {
        return Err(IpPacketError::Field);
    }
    if destination.is_unspecified() || destination.is_multicast() || is_icmp_error(invoking) {
        return Ok(None);
    }
    let too_big = matches!(kind, IcmpErrorKind::PacketTooBig { .. });
    match invoking {
        IpPacket::V4(p) => {
            if p.fragment().offset != 0
                || p.destination().is_multicast()
                || p.destination().is_broadcast()
                || p.source().is_broadcast()
                || p.source().octets()[0] == 0
            {
                return Ok(None);
            }
            if let IcmpErrorKind::PacketTooBig { mtu } = kind
                && mtu > 65535
            {
                return Err(IpPacketError::Field);
            }
        }
        IpPacket::V6(p) if p.destination().is_multicast() && !too_big => return Ok(None),
        IpPacket::V6(_) => (),
    }
    let v4 = source.is_ipv4();
    let quote_len = invoking.as_bytes().len().min(if v4 { 548 } else { 1232 });
    let payload_len = 8 + quote_len;
    let size = payload_len + if v4 { 20 } else { 40 };
    let body = match (source, destination) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            Ipv4Header::new(src, dst, IpProtocol::ICMP).encode_header(&[], payload_len, output)?
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            Ipv6Header::new(src, dst, IpProtocol::ICMPV6).encode_header(payload_len, output)?
        }
        _ => return Err(IpPacketError::Field),
    };
    body[..8].fill(0);
    match (v4, kind) {
        (true, IcmpErrorKind::NoRoute) => {
            body[0] = 3;
            body[1] = 0;
        }
        (true, IcmpErrorKind::AdministrativelyProhibited | IcmpErrorKind::SourcePolicy) => {
            body[0] = 3;
            body[1] = 13;
        }
        (true, IcmpErrorKind::PacketTooBig { mtu }) => {
            body[0] = 3;
            body[1] = 4;
            body[6..8].copy_from_slice(&(mtu as u16).to_be_bytes());
        }
        (true, IcmpErrorKind::HopLimitExceeded) => body[0] = 11,
        (false, IcmpErrorKind::NoRoute) => body[0] = 1,
        (false, IcmpErrorKind::AdministrativelyProhibited) => {
            body[0] = 1;
            body[1] = 1;
        }
        (false, IcmpErrorKind::SourcePolicy) => {
            body[0] = 1;
            body[1] = 5;
        }
        (false, IcmpErrorKind::PacketTooBig { mtu }) => {
            body[0] = 2;
            body[4..8].copy_from_slice(&mtu.to_be_bytes());
        }
        (false, IcmpErrorKind::HopLimitExceeded) => body[0] = 3,
    }
    body[8..].copy_from_slice(&invoking.as_bytes()[..quote_len]);
    let checksum = match (source, destination) {
        (IpAddr::V4(_), IpAddr::V4(_)) => internet_checksum(body),
        (IpAddr::V6(src), IpAddr::V6(dst)) => icmpv6_checksum(src, dst, body)?,
        _ => return Err(IpPacketError::Field),
    };
    body[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(Some(size))
}

/// Addresses and protocol from a possibly truncated ICMP quotation.
///
/// This is not a validated IP packet and must not be forwarded. The complete
/// header (including the extensions needed to identify the protocol) is required;
/// the quoted payload may be shorter than the original packet declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacketQuote {
    /// Original source.
    pub source: IpAddr,
    /// Original destination.
    pub destination: IpAddr,
    /// Original protocol, if known without reassembly.
    pub protocol: Option<IpProtocol>,
}

impl IpPacketQuote {
    /// Parse the header of an invoking packet quoted by an ICMP error.
    pub fn parse(bytes: &[u8]) -> Result<Self, IpPacketError> {
        let packet = match bytes.first().map(|b| b >> 4) {
            Some(4) => IpPacket::V4(super::Ipv4Packet::parse_inner(bytes, true)?),
            Some(6) => IpPacket::V6(super::Ipv6Packet::parse_inner(bytes, true)?),
            None => return Err(IpPacketError::Truncated),
            _ => return Err(IpPacketError::Version),
        };
        Ok(Self {
            source: packet.source(),
            destination: packet.destination(),
            protocol: packet.protocol(),
        })
    }
}

/// The two ICMPv6 echo message kinds used by link-MTU verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Icmpv6EchoKind {
    /// Echo Request.
    Request,
    /// Echo Reply.
    Reply,
}

/// A borrowed ICMPv6 echo message, independent of transport or probe tracking.
#[derive(Debug, Clone, Copy)]
pub struct Icmpv6Echo<'a> {
    /// Request or reply.
    pub kind: Icmpv6EchoKind,
    /// Identifier chosen by the sender.
    pub identifier: u16,
    /// Sequence number chosen by the sender.
    pub sequence: u16,
    /// Echoed bytes; parsing does not copy them.
    pub data: &'a [u8],
}

impl<'a> Icmpv6Echo<'a> {
    /// Decode a complete, unfragmented echo and verify its code and checksum.
    pub fn parse(packet: super::Ipv6Packet<'a>) -> Result<Self, IpPacketError> {
        if packet.protocol() != Some(IpProtocol::ICMPV6)
            || packet.fragment().is_some_and(|f| f.is_fragmented())
        {
            return Err(IpPacketError::Field);
        }
        let body = packet
            .upper_layer_payload()
            .ok_or(IpPacketError::Truncated)?;
        let header = body.get(..8).ok_or(IpPacketError::Truncated)?;
        let kind = match header[0] {
            128 => Icmpv6EchoKind::Request,
            129 => Icmpv6EchoKind::Reply,
            _ => return Err(IpPacketError::Field),
        };
        if header[1] != 0 {
            return Err(IpPacketError::Field);
        }
        if icmpv6_checksum(packet.source(), packet.destination(), body)? != 0 {
            return Err(IpPacketError::Checksum);
        }
        Ok(Self {
            kind,
            identifier: u16::from_be_bytes([header[4], header[5]]),
            sequence: u16::from_be_bytes([header[6], header[7]]),
            data: &body[8..],
        })
    }

    /// Construct the matching reply without copying its data.
    #[must_use]
    pub fn reply(self) -> Self {
        Self {
            kind: Icmpv6EchoKind::Reply,
            ..self
        }
    }

    /// Encode directly into the caller's packet buffer, including the IPv6 header.
    pub fn encode(
        self,
        source: Ipv6Addr,
        destination: Ipv6Addr,
        output: &mut [u8],
    ) -> Result<usize, IpPacketError> {
        let payload_len = self
            .data
            .len()
            .checked_add(8)
            .ok_or(IpPacketError::Length)?;
        let body = Ipv6Header::new(source, destination, IpProtocol::ICMPV6)
            .encode_header(payload_len, output)?;
        body[..8].fill(0);
        body[0] = match self.kind {
            Icmpv6EchoKind::Request => 128,
            Icmpv6EchoKind::Reply => 129,
        };
        body[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        body[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        body[8..].copy_from_slice(self.data);
        let checksum = icmpv6_checksum(source, destination, body)?;
        body[2..4].copy_from_slice(&checksum.to_be_bytes());
        Ok(40 + payload_len)
    }
}
