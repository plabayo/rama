//! ICMP forwarding errors without a socket or routing-table dependency.

use super::{
    InternetChecksum, IpPacket, IpPacketError, IpProtocol, Ipv4Header, Ipv6Header,
    internet_checksum,
};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    let mut body = [0; 1240];
    let body = &mut body[..8 + quote_len];
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
    let size = match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let sum = internet_checksum(body);
            body[2..4].copy_from_slice(&sum.to_be_bytes());
            Ipv4Header::new(source, destination, IpProtocol::ICMP).encode(&[], body, output)?
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            let sum = icmpv6_checksum(source, destination, body)?;
            body[2..4].copy_from_slice(&sum.to_be_bytes());
            Ipv6Header::new(source, destination, IpProtocol::ICMPV6).encode(body, output)?
        }
        _ => return Err(IpPacketError::Field),
    };
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
        match bytes.first().map(|b| b >> 4) {
            Some(4) => {
                if bytes.len() < 20 {
                    return Err(IpPacketError::Truncated);
                }
                let len = usize::from(bytes[0] & 15) * 4;
                if len < 20 || usize::from(u16::from_be_bytes([bytes[2], bytes[3]])) < len {
                    return Err(IpPacketError::Length);
                }
                let header = bytes.get(..len).ok_or(IpPacketError::Truncated)?;
                if internet_checksum(header) != 0 {
                    return Err(IpPacketError::Checksum);
                }
                Ok(Self {
                    source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]).into(),
                    destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]).into(),
                    protocol: Some(IpProtocol::new(bytes[9])),
                })
            }
            Some(6) => {
                if bytes.len() < 40 {
                    return Err(IpPacketError::Truncated);
                }
                let mut source = [0; 16];
                source.copy_from_slice(&bytes[8..24]);
                let mut destination = [0; 16];
                destination.copy_from_slice(&bytes[24..40]);
                let mut offset = 40;
                let mut next = bytes[6];
                let declared = 40 + usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
                let bytes = &bytes[..bytes.len().min(declared)];
                let mut count = 0;
                let protocol = loop {
                    if !matches!(next, 0 | 43 | 44 | 51 | 60) {
                        break Some(IpProtocol::new(next));
                    }
                    if count == 32 {
                        return Err(IpPacketError::ExtensionLimit);
                    }
                    count += 1;
                    let rest = bytes.get(offset..).ok_or(IpPacketError::Truncated)?;
                    if rest.len() < 2 {
                        return Err(IpPacketError::Truncated);
                    }
                    let len = match next {
                        44 => 8,
                        51 => (usize::from(rest[1]) + 2) * 4,
                        _ => (usize::from(rest[1]) + 1) * 8,
                    };
                    if len > rest.len() {
                        return Err(IpPacketError::Truncated);
                    }
                    if next == 44 && u16::from_be_bytes([rest[2], rest[3]]) & 0xfff8 != 0 {
                        break None;
                    }
                    offset += len;
                    next = rest[0];
                };
                Ok(Self {
                    source: Ipv6Addr::from(source).into(),
                    destination: Ipv6Addr::from(destination).into(),
                    protocol,
                })
            }
            None => Err(IpPacketError::Truncated),
            _ => Err(IpPacketError::Version),
        }
    }
}

/// Encode an ICMPv6 Echo Request or Reply, including its IPv6 header/checksum.
/// The caller chooses addresses, identifier, sequence and data (RFC 4443 §4).
/// No extension headers or fragmentation are generated.
pub fn encode_icmpv6_echo(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    identifier: u16,
    sequence: u16,
    data: &[u8],
    reply: bool,
    output: &mut [u8],
) -> Result<usize, IpPacketError> {
    let payload_len = data
        .len()
        .checked_add(8)
        .filter(|n| *n <= 65535)
        .ok_or(IpPacketError::Length)?;
    let total = 40 + payload_len;
    let output = output.get_mut(..total).ok_or(IpPacketError::Truncated)?;
    // Write the base header without a temporary packet-sized allocation.
    Ipv6Header::new(source, destination, IpProtocol::ICMPV6).encode(&[], output)?;
    output[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    let body = &mut output[40..];
    body[..8].fill(0);
    body[0] = if reply { 129 } else { 128 };
    body[4..6].copy_from_slice(&identifier.to_be_bytes());
    body[6..8].copy_from_slice(&sequence.to_be_bytes());
    body[8..].copy_from_slice(data);
    let checksum = icmpv6_checksum(source, destination, body)?;
    body[2..4].copy_from_slice(&checksum.to_be_bytes());
    Ok(total)
}
