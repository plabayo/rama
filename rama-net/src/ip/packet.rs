use super::{EcnCodepoint, IpProtocol, internet_checksum};
use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
};

/// An invalid packet or an operation that cannot be represented on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpPacketError {
    /// The input or output buffer is too short.
    Truncated,
    /// Neither IPv4 nor IPv6.
    Version,
    /// A header, payload, option or fragment length is inconsistent.
    Length,
    /// The IPv4 header checksum is incorrect.
    Checksum,
    /// Invalid reserved bits, options or extension-header structure.
    Header,
    /// More than 32 IPv6 extension headers.
    ExtensionLimit,
    /// IPv6 jumbograms are not supported by this packet representation.
    Jumbogram,
    /// A field cannot be represented by this header.
    Field,
    /// Forwarding would exhaust the TTL / Hop Limit.
    HopLimit,
}

impl fmt::Display for IpPacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated IP packet or output buffer",
            Self::Version => "unsupported IP version",
            Self::Length => "inconsistent IP length",
            Self::Checksum => "invalid IPv4 header checksum",
            Self::Header => "invalid IP header",
            Self::ExtensionLimit => "IPv6 extension header limit exceeded",
            Self::Jumbogram => "IPv6 jumbogram is not supported",
            Self::Field => "IP field outside its wire range",
            Self::HopLimit => "IP hop limit exhausted",
        })
    }
}

impl core::error::Error for IpPacketError {}

/// Fragment metadata. `offset` is measured in bytes, not wire units of eight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpFragment {
    /// Fragment identification.
    pub identification: u32,
    /// Offset in the original payload.
    pub offset: u16,
    /// More fragments follow.
    pub more: bool,
}

impl IpFragment {
    /// Whether this is part of a fragmented packet (rather than an atomic fragment).
    #[must_use]
    pub const fn is_fragmented(self) -> bool {
        self.offset != 0 || self.more
    }
}

/// A validated IPv4 packet view. Trailing bytes after Total Length are excluded.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<'a> {
    bytes: &'a [u8],
    header_len: usize,
}

impl<'a> Ipv4Packet<'a> {
    /// Validate lengths, options, fragmentation and the IPv4 header checksum.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, IpPacketError> {
        Self::parse_inner(bytes, false)
    }

    pub(super) fn parse_inner(bytes: &'a [u8], quoted: bool) -> Result<Self, IpPacketError> {
        if bytes.len() < 20 {
            return Err(IpPacketError::Truncated);
        }
        if bytes[0] >> 4 != 4 {
            return Err(IpPacketError::Version);
        }
        let header_len = usize::from(bytes[0] & 15) * 4;
        let total = usize::from(word(bytes, 2));
        if header_len < 20 || total < header_len {
            return Err(IpPacketError::Length);
        }
        let length = if quoted {
            bytes.len().min(total)
        } else {
            total
        };
        let bytes = bytes
            .get(..length)
            .filter(|bytes| bytes.len() >= header_len)
            .ok_or(IpPacketError::Truncated)?;
        if internet_checksum(&bytes[..header_len]) != 0 {
            return Err(IpPacketError::Checksum);
        }
        validate_ipv4_options(&bytes[20..header_len])?;
        let flags = word(bytes, 6);
        if flags & 0x8000 != 0 {
            return Err(IpPacketError::Header);
        }
        if flags & 0x2000 != 0 && (total == header_len || !(total - header_len).is_multiple_of(8)) {
            return Err(IpPacketError::Length);
        }
        if usize::from(flags & 0x1fff) * 8 + total > 65535 {
            return Err(IpPacketError::Length);
        }
        Ok(Self { bytes, header_len })
    }

    /// Complete packet, bounded by Total Length.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Header including options.
    #[must_use]
    pub fn header(self) -> &'a [u8] {
        &self.bytes[..self.header_len]
    }

    /// Options, including padding.
    #[must_use]
    pub fn options(self) -> &'a [u8] {
        &self.bytes[20..self.header_len]
    }

    /// Iterate over validated options without re-decoding lengths in callers.
    pub fn option_iter(self) -> Ipv4Options<'a> {
        Ipv4Options {
            remaining: self.options(),
        }
    }

    /// Payload (a fragment's payload if fragmented).
    #[must_use]
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[self.header_len..]
    }

    /// Source address.
    #[must_use]
    pub fn source(self) -> Ipv4Addr {
        v4(&self.bytes[12..16])
    }

    /// Destination address.
    #[must_use]
    pub fn destination(self) -> Ipv4Addr {
        v4(&self.bytes[16..20])
    }

    /// Protocol number, including on non-initial fragments.
    #[must_use]
    pub fn protocol(self) -> IpProtocol {
        IpProtocol::new(self.bytes[9])
    }

    /// Time to live.
    #[must_use]
    pub fn hop_limit(self) -> u8 {
        self.bytes[8]
    }

    /// DSCP and ECN bits.
    #[must_use]
    pub fn traffic_class(self) -> u8 {
        self.bytes[1]
    }

    /// Don't Fragment flag.
    #[must_use]
    pub fn dont_fragment(self) -> bool {
        self.bytes[6] & 0x40 != 0
    }

    /// Identification, byte offset and More Fragments flag.
    #[must_use]
    pub fn fragment(self) -> IpFragment {
        let flags = word(self.bytes, 6);
        IpFragment {
            identification: u32::from(word(self.bytes, 4)),
            offset: (flags & 0x1fff) * 8,
            more: flags & 0x2000 != 0,
        }
    }
}

/// A borrowed IPv4 option. Single-byte padding options have empty data.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Option<'a> {
    /// Wire option kind, preserving unknown options.
    pub kind: u8,
    /// Option bytes following the kind and length.
    pub data: &'a [u8],
}

/// Iterator over the options of a validated IPv4 header.
#[derive(Debug, Clone)]
pub struct Ipv4Options<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for Ipv4Options<'a> {
    type Item = Ipv4Option<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&kind, rest) = self.remaining.split_first()?;
        if kind <= 1 {
            self.remaining = if kind == 0 { &[] } else { rest };
            return Some(Ipv4Option { kind, data: &[] });
        }
        let length = usize::from(*rest.first()?);
        let data = self.remaining.get(2..length)?;
        self.remaining = self.remaining.get(length..)?;
        Some(Ipv4Option { kind, data })
    }
}

fn validate_ipv4_options(mut options: &[u8]) -> Result<(), IpPacketError> {
    while let Some((&kind, rest)) = options.split_first() {
        match kind {
            0 => {
                return if rest.iter().all(|b| *b == 0) {
                    Ok(())
                } else {
                    Err(IpPacketError::Header)
                };
            }
            1 => options = rest,
            _ => {
                let len = usize::from(*rest.first().ok_or(IpPacketError::Header)?);
                if len < 2 {
                    return Err(IpPacketError::Header);
                }
                options = options.get(len..).ok_or(IpPacketError::Header)?;
            }
        }
    }
    Ok(())
}

/// A validated IPv6 packet view, including a bounded extension-header walk.
///
/// Encrypted ESP payloads and unknown next-header numbers are left opaque.
/// Jumbograms require a different length model and are rejected explicitly.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Packet<'a> {
    bytes: &'a [u8],
    upper_offset: Option<NonZeroUsize>,
    protocol: Option<IpProtocol>,
    fragment: Option<IpFragment>,
}

impl<'a> Ipv6Packet<'a> {
    /// Validate base length and the structure of known extension headers.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, IpPacketError> {
        Self::parse_inner(bytes, false)
    }

    pub(super) fn parse_inner(bytes: &'a [u8], quoted: bool) -> Result<Self, IpPacketError> {
        if bytes.len() < 40 {
            return Err(IpPacketError::Truncated);
        }
        if bytes[0] >> 4 != 6 {
            return Err(IpPacketError::Version);
        }
        let payload_len = usize::from(word(bytes, 4));
        if payload_len == 0 && bytes.len() > 40 && bytes[6] == 0 {
            return Err(IpPacketError::Jumbogram);
        }
        let total = 40 + payload_len;
        let length = if quoted {
            bytes.len().min(total)
        } else {
            total
        };
        let bytes = bytes.get(..length).ok_or(IpPacketError::Truncated)?;
        let mut offset = 40;
        let mut next = bytes[6];
        let mut fragment = None;
        let mut count = 0;
        while is_extension(next) {
            if count == 32 {
                return Err(IpPacketError::ExtensionLimit);
            }
            count += 1;
            let ext = extension(bytes, offset, next)?;
            if next == 0 && offset != 40 {
                return Err(IpPacketError::Header);
            }
            if next == 0 || next == 60 {
                validate_ipv6_options(&ext[2..])?;
            }
            if next == 44 {
                if fragment.is_some() {
                    return Err(IpPacketError::Header);
                }
                let bits = word(ext, 2);
                let f = IpFragment {
                    identification: u32::from_be_bytes([ext[4], ext[5], ext[6], ext[7]]),
                    offset: bits & 0xfff8,
                    more: bits & 1 != 0,
                };
                let remaining = total - offset - 8;
                if f.more && (remaining == 0 || !remaining.is_multiple_of(8)) {
                    return Err(IpPacketError::Length);
                }
                if usize::from(f.offset) + remaining + offset - 40 > 65535 {
                    return Err(IpPacketError::Length);
                }
                fragment = Some(f);
                if f.offset != 0 {
                    // The next extension header might be in a different fragment.
                    return Ok(Self {
                        bytes,
                        upper_offset: None,
                        protocol: if IpProtocol::new(ext[0]).is_ipv6_extension() {
                            None
                        } else {
                            Some(IpProtocol::new(ext[0]))
                        },
                        fragment,
                    });
                }
            }
            next = ext[0];
            offset += ext.len();
        }
        Ok(Self {
            bytes,
            upper_offset: if next == IpProtocol::ESP.value()
                || next == IpProtocol::NO_NEXT_HEADER.value()
            {
                None
            } else {
                NonZeroUsize::new(offset)
            },
            protocol: (next != IpProtocol::ESP.value()).then_some(IpProtocol::new(next)),
            fragment,
        })
    }

    /// Complete packet, bounded by Payload Length.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Source address.
    #[must_use]
    pub fn source(self) -> Ipv6Addr {
        v6(&self.bytes[8..24])
    }

    /// Destination address.
    #[must_use]
    pub fn destination(self) -> Ipv6Addr {
        v6(&self.bytes[24..40])
    }

    /// The base header's next-header number.
    #[must_use]
    pub fn next_header(self) -> IpProtocol {
        IpProtocol::new(self.bytes[6])
    }

    /// First non-extension protocol, or `None` if a non-initial fragment hides it.
    #[must_use]
    pub fn protocol(self) -> Option<IpProtocol> {
        self.protocol
    }

    /// Hop Limit.
    #[must_use]
    pub fn hop_limit(self) -> u8 {
        self.bytes[7]
    }

    /// DSCP and ECN bits.
    #[must_use]
    pub fn traffic_class(self) -> u8 {
        (self.bytes[0] << 4) | (self.bytes[1] >> 4)
    }

    /// Twenty-bit Flow Label.
    #[must_use]
    pub fn flow_label(self) -> u32 {
        u32::from_be_bytes([0, self.bytes[1] & 15, self.bytes[2], self.bytes[3]])
    }

    /// Payload including extension headers.
    #[must_use]
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[40..]
    }

    /// Upper-layer bytes, absent for non-initial fragments, ESP and No Next Header.
    #[must_use]
    pub fn upper_layer_payload(self) -> Option<&'a [u8]> {
        self.upper_offset.map(|offset| &self.bytes[offset.get()..])
    }

    /// Fragment metadata, including atomic fragments.
    #[must_use]
    pub fn fragment(self) -> Option<IpFragment> {
        self.fragment
    }

    /// Known extension headers in wire order, including the Fragment header.
    #[must_use]
    pub fn extensions(self) -> Ipv6Extensions<'a> {
        Ipv6Extensions {
            bytes: self.bytes,
            offset: 40,
            next: self.bytes[6],
            done: false,
        }
    }
}

/// A borrowed IPv6 extension header. Unknown option bytes are retained.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Extension<'a> {
    /// Extension-header type.
    pub protocol: IpProtocol,
    /// Entire header, including its Next Header byte.
    pub bytes: &'a [u8],
}

/// Iterator over a previously validated packet's extension headers.
#[derive(Debug, Clone)]
pub struct Ipv6Extensions<'a> {
    bytes: &'a [u8],
    offset: usize,
    next: u8,
    done: bool,
}

impl<'a> Iterator for Ipv6Extensions<'a> {
    type Item = Ipv6Extension<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || !is_extension(self.next) {
            return None;
        }
        let bytes = extension(self.bytes, self.offset, self.next).ok()?;
        let protocol = IpProtocol::new(self.next);
        if self.next == 44 && word(bytes, 2) & 0xfff8 != 0 {
            self.done = true;
        }
        self.offset += bytes.len();
        self.next = bytes[0];
        Some(Ipv6Extension { protocol, bytes })
    }
}

fn is_extension(value: u8) -> bool {
    IpProtocol::new(value).is_ipv6_extension() && value != IpProtocol::ESP.value()
}

fn extension(bytes: &[u8], offset: usize, kind: u8) -> Result<&[u8], IpPacketError> {
    let rest = bytes.get(offset..).ok_or(IpPacketError::Truncated)?;
    if rest.len() < 2 {
        return Err(IpPacketError::Truncated);
    }
    let len = match kind {
        44 => 8,
        51 => (usize::from(rest[1]) + 2) * 4,
        _ => (usize::from(rest[1]) + 1) * 8,
    };
    if kind == 51 && len < 12 {
        return Err(IpPacketError::Header);
    }
    rest.get(..len).ok_or(IpPacketError::Truncated)
}

fn validate_ipv6_options(mut options: &[u8]) -> Result<(), IpPacketError> {
    while let Some((&kind, rest)) = options.split_first() {
        if kind == 0 {
            options = rest;
            continue;
        }
        if kind == 0xc2 {
            return Err(IpPacketError::Jumbogram);
        }
        let len = usize::from(*rest.first().ok_or(IpPacketError::Header)?) + 2;
        options = options.get(len..).ok_or(IpPacketError::Header)?;
    }
    Ok(())
}

/// A checked IP packet, independent of its link or tunnel protocol.
#[derive(Debug, Clone, Copy)]
pub enum IpPacket<'a> {
    /// IPv4 packet.
    V4(Ipv4Packet<'a>),
    /// IPv6 packet.
    V6(Ipv6Packet<'a>),
}

impl<'a> IpPacket<'a> {
    /// Parse one packet; [`Self::as_bytes`] excludes trailing link-layer padding.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, IpPacketError> {
        match bytes.first().map(|b| b >> 4) {
            Some(4) => Ipv4Packet::parse(bytes).map(Self::V4),
            Some(6) => Ipv6Packet::parse(bytes).map(Self::V6),
            None => Err(IpPacketError::Truncated),
            _ => Err(IpPacketError::Version),
        }
    }

    /// Complete packet bytes.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        match self {
            Self::V4(p) => p.as_bytes(),
            Self::V6(p) => p.as_bytes(),
        }
    }

    /// Append this validated packet and decrement its hop count.
    /// The IPv4 checksum is updated incrementally (RFC 1624); options need no reparse.
    /// An exhausted hop count or short output leaves the output untouched.
    pub fn encode_forwarded(
        self,
        mut output: impl rama_core::bytes::BufMut,
    ) -> Result<usize, IpPacketError> {
        if self.hop_limit() <= 1 {
            return Err(IpPacketError::HopLimit);
        }
        let bytes = self.as_bytes();
        if output.remaining_mut() < bytes.len() {
            return Err(IpPacketError::Truncated);
        }
        match self {
            Self::V4(_) => {
                let old = word(bytes, 8);
                let new = old - 256;
                let sum = u32::from(!word(bytes, 10)) + u32::from(!old) + u32::from(new);
                // Decrementing TTL changes this word by exactly -256, so the
                // unfolded sum is at most 0x1fefe and one carry fold suffices.
                let checksum = !(((sum & 0xffff) + (sum >> 16)) as u16);
                output.put_slice(&bytes[..8]);
                output.put_u16(new);
                output.put_u16(checksum);
                output.put_slice(&bytes[12..]);
            }
            Self::V6(_) => {
                output.put_slice(&bytes[..7]);
                output.put_u8(bytes[7] - 1);
                output.put_slice(&bytes[8..]);
            }
        }
        Ok(bytes.len())
    }

    /// Source address.
    #[must_use]
    pub fn source(self) -> IpAddr {
        match self {
            Self::V4(p) => p.source().into(),
            Self::V6(p) => p.source().into(),
        }
    }

    /// Destination address.
    #[must_use]
    pub fn destination(self) -> IpAddr {
        match self {
            Self::V4(p) => p.destination().into(),
            Self::V6(p) => p.destination().into(),
        }
    }

    /// Upper-layer protocol, if available without reassembly.
    #[must_use]
    pub fn protocol(self) -> Option<IpProtocol> {
        match self {
            Self::V4(p) => Some(p.protocol()),
            Self::V6(p) => p.protocol(),
        }
    }

    /// Upper-layer bytes, absent for non-initial fragments and No Next Header.
    #[must_use]
    pub fn upper_layer_payload(self) -> Option<&'a [u8]> {
        match self {
            Self::V4(p) if p.fragment().offset == 0 => Some(p.payload()),
            Self::V4(_) => None,
            Self::V6(p) => p.upper_layer_payload(),
        }
    }

    /// TTL / Hop Limit.
    #[must_use]
    pub fn hop_limit(self) -> u8 {
        match self {
            Self::V4(p) => p.hop_limit(),
            Self::V6(p) => p.hop_limit(),
        }
    }

    /// DSCP and ECN bits.
    #[must_use]
    pub fn traffic_class(self) -> u8 {
        match self {
            Self::V4(p) => p.traffic_class(),
            Self::V6(p) => p.traffic_class(),
        }
    }

    /// Explicit Congestion Notification codepoint.
    #[must_use]
    pub fn ecn(self) -> EcnCodepoint {
        EcnCodepoint::from_bits(self.traffic_class())
    }

    /// Fragment metadata; IPv4 has identification even when not fragmented.
    #[must_use]
    pub fn fragment(self) -> Option<IpFragment> {
        match self {
            Self::V4(p) => Some(p.fragment()),
            Self::V6(p) => p.fragment(),
        }
    }
}

/// IPv4 header fields for packet construction. Options are supplied to [`Self::encode`].
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    /// Source address.
    pub source: Ipv4Addr,
    /// Destination address.
    pub destination: Ipv4Addr,
    /// Payload protocol.
    pub protocol: IpProtocol,
    /// Time to live.
    pub hop_limit: u8,
    /// DSCP and ECN.
    pub traffic_class: u8,
    /// Packet identification and fragmentation metadata.
    /// Encoding requires a sixteen-bit identification and an eight-byte-aligned offset.
    pub fragment: IpFragment,
    /// Don't Fragment flag.
    pub dont_fragment: bool,
}

impl Ipv4Header {
    /// An unfragmented header with hop limit 64, no ECN/DSCP and identification zero.
    #[must_use]
    pub const fn new(source: Ipv4Addr, destination: Ipv4Addr, protocol: IpProtocol) -> Self {
        Self {
            source,
            destination,
            protocol,
            hop_limit: 64,
            traffic_class: 0,
            fragment: IpFragment {
                identification: 0,
                offset: 0,
                more: false,
            },
            dont_fragment: false,
        }
    }

    /// Set the IPv4 identification, whose wire width is sixteen bits.
    #[must_use]
    pub const fn with_identification(mut self, identification: u16) -> Self {
        self.fragment.identification = identification as u32;
        self
    }

    /// Set a fragment's byte offset and More Fragments flag.
    /// Offsets must be aligned to eight bytes; payload-dependent checks occur on encoding.
    pub const fn try_with_fragment(
        mut self,
        offset: u16,
        more: bool,
    ) -> Result<Self, IpPacketError> {
        if offset & 7 != 0 {
            return Err(IpPacketError::Field);
        }
        self.fragment.offset = offset;
        self.fragment.more = more;
        Ok(self)
    }

    /// Identification and fragment metadata.
    pub const fn fragment(&self) -> IpFragment {
        self.fragment
    }

    /// Serialize a complete packet. Options must include zero padding to a four-byte boundary.
    /// The output is untouched when any input is invalid.
    pub fn encode(
        &self,
        options: &[u8],
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, IpPacketError> {
        self.encode_header(options, payload.len(), output)?
            .copy_from_slice(payload);
        Ok(20 + options.len() + payload.len())
    }

    /// Write the header and return the caller-owned payload region to fill.
    /// Lengths and options are checked before touching the output.
    pub fn encode_header<'b>(
        &self,
        options: &[u8],
        payload_len: usize,
        output: &'b mut [u8],
    ) -> Result<&'b mut [u8], IpPacketError> {
        if options.len() > 40 || !options.len().is_multiple_of(4) {
            return Err(IpPacketError::Length);
        }
        validate_ipv4_options(options)?;
        let f = self.fragment;
        if f.identification > u32::from(u16::MAX) || f.offset & 7 != 0 {
            return Err(IpPacketError::Field);
        }
        let header_len = 20 + options.len();
        let total = header_len
            .checked_add(payload_len)
            .filter(|n| *n <= 65535)
            .ok_or(IpPacketError::Length)?;
        if (f.more && (payload_len == 0 || !payload_len.is_multiple_of(8)))
            || usize::from(f.offset) + total > 65535
        {
            return Err(IpPacketError::Length);
        }
        let out = output.get_mut(..total).ok_or(IpPacketError::Truncated)?;
        out[..header_len].fill(0);
        out[0] = 0x40 | (header_len / 4) as u8;
        out[1] = self.traffic_class;
        out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        out[4..6].copy_from_slice(&(f.identification as u16).to_be_bytes());
        let flags =
            (u16::from(self.dont_fragment) << 14) | (u16::from(f.more) << 13) | (f.offset / 8);
        out[6..8].copy_from_slice(&flags.to_be_bytes());
        out[8] = self.hop_limit;
        out[9] = self.protocol.value();
        out[12..16].copy_from_slice(&self.source.octets());
        out[16..20].copy_from_slice(&self.destination.octets());
        out[20..header_len].copy_from_slice(options);
        let checksum = internet_checksum(&out[..header_len]);
        out[10..12].copy_from_slice(&checksum.to_be_bytes());
        Ok(&mut out[header_len..])
    }
}

/// IPv6 base-header fields for construction; extension headers are supplied in the payload.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Header {
    /// Source address.
    pub source: Ipv6Addr,
    /// Destination address.
    pub destination: Ipv6Addr,
    /// First extension header or upper-layer protocol.
    pub next_header: IpProtocol,
    /// Hop Limit.
    pub hop_limit: u8,
    /// DSCP and ECN bits.
    pub traffic_class: u8,
    /// Twenty-bit Flow Label.
    flow_label: u32,
}

impl Ipv6Header {
    /// A header with hop limit 64, zero flow label and no ECN/DSCP.
    #[must_use]
    pub const fn new(source: Ipv6Addr, destination: Ipv6Addr, next_header: IpProtocol) -> Self {
        Self {
            source,
            destination,
            next_header,
            hop_limit: 64,
            traffic_class: 0,
            flow_label: 0,
        }
    }

    /// Set the twenty-bit IPv6 flow label.
    pub const fn try_with_flow_label(mut self, flow_label: u32) -> Result<Self, IpPacketError> {
        if flow_label > 0xfffff {
            return Err(IpPacketError::Field);
        }
        self.flow_label = flow_label;
        Ok(self)
    }

    /// The configured IPv6 flow label.
    pub const fn flow_label(&self) -> u32 {
        self.flow_label
    }

    /// Serialize a base header and payload. This does not validate extension bytes:
    /// use [`Ipv6Packet::parse`] to validate a complete packet built from raw extensions.
    /// The output is untouched when the base fields or buffer length are invalid.
    pub fn encode(&self, payload: &[u8], output: &mut [u8]) -> Result<usize, IpPacketError> {
        self.encode_header(payload.len(), output)?
            .copy_from_slice(payload);
        Ok(40 + payload.len())
    }

    /// Write the IPv6 base header and return its payload region for in-place encoding.
    pub fn encode_header<'b>(
        &self,
        payload_len: usize,
        output: &'b mut [u8],
    ) -> Result<&'b mut [u8], IpPacketError> {
        let len = u16::try_from(payload_len).map_err(|_error| IpPacketError::Length)?;
        let total = 40 + payload_len;
        let out = output.get_mut(..total).ok_or(IpPacketError::Truncated)?;
        let first = (6u32 << 28) | (u32::from(self.traffic_class) << 20) | self.flow_label;
        out[..4].copy_from_slice(&first.to_be_bytes());
        out[4..6].copy_from_slice(&len.to_be_bytes());
        out[6] = self.next_header.value();
        out[7] = self.hop_limit;
        out[8..24].copy_from_slice(&self.source.octets());
        out[24..40].copy_from_slice(&self.destination.octets());
        Ok(&mut out[40..])
    }
}

/// Decrement a forwarded packet's hop count once, updating the IPv4 checksum.
///
/// An invalid packet or exhausted hop count leaves the buffer unchanged. Call
/// before forwarding onto another link, not merely because a packet was received
/// or decapsulated. Locally generated packets do not need this operation.
pub fn decrement_hop_limit(bytes: &mut [u8]) -> Result<(), IpPacketError> {
    let packet = IpPacket::parse(bytes)?;
    let hop = packet.hop_limit();
    if hop <= 1 {
        return Err(IpPacketError::HopLimit);
    }
    match packet {
        IpPacket::V4(p) => {
            let len = p.header_len;
            bytes[8] = hop - 1;
            update_ipv4_checksum(&mut bytes[..len]);
        }
        IpPacket::V6(_) => bytes[7] = hop - 1,
    }
    Ok(())
}

/// Set DSCP/ECN bits, preserving the IPv6 flow label and repairing IPv4's checksum.
/// Invalid packets are left unchanged.
pub fn set_traffic_class(bytes: &mut [u8], traffic_class: u8) -> Result<(), IpPacketError> {
    match IpPacket::parse(bytes)? {
        IpPacket::V4(p) => {
            let len = p.header_len;
            bytes[1] = traffic_class;
            update_ipv4_checksum(&mut bytes[..len]);
        }
        IpPacket::V6(_) => {
            bytes[0] = 0x60 | (traffic_class >> 4);
            bytes[1] = (bytes[1] & 15) | (traffic_class << 4);
        }
    }
    Ok(())
}

fn update_ipv4_checksum(header: &mut [u8]) {
    header[10..12].fill(0);
    let sum = internet_checksum(header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn v4(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

fn v6(bytes: &[u8]) -> Ipv6Addr {
    let mut octets = [0; 16];
    octets.copy_from_slice(bytes);
    Ipv6Addr::from(octets)
}
