use crate::context::ContextId;
use rama_core::bytes::{BufMut, Bytes, BytesMut};
use rama_http::proto::capsule::CapsuleType;
use rama_net::{address::ip::ipnet::IpNet, ip::IpProtocol};
use rama_quic_proto::{VarInt, coding::Codec};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

/// ADDRESS_ASSIGN (RFC 9484 §4.7.1).
pub const ADDRESS_ASSIGN: CapsuleType = CapsuleType::from_static(1);

/// ADDRESS_REQUEST (RFC 9484 §4.7.2).
pub const ADDRESS_REQUEST: CapsuleType = CapsuleType::from_static(2);

/// ROUTE_ADVERTISEMENT (RFC 9484 §4.7.3).
pub const ROUTE_ADVERTISEMENT: CapsuleType = CapsuleType::from_static(3);

/// Invalid CONNECT-IP control state or framing. No peer data is included in errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectIpProtocolError {
    /// Input ends within a field.
    Truncated,
    /// IP version is neither 4 nor 6.
    Version,
    /// Invalid prefix length or nonzero host bits.
    Prefix,
    /// Request ID is zero, reused, unknown or outside the QUIC varint range.
    RequestId,
    /// ADDRESS_REQUEST contains no requested addresses.
    EmptyRequest,
    /// Route family, range, ordering or overlap is invalid.
    Route,
    /// Configured control-state bound would be exceeded.
    Limit,
    /// This is not a defined CONNECT-IP control capsule.
    CapsuleType,
}

impl fmt::Display for ConnectIpProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated CONNECT-IP field",
            Self::Version => "invalid CONNECT-IP address family",
            Self::Prefix => "invalid CONNECT-IP prefix",
            Self::RequestId => "invalid CONNECT-IP request identifier",
            Self::EmptyRequest => "empty CONNECT-IP address request",
            Self::Route => "invalid CONNECT-IP routes",
            Self::Limit => "CONNECT-IP control limit exceeded",
            Self::CapsuleType => "unknown CONNECT-IP control capsule",
        })
    }
}

impl std::error::Error for ConnectIpProtocolError {}

/// A nonzero address request identifier in the QUIC variable-length range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressRequestId(VarInt);

impl AddressRequestId {
    /// Validate a dynamic request identifier at construction.
    pub fn new(value: u64) -> Result<Self, ConnectIpProtocolError> {
        if value == 0 {
            return Err(ConnectIpProtocolError::RequestId);
        }
        VarInt::from_u64(value)
            .map(Self)
            .map_err(|_error| ConnectIpProtocolError::RequestId)
    }

    /// Construct a statically known request ID.
    ///
    /// # Panics
    /// Panics when zero or outside the QUIC variable-length range.
    pub const fn from_static(value: u64) -> Self {
        assert!(value != 0, "address request ID must be nonzero");
        Self(VarInt::from_static(value))
    }

    /// The numeric identifier.
    pub const fn value(self) -> u64 {
        self.0.into_inner()
    }

    const fn varint(self) -> VarInt {
        self.0
    }
}

/// One source prefix assigned to the peer. An assignment capsule is a full snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressAssignment {
    /// `None` for an unsolicited assignment; otherwise the corresponding request ID.
    pub request_id: Option<AddressRequestId>,
    /// Canonical assigned prefix, or 0.0.0.0/32 or ::/128 to reject a request.
    pub prefix: IpNet,
}

impl AddressAssignment {
    /// Whether the entry reports that an address request was refused.
    #[must_use]
    pub fn is_rejection(self) -> bool {
        self.prefix.addr().is_unspecified()
            && self.prefix.prefix_len() == family_bits(self.prefix.addr())
    }
}

/// A preferred source prefix requested from the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRequest {
    /// Nonzero identifier, unique for the lifetime of this endpoint's request stream.
    pub request_id: AddressRequestId,
    /// All-zero address indicates no address preference; prefix length remains meaningful.
    pub prefix: IpNet,
}

/// An inclusive IP address range the sender is willing to route.
///
/// Ranges need not be CIDRs. `protocol: None` encodes zero (all protocols);
/// `Some(HOP_BY_HOP)` cannot be represented here. ICMP remains permitted by
/// RFC 9484 even when another specific protocol is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRoute {
    pub(super) start: IpAddr,
    pub(super) end: IpAddr,
    pub(super) protocol: Option<IpProtocol>,
}

impl IpRoute {
    /// Construct an inclusive range. Both addresses must have the same family,
    /// the end must not precede the start, and protocol zero is represented by `None`.
    pub fn new(
        start: IpAddr,
        end: IpAddr,
        protocol: Option<IpProtocol>,
    ) -> Result<Self, ConnectIpProtocolError> {
        if start.is_ipv4() != end.is_ipv4()
            || start > end
            || protocol == Some(IpProtocol::HOP_BY_HOP)
        {
            return Err(ConnectIpProtocolError::Route);
        }
        Ok(Self {
            start,
            end,
            protocol,
        })
    }

    /// Route all addresses in a prefix, without allocating individual addresses.
    /// Protocol zero is represented by `None` (all protocols).
    pub fn from_prefix(
        prefix: IpNet,
        protocol: Option<IpProtocol>,
    ) -> Result<Self, ConnectIpProtocolError> {
        Self::new(prefix.network(), prefix.broadcast(), protocol)
    }

    /// Inclusive first address.
    pub const fn start(&self) -> IpAddr {
        self.start
    }

    /// Inclusive last address, of the same family.
    pub const fn end(&self) -> IpAddr {
        self.end
    }

    /// Restricted protocol, or all protocols.
    pub const fn protocol(&self) -> Option<IpProtocol> {
        self.protocol
    }

    /// Whether the address is in this range, irrespective of protocol.
    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        address.is_ipv4() == self.start.is_ipv4() && self.start <= address && address <= self.end
    }

    /// Whether this range permits an address and known protocol.
    #[must_use]
    pub fn allows(self, address: IpAddr, protocol: Option<IpProtocol>) -> bool {
        self.contains(address)
            && (self.protocol.is_none()
                || protocol.is_some_and(|p| {
                    Some(p) == self.protocol
                        || p == if address.is_ipv4() {
                            IpProtocol::ICMP
                        } else {
                            IpProtocol::ICMPV6
                        }
                }))
    }
}

/// CONNECT-IP control capsules. Unknown capsules are skipped by the HTTP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectIpCapsule {
    /// Complete assignment snapshot for the receiver.
    AddressAssign(Vec<AddressAssignment>),
    /// One or more requests for source prefixes.
    AddressRequest(Vec<AddressRequest>),
    /// Complete advertised route snapshot for the receiver.
    RouteAdvertisement(Vec<IpRoute>),
}

impl ConnectIpCapsule {
    /// Capsule type on the wire.
    #[must_use]
    pub fn capsule_type(&self) -> CapsuleType {
        match self {
            Self::AddressAssign(_) => ADDRESS_ASSIGN,
            Self::AddressRequest(_) => ADDRESS_REQUEST,
            Self::RouteAdvertisement(_) => ROUTE_ADVERTISEMENT,
        }
    }

    /// Decode a complete value, enforcing an entry bound before growing state.
    pub fn decode(
        ty: CapsuleType,
        mut value: &[u8],
        max_entries: usize,
    ) -> Result<Self, ConnectIpProtocolError> {
        match ty {
            ADDRESS_ASSIGN | ADDRESS_REQUEST => {
                let mut entries = Vec::new();
                while !value.is_empty() {
                    if entries.len() == max_entries {
                        return Err(ConnectIpProtocolError::Limit);
                    }
                    let request_id = VarInt::decode(&mut value)
                        .map_err(|_error| ConnectIpProtocolError::Truncated)?
                        .into_inner();
                    let request_id = if request_id == 0 {
                        None
                    } else {
                        Some(AddressRequestId::new(request_id)?)
                    };
                    let version = take_byte(&mut value)?;
                    let address = take_address(&mut value, version)?;
                    let prefix = IpNet::new(address, take_byte(&mut value)?)
                        .map_err(|_error| ConnectIpProtocolError::Prefix)?;
                    validate_prefix(prefix)?;
                    entries.push(AddressAssignment { request_id, prefix });
                }
                if ty == ADDRESS_ASSIGN {
                    Ok(Self::AddressAssign(entries))
                } else {
                    if entries.is_empty() {
                        return Err(ConnectIpProtocolError::EmptyRequest);
                    }
                    if entries.iter().any(|e| e.request_id.is_none()) {
                        return Err(ConnectIpProtocolError::RequestId);
                    }
                    Ok(Self::AddressRequest(
                        entries
                            .into_iter()
                            .map(|e| {
                                Ok(AddressRequest {
                                    request_id: e
                                        .request_id
                                        .ok_or(ConnectIpProtocolError::RequestId)?,
                                    prefix: e.prefix,
                                })
                            })
                            .collect::<Result<_, ConnectIpProtocolError>>()?,
                    ))
                }
            }
            ROUTE_ADVERTISEMENT => {
                let mut routes = Vec::new();
                while !value.is_empty() {
                    if routes.len() == max_entries {
                        return Err(ConnectIpProtocolError::Limit);
                    }
                    let version = take_byte(&mut value)?;
                    let start = take_address(&mut value, version)?;
                    let end = take_address(&mut value, version)?;
                    let protocol = match take_byte(&mut value)? {
                        0 => None,
                        v => Some(IpProtocol::new(v)),
                    };
                    routes.push(IpRoute::new(start, end, protocol)?);
                }
                validate_routes(&routes)?;
                Ok(Self::RouteAdvertisement(routes))
            }
            _ => Err(ConnectIpProtocolError::CapsuleType),
        }
    }

    /// Validate a capsule without allocating a serialized copy, and size its value.
    pub(super) fn encoded_len(&self, max_entries: usize) -> Result<usize, ConnectIpProtocolError> {
        match self {
            Self::AddressAssign(entries) => {
                if entries.len() > max_entries {
                    return Err(ConnectIpProtocolError::Limit);
                }
                entries.iter().try_fold(0, |len, e| {
                    Ok(len
                        + prefix_encoded_len(
                            e.request_id
                                .map_or(VarInt::from_u32(0), AddressRequestId::varint),
                            e.prefix,
                        )?)
                })
            }
            Self::AddressRequest(entries) => {
                if entries.is_empty() {
                    return Err(ConnectIpProtocolError::EmptyRequest);
                }
                if entries.len() > max_entries {
                    return Err(ConnectIpProtocolError::Limit);
                }
                entries.iter().try_fold(0, |len, e| {
                    Ok(len + prefix_encoded_len(e.request_id.varint(), e.prefix)?)
                })
            }
            Self::RouteAdvertisement(routes) => {
                if routes.len() > max_entries {
                    return Err(ConnectIpProtocolError::Limit);
                }
                validate_routes(routes)?;
                Ok(routes
                    .iter()
                    .map(|r| if r.start.is_ipv4() { 10 } else { 34 })
                    .sum())
            }
        }
    }

    /// Encode the value (the generic HTTP layer writes the capsule header).
    pub fn encode(&self, max_entries: usize) -> Result<Bytes, ConnectIpProtocolError> {
        let mut out = BytesMut::with_capacity(self.encoded_len(max_entries)?);
        self.encode_validated(&mut out);
        Ok(out.freeze())
    }

    /// Append a validated capsule value to a reusable caller-owned buffer.
    /// Invalid values leave the buffer untouched.
    pub fn encode_into<B: BufMut>(
        &self,
        out: &mut B,
        max_entries: usize,
    ) -> Result<(), ConnectIpProtocolError> {
        let size = self.encoded_len(max_entries)?;
        if out.remaining_mut() < size {
            return Err(ConnectIpProtocolError::Limit);
        }
        self.encode_validated(out);
        Ok(())
    }

    fn encode_validated<B: BufMut>(&self, out: &mut B) {
        match self {
            Self::AddressAssign(entries) => {
                for e in entries {
                    put_prefix(
                        out,
                        e.request_id
                            .map_or(VarInt::from_u32(0), AddressRequestId::varint),
                        e.prefix,
                    );
                }
            }
            Self::AddressRequest(entries) => {
                for e in entries {
                    put_prefix(out, e.request_id.varint(), e.prefix);
                }
            }
            Self::RouteAdvertisement(routes) => {
                for r in routes {
                    out.put_u8(if r.start.is_ipv4() { 4 } else { 6 });
                    put_address(out, r.start);
                    put_address(out, r.end);
                    out.put_u8(r.protocol.map_or(0, IpProtocol::value));
                }
            }
        }
    }
}

/// Validate the wire ordering, disjointness and all-protocol overlap rules.
///
/// Different specific protocols may overlap; protocol zero overlaps are rejected.
/// The latter check is optional in RFC 9484 and deliberately enforced here.
pub fn validate_routes(routes: &[IpRoute]) -> Result<(), ConnectIpProtocolError> {
    for r in routes {
        if r.start.is_ipv4() != r.end.is_ipv4()
            || r.start > r.end
            || r.protocol == Some(IpProtocol::HOP_BY_HOP)
        {
            return Err(ConnectIpProtocolError::Route);
        }
    }
    for pair in routes.windows(2) {
        let [a, b] = [pair[0], pair[1]];
        let ka = (a.start.is_ipv6(), a.protocol.map_or(0, IpProtocol::value));
        let kb = (b.start.is_ipv6(), b.protocol.map_or(0, IpProtocol::value));
        if ka > kb || (ka == kb && a.end >= b.start) {
            return Err(ConnectIpProtocolError::Route);
        }
    }
    // Binary search the sorted wildcard ranges; no quadratic comparison of all routes.
    for ipv6 in [false, true] {
        let begin = routes.partition_point(|r| !r.start.is_ipv6() && ipv6);
        let family = &routes[begin..];
        let wildcard_count =
            family.partition_point(|r| r.start.is_ipv6() == ipv6 && r.protocol.is_none());
        let wildcard = &family[..wildcard_count];
        for r in family[wildcard_count..]
            .iter()
            .take_while(|r| r.start.is_ipv6() == ipv6)
        {
            let i = wildcard.partition_point(|w| w.end < r.start);
            if wildcard.get(i).is_some_and(|w| w.start <= r.end) {
                return Err(ConnectIpProtocolError::Route);
            }
        }
    }
    Ok(())
}

fn validate_prefix(prefix: IpNet) -> Result<(), ConnectIpProtocolError> {
    if prefix.addr() != prefix.network() {
        Err(ConnectIpProtocolError::Prefix)
    } else {
        Ok(())
    }
}

fn family_bits(address: IpAddr) -> u8 {
    if address.is_ipv4() { 32 } else { 128 }
}

fn take_byte(input: &mut &[u8]) -> Result<u8, ConnectIpProtocolError> {
    let (&b, rest) = input
        .split_first()
        .ok_or(ConnectIpProtocolError::Truncated)?;
    *input = rest;
    Ok(b)
}

fn take_address(input: &mut &[u8], version: u8) -> Result<IpAddr, ConnectIpProtocolError> {
    let len = match version {
        4 => 4,
        6 => 16,
        _ => return Err(ConnectIpProtocolError::Version),
    };
    let raw = input.get(..len).ok_or(ConnectIpProtocolError::Truncated)?;
    let address = if version == 4 {
        IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))
    } else {
        let mut octets = [0; 16];
        octets.copy_from_slice(raw);
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    *input = &input[len..];
    Ok(address)
}

fn put_address<B: BufMut>(out: &mut B, address: IpAddr) {
    match address {
        IpAddr::V4(a) => out.put_slice(&a.octets()),
        IpAddr::V6(a) => out.put_slice(&a.octets()),
    }
}

fn prefix_encoded_len(id: VarInt, prefix: IpNet) -> Result<usize, ConnectIpProtocolError> {
    validate_prefix(prefix)?;
    Ok(id.size() + 2 + if prefix.addr().is_ipv4() { 4 } else { 16 })
}

// Called only after encoded_len has validated the prefixes and output capacity.
fn put_prefix<B: BufMut>(out: &mut B, id: VarInt, prefix: IpNet) {
    id.encode(out);
    out.put_u8(if prefix.addr().is_ipv4() { 4 } else { 6 });
    put_address(out, prefix.addr());
    out.put_u8(prefix.prefix_len());
}

/// Decode a datagram's context ID without imposing a UDP payload limit.
/// Unknown context IDs are returned so the session can discard them.
pub fn decode_ip_datagram(
    mut datagram: &[u8],
) -> Result<(ContextId, &[u8]), ConnectIpProtocolError> {
    let id =
        ContextId::decode(&mut datagram).map_err(|_error| ConnectIpProtocolError::Truncated)?;
    Ok((id, datagram))
}

/// Prefix an IP packet with context zero. IP validation belongs to the packet/session API.
#[must_use]
pub fn encode_ip_datagram(packet: &[u8]) -> Bytes {
    encode_ip_datagram_mut(packet).freeze()
}

// Keep the framing buffer mutable until forwarding edits have been applied.
pub(super) fn encode_ip_datagram_mut(packet: &[u8]) -> BytesMut {
    let mut out = BytesMut::with_capacity(1 + packet.len());
    out.put_u8(0);
    out.extend_from_slice(packet);
    out
}
