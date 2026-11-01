use super::{ConnectIpState, IpRoute};
use rama_net::{
    address::ip::ipnet::IpNet,
    ip::{
        IpPacket, IpProtocol,
        icmp::{IpPacketQuote, is_icmp_error},
    },
};
use std::net::IpAddr;

/// Why an IP packet was dropped. Control errors use a separate terminal error path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IpPacketDrop {
    /// Packet framing, length, checksum or extension chain is invalid.
    Invalid,
    /// Source is not authorized for this direction.
    Source,
    /// Destination or protocol is not authorized.
    Destination,
    /// The requested scope does not include this flow.
    Scope,
    /// The effective IP MTU is too small.
    TooLarge,
    /// IPv6 has not been enabled with a verified link MTU.
    Ipv6Disabled,
    /// Forwarding would exhaust the hop count.
    HopLimit,
    /// A packet/byte budget has been exhausted.
    Budget,
    /// Nonzero Context ID has no registered semantics.
    UnknownContext,
    /// Transport send queue is full.
    QueueFull,
}

/// Source-address authorization for one direction.
#[derive(Debug, Clone)]
pub enum IpSourcePolicy {
    /// Require an in-band assignment, constrained to these locally authorized prefixes.
    Assigned(Vec<IpNet>),
    /// Explicitly configured sources (e.g. a site-to-site routed network).
    Static(Vec<IpNet>),
}

impl Default for IpSourcePolicy {
    fn default() -> Self {
        Self::Static(Vec::new())
    }
}

impl IpSourcePolicy {
    fn allows(&self, address: IpAddr, assigned: &[super::AddressAssignment]) -> bool {
        let prefixes = match self {
            Self::Assigned(p) | Self::Static(p) => p,
        };
        prefixes.iter().any(|p| p.contains(&address))
            && (matches!(self, Self::Static(_))
                || assigned.iter().any(|a| a.prefix.contains(&address)))
    }
}

/// Local permissions for a packet direction; defaults to deny all.
#[derive(Debug, Clone)]
pub struct IpDirectionPolicy {
    /// Permitted packet sources.
    pub sources: IpSourcePolicy,
    /// Permitted destinations/protocols, independent of peer declarations.
    pub destinations: Vec<IpRoute>,
    /// Require an assignment or route advertised by the receiving endpoint too.
    /// Disable only when routes are configured out of band.
    pub require_advertised_route: bool,
}

impl Default for IpDirectionPolicy {
    fn default() -> Self {
        Self {
            sources: IpSourcePolicy::default(),
            destinations: Vec::new(),
            require_advertised_route: true,
        }
    }
}

/// Which endpoint originated the HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectIpRole {
    /// HTTP client.
    Client,
    /// HTTP proxy/server.
    Proxy,
}

/// Packet policy evaluated after decoding and before delivery/transmission.
///
/// Peer assignments/routes never expand these permissions. Populate resolved scope
/// addresses only after a bounded, authorized DNS lookup; they remain pinned for
/// the tunnel lifetime. A new resolution requires a new policy/tunnel.
#[derive(Debug, Clone)]
pub struct ConnectIpPolicy {
    /// Which side of the HTTP request this endpoint represents.
    pub role: ConnectIpRole,
    /// Outgoing packet permissions.
    pub send: IpDirectionPolicy,
    /// Incoming packet permissions.
    pub receive: IpDirectionPolicy,
    /// Requested target after resolution; empty means wildcard, still constrained
    /// by send/receive destination policy. A hostname resolving to no addresses
    /// must fail admission, not be represented by an empty list.
    pub scope_targets: Vec<IpNet>,
    /// Requested upper-layer protocol (None for wildcard).
    pub scope_protocol: Option<IpProtocol>,
}

impl ConnectIpPolicy {
    /// Deny all packet traffic until local permissions are configured.
    #[must_use]
    pub fn new(role: ConnectIpRole) -> Self {
        Self {
            role,
            send: IpDirectionPolicy::default(),
            receive: IpDirectionPolicy::default(),
            scope_targets: Vec::new(),
            scope_protocol: None,
        }
    }

    /// Check a packet against local policy and current control state.
    pub fn check(
        &self,
        packet: IpPacket<'_>,
        outgoing: bool,
        state: &ConnectIpState,
    ) -> Result<(), IpPacketDrop> {
        let direction = if outgoing { &self.send } else { &self.receive };
        let (source_assignments, dest_assignments, routes) = if outgoing {
            (
                state.local_addresses(),
                state.peer_addresses(),
                state.peer_routes(),
            )
        } else {
            (
                state.peer_addresses(),
                state.local_addresses(),
                state.local_routes(),
            )
        };
        let src = packet.source();
        let dst = packet.destination();
        let proto = packet.protocol();
        if let IpPacket::V4(p) = packet {
            let mut options = p.options();
            while let Some((&kind, rest)) = options.split_first() {
                match kind {
                    0 => break,
                    1 => options = rest,
                    // Loose/strict source routing can redirect after this check.
                    131 | 137 => return Err(IpPacketDrop::Destination),
                    _ => options = &options[usize::from(options[1])..],
                }
            }
        }
        // A routing header with Segments Left can change the final destination;
        // this proxy does not authorize that additional forwarding instruction.
        if let IpPacket::V6(p) = packet
            && p.extensions()
                .any(|e| e.protocol == IpProtocol::ROUTING && e.bytes[3] != 0)
        {
            return Err(IpPacketDrop::Destination);
        }
        // ICMP errors can originate at intermediate routers. Authorize their quoted
        // flow in the reverse direction instead of requiring the router's address
        // to be an assigned client address.
        if is_icmp_error(packet) {
            if packet.fragment().is_some_and(|f| f.is_fragmented()) {
                return Err(IpPacketDrop::Invalid);
            }
            let body = packet.upper_layer_payload().ok_or(IpPacketDrop::Invalid)?;
            let valid_checksum = match packet {
                IpPacket::V4(_) => rama_net::ip::internet_checksum(body) == 0,
                IpPacket::V6(p) => {
                    rama_net::ip::icmp::icmpv6_checksum(p.source(), p.destination(), body) == Ok(0)
                }
            };
            if !valid_checksum {
                return Err(IpPacketDrop::Invalid);
            }
            let quoted = IpPacketQuote::parse(body.get(8..).ok_or(IpPacketDrop::Invalid)?)
                .map_err(|_error| IpPacketDrop::Invalid)?;
            if quoted.source != dst {
                return Err(IpPacketDrop::Destination);
            }
            self.check_flow(
                quoted.source,
                quoted.destination,
                quoted.protocol,
                !outgoing,
                state,
            )?;
            return Ok(());
        }
        if !direction.sources.allows(src, source_assignments) {
            return Err(IpPacketDrop::Source);
        }
        if !direction.destinations.iter().any(|r| r.allows(dst, proto)) {
            return Err(IpPacketDrop::Destination);
        }
        if direction.require_advertised_route
            && !dest_assignments.iter().any(|a| a.prefix.contains(&dst))
            && !routes.iter().any(|r| r.allows(dst, proto))
        {
            return Err(IpPacketDrop::Destination);
        }
        self.check_scope(src, dst, proto, outgoing)
    }

    fn check_flow(
        &self,
        src: IpAddr,
        dst: IpAddr,
        proto: Option<IpProtocol>,
        outgoing: bool,
        state: &ConnectIpState,
    ) -> Result<(), IpPacketDrop> {
        let d = if outgoing { &self.send } else { &self.receive };
        let (sources, destinations, routes) = if outgoing {
            (
                state.local_addresses(),
                state.peer_addresses(),
                state.peer_routes(),
            )
        } else {
            (
                state.peer_addresses(),
                state.local_addresses(),
                state.local_routes(),
            )
        };
        if !d.sources.allows(src, sources) {
            return Err(IpPacketDrop::Source);
        }
        if !d.destinations.iter().any(|r| r.allows(dst, proto)) {
            return Err(IpPacketDrop::Destination);
        }
        if d.require_advertised_route
            && !destinations.iter().any(|a| a.prefix.contains(&dst))
            && !routes.iter().any(|r| r.allows(dst, proto))
        {
            return Err(IpPacketDrop::Destination);
        }
        self.check_scope(src, dst, proto, outgoing)
    }

    fn check_scope(
        &self,
        src: IpAddr,
        dst: IpAddr,
        proto: Option<IpProtocol>,
        outgoing: bool,
    ) -> Result<(), IpPacketDrop> {
        let toward_target = (self.role == ConnectIpRole::Client) == outgoing;
        let target = if toward_target { dst } else { src };
        if !self.scope_targets.is_empty() && !self.scope_targets.iter().any(|p| p.contains(&target))
        {
            return Err(IpPacketDrop::Scope);
        }
        if self.scope_protocol.is_some()
            && proto != self.scope_protocol
            && !proto.is_some_and(|p| {
                p == if src.is_ipv4() {
                    IpProtocol::ICMP
                } else {
                    IpProtocol::ICMPV6
                }
            })
        {
            return Err(IpPacketDrop::Scope);
        }
        Ok(())
    }
}
