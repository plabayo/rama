use super::{
    ConnectIpStateSnapshot, IpRoute,
    state::{AddressRanges, RouteIndex},
};
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
    fn allows(
        &self,
        address: IpAddr,
        assigned: &AddressRanges,
        compiled: Option<&AddressRanges>,
    ) -> bool {
        let prefixes = match self {
            Self::Assigned(p) | Self::Static(p) => p,
        };
        compiled.map_or_else(
            || prefixes.iter().any(|p| p.contains(&address)),
            |index| index.contains(address),
        ) && (matches!(self, Self::Static(_)) || assigned.contains(address))
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

#[derive(Debug)]
pub(super) struct PolicyIndex {
    sources: [AddressRanges; 2],
    destinations: [RouteIndex; 2],
    scope: AddressRanges,
}

impl PolicyIndex {
    pub(super) fn new(policy: &ConnectIpPolicy) -> Self {
        let sources = |direction: &IpDirectionPolicy| {
            let (IpSourcePolicy::Assigned(prefixes) | IpSourcePolicy::Static(prefixes)) =
                &direction.sources;
            AddressRanges::new(prefixes.iter().map(|p| (p.network(), p.broadcast())))
        };
        Self {
            sources: [sources(&policy.receive), sources(&policy.send)],
            destinations: [
                RouteIndex::new(&policy.receive.destinations),
                RouteIndex::new(&policy.send.destinations),
            ],
            scope: AddressRanges::new(
                policy
                    .scope_targets
                    .iter()
                    .map(|p| (p.network(), p.broadcast())),
            ),
        }
    }
}

/// Which endpoint originated the HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectIpRole {
    /// HTTP client.
    Client,
    /// HTTP proxy/server.
    Server,
}

/// Packet policy evaluated after decoding and before delivery/transmission.
///
/// Peer assignments/routes never expand these permissions. Populate resolved scope
/// addresses only after a bounded, authorized DNS lookup; they remain pinned for
/// the tunnel lifetime. A new resolution requires a new policy/tunnel.
#[derive(Debug, Clone)]
pub struct ConnectIpPolicy {
    /// Outgoing packet permissions.
    pub send: IpDirectionPolicy,
    /// Incoming packet permissions.
    pub receive: IpDirectionPolicy,
    /// Requested target after resolution; empty means wildcard, still constrained
    /// by send/receive destination policy. A hostname resolving to no addresses
    /// must fail admission, not be represented by an empty list.
    pub(super) scope_targets: Vec<IpNet>,
    /// Requested upper-layer protocol (None for wildcard).
    pub(super) scope_protocol: Option<IpProtocol>,
}

impl ConnectIpPolicy {
    /// Deny all packet traffic until local permissions are configured.
    #[must_use]
    pub fn new() -> Self {
        Self {
            send: IpDirectionPolicy::default(),
            receive: IpDirectionPolicy::default(),
            scope_targets: Vec::new(),
            scope_protocol: None,
        }
    }

    /// Resolved scope imposed by the handshake, in addition to local permissions.
    pub fn scope_targets(&self) -> &[IpNet] {
        &self.scope_targets
    }

    /// Requested upper-layer protocol; `None` means wildcard.
    pub fn scope_protocol(&self) -> Option<IpProtocol> {
        self.scope_protocol
    }

    /// Check a packet against local policy and current control state.
    pub fn check(
        &self,
        packet: IpPacket<'_>,
        outgoing: bool,
        role: ConnectIpRole,
        state: &ConnectIpStateSnapshot,
    ) -> Result<(), IpPacketDrop> {
        self.check_indexed(packet, outgoing, role, state, None)
    }

    pub(super) fn check_indexed(
        &self,
        packet: IpPacket<'_>,
        outgoing: bool,
        role: ConnectIpRole,
        state: &ConnectIpStateSnapshot,
        index: Option<&PolicyIndex>,
    ) -> Result<(), IpPacketDrop> {
        let direction = if outgoing { &self.send } else { &self.receive };
        let source_assignments = state.source_index(outgoing);
        let (dest_assignments, routes) = state.destination_index(outgoing);
        let src = packet.source();
        let dst = packet.destination();
        let proto = packet.protocol();
        if let IpPacket::V4(p) = packet
            && p.option_iter()
                .any(|option| matches!(option.kind, 131 | 137))
        {
            return Err(IpPacketDrop::Destination);
        }
        // A routing header with Segments Left can change the final destination;
        // this proxy does not authorize that additional forwarding instruction.
        if let IpPacket::V6(p) = packet
            && p.extensions()
                .any(|e| e.protocol == IpProtocol::ROUTING && e.bytes[3] != 0)
        {
            return Err(IpPacketDrop::Destination);
        }
        // ICMP routers may be outside the requested target scope, but their outer
        // source must still satisfy local anti-spoofing policy in this direction.
        if !direction.sources.allows(
            src,
            source_assignments,
            index.map(|i| &i.sources[usize::from(outgoing)]),
        ) {
            return Err(IpPacketDrop::Source);
        }
        // Authorize the quoted flow in reverse; scope alone is relaxed for the
        // outer router address (RFC 9484 section 7.2.1).
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
            self.check_flow(quoted, !outgoing, role, state, index)?;
            return Ok(());
        }
        if !index.map_or_else(
            || direction.destinations.iter().any(|r| r.allows(dst, proto)),
            |i| i.destinations[usize::from(outgoing)].allows(dst, proto),
        ) {
            return Err(IpPacketDrop::Destination);
        }
        if direction.require_advertised_route
            && !dest_assignments.contains(dst)
            && !routes.allows(dst, proto)
        {
            return Err(IpPacketDrop::Destination);
        }
        self.check_scope(src, dst, proto, outgoing, role, index)
    }

    fn check_flow(
        &self,
        flow: IpPacketQuote,
        outgoing: bool,
        role: ConnectIpRole,
        state: &ConnectIpStateSnapshot,
        index: Option<&PolicyIndex>,
    ) -> Result<(), IpPacketDrop> {
        let IpPacketQuote {
            source: src,
            destination: dst,
            protocol: proto,
        } = flow;
        let d = if outgoing { &self.send } else { &self.receive };
        let sources = state.source_index(outgoing);
        let (destinations, routes) = state.destination_index(outgoing);
        if !d.sources.allows(
            src,
            sources,
            index.map(|i| &i.sources[usize::from(outgoing)]),
        ) {
            return Err(IpPacketDrop::Source);
        }
        if !index.map_or_else(
            || d.destinations.iter().any(|r| r.allows(dst, proto)),
            |i| i.destinations[usize::from(outgoing)].allows(dst, proto),
        ) {
            return Err(IpPacketDrop::Destination);
        }
        if d.require_advertised_route && !destinations.contains(dst) && !routes.allows(dst, proto) {
            return Err(IpPacketDrop::Destination);
        }
        self.check_scope(src, dst, proto, outgoing, role, index)
    }

    fn check_scope(
        &self,
        src: IpAddr,
        dst: IpAddr,
        proto: Option<IpProtocol>,
        outgoing: bool,
        role: ConnectIpRole,
        index: Option<&PolicyIndex>,
    ) -> Result<(), IpPacketDrop> {
        let toward_target = (role == ConnectIpRole::Client) == outgoing;
        let target = if toward_target { dst } else { src };
        if !self.scope_targets.is_empty()
            && !index.map_or_else(
                || self.scope_targets.iter().any(|p| p.contains(&target)),
                |i| i.scope.contains(target),
            )
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

impl Default for ConnectIpPolicy {
    fn default() -> Self {
        Self::new()
    }
}
