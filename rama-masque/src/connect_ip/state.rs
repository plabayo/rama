use super::{
    AddressAssignment, AddressRequest, AddressRequestId, ConnectIpCapsule, ConnectIpProtocolError,
    IpRoute,
};
use ahash::{HashMap, HashSet};
use std::{
    num::{NonZeroU16, NonZeroU32},
    sync::Arc,
};

/// Bounds for directional control state, independent of packet queue limits.
#[derive(Debug, Clone, Copy)]
pub struct ConnectIpStateLimits {
    /// Maximum entries in an assignment, request or route snapshot.
    pub max_entries: NonZeroU16,
    /// Total distinct address requests per endpoint for this tunnel's lifetime.
    /// A finite history detects replay without unbounded growth; exhaustion closes
    /// the stream rather than forgetting IDs and permitting reuse.
    pub max_request_ids: NonZeroU32,
}

/// Immutable packet-routing state, without the request-ID history.
/// Cloning an `Arc` to this view does not copy routes, assignments or request maps.
#[derive(Debug, Clone, Default)]
pub struct ConnectIpStateSnapshot {
    local_addresses: Vec<AddressAssignment>,
    peer_addresses: Vec<AddressAssignment>,
    local_routes: Vec<IpRoute>,
    peer_routes: Vec<IpRoute>,
    local_address_index: AddressRanges,
    peer_address_index: AddressRanges,
    local_route_index: RouteIndex,
    peer_route_index: RouteIndex,
}

/// Sorted, merged address intervals; built only when a control snapshot changes.
#[derive(Debug, Clone, Default)]
pub(super) struct AddressRanges(Vec<(std::net::IpAddr, std::net::IpAddr)>);

impl AddressRanges {
    pub(super) fn new(ranges: impl Iterator<Item = (std::net::IpAddr, std::net::IpAddr)>) -> Self {
        let mut ranges: Vec<_> = ranges.collect();
        ranges.sort_unstable();
        let mut merged: Vec<(std::net::IpAddr, std::net::IpAddr)> =
            Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut()
                && last.0.is_ipv4() == start.is_ipv4()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        Self(merged)
    }

    pub(super) fn contains(&self, address: std::net::IpAddr) -> bool {
        let i = self.0.partition_point(|(_, end)| *end < address);
        self.0
            .get(i)
            .is_some_and(|(start, end)| *start <= address && address <= *end)
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct RouteIndex {
    protocols: Vec<(Option<rama_net::ip::IpProtocol>, AddressRanges)>,
    icmp: AddressRanges,
}

impl RouteIndex {
    pub(super) fn new(routes: &[IpRoute]) -> Self {
        let mut protocols: std::collections::BTreeMap<_, Vec<_>> =
            std::collections::BTreeMap::new();
        for route in routes {
            protocols
                .entry(route.protocol)
                .or_default()
                .push((route.start, route.end));
        }
        Self {
            protocols: protocols
                .into_iter()
                .map(|(p, ranges)| (p, AddressRanges::new(ranges.into_iter())))
                .collect(),
            icmp: AddressRanges::new(routes.iter().map(|r| (r.start, r.end))),
        }
    }

    pub(super) fn allows(
        &self,
        address: std::net::IpAddr,
        protocol: Option<rama_net::ip::IpProtocol>,
    ) -> bool {
        use rama_net::ip::IpProtocol;
        if protocol
            == Some(if address.is_ipv4() {
                IpProtocol::ICMP
            } else {
                IpProtocol::ICMPV6
            })
        {
            return self.icmp.contains(address);
        }
        let lookup = |p| {
            self.protocols
                .binary_search_by_key(&p, |(p, _)| *p)
                .ok()
                .is_some_and(|i| self.protocols[i].1.contains(address))
        };
        lookup(None) || protocol.is_some() && lookup(protocol)
    }
}

impl std::ops::Deref for ConnectIpState {
    type Target = ConnectIpStateSnapshot;

    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

impl ConnectIpStateSnapshot {
    pub(super) fn source_index(&self, outgoing: bool) -> &AddressRanges {
        if outgoing {
            &self.local_address_index
        } else {
            &self.peer_address_index
        }
    }

    pub(super) fn destination_index(&self, outgoing: bool) -> (&AddressRanges, &RouteIndex) {
        if outgoing {
            (&self.peer_address_index, &self.peer_route_index)
        } else {
            (&self.local_address_index, &self.local_route_index)
        }
    }

    /// Prefixes assigned to this endpoint.
    pub fn local_addresses(&self) -> &[AddressAssignment] {
        &self.local_addresses
    }

    /// Prefixes assigned to the peer.
    pub fn peer_addresses(&self) -> &[AddressAssignment] {
        &self.peer_addresses
    }

    /// Routes advertised by this endpoint.
    pub fn local_routes(&self) -> &[IpRoute] {
        &self.local_routes
    }

    /// Routes advertised by the peer.
    pub fn peer_routes(&self) -> &[IpRoute] {
        &self.peer_routes
    }
}

impl Default for ConnectIpStateLimits {
    fn default() -> Self {
        Self {
            max_entries: const { NonZeroU16::new(256).unwrap() },
            max_request_ids: const { NonZeroU32::new(4096).unwrap() },
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Requests {
    seen: HashMap<AddressRequestId, bool>, // ID -> requested address family (true for IPv6)
    pending: HashSet<AddressRequestId>,
}

impl Requests {
    fn request(
        &mut self,
        entries: &[AddressRequest],
        limit: usize,
    ) -> Result<(), ConnectIpProtocolError> {
        if self.seen.len().saturating_add(entries.len()) > limit {
            return Err(ConnectIpProtocolError::Limit);
        }
        let mut added = HashSet::default();
        for e in entries {
            if self.seen.contains_key(&e.request_id) || !added.insert(e.request_id) {
                return Err(ConnectIpProtocolError::RequestId);
            }
        }
        for e in entries {
            self.seen.insert(e.request_id, e.prefix.addr().is_ipv6());
            self.pending.insert(e.request_id);
        }
        Ok(())
    }

    fn assignment(&mut self, entries: &[AddressAssignment]) -> Result<(), ConnectIpProtocolError> {
        for e in entries {
            if let Some(id) = e.request_id
                && self.seen.get(&id) != Some(&e.prefix.addr().is_ipv6())
            {
                return Err(ConnectIpProtocolError::RequestId);
            }
        }
        for e in entries {
            if let Some(id) = e.request_id {
                self.pending.remove(&id);
            }
        }
        Ok(())
    }
}

/// Validated, directional address/route state for one CONNECT-IP request stream.
///
/// These are peer statements, not authorization. A policy must intersect them
/// with configured permissions before forwarding packets or installing routes.
#[derive(Debug, Clone)]
pub struct ConnectIpState {
    limits: ConnectIpStateLimits,
    snapshot: Arc<ConnectIpStateSnapshot>,
    local_requests: Requests,
    peer_requests: Requests,
    next_request_id: u64,
}

impl Default for ConnectIpState {
    fn default() -> Self {
        Self::new(ConnectIpStateLimits::default())
    }
}

impl ConnectIpState {
    /// Start a stream with no in-band assignments or advertised routes.
    #[must_use]
    pub fn new(limits: ConnectIpStateLimits) -> Self {
        Self {
            limits,
            snapshot: Arc::default(),
            local_requests: Requests::default(),
            peer_requests: Requests::default(),
            next_request_id: 1,
        }
    }

    /// The bounds used by this state.
    #[must_use]
    pub fn limits(&self) -> ConnectIpStateLimits {
        self.limits
    }

    /// Acquire a cheap immutable view of the current packet-routing state.
    pub fn snapshot(&self) -> Arc<ConnectIpStateSnapshot> {
        self.snapshot.clone()
    }

    /// Number of local requests not yet answered.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.local_requests.pending.len()
    }

    /// Reserve an unused local request ID. The request is recorded when sent.
    pub fn next_request_id(&mut self) -> Result<AddressRequestId, ConnectIpProtocolError> {
        while self
            .local_requests
            .seen
            .contains_key(&AddressRequestId::new(self.next_request_id)?)
        {
            self.next_request_id = self
                .next_request_id
                .checked_add(1)
                .ok_or(ConnectIpProtocolError::RequestId)?;
        }
        if self.next_request_id >= 1 << 62 {
            return Err(ConnectIpProtocolError::RequestId);
        }
        let id = self.next_request_id;
        self.next_request_id += 1;
        AddressRequestId::new(id)
    }

    /// Validate a received capsule and atomically publish its complete snapshot.
    pub fn receive(&mut self, capsule: &ConnectIpCapsule) -> Result<(), ConnectIpProtocolError> {
        self.apply(capsule, true)
    }

    /// Validate and record an outgoing capsule transactionally.
    /// If transmission subsequently fails or is cancelled, discard this state
    /// with its stream; a peer may already have observed part of the update.
    pub fn sent(&mut self, capsule: &ConnectIpCapsule) -> Result<(), ConnectIpProtocolError> {
        self.apply(capsule, false)
    }

    fn apply(
        &mut self,
        capsule: &ConnectIpCapsule,
        received: bool,
    ) -> Result<(), ConnectIpProtocolError> {
        // This validates all entries, including callers constructing capsules directly.
        capsule.encoded_len(usize::from(self.limits.max_entries.get()))?;
        match capsule {
            ConnectIpCapsule::AddressRequest(entries) => {
                let requests = if received {
                    &mut self.peer_requests
                } else {
                    &mut self.local_requests
                };
                requests.request(entries, self.limits.max_request_ids.get() as usize)?;
            }
            ConnectIpCapsule::AddressAssign(entries) => {
                let snapshot = Arc::make_mut(&mut self.snapshot);
                let (requests, addresses) = if received {
                    (&mut self.local_requests, &mut snapshot.local_addresses)
                } else {
                    (&mut self.peer_requests, &mut snapshot.peer_addresses)
                };
                requests.assignment(entries)?;
                addresses.clear();
                addresses.extend(entries.iter().copied().filter(|e| !e.is_rejection()));
                let index = AddressRanges::new(
                    addresses
                        .iter()
                        .map(|a| (a.prefix.network(), a.prefix.broadcast())),
                );
                if received {
                    snapshot.local_address_index = index;
                } else {
                    snapshot.peer_address_index = index;
                }
            }
            ConnectIpCapsule::RouteAdvertisement(routes) => {
                let snapshot = Arc::make_mut(&mut self.snapshot);
                if received {
                    snapshot.peer_routes.clone_from(routes);
                    snapshot.peer_route_index = RouteIndex::new(routes);
                } else {
                    snapshot.local_routes.clone_from(routes);
                    snapshot.local_route_index = RouteIndex::new(routes);
                }
            }
        }
        Ok(())
    }
}
