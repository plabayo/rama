use super::{AddressAssignment, AddressRequest, ConnectIpCapsule, ConnectIpProtocolError, IpRoute};
use ahash::{HashMap, HashSet};

/// Bounds for directional control state, independent of packet queue limits.
#[derive(Debug, Clone, Copy)]
pub struct ConnectIpStateLimits {
    /// Maximum entries in an assignment, request or route snapshot.
    pub max_entries: usize,
    /// Total distinct address requests per endpoint for this tunnel's lifetime.
    /// A finite history detects replay without unbounded growth; exhaustion closes
    /// the stream rather than forgetting IDs and permitting reuse.
    pub max_request_ids: usize,
}

impl Default for ConnectIpStateLimits {
    fn default() -> Self {
        Self {
            max_entries: 256,
            max_request_ids: 4096,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct Requests {
    seen: HashMap<u64, bool>, // ID -> requested address family (true for IPv6)
    pending: HashSet<u64>,
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
            if e.request_id == 0
                || self.seen.contains_key(&e.request_id)
                || !added.insert(e.request_id)
            {
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
            if e.request_id != 0 && self.seen.get(&e.request_id) != Some(&e.prefix.addr().is_ipv6())
            {
                return Err(ConnectIpProtocolError::RequestId);
            }
        }
        for e in entries {
            self.pending.remove(&e.request_id);
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
    local_addresses: Vec<AddressAssignment>,
    peer_addresses: Vec<AddressAssignment>,
    local_routes: Vec<IpRoute>,
    peer_routes: Vec<IpRoute>,
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
            local_addresses: Vec::new(),
            peer_addresses: Vec::new(),
            local_routes: Vec::new(),
            peer_routes: Vec::new(),
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

    /// Prefixes the peer assigned to this endpoint, excluding explicit rejections.
    #[must_use]
    pub fn local_addresses(&self) -> &[AddressAssignment] {
        &self.local_addresses
    }

    /// Prefixes this endpoint assigned to its peer, excluding explicit rejections.
    #[must_use]
    pub fn peer_addresses(&self) -> &[AddressAssignment] {
        &self.peer_addresses
    }

    /// Routes this endpoint advertised.
    #[must_use]
    pub fn local_routes(&self) -> &[IpRoute] {
        &self.local_routes
    }

    /// Routes the peer advertised; these remain subject to local policy.
    #[must_use]
    pub fn peer_routes(&self) -> &[IpRoute] {
        &self.peer_routes
    }

    /// Number of local requests not yet answered.
    #[must_use]
    pub fn pending_requests(&self) -> usize {
        self.local_requests.pending.len()
    }

    /// Reserve an unused local request ID. The request is recorded when sent.
    pub fn next_request_id(&mut self) -> Result<u64, ConnectIpProtocolError> {
        while self.local_requests.seen.contains_key(&self.next_request_id) {
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
        Ok(id)
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
        capsule.encoded_len(self.limits.max_entries)?;
        match capsule {
            ConnectIpCapsule::AddressRequest(entries) => {
                let requests = if received {
                    &mut self.peer_requests
                } else {
                    &mut self.local_requests
                };
                requests.request(entries, self.limits.max_request_ids)?;
            }
            ConnectIpCapsule::AddressAssign(entries) => {
                let (requests, addresses) = if received {
                    (&mut self.local_requests, &mut self.local_addresses)
                } else {
                    (&mut self.peer_requests, &mut self.peer_addresses)
                };
                requests.assignment(entries)?;
                addresses.clear();
                addresses.extend(entries.iter().copied().filter(|e| !e.is_rejection()));
            }
            ConnectIpCapsule::RouteAdvertisement(routes) => {
                if received {
                    self.peer_routes.clone_from(routes);
                } else {
                    self.local_routes.clone_from(routes);
                }
            }
        }
        Ok(())
    }
}
