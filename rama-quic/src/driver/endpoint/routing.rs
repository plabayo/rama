//! Optional control-plane routing between independent endpoints.
//!
//! The native index publishes identifier installation and retirement. This directory only
//! selects an endpoint for a new transport association; packet authentication and routing
//! remain native. No directory operation runs for established association packets.

use super::Endpoint;
use crate::proto::RouteObserver;
use ahash::HashMap;
use parking_lot::Mutex;
use rama_net::address::{SocketAddress, ip::IntoCanonicalIpAddr as _};
use rama_quic_proto::{
    ConnectionId,
    packet::{FixedLengthConnectionIdParser, RoutingPacket},
};
use std::{
    io,
    num::NonZeroUsize,
    sync::{Arc, Weak},
};

/// Bounded routing hints for endpoints in one trusted policy domain.
///
/// Register endpoints before admitting their first connection. Keep each registration alive
/// for its connection's lifetime. Original destination is part of every lookup. The directory
/// does not share endpoint drivers, connection locks, TLS configuration or payload queues.
#[derive(Debug, Clone)]
pub struct EndpointRouteDirectory {
    shared: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    limit: usize,
    next: u64,
    cid_lengths: [usize; rama_quic_proto::MAX_CID_SIZE + 1],
    owners: HashMap<u64, Owner>,
    routes: HashMap<(SocketAddress, ConnectionId, bool), Vec<u64>>,
}

#[derive(Debug)]
struct Owner {
    endpoint: Endpoint,
    cid_len: usize,
}

/// Keeps one endpoint's routing hints registered. Dropping it removes all hints atomically.
#[derive(Debug)]
pub struct EndpointRouteRegistration {
    observer: Arc<Observer>,
}

impl EndpointRouteRegistration {
    /// Identity of this registration, useful for associating application transport state.
    pub fn id(&self) -> u64 {
        self.observer.id
    }
}

#[derive(Debug)]
struct Observer {
    directory: Weak<Mutex<State>>,
    id: u64,
    local: SocketAddress,
}

/// A routing hint, not proof of packet authenticity or current CID ownership.
#[derive(Debug, Clone)]
pub struct EndpointRoute {
    pub registration: u64,
    pub endpoint: Endpoint,
}

impl EndpointRouteDirectory {
    pub fn new(max_endpoints: NonZeroUsize) -> Self {
        Self {
            shared: Arc::new(Mutex::new(State {
                limit: max_endpoints.get(),
                next: 0,
                cid_lengths: [0; rama_quic_proto::MAX_CID_SIZE + 1],
                owners: HashMap::default(),
                routes: HashMap::default(),
            })),
        }
    }

    /// Whether the registration budget is currently exhausted. This snapshot reserves no slot.
    pub fn is_full(&self) -> bool {
        let state = self.shared.lock();
        state.owners.len() >= state.limit
    }

    /// Register an independent endpoint. An endpoint can belong to only one directory.
    pub fn register(
        &self,
        endpoint: &Endpoint,
        local: SocketAddress,
    ) -> io::Result<EndpointRouteRegistration> {
        let local = local.into_canonical_ip_addr();
        if local.ip_addr.is_unspecified() || local.port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "routing requires a concrete original destination",
            ));
        }
        // Lock order is endpoint -> directory, also used by native CID notifications.
        let mut endpoint_state = endpoint.inner.state.lock();
        if endpoint_state.inner.has_route_observer() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "endpoint already has a routing registration",
            ));
        }
        let cid_len = endpoint_state.inner.routing_cid_len();
        if cid_len == 0 || cid_len > rama_quic_proto::MAX_CID_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "migration routing requires nonempty connection IDs",
            ));
        }
        let observer = {
            let mut state = self.shared.lock();
            if state.owners.len() >= state.limit {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "endpoint routing directory is full",
                ));
            }
            let id = state.next;
            state.next = id
                .checked_add(1)
                .ok_or_else(|| io::Error::other("routing identity exhausted"))?;
            state.cid_lengths[cid_len] += 1;
            state.owners.insert(
                id,
                Owner {
                    endpoint: endpoint.clone(),
                    cid_len,
                },
            );
            Arc::new(Observer {
                directory: Arc::downgrade(&self.shared),
                id,
                local,
            })
        };
        endpoint_state.inner.observe_routes(observer.clone());
        Ok(EndpointRouteRegistration { observer })
    }

    /// Select an endpoint using its native CID lifecycle hints, borrowing the datagram.
    ///
    /// A returned hint may retire immediately. Once returned, send to that endpoint or drop;
    /// never reinterpret a later native rejection as permission to forward elsewhere.
    /// Colliding identifiers are ambiguous and are refused, not resolved by iteration order.
    pub fn route(&self, local: SocketAddress, data: &[u8]) -> io::Result<Option<EndpointRoute>> {
        let local = local.into_canonical_ip_addr();
        let mut state = self.shared.lock();
        let lengths = state.cid_lengths;
        let mut selected = None;
        for (len, present) in lengths.into_iter().enumerate() {
            if present == 0 {
                continue;
            }
            let Ok(packet) = RoutingPacket::decode(
                data,
                &FixedLengthConnectionIdParser::new(len),
                crate::proto::DEFAULT_SUPPORTED_VERSIONS,
                true,
            ) else {
                continue;
            };
            for initial in [false, true] {
                if initial && !packet.is_initial_or_0rtt() {
                    continue;
                }
                if let Some(ids) = state.routes.get(&(local, *packet.dst_cid(), initial)) {
                    for id in ids {
                        if selected.is_some_and(|previous| previous != *id) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "ambiguous QUIC endpoint route",
                            ));
                        }
                        selected = Some(*id);
                    }
                }
            }
        }
        Ok(selected.and_then(|id| {
            state.owners.get_mut(&id).map(|owner| EndpointRoute {
                registration: id,
                endpoint: owner.endpoint.clone(),
            })
        }))
    }
}

impl RouteObserver for Observer {
    fn insert(&self, cid: ConnectionId, initial: bool) {
        let Some(shared) = self.directory.upgrade() else {
            return;
        };
        let mut state = shared.lock();
        if !state.owners.contains_key(&self.id) {
            return;
        }
        let ids = state.routes.entry((self.local, cid, initial)).or_default();
        if !ids.contains(&self.id) {
            ids.push(self.id);
        }
    }

    fn remove(&self, cid: ConnectionId, initial: bool) {
        let Some(shared) = self.directory.upgrade() else {
            return;
        };
        let mut state = shared.lock();
        let key = (self.local, cid, initial);
        if let Some(ids) = state.routes.get_mut(&key) {
            ids.retain(|id| *id != self.id);
            if ids.is_empty() {
                state.routes.remove(&key);
            }
        }
    }
}

impl Drop for EndpointRouteRegistration {
    fn drop(&mut self) {
        let Some(shared) = self.observer.directory.upgrade() else {
            return;
        };
        let owner = {
            let mut state = shared.lock();
            state.routes.retain(|_, ids| {
                ids.retain(|id| *id != self.observer.id);
                !ids.is_empty()
            });
            let owner = state.owners.remove(&self.observer.id);
            if let Some(owner) = &owner {
                state.cid_lengths[owner.cid_len] -= 1;
            }
            owner
        };
        // Endpoint destruction may drop native state; never do that under the directory lock.
        drop(owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::graceful::WeakScope;
    use rama_udp::test_utils::MemoryDatagramSocket;

    fn endpoint(port: u16) -> Endpoint {
        let (socket, _) = MemoryDatagramSocket::pair(
            ([127, 0, 0, 1], port),
            ([127, 0, 0, 1], 8000),
            rama_utils::macros::nonzero!(4),
        );
        Endpoint::build(WeakScope::detached())
            .with_datagram_socket(socket)
            .unwrap()
    }

    fn packet(cid: ConnectionId) -> Vec<u8> {
        let mut packet = vec![0x40];
        packet.extend_from_slice(&cid);
        packet.extend_from_slice(&[0; 32]);
        packet
    }

    #[tokio::test]
    async fn routes_are_destination_scoped_retireable_and_removed_with_registration() {
        let directory = EndpointRouteDirectory::new(rama_utils::macros::nonzero!(2));
        let local = ([127, 0, 0, 1], 443).into();
        let registration = directory.register(&endpoint(443), local).unwrap();
        let cid = ConnectionId::new(&[7; 8]);
        registration.observer.insert(cid, false);
        let packet = packet(cid);
        assert_eq!(
            directory
                .route(local, &packet)
                .unwrap()
                .unwrap()
                .registration,
            registration.id()
        );
        assert!(
            directory
                .route(([127, 0, 0, 2], 443).into(), &packet)
                .unwrap()
                .is_none()
        );
        registration.observer.remove(cid, false);
        assert!(directory.route(local, &packet).unwrap().is_none());
        registration.observer.insert(cid, false);
        let observer = registration.observer.clone();
        drop(registration);
        // A racing native issue after deregistration cannot resurrect a stale owner.
        observer.insert(ConnectionId::new(&[8; 8]), false);
        assert!(directory.shared.lock().routes.is_empty());
        assert!(directory.shared.lock().owners.is_empty());
    }

    #[tokio::test]
    async fn identifier_collision_fails_closed_and_capacity_releases() {
        let directory = EndpointRouteDirectory::new(rama_utils::macros::nonzero!(2));
        let local = ([127, 0, 0, 1], 443).into();
        let first = directory.register(&endpoint(443), local).unwrap();
        let second = directory.register(&endpoint(443), local).unwrap();
        directory.register(&endpoint(443), local).unwrap_err();
        let cid = ConnectionId::new(&[9; 8]);
        first.observer.insert(cid, false);
        second.observer.insert(cid, false);
        assert_eq!(
            directory.route(local, &packet(cid)).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        drop(first);
        assert_eq!(
            directory
                .route(local, &packet(cid))
                .unwrap()
                .unwrap()
                .registration,
            second.id()
        );
        let _third = directory.register(&endpoint(443), local).unwrap();
    }
}
