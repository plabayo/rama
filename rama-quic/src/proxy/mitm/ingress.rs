//! Route intercepted transport paths to independent native QUIC endpoints.
//!
//! Install this as the ClientHello inspector's optional router, after source admission.
//! Known packets retain their endpoint; new handshakes retain normal inspection and policy.
//! Every intercepted connection owns an independent endpoint, origin connection and relay.
//! One registry spans a trusted policy identity boundary; original destination remains part of routing.
//! Provider-scoped `run_connection` keeps admitted MITM work alive across platform flow closure.
//! Packet payloads are never queued in the registry, and established paths never consult it.

use crate::{Endpoint, EndpointRouteDirectory, EndpointRouteRegistration, ServerConfig};
use ahash::HashMap;
use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    graceful::WeakScope,
};
use rama_net::address::{SocketAddress, ip::IntoCanonicalIpAddr as _};
use rama_quic_proto::VarInt;
use rama_udp::{
    DatagramCapabilities, DatagramGroup, DatagramGroupAttachment, DatagramSocket,
    DatagramSocketGroup, DatagramSocketGroupConfig, PrefixedDatagramSocket,
};
use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::sync::Notify;

/// Resource bounds for one trusted migration-routing identity. No payload queue is introduced.
///
/// A policy identity boundary is an isolation boundary, not a DNS name or destination address: for
/// example, one process audit token in a system proxy, or one authenticated tunnel tenant.
#[derive(Debug, Clone, Copy)]
pub struct QuicMitmIngressConfig {
    /// Maximum concurrently registered independent connections in this policy identity boundary.
    pub max_registered_connections: NonZeroUsize,
    /// Maximum simultaneous transport paths for one connection, including its original path.
    /// Use at least two to admit a new path while preserving the validated current path.
    /// Obsolete paths are evicted; this is not a lifetime limit on migration count.
    pub max_paths_per_connection: NonZeroUsize,
    /// Release a newly attached path unless it is the validated current peer by this deadline.
    /// Probing an alternate path without selecting it beyond this deadline loses that path.
    pub path_validation_timeout: std::time::Duration,
    /// `None` preserves each connection's first path's native capabilities. Supply a conservative profile
    /// explicitly when paths may use different transport providers. Weaker paths are refused.
    pub capabilities: Option<DatagramCapabilities>,
}

/// Bounds for a collection of independent interception policy identities.
#[derive(Debug, Clone, Copy)]
pub struct QuicMitmIngressByIdentityConfig {
    pub max_identities: NonZeroUsize,
    pub ingress: QuicMitmIngressConfig,
}

/// Reusable transparent-proxy ingress registry, keyed by the caller's trusted policy identity.
///
/// For example, use an Apple audit token (including process generation), or a WFP/Linux
/// identity with equivalent isolation. Never substitute an ambiguous PID or socket address.
/// Exhausted capacity returns `None`; callers must also isolate flows with unknown identity.
/// Clones share a cache. Only new associations consult it; established packets do not.
#[derive(Debug, Clone)]
pub struct QuicMitmIngressByIdentity<K> {
    identities: Arc<Mutex<HashMap<K, QuicMitmIngress>>>,
    scope: WeakScope,
    config: QuicMitmIngressByIdentityConfig,
}

impl<K: Eq + std::hash::Hash> QuicMitmIngressByIdentity<K> {
    pub fn new(scope: impl Into<WeakScope>, config: QuicMitmIngressByIdentityConfig) -> Self {
        Self {
            identities: Arc::default(),
            scope: scope.into(),
            config,
        }
    }

    pub fn get_or_create(&self, identity: K) -> Option<QuicMitmIngress> {
        let mut identities = self.identities.lock();
        if let Some(ingress) = identities.get(&identity) {
            return Some(ingress.clone());
        }

        if identities.len() >= self.config.max_identities.get() {
            identities.retain(|_, ingress| !ingress.is_idle());
        }
        if identities.len() >= self.config.max_identities.get() {
            return None;
        }

        let ingress = QuicMitmIngress::new(self.scope.clone(), self.config.ingress);
        identities.insert(identity, ingress.clone());
        Some(ingress)
    }
}

/// Coordinate migration between platform flows without sharing connection endpoints.
///
/// Use one instance per trusted policy identity boundary. Install it with
/// [`super::super::PeekQuicClientHelloService::with_router`] and pass the same instance to
/// [`super::QuicMitmRelay::with_migration_ingress`]. Each intercepted connection registers its
/// own native endpoint. CID matches are routing hints, never authentication; a stale match
/// is dropped rather than passed to policy. Scope admitted MITM work with `run_connection`.
#[derive(Debug, Clone)]
pub struct QuicMitmIngress {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    scope: WeakScope,
    connections: Mutex<HashMap<u64, Weak<Group>>>,
    directory: EndpointRouteDirectory,
    unregistered: AtomicU64,
    paths: NonZeroUsize,
    path_validation_timeout: std::time::Duration,
    capabilities: Option<DatagramCapabilities>,
}

#[derive(Debug)]
struct Group {
    owner: Weak<Shared>,
    endpoint: Endpoint,
    sockets: DatagramGroup,
    registration: EndpointRouteRegistration,
    closed: AtomicBool,
    stopped: Notify,
    paths: Mutex<VecDeque<SocketAddress>>,
    connection: Mutex<Option<crate::driver::WeakConnection>>,
    max_paths: usize,
    path_validation_timeout: std::time::Duration,
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.upgrade() {
            owner.connections.lock().remove(&self.registration.id());
        }
        self.endpoint
            .close(VarInt::from_u32(0), b"MITM ingress group closed");
    }
}

impl QuicMitmIngress {
    /// Configure one policy identity boundary. Use an application/provider scope, not a platform flow's
    /// scope: logical connections must survive the original flow closing.
    pub fn new(scope: impl Into<WeakScope>, config: QuicMitmIngressConfig) -> Self {
        Self {
            shared: Arc::new(Shared {
                scope: scope.into(),
                connections: Mutex::new(HashMap::default()),
                directory: EndpointRouteDirectory::new(config.max_registered_connections),
                unregistered: AtomicU64::new(0),
                paths: config.max_paths_per_connection,
                path_validation_timeout: config.path_validation_timeout,
                capabilities: config.capabilities,
            }),
        }
    }

    /// Run an admitted MITM connection in the provider scope, independently of its first
    /// platform flow. Call only after policy selects interception; raw forwarding should
    /// retain its caller's cancellation. Move admission permits and other lifetime guards
    /// into `connection`, so cancelling the caller cannot release them prematurely.
    pub async fn run_connection<O: Send + 'static>(
        &self,
        connection: impl std::future::Future<Output = Result<O, BoxError>> + Send + 'static,
    ) -> Result<O, BoxError> {
        let scope = self
            .shared
            .scope
            .try_hold()
            .map_err(|_closed| BoxError::from_static_str("QUIC MITM ingress scope closed"))?;
        scope
            .spawn_task(connection)
            .await?
            .ok_or_else(|| BoxError::from_static_str("QUIC MITM ingress scope aborted"))?
    }

    /// New connections served normally without migration registration because the directory
    /// was full. Known-CID paths never use this fallback.
    pub fn unregistered_connections(&self) -> u64 {
        self.shared.unregistered.load(Ordering::Relaxed)
    }

    /// Whether this is the last handle and no path, connection or acquisition needs its
    /// endpoints. Useful for evicting idle policy identities from an application's bounded cache.
    /// A false result may become true later; callers must still serialize their cache access.
    pub fn is_idle(&self) -> bool {
        Arc::strong_count(&self.shared) == 1
            && self
                .shared
                .connections
                .lock()
                .values()
                .all(|group| group.strong_count() == 0)
    }

    fn group(
        &self,
        local: SocketAddress,
        capabilities: DatagramCapabilities,
        server: ServerConfig,
    ) -> std::io::Result<Arc<Group>> {
        // Each admitted connection owns its endpoint; only route registration is shared.
        let group = self.create_group(
            local,
            self.shared.capabilities.unwrap_or(capabilities),
            server,
        )?;
        let mut connections = self.shared.connections.lock();
        connections.insert(group.registration.id(), Arc::downgrade(&group));
        Ok(group)
    }

    fn create_group(
        &self,
        local: SocketAddress,
        capabilities: DatagramCapabilities,
        server: ServerConfig,
    ) -> std::io::Result<Arc<Group>> {
        let (socket, sockets) = DatagramSocketGroup::new(
            local,
            DatagramSocketGroupConfig {
                max_paths: self.shared.paths,
                capabilities,
            },
        );
        let endpoint = Endpoint::build(self.shared.scope.clone())
            .with_server_config(server)
            .with_datagram_socket(socket)
            .map_err(std::io::Error::other)?;

        endpoint.preserve_ingress_transport();
        let registration = self.shared.directory.register(&endpoint, local)?;
        Ok(Arc::new(Group {
            owner: Arc::downgrade(&self.shared),
            endpoint,
            sockets,
            registration,
            closed: AtomicBool::new(false),
            stopped: Notify::new(),
            paths: Mutex::new(VecDeque::new()),
            connection: Mutex::new(None),
            max_paths: self.shared.paths.get(),
            path_validation_timeout: self.shared.path_validation_timeout,
        }))
    }

    fn accept_unregistered<S: DatagramSocket>(
        &self,
        socket: S,
        server: ServerConfig,
    ) -> Result<Attempt, BoxError> {
        // Only new policy-approved connections fall back; routed paths never enter accept.
        let endpoint = Endpoint::build(self.shared.scope.clone())
            .with_server_config(server)
            .with_datagram_socket(socket)?;
        self.shared.unregistered.fetch_add(1, Ordering::Relaxed);
        Ok(Attempt {
            endpoint,
            group: None,
            _attachment: None,
        })
    }

    pub(super) fn accept<S: DatagramSocket>(
        &self,
        socket: S,
        server: ServerConfig,
    ) -> Result<Attempt, BoxError> {
        if self.shared.directory.is_full() {
            return self.accept_unregistered(socket, server);
        }
        let group = match self.group(
            socket.local_addr()?.into_canonical_ip_addr(),
            socket.capabilities(),
            server.clone(),
        ) {
            Ok(group) => group,
            Err(error) if error.kind() == std::io::ErrorKind::StorageFull => {
                // Another attempt claimed the final registration after the capacity snapshot.
                return self.accept_unregistered(socket, server);
            }
            Err(error) => return Err(error.into()),
        };
        let attachment = group.attach(socket)?;
        Ok(Attempt {
            endpoint: group.endpoint.clone(),
            group: Some(group),
            _attachment: Some(Box::new(attachment)),
        })
    }
}

pub(super) struct Attempt {
    endpoint: Endpoint,
    group: Option<Arc<Group>>,
    _attachment: Option<Box<dyn Send + Sync>>,
}

impl Attempt {
    pub(super) fn established(&self, connection: &crate::Connection) {
        if let Some(group) = &self.group {
            *group.connection.lock() = Some(connection.downgrade());
            let connection = connection.downgrade();
            let sockets = group.sockets.clone();
            group.endpoint.on_unrouted_datagram(move |peer| {
                // A released client/NAT port can be reused before its old platform flow
                // expires. Retire only an obsolete association; untrusted CID misses must
                // not evict the connection's authenticated current path.
                if connection.remote_address().map(SocketAddress::from) != Some(peer) {
                    sockets.detach(peer);
                    true
                } else {
                    false
                }
            });
        }
    }

    pub(super) fn endpoint(&self) -> Endpoint {
        self.endpoint.clone()
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(group) = &self.group {
            group.closed.store(true, Ordering::Release);
            group.stopped.notify_waiters();
        }
    }
}

impl Group {
    fn attach<S: DatagramSocket>(&self, socket: S) -> Result<DatagramGroupAttachment<S>, BoxError> {
        let peer = socket.peer_addr()?.into_canonical_ip_addr();
        let mut paths = self.paths.lock();
        paths.retain(|peer| self.sockets.contains_path(*peer));
        if self.sockets.contains_path(peer) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "QUIC path already registered",
            )
            .into());
        }
        let active = self
            .connection
            .lock()
            .as_ref()
            .and_then(|connection| connection.remote_address())
            .map(SocketAddress::from)
            // Until the handshake establishes a connection, protect its original path.
            .or_else(|| paths.front().copied());
        if self.sockets.path_count() >= self.max_paths {
            // Preserve the authenticated current path. Obsolete/pending paths must not
            // prevent a client from bringing its next transport into a bounded set.
            if let Some(index) = paths
                .iter()
                .position(|path| Some(*path) != active && *path != peer)
                && let Some(old) = paths.remove(index)
            {
                self.sockets.detach(old);
            }
        }
        let attachment = self.sockets.attach(socket)?;
        paths.retain(|path| *path != peer);
        paths.push_back(peer);
        Ok(attachment)
    }

    async fn run_path<S>(&self, attachment: DatagramGroupAttachment<S>) -> Result<(), BoxError> {
        let peer = attachment.peer_addr();
        let stopped = self.stopped.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        if self.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        let run = attachment.run();
        tokio::pin!(run);
        tokio::select! {
            result = &mut run => return result.map_err(Into::into),
            () = &mut stopped => return Ok(()),
            () = tokio::time::sleep(self.path_validation_timeout) => {},
        }
        let active = self
            .connection
            .lock()
            .as_ref()
            .and_then(|connection| connection.remote_address())
            .map(SocketAddress::from);
        if active != Some(peer) {
            return Ok(());
        }
        tokio::select! {
            result = run => result.map_err(Into::into),
            () = stopped => Ok(()),
        }
    }
}

/// A terminal route decision for one new transport path of an existing connection.
#[derive(Debug)]
pub struct QuicMitmRoute {
    group: Option<Arc<Group>>,
}

impl super::super::QuicPeekRouter<()> for QuicMitmIngress {
    type Route = QuicMitmRoute;

    fn route<Socket: DatagramSocket>(
        &self,
        socket: &Socket,
        metadata: &rama_udp::DatagramMetadata,
        data: &[u8],
    ) -> Result<Option<QuicMitmRoute>, BoxError> {
        let local = socket.local_addr()?.into_canonical_ip_addr();
        let Some(route) = self.shared.directory.route(local, data)? else {
            return Ok(None);
        };
        let group = self
            .shared
            .connections
            .lock()
            .get(&route.registration)
            .and_then(Weak::upgrade);
        // Even if native ownership retired after the directory lookup, do not run policy.
        let group = group.filter(|_| {
            route
                .endpoint
                .routes_datagram(metadata.peer, Some(local), data)
        });
        Ok(Some(QuicMitmRoute { group }))
    }
}

impl super::super::QuicPeekRoute<()> for QuicMitmRoute {
    async fn serve<Socket: DatagramSocket>(
        self,
        socket: PrefixedDatagramSocket<Socket>,
    ) -> Result<(), BoxError> {
        if let Some(group) = self.group {
            group.run_path(group.attach(socket)?).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        proxy::{NoQuicRejectError, PeekQuicClientHelloService},
        tls::BoringTlsProvider,
    };
    use rama_core::{
        Service as _,
        service::{RejectService, service_fn},
    };
    use rama_udp::DatagramSocketExt as _;
    use rama_udp::{DatagramSenderExt as _, SendDatagram, test_utils::MemoryDatagramSocket};
    fn n(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).unwrap()
    }

    #[tokio::test]
    async fn unknown_flow_keeps_its_first_datagram_and_metadata_for_policy() {
        let ingress = QuicMitmIngress::new(
            WeakScope::detached(),
            QuicMitmIngressConfig {
                max_registered_connections: n(1),
                max_paths_per_connection: n(2),
                path_validation_timeout: std::time::Duration::from_secs(5),
                capabilities: None,
            },
        );
        // Even when a destination already has a native endpoint, unknown traffic must reach
        // the configured policy rather than be classified as an established connection.
        let local: SocketAddress = ([127, 0, 0, 1], 443).into();
        let _endpoint = ingress
            .group(
                local,
                DatagramCapabilities::portable(),
                crate::test_helpers::server(&crate::test_helpers::identity()),
            )
            .unwrap();
        let (socket, client) = MemoryDatagramSocket::pair(local, ([127, 0, 0, 1], 1234), n(2));
        client
            .create_sender()
            .send(SendDatagram::new(local, b"unknown traffic"))
            .await
            .unwrap();
        let policy = PeekQuicClientHelloService::new(
            BoringTlsProvider,
            RejectService::<(), _>::new(NoQuicRejectError),
        )
        .with_router(ingress)
        .with_fallback(service_fn(
            move |mut socket: PrefixedDatagramSocket<MemoryDatagramSocket>| async move {
                let mut buffer = [0; 64];
                let metadata = socket.recv(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..metadata.len], b"unknown traffic");
                assert_eq!(metadata.local, local);
                assert_eq!(metadata.peer.port, 1234);
                Ok::<_, BoxError>(())
            },
        ));
        policy.serve(socket).await.unwrap();
    }

    #[tokio::test]
    async fn registration_bound_releases_when_its_connection_owner_drops() {
        let ingress = QuicMitmIngress::new(
            WeakScope::detached(),
            QuicMitmIngressConfig {
                max_registered_connections: n(1),
                max_paths_per_connection: n(2),
                path_validation_timeout: std::time::Duration::from_secs(5),
                capabilities: None,
            },
        );
        let first = ingress
            .group(
                ([127, 0, 0, 1], 443).into(),
                DatagramCapabilities::portable(),
                crate::test_helpers::server(&crate::test_helpers::identity()),
            )
            .unwrap();
        ingress
            .group(
                ([127, 0, 0, 2], 443).into(),
                DatagramCapabilities::portable(),
                crate::test_helpers::server(&crate::test_helpers::identity()),
            )
            .unwrap_err();
        drop(first);
        let second = ingress
            .group(
                ([127, 0, 0, 2], 443).into(),
                DatagramCapabilities::portable(),
                crate::test_helpers::server(&crate::test_helpers::identity()),
            )
            .unwrap();
        assert_eq!(ingress.shared.connections.lock().len(), 1);
        assert!(!ingress.is_idle());
        drop(second);
        assert!(ingress.is_idle());
        let other = ingress.clone();
        assert!(!ingress.is_idle());
        drop(other);
        assert!(ingress.is_idle());
    }

    #[tokio::test(start_paused = true)]
    async fn silent_new_flow_uses_inspection_deadline_and_fallback() {
        let ingress = QuicMitmIngress::new(
            WeakScope::detached(),
            QuicMitmIngressConfig {
                max_registered_connections: n(1),
                max_paths_per_connection: n(1),
                path_validation_timeout: std::time::Duration::from_secs(5),
                capabilities: None,
            },
        );
        let (socket, _client) =
            MemoryDatagramSocket::pair(([127, 0, 0, 1], 443), ([127, 0, 0, 1], 1234), n(1));
        let policy = PeekQuicClientHelloService::new(
            BoringTlsProvider,
            RejectService::<(), _>::new(NoQuicRejectError),
        )
        .with_router(ingress)
        .with_peek_timeout(std::time::Duration::from_millis(50))
        .with_fallback(service_fn(
            |_: PrefixedDatagramSocket<MemoryDatagramSocket>| async { Ok::<_, BoxError>(()) },
        ));
        let started = tokio::time::Instant::now();
        policy.serve(socket).await.unwrap();
        assert_eq!(started.elapsed(), std::time::Duration::from_millis(50));
    }

    #[tokio::test]
    async fn full_registry_keeps_new_connections_on_unregistered_endpoints() {
        let ingress = QuicMitmIngress::new(
            WeakScope::detached(),
            QuicMitmIngressConfig {
                max_registered_connections: n(1),
                max_paths_per_connection: n(2),
                path_validation_timeout: std::time::Duration::from_secs(5),
                capabilities: None,
            },
        );
        let identity = crate::test_helpers::identity();
        let server = crate::test_helpers::server(&identity);
        let local: SocketAddress = ([127, 0, 0, 1], 443).into();
        let (first, _peer) = MemoryDatagramSocket::pair(local, ([127, 0, 0, 1], 1000), n(8));
        let _registered = ingress.accept(first, server.clone()).unwrap();
        let (second, client) = MemoryDatagramSocket::pair(local, ([127, 0, 0, 1], 1001), n(8));
        let unregistered = ingress.accept(second, server).unwrap();
        assert!(unregistered.group.is_none());
        assert_eq!(ingress.unregistered_connections(), 1);
        let client = Endpoint::build(WeakScope::detached())
            .with_datagram_socket(client)
            .unwrap();
        let connecting = client
            .connect_with(
                crate::test_helpers::client(&identity),
                local.into(),
                "localhost",
            )
            .unwrap();
        let (client_connection, server_connection) = tokio::join!(connecting, async {
            unregistered.endpoint.accept().await.unwrap().await
        });
        let client_connection = client_connection.unwrap();
        let server_connection = server_connection.unwrap();
        client_connection.close(VarInt::from_u32(0), b"done");
        server_connection.closed().await;
    }

    #[tokio::test]
    async fn unknown_cid_cannot_retire_the_validated_current_path() {
        unknown_cid_path_retirement(false).await;
    }

    #[tokio::test]
    async fn unknown_cid_releases_an_obsolete_memory_transport() {
        unknown_cid_path_retirement(true).await;
    }

    async fn unknown_cid_path_retirement(retire: bool) {
        use rama_udp::DatagramSenderExt as _;
        let identity = crate::test_helpers::identity();
        let ingress = QuicMitmIngress::new(
            WeakScope::detached(),
            QuicMitmIngressConfig {
                max_registered_connections: n(1),
                max_paths_per_connection: n(2),
                path_validation_timeout: std::time::Duration::from_secs(5),
                capabilities: None,
            },
        );
        let local = SocketAddress::local_ipv4(443);
        let (socket, client_socket) =
            MemoryDatagramSocket::pair(local, SocketAddress::local_ipv4(1000), n(32));
        let mut raw = client_socket.create_sender();
        let attempt = ingress
            .accept(socket, crate::test_helpers::server(&identity))
            .unwrap();
        let client_endpoint = Endpoint::build(WeakScope::detached())
            .with_datagram_socket(client_socket)
            .unwrap();
        let connecting = client_endpoint
            .connect_with(
                crate::test_helpers::client(&identity),
                local.into(),
                "localhost",
            )
            .unwrap();
        let (client, server) = tokio::join!(connecting, async {
            attempt.endpoint.accept().await.unwrap().await
        });
        let (client, server) = (client.unwrap(), server.unwrap());
        attempt.established(&server);
        let replacement = if retire {
            let (new_server, new_client) =
                MemoryDatagramSocket::pair(local, SocketAddress::local_ipv4(1001), n(32));
            let attachment = attempt.group.as_ref().unwrap().attach(new_server).unwrap();
            client_endpoint.rebind_datagram_socket(new_client).unwrap();
            let (mut send, _recv) = client.open_bi().await.unwrap();
            send.write_all(b"move").await.unwrap();
            send.finish().unwrap();
            let (_send, mut recv) = server.accept_bi().await.unwrap();
            assert_eq!(recv.read_to_end(32).await.unwrap(), b"move");
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while server.downgrade().remote_address().unwrap().port() != 1001 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            Some(attachment)
        } else {
            None
        };
        raw.send(rama_udp::SendDatagram::new(local, &[0x40; 64]))
            .await
            .unwrap();
        if retire {
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while attempt
                    .group
                    .as_ref()
                    .unwrap()
                    .sockets
                    .contains_path(SocketAddress::local_ipv4(1000))
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        let (mut send, _receive) = client.open_bi().await.unwrap();
        send.write_all(b"still here").await.unwrap();
        send.finish().unwrap();
        let (_send, mut receive) =
            tokio::time::timeout(std::time::Duration::from_secs(2), server.accept_bi())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(receive.read_to_end(32).await.unwrap(), b"still here");
        assert_eq!(attempt.group.as_ref().unwrap().sockets.path_count(), 1);
        client.close(VarInt::from_u32(0), b"done");
        tokio::time::timeout(std::time::Duration::from_secs(2), server.closed())
            .await
            .unwrap();
        drop(replacement);
    }

    #[tokio::test]
    async fn pending_handshake_keeps_original_path_and_refuses_transport_replacement() {
        let ingress = QuicMitmIngress::new(
            WeakScope::detached(),
            QuicMitmIngressConfig {
                max_registered_connections: n(1),
                max_paths_per_connection: n(2),
                path_validation_timeout: std::time::Duration::from_secs(5),
                capabilities: None,
            },
        );
        let local: SocketAddress = ([127, 0, 0, 1], 443).into();
        let (original, _peer) = MemoryDatagramSocket::pair(local, ([127, 0, 0, 1], 1000), n(8));
        let attempt = ingress
            .accept(
                original,
                crate::test_helpers::server(&crate::test_helpers::identity()),
            )
            .unwrap();
        let group = attempt.group.as_ref().unwrap();
        let mut pending = Vec::new();
        for port in 1001..1005 {
            let (socket, peer) = MemoryDatagramSocket::pair(local, ([127, 0, 0, 1], port), n(8));
            pending.push((group.attach(socket).unwrap(), peer));
            assert!(group.sockets.contains_path(([127, 0, 0, 1], 1000).into()));
            assert!(group.sockets.contains_path(([127, 0, 0, 1], port).into()));
            assert_eq!(group.sockets.path_count(), 2);
        }
        let (replacement, _peer) = MemoryDatagramSocket::pair(local, ([127, 0, 0, 1], 2000), n(8));
        assert_eq!(
            group
                .endpoint
                .rebind_datagram_socket(replacement)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
        assert_eq!(group.sockets.path_count(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn unvalidated_path_expires_and_releases_its_slot() {
        let ingress = QuicMitmIngress::new(
            WeakScope::detached(),
            QuicMitmIngressConfig {
                max_registered_connections: n(1),
                max_paths_per_connection: n(2),
                path_validation_timeout: std::time::Duration::from_millis(50),
                capabilities: None,
            },
        );
        let local: SocketAddress = ([127, 0, 0, 1], 443).into();
        let (path, _peer) = MemoryDatagramSocket::pair(local, ([127, 0, 0, 1], 1000), n(8));
        let group = ingress
            .group(
                local,
                path.capabilities(),
                crate::test_helpers::server(&crate::test_helpers::identity()),
            )
            .unwrap();
        let attachment = group.attach(path).unwrap();
        assert_eq!(group.sockets.path_count(), 1);
        group.run_path(attachment).await.unwrap();
        assert_eq!(group.sockets.path_count(), 0);
    }

    #[test]
    fn identities_bound_active_keys_and_evict_only_idle_entries() {
        let identities = QuicMitmIngressByIdentity::new(
            WeakScope::detached(),
            QuicMitmIngressByIdentityConfig {
                max_identities: n(2),
                ingress: QuicMitmIngressConfig {
                    max_registered_connections: n(1),
                    max_paths_per_connection: n(2),
                    path_validation_timeout: std::time::Duration::from_secs(5),
                    capabilities: None,
                },
            },
        );
        let first = identities.get_or_create((42, 1)).unwrap();
        let same = identities.get_or_create((42, 1)).unwrap();
        assert!(Arc::ptr_eq(&first.shared, &same.shared));
        let reused_pid = identities.get_or_create((42, 2)).unwrap();
        assert!(!Arc::ptr_eq(&first.shared, &reused_pid.shared));
        assert!(identities.get_or_create((43, 1)).is_none());
        drop((first, same));
        let other = identities.get_or_create((43, 1)).unwrap();
        assert!(!Arc::ptr_eq(&other.shared, &reused_pid.shared));
        assert_eq!(identities.identities.lock().len(), 2);
    }
}
