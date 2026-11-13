//! Optional policy supervision for independent ingress and egress QUIC paths.
//!
//! Validated QUIC address changes and trusted platform network snapshots are separate inputs.
//! A policy chooses whether either leg needs a replacement transport. The layer adds no
//! packet queue or per-packet callback; it runs only on these control-plane notifications.

use crate::{Connection, LocalMigrationCapability};
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::Extensions,
    graceful::WeakScope,
    io::BridgeIo,
    service::BoxService,
};
use rama_net::address::SocketAddress;
use rama_quic_proto::VarInt;
use rama_udp::DatagramSocket;
use rama_utils::{guard::DropGuard, reactive::Changed};
use std::{fmt, io, sync::Arc, time::Duration};
use tokio::sync::watch;

/// Which independently terminated side a policy is considering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicMigrationSide {
    Ingress,
    Egress,
}

/// Platform reachability, independent of QUIC's authenticated path validation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum QuicNetworkAvailability {
    #[default]
    Unknown,
    Available,
    Unavailable,
}

/// Latest trusted platform state for one side. Extensions carry platform/policy metadata.
#[derive(Debug, Clone, Default)]
pub struct QuicNetworkPath {
    pub revision: u64,
    pub availability: QuicNetworkAvailability,
    pub context: Extensions,
}

/// Full latest state, so coalescing notifications never loses one side's update.
#[derive(Debug, Clone, Default)]
pub struct QuicNetworkSnapshot {
    pub ingress: QuicNetworkPath,
    pub egress: QuicNetworkPath,
}

/// A bounded, coalescing source of trusted network/interface/policy changes.
///
/// Publish platform observations here, never unauthenticated packet claims. A source may be
/// shared by many policy layers; each reader receives the latest complete snapshot, not a
/// growing event queue. A policy can use context to preserve interface or tunnel constraints.
#[derive(Debug, Clone)]
pub struct QuicNetworkChanges {
    state: watch::Sender<QuicNetworkSnapshot>,
}

impl Default for QuicNetworkChanges {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicNetworkChanges {
    pub fn new() -> Self {
        Self {
            state: watch::channel(QuicNetworkSnapshot::default()).0,
        }
    }

    pub fn update(
        &self,
        side: QuicMigrationSide,
        availability: QuicNetworkAvailability,
        context: Extensions,
    ) {
        self.state.send_modify(|state| {
            let path = match side {
                QuicMigrationSide::Ingress => &mut state.ingress,
                QuicMigrationSide::Egress => &mut state.egress,
            };
            path.revision = path.revision.wrapping_add(1);
            path.availability = availability;
            path.context = context;
        });
    }

    pub fn snapshot(&self) -> QuicNetworkSnapshot {
        self.state.borrow().clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicMigrationTrigger {
    Initial,
    /// The native connection has authenticated the packet and validated its new path.
    ValidatedPath(QuicMigrationSide),
    NetworkChanged,
}

/// Current connection handles and latest trusted network state for policy evaluation.
#[derive(Debug, Clone)]
pub struct QuicMigrationInput {
    pub trigger: QuicMigrationTrigger,
    pub ingress: Connection,
    pub egress: Connection,
    pub network: QuicNetworkSnapshot,
}

/// An owned, prepared transport. No application bytes are copied or replayed by replacement.
/// Preparing it does not change a connection; the supervisor applies the latest decision.
pub struct QuicTransportReplacement {
    local: SocketAddress,
    apply: Box<dyn FnOnce(&Connection) -> io::Result<()> + Send>,
    on_applied: Option<Box<dyn FnOnce() + Send>>,
}

impl fmt::Debug for QuicTransportReplacement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicTransportReplacement")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl QuicTransportReplacement {
    pub fn new(socket: impl DatagramSocket) -> io::Result<Self> {
        Ok(Self {
            local: socket.local_addr()?,
            apply: Box::new(move |connection| connection.rebind_datagram_socket(socket)),
            on_applied: None,
        })
    }

    rama_utils::macros::generate_set_and_with! {
        /// Observe successful transport registration, including deferred adoption.
        /// This is not confirmation of peer path validation. Cancellation or a rejected
        /// replacement drops the callback without running it. The callback must not block.
        pub fn on_applied(mut self, callback: impl FnOnce() + Send + 'static) -> Self {
            self.on_applied = Some(Box::new(callback));
            self
        }
    }

    fn apply(self, connection: &Connection) -> Result<(), BoxError> {
        match connection.local_migration_capability(self.local) {
            LocalMigrationCapability::SameAddress
            | LocalMigrationCapability::Ready
            | LocalMigrationCapability::Deferred => {
                (self.apply)(connection)?;
                if let Some(on_applied) = self.on_applied {
                    on_applied();
                }
                Ok(())
            }
            LocalMigrationCapability::Prohibited => Err(BoxError::from_static_str(
                "QUIC role or peer prohibits the requested local address change",
            )),
            LocalMigrationCapability::Closed => Err(BoxError::from_static_str(
                "QUIC migration connection closed",
            )),
        }
    }
}

#[derive(Debug, Default)]
pub enum QuicPathAction {
    #[default]
    Keep,
    /// Same socket, but the physical network changed: reset RTT/congestion/MTU estimates.
    Refresh,
    /// Register a new transport. Adoption may be deferred by native QUIC constraints.
    Replace(QuicTransportReplacement),
}

impl QuicPathAction {
    fn apply(self, connection: &Connection) -> Result<(), BoxError> {
        match self {
            Self::Keep => Ok(()),
            Self::Refresh => {
                connection.path_changed();
                Ok(())
            }
            Self::Replace(transport) => transport.apply(connection),
        }
    }
}

/// Decisions are independent. Keeping ingress while replacing egress is an ordinary case.
/// A transparent ingress backed by QuicMitmIngress accepts Keep or Refresh. Replace is
/// refused: platform paths must join its existing aggregate through the ingress router.
#[derive(Debug, Default)]
pub struct QuicMigrationDecision {
    pub ingress: QuicPathAction,
    pub egress: QuicPathAction,
}

/// What to do when policy evaluation, its deadline or transport replacement fails.
#[derive(Debug, Clone, Copy)]
pub enum QuicMigrationFailureAction {
    /// Keep existing transports and reconsider on the next observation.
    Keep,
    /// Close both legs, for policies where retaining the old path is forbidden.
    Close,
}

#[derive(Debug, Clone)]
pub struct QuicMigrationConfig {
    /// Owns the optional control-plane task; aborting the scope stops the relay.
    pub scope: WeakScope,
    pub decision_timeout: Duration,
    pub failure_action: QuicMigrationFailureAction,
    /// Code for Close on failure, or cancellation of the serving future.
    pub failure_code: VarInt,
}

/// Supervise an established QUIC relay with a normal Rama policy service.
///
/// The policy may prepare transports using native sockets, NE/WFP adapters, tunnels or any
/// other DatagramSocket factory. It must preserve the deployment's egress routing policy.
/// Newer notifications cancel an unfinished decision; prepared transports are dropped.
/// Independent connections must have dedicated endpoints for transport replacement.
#[derive(Debug, Clone)]
pub struct QuicMigrationLayer {
    policy: BoxService<QuicMigrationInput, QuicMigrationDecision, BoxError>,
    network: Option<QuicNetworkChanges>,
    decision_gate: Option<Arc<tokio::sync::Semaphore>>,
    config: QuicMigrationConfig,
}

impl QuicMigrationLayer {
    pub fn new<P>(policy: P, config: QuicMigrationConfig) -> Self
    where
        P: Service<QuicMigrationInput, Output = QuicMigrationDecision, Error = BoxError>,
    {
        Self {
            policy: BoxService::new(policy),
            network: None,
            decision_gate: None,
            config,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound concurrent policy preparations across connections sharing this gate.
        /// Waiting does not consume the decision timeout. New observations and connection
        /// closure cancel the wait; the permit is released after applying the decision.
        /// This does not bound native QUIC path validations or add packet-path work.
        pub fn decision_gate(mut self, gate: Arc<tokio::sync::Semaphore>) -> Self {
            self.decision_gate = Some(gate);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Subscribe to trusted platform network changes in addition to native path changes.
        pub fn network_changes(mut self, changes: QuicNetworkChanges) -> Self {
            self.network = Some(changes);
            self
        }
    }

    async fn supervise(&self, ingress: &Connection, egress: &Connection) -> Result<(), BoxError> {
        let mut ingress_changes = ingress.path_watch();
        let mut egress_changes = egress.path_watch();
        let mut network = self.network.as_ref().map(|source| source.state.subscribe());
        let mut trigger = QuicMigrationTrigger::Initial;
        loop {
            let input = QuicMigrationInput {
                trigger,
                ingress: ingress.clone(),
                egress: egress.clone(),
                network: self
                    .network
                    .as_ref()
                    .map_or_else(QuicNetworkSnapshot::default, QuicNetworkChanges::snapshot),
            };
            // Admission precedes the deadline: queued work retains its preparation budget.
            // The whole operation remains cancellable on closure or a newer observation.
            let prepare_and_apply = async {
                let _permit = if let Some(gate) = &self.decision_gate {
                    Some(gate.acquire().await.map_err(|_closed| {
                        BoxError::from_static_str("QUIC migration decision gate closed")
                    })?)
                } else {
                    None
                };
                let decision =
                    tokio::time::timeout(self.config.decision_timeout, self.policy.serve(input))
                        .await
                        .map_err(|_elapsed| {
                            BoxError::from_static_str("QUIC migration policy deadline exceeded")
                        })??;
                decision.ingress.apply(ingress)?;
                decision.egress.apply(egress)
            };
            // Prefer a newer observation over an already-ready stale decision.
            let result = tokio::select! {
                biased;
                next = next_trigger(&mut ingress_changes, &mut egress_changes, &mut network, ingress, egress) => {
                    let Some(next) = next else { return Ok(()); };
                    trigger = next; continue;
                }
                result = prepare_and_apply => result,
            };
            if let Err(error) = result {
                match self.config.failure_action {
                    QuicMigrationFailureAction::Close => return Err(error),
                    QuicMigrationFailureAction::Keep => {
                        rama_core::telemetry::tracing::debug!(%error, "retaining QUIC paths after migration policy failure");
                    }
                }
            }
            let Some(next) = next_trigger(
                &mut ingress_changes,
                &mut egress_changes,
                &mut network,
                ingress,
                egress,
            )
            .await
            else {
                return Ok(());
            };
            trigger = next;
        }
    }
}

async fn next_trigger(
    ingress_changes: &mut Changed<usize>,
    egress_changes: &mut Changed<usize>,
    network: &mut Option<watch::Receiver<QuicNetworkSnapshot>>,
    ingress: &Connection,
    egress: &Connection,
) -> Option<QuicMigrationTrigger> {
    tokio::select! {
        change = ingress_changes.changed() => change.map(|_| QuicMigrationTrigger::ValidatedPath(QuicMigrationSide::Ingress)),
        change = egress_changes.changed() => change.map(|_| QuicMigrationTrigger::ValidatedPath(QuicMigrationSide::Egress)),
        () = async {
            if let Some(network) = network { let _closed = network.changed().await; }
            else { std::future::pending::<()>().await; }
        } => Some(QuicMigrationTrigger::NetworkChanged),
        _closed = ingress.closed() => None,
        _closed = egress.closed() => None,
    }
}

impl<S> Layer<S> for QuicMigrationLayer {
    type Service = QuicMigrationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        QuicMigrationService {
            inner,
            layer: self.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        QuicMigrationService { inner, layer: self }
    }
}

#[derive(Debug, Clone)]
pub struct QuicMigrationService<S> {
    inner: S,
    layer: QuicMigrationLayer,
}

impl<S> Service<BridgeIo<Connection, Connection>> for QuicMigrationService<S>
where
    S: Service<BridgeIo<Connection, Connection>, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(
        &self,
        input: BridgeIo<Connection, Connection>,
    ) -> Result<Self::Output, BoxError> {
        let ingress = input.0.clone();
        let egress = input.1.clone();
        let mut close = DropGuard::new(|| {
            ingress.close(
                self.layer.config.failure_code,
                b"QUIC migration policy ended",
            );
            egress.close(
                self.layer.config.failure_code,
                b"QUIC migration policy ended",
            );
        });
        let scope = self
            .layer
            .config
            .scope
            .try_hold()
            .map_err(|_closed| BoxError::from_static_str("QUIC migration scope closed"))?;
        let layer = self.layer.clone();
        let watched_ingress = ingress.clone();
        let watched_egress = egress.clone();
        // Give control-plane watches their own waker: packet-driven relay polls must not
        // repeatedly consult path watches or network state when no migration occurs.
        let mut monitor = scope.into_spawn_task(async move {
            layer.supervise(&watched_ingress, &watched_egress).await
        });
        let abort = monitor.abort_handle();
        let _stop_monitor = DropGuard::new(move || abort.abort());
        let inner = self.inner.serve(input);
        tokio::pin!(inner);
        let result = tokio::select! {
            result = &mut inner => result.map_err(Into::into),
            result = &mut monitor => {
                result?.ok_or_else(|| BoxError::from_static_str("QUIC migration scope aborted"))??;
                inner.await.map_err(Into::into)
            }
        };
        if result.is_ok() {
            close.disarm();
        }
        result
    }
}

/// Common egress-only policy: ask a factory initially, and when a trusted network update or validated
/// ingress move requires another transport. The factory returns None to retain the old one.
/// Its own egress move does not recursively trigger another replacement.
#[derive(Debug, Clone)]
pub struct QuicEgressMigration<F> {
    factory: F,
}

impl<F> QuicEgressMigration<F> {
    pub fn new(factory: F) -> Self {
        Self { factory }
    }
}

impl<F, Socket> Service<QuicMigrationInput> for QuicEgressMigration<F>
where
    F: Service<QuicMigrationInput, Output = Option<Socket>, Error: Into<BoxError>>,
    Socket: DatagramSocket,
{
    type Output = QuicMigrationDecision;
    type Error = BoxError;

    async fn serve(&self, input: QuicMigrationInput) -> Result<Self::Output, BoxError> {
        if matches!(
            input.trigger,
            QuicMigrationTrigger::ValidatedPath(QuicMigrationSide::Egress)
        ) {
            return Ok(QuicMigrationDecision::default());
        }
        let egress = match self.factory.serve(input).await.map_err(Into::into)? {
            Some(socket) => QuicPathAction::Replace(QuicTransportReplacement::new(socket)?),
            None => QuicPathAction::Keep,
        };
        Ok(QuicMigrationDecision {
            ingress: QuicPathAction::Keep,
            egress,
        })
    }
}

#[cfg(all(test, feature = "boring"))]
mod tests {
    use super::*;
    use crate::{Endpoint, test_helpers};
    use rama_core::service::service_fn;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::time::timeout;

    #[expect(clippy::unwrap_used, reason = "test fixture construction")]
    async fn pair() -> (Endpoint, Endpoint, Connection, Connection) {
        let identity = test_helpers::identity();
        let server_tls = rama_tls::server::TlsServerConfig::new()
            .with_alpn([b"migration-test".as_slice().into()].into_iter().collect())
            .with_server_auth(identity.clone());
        let client_tls = rama_tls::client::TlsClientConfig::new()
            .with_alpn([b"migration-test".as_slice().into()].into_iter().collect())
            .try_with_server_trust_anchors([identity.cert_chain.last().unwrap().clone()])
            .unwrap();
        let server_config =
            crate::ServerConfig::try_from_rama_tls(&server_tls, crate::tls::TlsOptions::default())
                .unwrap();
        let client_config =
            crate::ClientConfig::try_from_rama_tls(&client_tls, crate::tls::TlsOptions::default())
                .unwrap();
        let server = Endpoint::build(WeakScope::detached())
            .with_server_config(server_config)
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let client = Endpoint::build(WeakScope::detached())
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let connecting = client
            .connect_with(client_config, server.local_addr().unwrap(), "localhost")
            .unwrap();
        let (client_connection, server_connection) =
            tokio::join!(connecting, async { server.accept().await.unwrap().await });
        (
            client,
            server,
            client_connection.unwrap(),
            server_connection.unwrap(),
        )
    }

    #[test]
    fn network_updates_coalesce_without_losing_the_other_side() {
        let changes = QuicNetworkChanges::new();
        let mut subscription = changes.state.subscribe();
        changes.update(
            QuicMigrationSide::Ingress,
            QuicNetworkAvailability::Unavailable,
            Extensions::new(),
        );
        changes.update(
            QuicMigrationSide::Egress,
            QuicNetworkAvailability::Available,
            Extensions::new(),
        );
        let latest = subscription.borrow_and_update();
        assert_eq!(latest.ingress.revision, 1);
        assert_eq!(latest.egress.revision, 1);
        assert_eq!(
            latest.ingress.availability,
            QuicNetworkAvailability::Unavailable
        );
        assert_eq!(
            latest.egress.availability,
            QuicNetworkAvailability::Available
        );
    }

    #[tokio::test]
    async fn egress_network_move_preserves_ingress_and_existing_stream_relay() {
        timeout(Duration::from_secs(15), async {
            let (client_endpoint, ingress_endpoint, client, ingress) = pair().await;
            let (egress_endpoint, origin_endpoint, egress, origin) = pair().await;
            let ingress_peer = ingress.remote_address();
            let original_egress_peer = origin.remote_address();
            let changes = QuicNetworkChanges::new();
            let calls = Arc::new(AtomicUsize::new(0));
            let count = calls.clone();
            let policy = QuicEgressMigration::new(service_fn(move |input: QuicMigrationInput| {
                let count = count.clone();
                async move {
                    if input.trigger != QuicMigrationTrigger::NetworkChanged {
                        return Ok::<_, BoxError>(None);
                    }
                    count.fetch_add(1, Ordering::Relaxed);
                    Ok(Some(
                        rama_udp::UdpPacketSocket::bind(SocketAddress::local_ipv4(0)).await?,
                    ))
                }
            }));
            let service = QuicMigrationLayer::new(
                policy,
                QuicMigrationConfig {
                    scope: WeakScope::detached(),
                    decision_timeout: Duration::from_secs(2),
                    failure_action: QuicMigrationFailureAction::Close,
                    failure_code: VarInt::from_u32(1),
                },
            )
            .with_network_changes(changes.clone())
            .into_layer(super::super::QuicRelay::new(VarInt::from_u32(1)).with_datagrams(true));
            let observed_ingress = ingress.clone();
            let relay = tokio::spawn(async move { service.serve(BridgeIo(ingress, egress)).await });
            let observed_origin = origin.clone();
            let echo = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut send, mut receive) = origin.accept_bi().await.unwrap();
                    let bytes = receive.read_to_end(64).await.unwrap();
                    send.write_all(&bytes).await.unwrap();
                    send.finish().unwrap();
                }
                origin.closed().await;
            });
            for round in 0..2 {
                if round == 1 {
                    changes.update(
                        QuicMigrationSide::Egress,
                        QuicNetworkAvailability::Available,
                        Extensions::new(),
                    );
                    while calls.load(Ordering::Relaxed) == 0 {
                        tokio::task::yield_now().await;
                    }
                }
                let (mut send, mut receive) = client.open_bi().await.unwrap();
                send.write_all(b"same logical relay").await.unwrap();
                send.finish().unwrap();
                assert_eq!(
                    receive.read_to_end(64).await.unwrap(),
                    b"same logical relay"
                );
            }
            while observed_origin.remote_address() == original_egress_peer {
                tokio::task::yield_now().await;
            }
            assert_eq!(observed_ingress.remote_address(), ingress_peer);
            assert_eq!(calls.load(Ordering::Relaxed), 1);
            client.close(VarInt::from_u32(0), b"done");
            relay.await.unwrap().unwrap();
            echo.await.unwrap();
            for endpoint in [
                client_endpoint,
                ingress_endpoint,
                egress_endpoint,
                origin_endpoint,
            ] {
                endpoint.shutdown_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn policy_timeout_closes_both_legs_and_cancels_pending_work() {
        let (client_endpoint, ingress_endpoint, client, ingress) = pair().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = pair().await;
        let dropped = Arc::new(AtomicUsize::new(0));
        let observed = dropped.clone();
        let policy = service_fn(move |_: QuicMigrationInput| {
            let dropped = dropped.clone();
            async move {
                let _guard = DropGuard::new(move || {
                    dropped.fetch_add(1, Ordering::Relaxed);
                });
                std::future::pending::<Result<QuicMigrationDecision, BoxError>>().await
            }
        });
        let service = QuicMigrationLayer::new(
            policy,
            QuicMigrationConfig {
                scope: WeakScope::detached(),
                decision_timeout: Duration::from_millis(10),
                failure_action: QuicMigrationFailureAction::Close,
                failure_code: VarInt::from_u32(42),
            },
        )
        .into_layer(service_fn(|_: BridgeIo<Connection, Connection>| async {
            std::future::pending::<Result<(), BoxError>>().await
        }));
        let error = timeout(
            Duration::from_secs(2),
            service.serve(BridgeIo(ingress, egress)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("deadline"));
        assert_eq!(observed.load(Ordering::Relaxed), 1);
        for connection in [client, origin] {
            let reason = timeout(Duration::from_secs(2), connection.closed())
                .await
                .unwrap();
            assert!(
                matches!(reason, crate::ConnectionError::ApplicationClosed(close)
                if close.error_code == VarInt::from_u32(42))
            );
        }
        for endpoint in [
            client_endpoint,
            ingress_endpoint,
            egress_endpoint,
            origin_endpoint,
        ] {
            endpoint.shutdown_now().await;
        }
    }

    #[tokio::test]
    async fn keep_on_failure_preserves_connections_and_waits_for_new_observation() {
        let (client_endpoint, ingress_endpoint, client, ingress) = pair().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = pair().await;
        let notified = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let called = notified.clone();
        let counted = calls.clone();
        let changes = QuicNetworkChanges::new();
        let layer = QuicMigrationLayer::new(
            service_fn(move |_: QuicMigrationInput| {
                let called = called.clone();
                let counted = counted.clone();
                async move {
                    counted.fetch_add(1, Ordering::Relaxed);
                    called.notify_one();
                    Err::<QuicMigrationDecision, _>(BoxError::from_static_str(
                        "replacement unavailable",
                    ))
                }
            }),
            QuicMigrationConfig {
                scope: WeakScope::detached(),
                decision_timeout: Duration::from_secs(2),
                failure_action: QuicMigrationFailureAction::Keep,
                failure_code: VarInt::from_u32(42),
            },
        )
        .with_network_changes(changes.clone());
        let monitor = tokio::spawn(async move { layer.supervise(&ingress, &egress).await });
        timeout(Duration::from_secs(2), notified.notified())
            .await
            .unwrap();
        assert!(!monitor.is_finished());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(client.close_reason().is_none() && origin.close_reason().is_none());
        changes.update(
            QuicMigrationSide::Egress,
            QuicNetworkAvailability::Available,
            Extensions::new(),
        );
        timeout(Duration::from_secs(2), notified.notified())
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert!(!monitor.is_finished());
        client.close(VarInt::from_u32(0), b"done");
        timeout(Duration::from_secs(2), monitor)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        origin.close(VarInt::from_u32(0), b"done");
        for endpoint in [
            client_endpoint,
            ingress_endpoint,
            egress_endpoint,
            origin_endpoint,
        ] {
            endpoint.shutdown_now().await;
        }
    }

    #[tokio::test]
    async fn newer_network_snapshot_cancels_unfinished_policy() {
        let (client_endpoint, ingress_endpoint, client, ingress) = pair().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = pair().await;
        let changes = QuicNetworkChanges::new();
        let started = Arc::new(tokio::sync::Notify::new());
        let finished = Arc::new(tokio::sync::Notify::new());
        let cancelled = Arc::new(AtomicUsize::new(0));
        let started_policy = started.clone();
        let finished_policy = finished.clone();
        let cancelled_policy = cancelled.clone();
        let policy = service_fn(move |input: QuicMigrationInput| {
            let started = started_policy.clone();
            let finished = finished_policy.clone();
            let cancelled = cancelled_policy.clone();
            async move {
                if input.trigger == QuicMigrationTrigger::Initial {
                    let _guard = DropGuard::new(move || {
                        cancelled.fetch_add(1, Ordering::Relaxed);
                    });
                    started.notify_one();
                    std::future::pending::<()>().await;
                }
                assert_eq!(input.network.egress.revision, 1);
                finished.notify_one();
                Ok::<_, BoxError>(QuicMigrationDecision::default())
            }
        });
        let layer = QuicMigrationLayer::new(
            policy,
            QuicMigrationConfig {
                scope: WeakScope::detached(),
                decision_timeout: Duration::from_secs(5),
                failure_action: QuicMigrationFailureAction::Close,
                failure_code: VarInt::from_u32(42),
            },
        )
        .with_network_changes(changes.clone());
        let monitor = tokio::spawn(async move { layer.supervise(&ingress, &egress).await });
        timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        changes.update(
            QuicMigrationSide::Egress,
            QuicNetworkAvailability::Available,
            Extensions::new(),
        );
        timeout(Duration::from_secs(2), finished.notified())
            .await
            .unwrap();
        assert_eq!(cancelled.load(Ordering::Relaxed), 1);
        client.close(VarInt::from_u32(0), b"done");
        timeout(Duration::from_secs(2), monitor)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        origin.close(VarInt::from_u32(0), b"done");
        for endpoint in [
            client_endpoint,
            ingress_endpoint,
            egress_endpoint,
            origin_endpoint,
        ] {
            endpoint.shutdown_now().await;
        }
    }

    #[tokio::test]
    async fn closed_decision_gate_respects_keep_and_connection_closure() {
        let (client_endpoint, ingress_endpoint, client, ingress) = pair().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = pair().await;
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        gate.close();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let layer = QuicMigrationLayer::new(
            service_fn(move |_: QuicMigrationInput| {
                count.fetch_add(1, Ordering::Relaxed);
                async { Ok::<_, BoxError>(QuicMigrationDecision::default()) }
            }),
            QuicMigrationConfig {
                scope: WeakScope::detached(),
                decision_timeout: Duration::from_millis(10),
                failure_action: QuicMigrationFailureAction::Keep,
                failure_code: VarInt::from_u32(42),
            },
        )
        .with_decision_gate(gate);
        let monitor = tokio::spawn(async move { layer.supervise(&ingress, &egress).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!monitor.is_finished());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(client.close_reason().is_none() && origin.close_reason().is_none());
        client.close(VarInt::from_u32(0), b"done");
        timeout(Duration::from_secs(2), monitor)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        origin.close(VarInt::from_u32(0), b"done");
        for endpoint in [
            client_endpoint,
            ingress_endpoint,
            egress_endpoint,
            origin_endpoint,
        ] {
            endpoint.shutdown_now().await;
        }
    }

    #[tokio::test]
    async fn replacement_acknowledges_only_successful_registration() {
        let (client_endpoint, server_endpoint, client, server) = pair().await;
        let acknowledged = Arc::new(AtomicUsize::new(0));
        for (connection, expected_success) in [(&server, false), (&client, true)] {
            let count = acknowledged.clone();
            let socket = rama_udp::UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
                .await
                .unwrap();
            let replacement = QuicTransportReplacement::new(socket)
                .unwrap()
                .with_on_applied(move || {
                    count.fetch_add(1, Ordering::Relaxed);
                });
            assert_eq!(replacement.apply(connection).is_ok(), expected_success);
            assert_eq!(
                acknowledged.load(Ordering::Relaxed),
                usize::from(expected_success)
            );
        }
        client.close(VarInt::from_u32(0), b"done");
        server.close(VarInt::from_u32(0), b"done");
        client_endpoint.shutdown_now().await;
        server_endpoint.shutdown_now().await;
    }

    #[tokio::test]
    async fn admission_wait_does_not_consume_the_policy_deadline() {
        let (client_endpoint, ingress_endpoint, client, ingress) = pair().await;
        let (egress_endpoint, origin_endpoint, egress, origin) = pair().await;
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        let held = gate.clone().acquire_owned().await.unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let finished = Arc::new(tokio::sync::Notify::new());
        let done = finished.clone();
        let layer = QuicMigrationLayer::new(
            service_fn(move |_input: QuicMigrationInput| {
                count.fetch_add(1, Ordering::Relaxed);
                done.notify_one();
                async { Ok::<_, BoxError>(QuicMigrationDecision::default()) }
            }),
            QuicMigrationConfig {
                scope: WeakScope::detached(),
                decision_timeout: Duration::from_millis(20),
                failure_action: QuicMigrationFailureAction::Close,
                failure_code: VarInt::from_u32(42),
            },
        )
        .with_decision_gate(gate.clone());
        let monitor = tokio::spawn(async move { layer.supervise(&ingress, &egress).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert!(!monitor.is_finished());
        drop(held);
        timeout(Duration::from_secs(2), finished.notified())
            .await
            .unwrap();
        // The permit must not remain held while waiting for the next network event.
        let permit = timeout(Duration::from_secs(2), gate.acquire())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        drop(permit);
        client.close(VarInt::from_u32(0), b"done");
        timeout(Duration::from_secs(2), monitor)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        origin.close(VarInt::from_u32(0), b"done");
        for endpoint in [
            client_endpoint,
            ingress_endpoint,
            egress_endpoint,
            origin_endpoint,
        ] {
            endpoint.shutdown_now().await;
        }
    }

    #[tokio::test]
    async fn local_migration_reports_server_constraint_and_connection_closure() {
        let (client_endpoint, server_endpoint, client, server) = pair().await;
        assert_eq!(
            server.local_migration_capability(SocketAddress::local_ipv4(1)),
            LocalMigrationCapability::Prohibited
        );
        assert_eq!(
            server.local_migration_capability(server.local_socket_address().unwrap()),
            LocalMigrationCapability::SameAddress
        );
        server.close(VarInt::from_u32(0), b"done");
        assert_eq!(
            server.local_migration_capability(SocketAddress::local_ipv4(1)),
            LocalMigrationCapability::Closed
        );
        client.closed().await;
        client_endpoint.shutdown_now().await;
        server_endpoint.shutdown_now().await;
    }
}
