//! Opt-in recovery of a forwarding association's egress transport.
//!
//! A trusted owner requests recovery after a routing change. Preparation leaves the old
//! path running; adoption cancels both old copy directions and restarts them with the same
//! ingress. In-flight datagrams may be lost, never replayed. This does not preserve sessions
//! in protocols which cannot tolerate a source-address change, or migrate the remote peer.

use super::{CopyError, DatagramForwardError, DatagramForwardService, Peer};
use crate::{DatagramError, DatagramSender as _, DatagramSocket, DatagramSocketExt as _};
use rama_core::{
    Service,
    error::{BoxError, BoxErrorExt as _},
    futures::task::AtomicWaker,
    io::BridgeIo,
    telemetry::tracing,
};
use rama_net::address::ip::IntoCanonicalIpAddr as _;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};
use tokio::{
    sync::{Semaphore, oneshot, watch},
    time::{Instant, timeout},
};

/// A bounded, coalescing signal from a trusted network or routing-policy observer.
///
/// Call [`Self::request_recovery`] when a usable replacement path should be prepared, not
/// for every packet or repeated identical platform observation. Signals before an association
/// subscribes are already reflected in its initial connector call. Clones share the source.
#[derive(Debug, Clone)]
pub struct DatagramRecoverySignal(watch::Sender<DatagramRecoveryState>);

/// Trusted routing revision and whether a usable replacement can be prepared.
/// Repeated identical snapshots are ignored. Revisions need only change, not increase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DatagramRecoveryState {
    pub revision: u64,
    pub available: bool,
}

impl Default for DatagramRecoverySignal {
    fn default() -> Self {
        Self(watch::channel(DatagramRecoveryState::default()).0)
    }
}

impl DatagramRecoverySignal {
    /// Create a source with no pending recovery request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request preparation, advancing this source's locally managed revision.
    pub fn request_recovery(&self) {
        self.0.send_modify(|state| {
            state.revision = state.revision.wrapping_add(1);
            state.available = true;
        });
    }

    /// Cancel unfinished preparations when the network is unavailable. Existing forwarding
    /// is retained, and an existing outage deadline is never extended.
    pub fn suspend_recovery(&self) {
        self.0.send_modify(|state| {
            state.revision = state.revision.wrapping_add(1);
            state.available = false;
        });
    }

    /// Publish an externally managed routing revision, ignoring identical snapshots.
    /// Use this mode or the local request/suspend methods; do not mix revision owners.
    pub fn update(&self, snapshot: DatagramRecoveryState) {
        self.0.send_if_modified(|current| {
            if *current == snapshot {
                return false;
            }
            *current = snapshot;
            true
        });
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<DatagramRecoveryState> {
        self.0.subscribe()
    }
}

/// What happens when preparing or validating a replacement fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramRecoveryFailureAction {
    /// Continue on the old transport if it still works; otherwise wait within the outage deadline.
    Keep,
    /// End the association. Use when retaining its old route is forbidden.
    Close,
}

/// Preparation and outage policy for opt-in egress transport recovery.
#[derive(Debug, Clone)]
pub struct DatagramRecoveryConfig {
    /// Bounds connector work after obtaining the shared gate. New signals supersede preparation.
    pub preparation_timeout: Duration,
    /// Maximum wait after an egress I/O failure. New signals do not extend this deadline.
    /// No unsolicited retries occur: a trusted recovery signal is required.
    /// Host/network-unreachable errors may come from a remote router, not a local change;
    /// waiting then delays failure reporting by this bound. A custom egress reporting Closed
    /// also waits and ends with a recovery error at the deadline, unlike plain forwarding.
    pub unavailable_timeout: Duration,
    pub failure_action: DatagramRecoveryFailureAction,
}

/// Recovery controls shared by a set of independently forwarded associations.
///
/// No tasks, payload queues, or per-packet locks are added. Dropping the serving future
/// cancels preparation and forwarding. The optional gate bounds concurrent connector calls.
#[derive(Debug, Clone)]
pub struct DatagramRecovery {
    pub(super) signal: DatagramRecoverySignal,
    config: DatagramRecoveryConfig,
    gate: Option<Arc<Semaphore>>,
}

impl DatagramRecovery {
    /// Combine an observation source with explicit recovery deadlines and failure policy.
    pub fn new(signal: DatagramRecoverySignal, config: DatagramRecoveryConfig) -> Self {
        Self {
            signal,
            config,
            gate: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Share a concurrency limit across replacement preparations; queue time is not connector time.
        pub fn preparation_gate(mut self, gate: Arc<Semaphore>) -> Self {
            self.gate = Some(gate);
            self
        }
    }

    async fn prepare<S, F>(&self, factory: &F) -> Result<S, BoxError>
    where
        S: DatagramSocket,
        F: Service<(), Output = S>,
        F::Error: Into<BoxError>,
    {
        let _permit = match &self.gate {
            Some(gate) => Some(gate.acquire().await.map_err(BoxError::from)?),
            None => None,
        };
        timeout(self.config.preparation_timeout, factory.serve(()))
            .await
            .map_err(|_elapsed| BoxError::from_static_str("UDP recovery preparation timed out"))?
            .map_err(Into::into)
    }
}

impl DatagramForwardService {
    /// Forward with an explicitly authorized egress replacement factory.
    ///
    /// The factory must preserve routing restrictions and return a socket connected to the
    /// original peer. Capabilities are rechecked before adoption. The same ingress is retained.
    /// A receive-side ingress closure ends immediately; this opt-in mode does not drain a
    /// closing association. Egress path failures wait for recovery within the configured
    /// bound. Ingress packets received while egress is unavailable are discarded, avoiding
    /// stale replay and observing ingress closure promptly. Pending receives must be cancel-safe,
    /// as DatagramSocket requires.
    /// Peer refusal, packet-size and metadata errors remain terminal according to packet policy.
    pub async fn forward_with_recovery<A, B, F>(
        &self,
        peers: BridgeIo<Peer<A>, Peer<B>>,
        recovery: &DatagramRecovery,
        factory: F,
    ) -> Result<(), BoxError>
    where
        A: DatagramSocket,
        B: DatagramSocket,
        F: Service<(), Output = B>,
        F::Error: Into<BoxError>,
    {
        self.forward_recovering(peers, recovery, factory, recovery.signal.subscribe())
            .await
    }

    pub(super) async fn forward_recovering<A, B, F>(
        &self,
        BridgeIo(mut ingress, mut egress): BridgeIo<Peer<A>, Peer<B>>,
        recovery: &DatagramRecovery,
        factory: F,
        mut changes: watch::Receiver<DatagramRecoveryState>,
    ) -> Result<(), BoxError>
    where
        A: DatagramSocket,
        B: DatagramSocket,
        F: Service<(), Output = B>,
        F::Error: Into<BoxError>,
    {
        ingress.address = ingress.address.into_canonical_ip_addr();
        egress.address = egress.address.into_canonical_ip_addr();
        loop {
            let mut to_ingress = ingress.socket.create_sender();
            let mut to_egress = egress.socket.create_sender();
            self.check(&ingress.socket, &to_egress, egress.source_ip)?;
            self.check(&egress.socket, &to_ingress, ingress.source_ip)?;

            let ingress_receive = ingress.socket.capabilities();
            let ingress_send = to_ingress.capabilities();

            let next = {
                let (failed, mut failure) = oneshot::channel();
                let forwarding = async {
                    let (outbound, result) = {
                        tokio::select! {
                            result = self.copy_direction(&mut ingress.socket, ingress.address,
                                &mut to_egress, egress.address, egress.source_ip) => (true, result),
                            result = self.copy_direction(&mut egress.socket, egress.address,
                                &mut to_ingress, ingress.address, ingress.source_ip) => (false, result),
                        }
                    };
                    let Err(error) = result else {
                        return Ok(());
                    };
                    let egress_failure = matches!(
                        (&error, outbound),
                        (CopyError::Send(_), true) | (CopyError::Receive(_), false)
                    );
                    if !egress_failure || !error.is_recoverable_path_failure() {
                        return match error.into_error() {
                            DatagramForwardError::Datagram(DatagramError::Closed) => Ok(()),
                            error => Err(BoxError::from(error)),
                        };
                    }
                    tracing::debug!(target: "rama_udp::recovery", error = %error.into_error(), "egress unavailable; waiting for recovery");
                    let _closed = failed.send(());

                    // Keep observing ingress closure while the supervisor prepares recovery.
                    // These datagrams have no usable egress and are deliberately not replayed.
                    let mut discard = vec![0; self.buffer_bytes.get()];
                    loop {
                        tokio::task::consume_budget().await;
                        let metadata = match ingress.socket.recv(&mut discard).await {
                            Ok(metadata) => metadata,
                            Err(DatagramError::Closed) => return Ok(()),
                            Err(error) => return Err(error.into()),
                        };
                        match self.validate(&metadata, discard.len(), ingress.address) {
                            Ok(()) => {}
                            Err(DatagramForwardError::Truncated)
                                if self.drop_truncated(ingress.address) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                };
                tokio::pin!(forwarding);
                let mut failure_observed = false;
                let mut outage = None;
                let mut preparation: Option<Preparation<'_, B>> = None;

                loop {
                    tokio::select! {
                        biased;
                        // Expiry wins even under an unending stream of network observations.
                        () = wait_optional(outage.map(tokio::time::sleep_until)), if outage.is_some() => {
                            return Err(BoxError::from_static_str("UDP egress recovery deadline expired"));
                        }
                        result = &mut failure, if !failure_observed => {
                            failure_observed = true;
                            if result.is_ok() {
                                outage = Some(Instant::now() + recovery.config.unavailable_timeout);
                            }
                        }
                        result = &mut forwarding => return result,
                        changed = wake_gated(changes.changed()) => {
                            if changed.is_err() {
                                return Err(BoxError::from_static_str("UDP recovery signal closed"));
                            }
                            let available = changes.borrow_and_update().available;
                            preparation = if available {
                                Some(Box::pin(wake_gated(recovery.prepare(&factory))))
                            } else {
                                None
                            };
                            if available {
                                tracing::trace!(target: "rama_udp::recovery", "preparing egress replacement");
                            } else {
                                tracing::trace!(target: "rama_udp::recovery", "cancelled preparation while network unavailable");
                            }
                        }
                        result = wait_optional(preparation.as_mut()), if preparation.is_some() => {
                            preparation = None;
                            let result = result.and_then(|socket| {
                                if socket.peer_addr()?.into_canonical_ip_addr() != egress.address {
                                    return Err(BoxError::from_static_str("UDP recovery changed the authorized peer"));
                                }
                                self.check_capabilities(socket.capabilities(), ingress_send, ingress.source_ip)?;
                                self.check_capabilities(ingress_receive, socket.create_sender().capabilities(), egress.source_ip)?;
                                Ok(socket)
                            });
                            match result {
                                Ok(socket) => break socket,
                                Err(error) => {
                                    tracing::debug!(target: "rama_udp::recovery", %error, "egress preparation failed");
                                    if recovery.config.failure_action == DatagramRecoveryFailureAction::Close {
                                        return Err(error);
                                    }
                                }
                            }
                        }

                    }
                }
            };

            // All old polling futures and send handles must be dropped before retiring the socket.
            drop(to_egress);
            drop(to_ingress);
            egress.socket = next;
            tracing::trace!(target: "rama_udp::recovery", "egress transport replaced");
        }
    }
}

type Preparation<'a, S> = Pin<Box<dyn Future<Output = Result<S, BoxError>> + Send + 'a>>;

async fn wait_optional<F: Future>(future: Option<F>) -> F::Output {
    match future {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

// Only the signal's own wake polls its shared watch registration again. Packet wakes touch
// this per-association atomic, never the shared notification waiters lock.
struct ControlWake {
    ready: AtomicBool,
    parent: AtomicWaker,
}

impl Wake for ControlWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.store(true, Ordering::Release);
        self.parent.wake();
    }
}

async fn wake_gated<F: Future>(future: F) -> F::Output {
    let wake = Arc::new(ControlWake {
        ready: AtomicBool::new(true),
        parent: AtomicWaker::new(),
    });
    let waker = Waker::from(wake.clone());
    tokio::pin!(future);
    std::future::poll_fn(|cx| {
        wake.parent.register(cx.waker());
        if !wake.ready.swap(false, Ordering::AcqRel) {
            return Poll::Pending;
        }
        future.as_mut().poll(&mut Context::from_waker(&waker))
    })
    .await
}

#[cfg(test)]
mod tests;
