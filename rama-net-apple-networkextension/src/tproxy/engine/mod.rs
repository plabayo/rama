use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use rama_core::{
    bytes::Bytes,
    extensions::ExtensionsRef,
    graceful::{Shutdown, ShutdownGuard},
    io::BridgeIo,
    rt::Executor,
    service::Service,
    watchdog::{WatchdogRegistration, record_heartbeat},
};
pub use rama_core::watchdog::WatchdogConfig;
use rama_net::{
    conn::is_connection_error,
    proxy::{BridgeCloseReason, IdleGuard, ProxyTarget},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{
        Notify,
        mpsc::{self, error::TrySendError},
        oneshot,
    },
};

use crate::{
    NwTcpStream, NwUdpSocket, TcpFlow, UdpFlow,
    tproxy::{
        TransparentProxyFlowMeta,
        types::{NwTcpConnectOptions, NwUdpConnectOptions},
    },
};

mod svc_context;
pub use self::svc_context::TransparentProxyServiceContext;

mod boxed;
pub use self::boxed::{
    BoxedClosedSink, BoxedDemandSink, BoxedServerBytesSink, BoxedTransparentProxyEngine,
    log_engine_build_error,
};

mod handler;
pub use self::handler::{FlowAction, TransparentProxyHandler, TransparentProxyHandlerFactory};

mod builder;
pub use self::builder::TransparentProxyEngineBuilder;

mod runtime;
pub use self::runtime::{
    DefaultTransparentProxyAsyncRuntimeFactory, TransparentProxyAsyncRuntimeFactory,
};

/// Default deadline for flow-handler decisions. Tuned via
/// [`TransparentProxyEngineBuilder::with_decision_deadline`].
pub(super) const DEFAULT_DECISION_DEADLINE: Duration = Duration::from_secs(1);

/// Action taken when a flow handler exceeds the configured decision deadline.
///
/// The deadline exists to prevent a hung handler from holding kernel flow
/// ownership indefinitely. On expiry the engine takes one of these actions
/// instead of waiting for the handler to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionDeadlineAction {
    /// Reject the flow back to the kernel (treats it like
    /// [`FlowAction::Blocked`]). This is the default — a handler that cannot
    /// produce a decision in time is treated as untrusted rather than letting
    /// the flow through.
    Block,
    /// Let the flow pass through unintercepted (treats it like
    /// [`FlowAction::Passthrough`]). Use when failing-open is preferable to
    /// failing-closed for your deployment.
    Passthrough,
}

impl DecisionDeadlineAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Passthrough => "passthrough",
        }
    }
}

const DEFAULT_TCP_FLOW_BUFFER_SIZE: usize = 64 * 1024; // 64 KiB
/// Number of `Bytes` chunks each TCP per-flow channel (ingress and egress) will
/// buffer before we tell Swift to stop reading from the kernel and wait for a
/// demand callback to resume. Each chunk is whatever Swift hands us in one
/// `flow.readData` / `connection.receive` callback (typically 4–64 KiB).
///
/// We bound this to keep per-flow worst-case memory in check: the prior
/// unbounded design let one slow flow buffer arbitrary pending bytes, which
/// under sustained traffic exhausted Apple's per-flow NE kernel buffer and
/// aborted the shared NEAppProxyProvider director, killing every flow on the
/// extension.
///
/// 1024 chunks is sized for HTTP/2 multiplexing: a single TCP flow can carry
/// hundreds of concurrent streams, each with its own ~1 MiB initial flow
/// window. With 1024 × 64 KiB = ~64 MiB of headroom per direction we comfortably
/// absorb a handful of in-flight streams before Swift has to pause kernel
/// reads. Smaller values starve high-fan-in h2 connections
/// and cause stalls on large body transfers.
const DEFAULT_TCP_CHANNEL_CAPACITY: usize = 1024;
/// Bound on the UDP ingress and egress channels. UDP datagrams are inherently
/// lossy, so on a full channel we drop the datagram rather than block; the
/// bound is just a memory cap.
const DEFAULT_UDP_CHANNEL_CAPACITY: usize = 1024;

type BytesSink = Arc<dyn Fn(Bytes) + Send + Sync + 'static>;
/// Variant of [`BytesSink`] used for the response / upstream-write directions
/// where Swift's writer pump is the consumer. Returns a [`TcpDeliverStatus`]
/// so the Rust producer (the bridge) can pause when Swift's pending queue is
/// full and resume only after the matching `signal_*_drain` call from Swift.
type BytesStatusSink = Arc<dyn Fn(Bytes) -> TcpDeliverStatus + Send + Sync + 'static>;
type ClosedSink = Arc<dyn Fn() + Send + Sync + 'static>;
type DemandSink = Arc<dyn Fn() + Send + Sync + 'static>;

pub enum SessionFlowAction<S> {
    Intercept(S),
    Blocked,
    Passthrough,
}

/// Outcome of a Swift → Rust byte-delivery FFI call
/// ([`TransparentProxyTcpSession::on_client_bytes`] /
/// [`TransparentProxyTcpSession::on_egress_bytes`]).
///
/// We deliberately use a tri-state rather than a `bool` so Swift can tell
/// transient backpressure (`Paused` — wait for the matching demand callback
/// and then resume) apart from terminal "session is gone" (`Closed` — stop
/// the read pump immediately, no demand callback will ever fire). Collapsing
/// these into a single "false" left Swift's pumps sitting paused during
/// teardown, waiting on a demand callback that could only arrive via the
/// outer `on_server_closed` cleanup path.
///
/// `repr(u8)` is C-ABI-compatible: the FFI thunks return this directly, the
/// matching C header / Swift wrappers see plain `uint8_t` / `UInt8`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpDeliverStatus {
    /// The chunk was queued. Swift may keep reading from the kernel.
    Accepted = 0,
    /// The chunk was rejected because the per-flow channel is full. Swift
    /// must pause reads until the matching `on_*_read_demand` callback fires.
    Paused = 1,
    /// The chunk was rejected because the per-flow channel is closed (session
    /// teardown or write-side failure on the bridge). Swift must terminate
    /// the read pump — no further demand callback will fire.
    Closed = 2,
}

// Pin the ABI shape: the C header declares `RamaTcpDeliverStatus` as
// `enum : uint8_t`, and the Swift bridge imports it as a 1-byte rawValue.
// If anyone ever drops the `#[repr(u8)]` (or changes the discriminant size)
// without updating the C/Swift side in lockstep, this assertion fails at
// compile time instead of corrupting return values at runtime.
const _: () = assert!(std::mem::size_of::<TcpDeliverStatus>() == 1);

pub struct TransparentProxyEngine<H> {
    rt: tokio::runtime::Runtime,
    handler: H,
    tcp_flow_buffer_size: usize,
    tcp_channel_capacity: usize,
    udp_channel_capacity: usize,
    tcp_idle_timeout: Option<Duration>,
    // Will be plumbed through to UDP bridges in a follow-up; currently captured
    // from the builder but not yet observed.
    #[allow(dead_code)]
    udp_idle_timeout: Option<Duration>,
    decision_deadline: Duration,
    decision_deadline_action: DecisionDeadlineAction,
    heartbeat: Option<Arc<AtomicU64>>,
    _watchdog: Option<WatchdogRegistration>,
    shutdown: Option<Shutdown>,
    stop_trigger: Option<oneshot::Sender<()>>,
}

impl<H> TransparentProxyEngine<H>
where
    H: TransparentProxyHandler,
{
    pub fn transparent_proxy_config(&self) -> crate::tproxy::TransparentProxyConfig {
        self.handler.transparent_proxy_config()
    }

    pub fn handle_app_message(&self, message: Bytes) -> Option<Bytes> {
        let Some(guard) = self.shutdown_guard() else {
            tracing::error!(
                message_len = message.len(),
                "handle_app_message called after transparent proxy engine was already stopped"
            );
            return None;
        };

        let exec = Executor::graceful(guard);
        let handler = self.handler.clone();

        block_on_async_task(&self.rt, handler.handle_app_message(exec, message))
    }

    pub fn new_tcp_session<OnBytes, OnDemand, OnClosed>(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_bytes: OnBytes,
        on_client_read_demand: OnDemand,
        on_server_closed: OnClosed,
    ) -> SessionFlowAction<TransparentProxyTcpSession>
    where
        OnBytes: Fn(Bytes) -> TcpDeliverStatus + Send + Sync + 'static,
        OnDemand: Fn() + Send + Sync + 'static,
        OnClosed: Fn() + Send + Sync + 'static,
    {
        let Some(guard) = self.shutdown_guard() else {
            tracing::error!(
                protocol = ?meta.protocol,
                "shutdown_guard called after transparent proxy engine was already stopped; passing tcp flow through"
            );
            return SessionFlowAction::Passthrough;
        };

        let tcp_flow_buffer_size = self.tcp_flow_buffer_size;
        let tcp_channel_capacity = self.tcp_channel_capacity;
        let tcp_idle_timeout = self.tcp_idle_timeout;
        let decision_deadline = self.decision_deadline;
        let decision_deadline_action = self.decision_deadline_action;
        let heartbeat = self.heartbeat.clone();
        let exec = Executor::graceful(guard.clone());
        let handler = self.handler.clone();

        block_on_async_task(
            &self.rt,
            new_tcp_session_flow_action(
                guard,
                exec,
                meta,
                tcp_flow_buffer_size,
                tcp_channel_capacity,
                tcp_idle_timeout,
                decision_deadline,
                decision_deadline_action,
                heartbeat,
                on_server_bytes,
                on_client_read_demand,
                on_server_closed,
                handler,
            ),
        )
    }

    pub fn new_udp_session<OnDatagram, OnClosed, OnDemand>(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_datagram: OnDatagram,
        on_client_read_demand: OnDemand,
        on_server_closed: OnClosed,
    ) -> SessionFlowAction<TransparentProxyUdpSession>
    where
        OnDatagram: Fn(Bytes) + Send + Sync + 'static,
        OnClosed: Fn() + Send + Sync + 'static,
        OnDemand: Fn() + Send + Sync + 'static,
    {
        let Some(guard) = self.shutdown_guard() else {
            tracing::error!(
                protocol = ?meta.protocol,
                "shutdown_guard called after transparent proxy engine was already stopped; passing udp flow through"
            );
            return SessionFlowAction::Passthrough;
        };

        let udp_channel_capacity = self.udp_channel_capacity;
        let decision_deadline = self.decision_deadline;
        let decision_deadline_action = self.decision_deadline_action;
        let heartbeat = self.heartbeat.clone();
        let exec = Executor::graceful(guard.clone());
        let handler = self.handler.clone();

        block_on_async_task(
            &self.rt,
            new_udp_session_flow_action(
                guard,
                exec,
                meta,
                udp_channel_capacity,
                decision_deadline,
                decision_deadline_action,
                heartbeat,
                on_server_datagram,
                on_client_read_demand,
                on_server_closed,
                handler,
            ),
        )
    }

    pub fn stop(mut self, reason: i32) {
        self.shutdown_blocking(reason);
    }

    fn shutdown_guard(&self) -> Option<ShutdownGuard> {
        self.shutdown.as_ref().map(Shutdown::guard)
    }
}

// ── TCP session ──────────────────────────────────────────────────────────────

/// Data held between `new_tcp_session` and `activate`.
struct TcpSessionPendingData {
    /// Delivers the completed `BridgeIo` to the waiting service task.
    bridge_tx: oneshot::Sender<BridgeIo<TcpFlow, NwTcpStream>>,
    /// Ingress (client→Rust) bytes; handed to the ingress bridge at activate.
    client_rx: mpsc::Receiver<Bytes>,
    /// Ingress paused flag, shared with `on_client_bytes` and the bridge.
    /// See [`TransparentProxyTcpSession::client_paused`].
    client_paused: Arc<AtomicBool>,
    /// Rust→Swift: signal Swift it can resume reading from the intercepted flow.
    /// Fired by the ingress bridge after it drained a chunk while
    /// `client_paused` was set.
    on_client_read_demand: DemandSink,
    /// Rust→Swift: response bytes back to the intercepted client flow.
    /// Returns a [`TcpDeliverStatus`] so the bridge can pause when Swift's
    /// writer pump is full and wait for the matching `signal_server_drain`.
    on_server_bytes: BytesStatusSink,
    /// Notified by `TransparentProxyTcpSession::signal_server_drain` when the
    /// Swift writer pump for the intercepted flow has drained capacity.
    /// The ingress bridge awaits on it after `on_server_bytes` returns
    /// `Paused`.
    server_write_notify: Arc<Notify>,
    /// Rust→Swift: ingress response stream done.
    on_server_closed: ClosedSink,
    /// Both ingress and egress duplex buffer size.
    tcp_flow_buffer_size: usize,
    /// Capacity of the bounded ingress and egress mpsc channels (in chunks).
    tcp_channel_capacity: usize,
    /// Optional per-flow idle timeout. `None` disables idle detection.
    tcp_idle_timeout: Option<Duration>,
    /// Per-flow metadata inserted into `TcpFlow` extensions at activate.
    meta: TransparentProxyFlowMeta,
    /// Flow-scoped guard; held by bridge tasks to delay shutdown until they finish.
    flow_guard: ShutdownGuard,
    /// Runtime handle used to spawn bridge tasks from outside the async context.
    ///
    /// `activate` is called by Swift from an external (non-Tokio) thread after the
    /// egress `NWConnection` is ready.  We cannot use `tokio::spawn` from there —
    /// it requires an active runtime context.  Storing a `Handle` lets us call
    /// `Handle::spawn`, which works from any thread on multi-thread runtimes.
    rt_handle: tokio::runtime::Handle,
    /// Handler-supplied egress options (may be `None` for NW defaults).
    egress_connect_options: Option<NwTcpConnectOptions>,
}

pub struct TransparentProxyTcpSession {
    // ingress data path
    client_tx: Option<mpsc::Sender<Bytes>>,
    /// `true` while Swift has been told to stop calling `on_client_bytes`
    /// (because the ingress channel was full). Cleared by the ingress bridge
    /// after it drains a chunk; the bridge then fires
    /// `on_client_read_demand` to wake Swift.
    client_paused: Arc<AtomicBool>,
    saw_client_bytes: bool,
    /// Symmetric counterpart of `client_paused` for the response direction
    /// (Rust → Swift writer pump). Notified by Swift via
    /// [`Self::signal_server_drain`] when its writer drains capacity, awaited
    /// by the ingress bridge after `on_server_bytes` returns `Paused`.
    server_write_notify: Arc<Notify>,

    // egress data path (populated by activate)
    egress_tx: Option<mpsc::Sender<Bytes>>,
    /// Same role as `client_paused` but for the egress (NWConnection→Rust)
    /// channel; populated at `activate`.
    egress_paused: Option<Arc<AtomicBool>>,
    /// Symmetric counterpart for the egress request direction (Rust →
    /// Swift NWConnection writer pump); populated at `activate`. Notified by
    /// Swift via [`Self::signal_egress_drain`].
    egress_write_notify: Option<Arc<Notify>>,

    // lifecycle
    callback_active: Arc<parking_lot::Mutex<bool>>,
    flow_stop_tx: Option<oneshot::Sender<()>>,

    // pre-activate state
    pending: Option<TcpSessionPendingData>,

    // tasks
    ingress_bridge_task: Option<tokio::task::JoinHandle<()>>,
    egress_bridge_task: Option<tokio::task::JoinHandle<()>>,
    service_task: Option<tokio::task::JoinHandle<()>>,
}

impl TransparentProxyTcpSession {
    /// Called by Swift when client bytes arrive on the intercepted flow.
    ///
    /// See [`TcpDeliverStatus`] for the return contract. Never blocks the
    /// calling thread: this is invoked synchronously from a Swift dispatch
    /// queue, so we use `try_reserve` and surface fullness as a pause signal
    /// instead of awaiting capacity.
    ///
    /// Important: when this returns `Paused` the bytes are NOT taken — we
    /// reserve the channel slot only on the success path, so no allocation
    /// happens on overflow. Swift MUST retain the rejected `Data` and replay
    /// it before issuing the next `flow.readData`, otherwise the byte stream
    /// gets a hole and the downstream TLS layer surfaces "bad record MAC".
    #[must_use = "the caller must honor the returned backpressure / closed signal"]
    pub fn on_client_bytes(&mut self, bytes: &[u8]) -> TcpDeliverStatus {
        if bytes.is_empty() {
            return TcpDeliverStatus::Accepted;
        }
        self.saw_client_bytes = true;
        let Some(tx) = self.client_tx.as_mut() else {
            return TcpDeliverStatus::Closed;
        };
        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(Bytes::copy_from_slice(bytes));
                TcpDeliverStatus::Accepted
            }
            Err(TrySendError::Full(())) => {
                self.client_paused.store(true, Ordering::Release);
                TcpDeliverStatus::Paused
            }
            Err(TrySendError::Closed(())) => TcpDeliverStatus::Closed,
        }
    }

    /// Called by Swift when the intercepted flow signals read-EOF.
    ///
    /// We drop the per-flow ingress sender so the bridge's `recv()` drains
    /// any buffered chunks and then returns `None`, which is its natural
    /// EOF signal. Using a side-channel (e.g. a `watch::Sender<bool>`)
    /// would create a select-fairness race against `read_half.read()`
    /// that can either drop the last chunk (too-eager EOF) or starve the
    /// response direction (over-prioritised EOF).
    pub fn on_client_eof(&mut self) {
        if !self.saw_client_bytes {
            self.cancel();
            return;
        }
        self.client_tx = None;
    }

    /// Called by Swift when bytes arrive from the egress `NWConnection`.
    ///
    /// See [`Self::on_client_bytes`] for the return contract — same shape and
    /// the same "Swift MUST replay rejected bytes before its next receive"
    /// requirement.
    #[must_use = "the caller must honor the returned backpressure / closed signal"]
    pub fn on_egress_bytes(&mut self, bytes: &[u8]) -> TcpDeliverStatus {
        if bytes.is_empty() {
            return TcpDeliverStatus::Accepted;
        }
        let Some(tx) = self.egress_tx.as_mut() else {
            return TcpDeliverStatus::Closed;
        };
        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(Bytes::copy_from_slice(bytes));
                TcpDeliverStatus::Accepted
            }
            Err(TrySendError::Full(())) => {
                if let Some(paused) = self.egress_paused.as_ref() {
                    paused.store(true, Ordering::Release);
                }
                TcpDeliverStatus::Paused
            }
            Err(TrySendError::Closed(())) => TcpDeliverStatus::Closed,
        }
    }

    /// Called by Swift when its `TcpClientWritePump` (response writer) has
    /// drained capacity after `on_server_bytes` returned `Paused`.
    ///
    /// Wakes the ingress bridge so it can resume forwarding response bytes.
    /// Idempotent — the underlying `Notify` collapses redundant signals into
    /// a single permit.
    pub fn signal_server_drain(&self) {
        self.server_write_notify.notify_one();
    }

    /// Symmetric counterpart of [`Self::signal_server_drain`] for the egress
    /// request direction. Called by Swift when its `NwTcpConnectionWritePump`
    /// has drained capacity after `on_write_to_egress` returned `Paused`.
    pub fn signal_egress_drain(&self) {
        if let Some(notify) = &self.egress_write_notify {
            notify.notify_one();
        }
    }

    /// Called by Swift when the egress `NWConnection` closes or fails.
    ///
    /// Same channel-close pattern as [`Self::on_client_eof`].
    pub fn on_egress_eof(&mut self) {
        self.egress_tx = None;
    }

    /// Return the handler-supplied egress connect options, if any.
    pub fn egress_connect_options(&self) -> Option<&NwTcpConnectOptions> {
        self.pending
            .as_ref()
            .and_then(|p| p.egress_connect_options.as_ref())
    }

    /// Activate the session after the egress `NWConnection` is ready and the
    /// intercepted flow has been successfully opened.
    ///
    /// * `on_write_to_egress` — Rust→Swift: service bytes destined for the remote server.
    ///   Returns a [`TcpDeliverStatus`] so the egress bridge can pause when
    ///   Swift's `NwTcpConnectionWritePump` is full.
    /// * `on_egress_read_demand` — Rust→Swift: signal Swift it can resume reading
    ///   from the egress `NWConnection` after `on_egress_bytes` returned `Paused`.
    /// * `on_close_egress` — Rust→Swift: egress stream is done writing.
    pub fn activate<OnEgressWrite, OnEgressDemand, OnEgressClose>(
        &mut self,
        on_write_to_egress: OnEgressWrite,
        on_egress_read_demand: OnEgressDemand,
        on_close_egress: OnEgressClose,
    ) where
        OnEgressWrite: Fn(Bytes) -> TcpDeliverStatus + Send + Sync + 'static,
        OnEgressDemand: Fn() + Send + Sync + 'static,
        OnEgressClose: Fn() + Send + Sync + 'static,
    {
        let Some(pending) = self.pending.take() else {
            tracing::warn!(
                "TransparentProxyTcpSession::activate called on already-active or cancelled session"
            );
            return;
        };

        let TcpSessionPendingData {
            bridge_tx,
            client_rx,
            client_paused,
            on_client_read_demand,
            on_server_bytes,
            server_write_notify,
            on_server_closed,
            tcp_flow_buffer_size,
            tcp_channel_capacity,
            tcp_idle_timeout,
            meta,
            flow_guard,
            rt_handle,
            egress_connect_options: _,
        } = pending;

        // ingress stream (client ↔ service)
        let (ingress_user, ingress_internal) = tokio::io::duplex(tcp_flow_buffer_size);
        let ingress_stream =
            TcpFlow::new(ingress_user, Some(Executor::graceful(flow_guard.clone())));
        let remote_endpoint = meta.remote_endpoint.clone();
        let meta_arc = Arc::new(meta);
        ingress_stream.extensions().insert_arc(meta_arc.clone());
        if let Some(remote) = remote_endpoint {
            ingress_stream.extensions().insert(ProxyTarget(remote));
        }

        // egress stream (service ↔ NWConnection)
        let (egress_user, egress_internal) = tokio::io::duplex(tcp_flow_buffer_size);
        let egress_stream = NwTcpStream::new(egress_user);

        let (egress_client_tx, egress_client_rx) = mpsc::channel::<Bytes>(tcp_channel_capacity);
        let egress_paused = Arc::new(AtomicBool::new(false));
        let egress_write_notify = Arc::new(Notify::new());
        self.egress_tx = Some(egress_client_tx);
        self.egress_paused = Some(egress_paused.clone());
        self.egress_write_notify = Some(egress_write_notify.clone());

        // guard egress callbacks
        let egress_bytes_sink: BytesStatusSink = Arc::new(on_write_to_egress);
        let egress_closed_sink: ClosedSink = Arc::new(on_close_egress);
        let egress_demand_sink: DemandSink = Arc::new(on_egress_read_demand);
        let guarded_egress_bytes =
            guarded_bytes_status_sink(self.callback_active.clone(), egress_bytes_sink);
        let guarded_egress_closed =
            guarded_closed_sink(self.callback_active.clone(), egress_closed_sink);
        let guarded_egress_demand =
            guarded_demand_sink(self.callback_active.clone(), egress_demand_sink);

        // Spawn bridge tasks via the stored runtime handle so that `activate` can be
        // called from an external (non-Tokio) thread — e.g. a Swift dispatch queue.
        // We clone the flow_guard into each task to keep the shutdown barrier alive
        // until the task completes, matching the semantics of `spawn_task`.

        // spawn ingress bridge (client ↔ service)
        self.ingress_bridge_task = Some({
            let guard = flow_guard.clone();
            let meta = meta_arc.clone();
            rt_handle.spawn(async move {
                run_tcp_bridge(
                    ingress_internal,
                    client_rx,
                    client_paused,
                    on_client_read_demand,
                    on_server_bytes,
                    server_write_notify,
                    on_server_closed,
                    guard,
                    meta,
                    tcp_idle_timeout,
                    BridgeDirection::Ingress,
                )
                .await;
            })
        });

        // spawn egress bridge (service ↔ NWConnection)
        self.egress_bridge_task = Some({
            let guard = flow_guard;
            let meta = meta_arc;
            rt_handle.spawn(async move {
                run_tcp_bridge(
                    egress_internal,
                    egress_client_rx,
                    egress_paused,
                    guarded_egress_demand,
                    guarded_egress_bytes,
                    egress_write_notify,
                    guarded_egress_closed,
                    guard,
                    meta,
                    tcp_idle_timeout,
                    BridgeDirection::Egress,
                )
                .await;
            })
        });

        // deliver BridgeIo to the waiting service task
        let _ = bridge_tx.send(BridgeIo(ingress_stream, egress_stream));
    }

    pub fn cancel(&mut self) {
        // Soundness note for the Swift `context` lifetime contract:
        // bridge tasks dispatch to the user-supplied closures only after
        // re-checking `callback_active` under this synchronous Mutex (see
        // `guarded_bytes_sink`/`guarded_closed_sink` at the bottom of this
        // file). Flipping the flag here, *before* aborting the tasks and
        // dropping the channels, ensures that any callback already past the
        // check has its dispatch dropped instead of reaching the Swift
        // `context` after `cancel` has returned. Keep this Mutex sync — an
        // async lock would let callbacks slip through the gap between the
        // check and the actual call.
        *self.callback_active.lock() = false;
        // Drop the senders so the bridge's `recv()` returns `None` after
        // draining anything still buffered. This is the natural EOF
        // signal — no separate watch channel needed.
        self.client_tx = None;
        self.egress_tx = None;
        self.egress_paused = None;
        // Wake any bridge that's parked in `notify.notified().await` so it
        // can observe the cancellation and exit promptly. Notify is
        // sticky — these are no-ops if nobody's waiting.
        self.server_write_notify.notify_one();
        if let Some(notify) = &self.egress_write_notify {
            notify.notify_one();
        }
        self.egress_write_notify = None;
        if let Some(tx) = self.flow_stop_tx.take() {
            let _ = tx.send(());
        }
        // Drop pending — this drops bridge_tx, making bridge_rx.await return Err.
        self.pending = None;
        for task in [
            self.ingress_bridge_task.take(),
            self.egress_bridge_task.take(),
            self.service_task.take(),
        ]
        .into_iter()
        .flatten()
        {
            task.abort();
        }
    }
}

impl Drop for TransparentProxyTcpSession {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[allow(clippy::too_many_arguments)]
async fn new_tcp_session_flow_action<OnBytes, OnDemand, OnClosed, H>(
    parent_guard: ShutdownGuard,
    exec: Executor,
    meta: TransparentProxyFlowMeta,
    tcp_flow_buffer_size: usize,
    tcp_channel_capacity: usize,
    tcp_idle_timeout: Option<Duration>,
    decision_deadline: Duration,
    decision_deadline_action: DecisionDeadlineAction,
    heartbeat: Option<Arc<AtomicU64>>,
    on_server_bytes: OnBytes,
    on_client_read_demand: OnDemand,
    on_server_closed: OnClosed,
    handler: H,
) -> SessionFlowAction<TransparentProxyTcpSession>
where
    OnBytes: Fn(Bytes) -> TcpDeliverStatus + Send + Sync + 'static,
    OnDemand: Fn() + Send + Sync + 'static,
    OnClosed: Fn() + Send + Sync + 'static,
    H: TransparentProxyHandler,
{
    let egress_connect_options = handler.egress_tcp_connect_options(&meta);
    let flow_id = meta.flow_id;
    let flow_protocol = meta.protocol;
    let flow_action =
        match tokio::time::timeout(decision_deadline, handler.match_tcp_flow(exec, meta)).await {
            Ok(action) => {
                if let Some(hb) = heartbeat.as_ref() {
                    record_heartbeat(hb);
                }
                action
            }
            Err(_) => {
                emit_decision_deadline_event(
                    flow_id,
                    flow_protocol,
                    decision_deadline,
                    decision_deadline_action,
                );
                return match decision_deadline_action {
                    DecisionDeadlineAction::Block => SessionFlowAction::Blocked,
                    DecisionDeadlineAction::Passthrough => SessionFlowAction::Passthrough,
                };
            }
        };

    let (service, mut meta) = match flow_action {
        FlowAction::Intercept { service, meta } => (service, meta),
        FlowAction::Blocked => return SessionFlowAction::Blocked,
        FlowAction::Passthrough => return SessionFlowAction::Passthrough,
    };
    meta.intercept_decision = Some(crate::tproxy::types::TransparentProxyFlowAction::Intercept);

    let (flow_stop_tx, flow_stop_rx) = oneshot::channel::<()>();
    let flow_shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = flow_stop_rx => {}
            _ = parent_guard.cancelled() => {}
        }
    });
    let flow_guard = flow_shutdown.guard();

    let (client_tx, client_rx) = mpsc::channel::<Bytes>(tcp_channel_capacity);
    let client_paused = Arc::new(AtomicBool::new(false));
    let (bridge_tx, bridge_rx) = oneshot::channel::<BridgeIo<TcpFlow, NwTcpStream>>();
    let server_write_notify = Arc::new(Notify::new());

    let callback_active = Arc::new(parking_lot::Mutex::new(true));
    let on_server_bytes_guarded =
        guarded_bytes_status_sink(callback_active.clone(), Arc::new(on_server_bytes));
    let on_server_closed_guarded =
        guarded_closed_sink(callback_active.clone(), Arc::new(on_server_closed));
    let on_client_read_demand_guarded =
        guarded_demand_sink(callback_active.clone(), Arc::new(on_client_read_demand));

    // Capture the current runtime handle so `activate` can spawn bridge tasks from
    // any thread (including an external Swift thread) via `Handle::spawn`.
    let rt_handle = tokio::runtime::Handle::current();

    tracing::debug!(protocol = ?meta.protocol, "new tcp session (pending egress connection)");

    // Service task waits for BridgeIo, then serves it.
    let service_task = flow_guard.spawn_task(async move {
        let Ok(bridge) = bridge_rx.await else {
            return; // cancelled before activate
        };
        let Ok(()) = service.serve(bridge).await;
    });

    let pending = TcpSessionPendingData {
        bridge_tx,
        client_rx,
        client_paused: client_paused.clone(),
        on_client_read_demand: on_client_read_demand_guarded,
        on_server_bytes: on_server_bytes_guarded,
        server_write_notify: server_write_notify.clone(),
        on_server_closed: on_server_closed_guarded,
        tcp_flow_buffer_size,
        tcp_channel_capacity,
        tcp_idle_timeout,
        meta,
        flow_guard,
        rt_handle,
        egress_connect_options,
    };

    SessionFlowAction::Intercept(TransparentProxyTcpSession {
        client_tx: Some(client_tx),
        client_paused,
        saw_client_bytes: false,
        server_write_notify,
        egress_tx: None,
        egress_paused: None,
        egress_write_notify: None,
        callback_active,
        flow_stop_tx: Some(flow_stop_tx),
        pending: Some(pending),
        ingress_bridge_task: None,
        egress_bridge_task: None,
        service_task: Some(service_task),
    })
}

// ── UDP session ──────────────────────────────────────────────────────────────

/// Data held between `new_udp_session` and `activate`.
struct UdpSessionPendingData {
    /// Delivers the completed `BridgeIo` to the waiting service task.
    bridge_tx: oneshot::Sender<BridgeIo<UdpFlow, NwUdpSocket>>,
    /// Ingress datagrams (client→Rust); handed to `UdpFlow` at activate.
    client_rx: mpsc::Receiver<Bytes>,
    /// Rust→Swift: datagram back to the intercepted client flow.
    on_server_datagram: BytesSink,
    /// Demand sink captured into `UdpFlow` at activate.
    client_read_demand_sink: DemandSink,
    /// Capacity used for the egress mpsc channel created at activate.
    udp_channel_capacity: usize,
    /// Per-flow metadata.
    meta: TransparentProxyFlowMeta,
    /// Handler-supplied egress options.
    egress_connect_options: Option<NwUdpConnectOptions>,
}

pub struct TransparentProxyUdpSession {
    client_tx: Option<mpsc::Sender<Bytes>>,
    on_client_read_demand: DemandSink,

    /// Egress datagrams (NWConnection→Rust, populated by activate).
    egress_tx: Option<mpsc::Sender<Bytes>>,

    flow_stop_tx: Option<oneshot::Sender<()>>,
    pending: Option<UdpSessionPendingData>,
    service_task: Option<tokio::task::JoinHandle<()>>,
}

impl TransparentProxyUdpSession {
    pub fn on_client_datagram(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(tx) = self.client_tx.as_mut() {
            // Bounded channel + lossy semantics: when the service can't keep up
            // we drop the datagram rather than block the FFI thread or grow the
            // queue without bound. UDP is lossy by design, so this matches what
            // the wire protocol already tolerates.
            match tx.try_send(Bytes::copy_from_slice(bytes)) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Closed(_)) => return,
            }
            (self.on_client_read_demand)();
        }
    }

    pub fn on_client_close(&mut self) {
        self.client_tx = None;
        self.egress_tx = None;
        if let Some(tx) = self.flow_stop_tx.take() {
            let _ = tx.send(());
        }
        self.pending = None;
        if let Some(task) = self.service_task.take() {
            task.abort();
        }
    }

    /// Called by Swift when a datagram arrives from the egress `NWConnection`.
    ///
    /// Same drop-on-full semantics as [`Self::on_client_datagram`].
    pub fn on_egress_datagram(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(tx) = self.egress_tx.as_mut() {
            let _ = tx.try_send(Bytes::copy_from_slice(bytes));
        }
    }

    /// Return the handler-supplied egress connect options, if any.
    pub fn egress_connect_options(&self) -> Option<&NwUdpConnectOptions> {
        self.pending
            .as_ref()
            .and_then(|p| p.egress_connect_options.as_ref())
    }

    /// Activate the session once the egress `NWConnection` is ready.
    ///
    /// `on_send_to_egress` — Rust→Swift: dispatch a datagram to the NWConnection.
    pub fn activate<OnSendToEgress>(&mut self, on_send_to_egress: OnSendToEgress)
    where
        OnSendToEgress: Fn(Bytes) + Send + Sync + 'static,
    {
        let Some(pending) = self.pending.take() else {
            tracing::warn!(
                "TransparentProxyUdpSession::activate called on already-active or cancelled session"
            );
            return;
        };

        let UdpSessionPendingData {
            bridge_tx,
            client_rx,
            on_server_datagram,
            client_read_demand_sink,
            udp_channel_capacity,
            meta,
            egress_connect_options: _,
        } = pending;

        // ingress flow (client ↔ service)
        let ingress_flow = UdpFlow::new_with_io_demand(
            client_rx,
            on_server_datagram,
            Some(client_read_demand_sink),
        );
        let remote_endpoint = meta.remote_endpoint.clone();
        let protocol = meta.protocol;
        ingress_flow.extensions().insert_arc(Arc::new(meta));
        if let Some(remote) = remote_endpoint {
            ingress_flow.extensions().insert(ProxyTarget(remote));
        }

        // egress socket (service ↔ NWConnection)
        let (egress_client_tx, egress_client_rx) = mpsc::channel::<Bytes>(udp_channel_capacity);
        let egress_sink: BytesSink = Arc::new(on_send_to_egress);
        let egress_socket = NwUdpSocket::new(egress_client_rx, egress_sink);
        self.egress_tx = Some(egress_client_tx);

        tracing::debug!(protocol = ?protocol, "udp session activated");

        let _ = bridge_tx.send(BridgeIo(ingress_flow, egress_socket));
    }
}

impl Drop for TransparentProxyUdpSession {
    fn drop(&mut self) {
        self.on_client_close();
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn new_udp_session_flow_action<OnDatagram, OnClosed, OnDemand, H>(
    parent_guard: ShutdownGuard,
    exec: Executor,
    meta: TransparentProxyFlowMeta,
    udp_channel_capacity: usize,
    decision_deadline: Duration,
    decision_deadline_action: DecisionDeadlineAction,
    heartbeat: Option<Arc<AtomicU64>>,
    on_server_datagram: OnDatagram,
    on_client_read_demand: OnDemand,
    on_server_closed: OnClosed,
    handler: H,
) -> SessionFlowAction<TransparentProxyUdpSession>
where
    OnDatagram: Fn(Bytes) + Send + Sync + 'static,
    OnClosed: Fn() + Send + Sync + 'static,
    OnDemand: Fn() + Send + Sync + 'static,
    H: TransparentProxyHandler,
{
    let egress_connect_options = handler.egress_udp_connect_options(&meta);
    let flow_id = meta.flow_id;
    let flow_protocol = meta.protocol;
    let flow_action =
        match tokio::time::timeout(decision_deadline, handler.match_udp_flow(exec, meta)).await {
            Ok(action) => {
                if let Some(hb) = heartbeat.as_ref() {
                    record_heartbeat(hb);
                }
                action
            }
            Err(_) => {
                emit_decision_deadline_event(
                    flow_id,
                    flow_protocol,
                    decision_deadline,
                    decision_deadline_action,
                );
                return match decision_deadline_action {
                    DecisionDeadlineAction::Block => SessionFlowAction::Blocked,
                    DecisionDeadlineAction::Passthrough => SessionFlowAction::Passthrough,
                };
            }
        };
    let (service, mut meta) = match flow_action {
        FlowAction::Intercept { service, meta } => (service, meta),
        FlowAction::Blocked => return SessionFlowAction::Blocked,
        FlowAction::Passthrough => return SessionFlowAction::Passthrough,
    };
    meta.intercept_decision = Some(crate::tproxy::types::TransparentProxyFlowAction::Intercept);

    let (flow_stop_tx, flow_stop_rx) = oneshot::channel::<()>();
    let flow_shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = flow_stop_rx => {}
            _ = parent_guard.cancelled() => {}
        }
    });
    let flow_guard = flow_shutdown.guard();

    let (client_tx, client_rx) = mpsc::channel::<Bytes>(udp_channel_capacity);
    let (bridge_tx, bridge_rx) = oneshot::channel::<BridgeIo<UdpFlow, NwUdpSocket>>();

    let callback_active_demand = Arc::new(parking_lot::Mutex::new(true));
    let datagram_sink: BytesSink = Arc::new(on_server_datagram);
    let closed_sink: ClosedSink = Arc::new(on_server_closed);
    let user_demand_sink: DemandSink = Arc::new(on_client_read_demand);
    let client_read_demand_sink = guarded_demand_sink(callback_active_demand, user_demand_sink);

    tracing::debug!(protocol = ?meta.protocol, "new udp session (pending egress connection)");

    // Service task waits for BridgeIo; calls closed_sink when done.
    let service_task = flow_guard.spawn_task(async move {
        let Ok(bridge) = bridge_rx.await else {
            return; // cancelled before activate
        };
        let Ok(()) = service.serve(bridge).await;
        closed_sink();
    });

    let pending = UdpSessionPendingData {
        bridge_tx,
        client_rx,
        on_server_datagram: datagram_sink,
        client_read_demand_sink: client_read_demand_sink.clone(),
        udp_channel_capacity,
        meta,
        egress_connect_options,
    };

    SessionFlowAction::Intercept(TransparentProxyUdpSession {
        client_tx: Some(client_tx),
        on_client_read_demand: client_read_demand_sink,
        egress_tx: None,
        flow_stop_tx: Some(flow_stop_tx),
        pending: Some(pending),
        service_task: Some(service_task),
    })
}

// ── Shared helpers ────────────────────────────────────────────────────────────

fn block_on_async_task<F>(rt: &tokio::runtime::Runtime, future: F) -> F::Output
where
    F: Future<Output: Send> + Send,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::MultiThread
            ) =>
        {
            tokio::task::block_in_place(|| rt.block_on(future))
        }
        Ok(handle)
            if matches!(
                handle.runtime_flavor(),
                tokio::runtime::RuntimeFlavor::CurrentThread
            ) =>
        {
            std::thread::scope(|scope| {
                let join = scope.spawn(|| rt.block_on(future));
                match join.join() {
                    Ok(output) => output,
                    Err(panic) => std::panic::resume_unwind(panic),
                }
            })
        }
        _ => rt.block_on(future),
    }
}

impl<H> Drop for TransparentProxyEngine<H> {
    fn drop(&mut self) {
        self.shutdown_blocking(0);
    }
}

impl<H> TransparentProxyEngine<H> {
    fn shutdown_blocking(&mut self, reason: i32) {
        let Some(shutdown) = self.shutdown.take() else {
            return;
        };

        tracing::info!(reason, "transparent proxy engine stopping");
        if let Some(stop_trigger) = self.stop_trigger.take() {
            let _ = stop_trigger.send(());
        }

        let time = block_on_async_task(&self.rt, shutdown.shutdown());
        tracing::info!(?time, reason, "transparent proxy engine stopped");
    }
}

fn guarded_bytes_status_sink(
    callback_active: Arc<parking_lot::Mutex<bool>>,
    user_bytes_sink: BytesStatusSink,
) -> BytesStatusSink {
    Arc::new(move |bytes: Bytes| -> TcpDeliverStatus {
        if !*callback_active.lock() {
            // Session is being torn down: report Closed so the bridge breaks
            // its select loop and `on_server_closed` fires once at the end.
            return TcpDeliverStatus::Closed;
        }
        user_bytes_sink(bytes)
    })
}

fn guarded_closed_sink(
    callback_active: Arc<parking_lot::Mutex<bool>>,
    user_closed_sink: ClosedSink,
) -> ClosedSink {
    Arc::new(move || {
        if !*callback_active.lock() {
            return;
        }
        user_closed_sink();
    })
}

fn guarded_demand_sink(
    callback_active: Arc<parking_lot::Mutex<bool>>,
    user_demand_sink: DemandSink,
) -> DemandSink {
    Arc::new(move || {
        if !*callback_active.lock() {
            return;
        }
        user_demand_sink();
    })
}

/// Direction tag for [`run_tcp_bridge`] used in close-log emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BridgeDirection {
    /// Client ↔ service ingress bridge (FFI client_rx ↔ service duplex).
    Ingress,
    /// Service ↔ NWConnection egress bridge.
    Egress,
}

impl BridgeDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_tcp_bridge(
    internal: tokio::io::DuplexStream,
    mut client_rx: mpsc::Receiver<Bytes>,
    paused: Arc<AtomicBool>,
    on_read_demand: DemandSink,
    on_server_bytes: BytesStatusSink,
    server_write_notify: Arc<Notify>,
    on_server_closed: ClosedSink,
    flow_guard: ShutdownGuard,
    meta: Arc<TransparentProxyFlowMeta>,
    idle_timeout: Option<Duration>,
    direction: BridgeDirection,
) {
    let (mut read_half, mut write_half) = tokio::io::split(internal);
    let mut buf = vec![0u8; 16 * 1024];
    // Set to true once the write side is finished so we keep draining read_half even
    // if the service dropped its read side before the bridge had a chance to read its
    // response bytes.  Without this flag, a write failure would cause a `break` that
    // races against any already-buffered server response bytes.
    let mut write_done = false;
    // Set to true once `on_server_bytes` reports the session is gone; we then
    // exit the loop and fire `on_server_closed` once.
    let mut server_closed = false;
    // Bytes that `on_server_bytes` rejected with `Paused`. Swift does NOT
    // take ownership on a `Paused` return, so we MUST replay this chunk
    // after `server_write_notify` fires before reading any more from the
    // duplex — otherwise we punch a hole in the byte stream and the
    // downstream TLS layer surfaces "bad record MAC" once the gap reaches
    // the decryptor. Symmetric to the Swift-side `pendingData` retain
    // pattern for the Swift → Rust direction.
    let mut pending_to_server: Option<Bytes> = None;

    let mut bytes_in: u64 = 0; // bytes written to the duplex (FFI -> service)
    let mut bytes_out: u64 = 0; // bytes read from the duplex (service -> FFI)
    let progress = Arc::new(AtomicU64::new(0));
    let mut last_progress: u64 = 0;
    let mut idle = idle_timeout.map(IdleGuard::new);

    let close_reason = loop {
        if server_closed {
            break BridgeCloseReason::PeerEofRight;
        }

        // Drain any pending replay before reading more from the duplex.
        if let Some(bytes) = pending_to_server.take() {
            match on_server_bytes(bytes.clone()) {
                TcpDeliverStatus::Accepted => {
                    progress.fetch_add(1, Ordering::Relaxed);
                }
                TcpDeliverStatus::Paused => {
                    pending_to_server = Some(bytes);
                    // Wait for drain or shutdown — never block here forever.
                    tokio::select! {
                        biased;
                        () = flow_guard.cancelled() => {
                            break BridgeCloseReason::Shutdown;
                        }
                        () = server_write_notify.notified() => {
                            continue;
                        }
                    }
                }
                TcpDeliverStatus::Closed => {
                    server_closed = true;
                    continue;
                }
            }
        }

        tokio::select! {
            // No `biased;` between the two data arms — both must remain fair
            // so that sustained traffic in one direction can't starve the
            // other (think a busy h2 connection with continuous response data
            // arriving while the client also pumps WINDOW_UPDATEs). The
            // shutdown and idle arms are explicitly biased above the data
            // arms so they fire promptly when relevant.

            // Per-flow shutdown — drain immediately.
            () = flow_guard.cancelled() => {
                break BridgeCloseReason::Shutdown;
            }

            // Idle timeout — re-arm if progress observed; otherwise close.
            _ = async {
                match idle.as_mut() {
                    Some(g) => g.tick().await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let cur = progress.load(Ordering::Relaxed);
                if cur != last_progress {
                    last_progress = cur;
                    if let Some(g) = idle.as_mut() {
                        g.reset();
                    }
                    continue;
                }
                break BridgeCloseReason::IdleTimeout;
            }

            maybe = client_rx.recv(), if !write_done => {
                if let Some(bytes) = maybe {
                    // We just freed a slot — if Swift was paused waiting for capacity,
                    // wake it once. Edge-triggered: only the swap from `true` actually
                    // fires the callback, so we never spam Swift with redundant demand
                    // signals while the channel is draining.
                    if paused.swap(false, Ordering::AcqRel) {
                        on_read_demand();
                    }
                    let n = bytes.len() as u64;
                    if let Err(err) = write_half.write_all(&bytes).await {
                        if is_connection_error(&err) {
                            tracing::trace!(direction = direction.as_str(), %err, "tcp bridge write_all conn error");
                        } else {
                            tracing::debug!(direction = direction.as_str(), %err, "tcp bridge write_all failed");
                        }
                        // The service dropped its read side (e.g. it already wrote its
                        // response and returned).  Stop writing, but keep reading so
                        // any buffered response bytes still reach the client.
                        //
                        // Close the receiver: any subsequent `try_send` from the FFI
                        // side returns `TrySendError::Closed` so Swift stops queueing
                        // bytes that no one will ever read. Without this the FFI tx
                        // accumulates Bytes until the task aborts, which under
                        // sustained load lets a single broken flow keep buffering.
                        write_done = true;
                        client_rx.close();
                    } else {
                        bytes_in += n;
                        progress.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    // FFI sender dropped (EOF or cancel). Drain done; close
                    // the write side so the service sees end-of-stream.
                    let _ = write_half.shutdown().await;
                    write_done = true;
                }
            }
            read_res = read_half.read(&mut buf) => {
                match read_res {
                    Ok(0) => {
                        break BridgeCloseReason::PeerEofLeft;
                    }
                    Err(err) => {
                        let conn_err = is_connection_error(&err);
                        if conn_err {
                            tracing::trace!(direction = direction.as_str(), %err, "tcp bridge read_half conn error");
                        } else {
                            tracing::debug!(direction = direction.as_str(), %err, "tcp bridge read_half failed");
                        }
                        break BridgeCloseReason::ReadErrorLeft;
                    }
                    Ok(n) => {
                        // Symmetric backpressure: Swift's writer pump may be
                        // full. We must not just hand it more bytes — that's
                        // what leads to unbounded `pending` growth and
                        // eventually `ENOBUFS` on `flow.write` /
                        // `connection.send`. On `Paused`, hold the chunk
                        // (Swift did NOT take it) and suspend the bridge
                        // until `signal_*_drain` fires.
                        let bytes = Bytes::copy_from_slice(&buf[..n]);
                        match on_server_bytes(bytes.clone()) {
                            TcpDeliverStatus::Accepted => {
                                bytes_out += n as u64;
                                progress.fetch_add(1, Ordering::Relaxed);
                            }
                            TcpDeliverStatus::Paused => {
                                pending_to_server = Some(bytes);
                                tokio::select! {
                                    biased;
                                    () = flow_guard.cancelled() => {
                                        break BridgeCloseReason::Shutdown;
                                    }
                                    () = server_write_notify.notified() => {}
                                }
                            }
                            TcpDeliverStatus::Closed => {
                                // Session torn down on the Swift side; no
                                // demand will follow. Stop the loop after
                                // this iteration so `on_server_closed`
                                // fires exactly once.
                                server_closed = true;
                            }
                        }
                    }
                }
            }
        }
    };

    emit_tcp_bridge_close_event(direction, close_reason, &meta, bytes_in, bytes_out);
    on_server_closed();
}

fn emit_decision_deadline_event(
    flow_id: u64,
    protocol: crate::tproxy::TransparentProxyFlowProtocol,
    deadline: Duration,
    action: DecisionDeadlineAction,
) {
    let deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
    tracing::warn!(
        target: "rama_apple_ne::tproxy",
        flow_id,
        protocol = protocol.as_str(),
        deadline_ms,
        action = action.as_str(),
        reason = %BridgeCloseReason::HandlerDeadline,
        "transparent proxy flow handler exceeded decision deadline",
    );
}

fn emit_tcp_bridge_close_event(
    direction: BridgeDirection,
    reason: BridgeCloseReason,
    meta: &TransparentProxyFlowMeta,
    bytes_in: u64,
    bytes_out: u64,
) {
    let age_ms = u64::try_from(meta.age().as_millis()).unwrap_or(u64::MAX);
    let bundle_id = meta
        .source_app_bundle_identifier
        .as_ref()
        .map(ToString::to_string);
    let signing_id = meta
        .source_app_signing_identifier
        .as_ref()
        .map(ToString::to_string);
    let local = meta.local_endpoint.as_ref().map(ToString::to_string);
    let remote = meta.remote_endpoint.as_ref().map(ToString::to_string);
    let decision = meta.intercept_decision.map(|d| d.as_str());

    tracing::info!(
        target: "rama_apple_ne::tproxy",
        flow_id = meta.flow_id,
        protocol = meta.protocol.as_str(),
        direction = direction.as_str(),
        reason = %reason,
        age_ms,
        bytes_in,
        bytes_out,
        pid = meta.source_app_pid,
        bundle_id,
        signing_id,
        local,
        remote,
        decision,
        "transparent proxy tcp flow closed",
    );
}

#[cfg(test)]
mod tests;
