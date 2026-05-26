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
};
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

use std::net::SocketAddr;

use crate::{
    Datagram, NwTcpStream, TcpFlow, UdpFlow,
    tproxy::{TransparentProxyFlowMeta, types::NwTcpConnectOptions},
};

mod svc_context;
pub use self::svc_context::TransparentProxyServiceContext;

mod boxed;
pub use self::boxed::{
    BoxedClosedSink, BoxedDemandSink, BoxedServerBytesSink, BoxedServerDatagramSink,
    BoxedTransparentProxyEngine, log_engine_build_error,
};

mod handler;
pub use self::handler::{FlowAction, TransparentProxyHandler, TransparentProxyHandlerFactory};

mod builder;
pub use self::builder::TransparentProxyEngineBuilder;

mod runtime;
pub use self::runtime::{
    DefaultTransparentProxyAsyncRuntimeFactory, TransparentProxyAsyncRuntime,
    TransparentProxyAsyncRuntimeFactory,
};

mod promote;
pub use self::promote::{Promote, PromoteError, PromoteHandle, PromoteLayer};

/// Default deadline for flow-handler decisions. Tuned via
/// [`TransparentProxyEngineBuilder::with_decision_deadline`].
pub const DEFAULT_DECISION_DEADLINE: Duration = Duration::from_secs(3);

/// Default per-flow TCP idle backstop. The engine applies this when
/// the builder's `tcp_idle_timeout` is left unset; explicit `None` via
/// [`TransparentProxyEngineBuilder::without_tcp_idle_timeout`] opts
/// out. Generous by design — it backstops wedged flows, not normal
/// idle aging.
pub const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_mins(15);

/// Default per-flow UDP max-lifetime cap. Mirrors
/// [`DEFAULT_TCP_IDLE_TIMEOUT`] for UDP; opt out via
/// [`TransparentProxyEngineBuilder::without_udp_max_flow_lifetime`].
pub const DEFAULT_UDP_MAX_FLOW_LIFETIME: Duration = Duration::from_mins(15);

/// Default per-UDP-flow idle timeout — close the flow when no
/// datagrams have been observed in either direction for this long.
/// Distinct from [`DEFAULT_UDP_MAX_FLOW_LIFETIME`]: that is a hard
/// wall-clock cap from flow start (whether active or idle); this
/// resets on each datagram. Opt out via
/// [`TransparentProxyEngineBuilder::without_udp_idle_timeout`].
///
/// 60 s is the smallest window that comfortably exceeds typical
/// real-world UDP-flow idle gaps (DNS retry cadence, NAT-keepalive
/// intervals, mDNS jitter). Active flows — QUIC long-poll, WebRTC
/// media — push the deadline forward on every datagram so they're
/// unaffected.
pub const DEFAULT_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

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

impl std::fmt::Display for DecisionDeadlineAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Block => "block",
            Self::Passthrough => "passthrough",
        })
    }
}

/// Default duplex buffer size between the per-flow bridge and the service.
/// Two duplexes per TCP flow (ingress + egress) at this size each, fixed
/// at flow creation, so this is a per-flow memory floor of `2× this`.
///
/// 16 KiB matches the bridge's own read buffer ([`run_tcp_bridge`]). For
/// L4 transparent forwarding this is plenty of burst absorption — the
/// bridge always copies out before the next read. Handlers that terminate
/// HTTP/2 (or other heavy fan-in protocols) should raise this via
/// [`TransparentProxyEngineBuilder::tcp_flow_buffer_size`].
const DEFAULT_TCP_FLOW_BUFFER_SIZE: usize = 16 * 1024;
/// Number of `Bytes` chunks each TCP per-flow channel (ingress and egress)
/// will buffer before backpressuring Swift. Each chunk is whatever Swift
/// hands us in one `flow.readData` / `connection.receive` callback
/// (typically 4–64 KiB).
///
/// 32 chunks is sized for L4 transparent forwarding (the design centre of
/// this engine). At ~16 KiB per chunk that gives ~512 KiB of worst-case
/// headroom per direction, ~1 MiB per flow under saturation. Handlers
/// that terminate HTTP/2 (or other heavy fan-in protocols) should raise
/// this via [`TransparentProxyEngineBuilder::tcp_channel_capacity`].
const DEFAULT_TCP_CHANNEL_CAPACITY: usize = 32;
/// Bound on the UDP ingress and egress channels. UDP datagrams are inherently
/// lossy, so on a full channel we drop the datagram rather than block; the
/// bound is just a memory cap.
const DEFAULT_UDP_CHANNEL_CAPACITY: usize = 32;

/// Default for [`TransparentProxyEngineBuilder::with_tcp_paused_drain_max_wait`].
/// Backstops a stuck downstream writer (a Swift `flow.write`
/// completion handler that never invokes `signalServerDrain`, a logic
/// bug clearing `pausedSignaled` without firing `onDrained`) so the
/// bridge can't wedge waiting for a notification that never arrives.
/// The flow closes with [`BridgeCloseReason::PausedTimeout`] on
/// expiry.
pub const DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT: Duration = Duration::from_mins(1);

/// TCP response / upstream-write sink. Returns a [`TcpDeliverStatus`]
/// so the Rust producer (the bridge) can pause when Swift's pending
/// queue is full and resume only after the matching `signal_*_drain`
/// call from Swift.
type BytesStatusSink = Arc<dyn Fn(Bytes) -> TcpDeliverStatus + Send + Sync + 'static>;
/// UDP datagram sink. Carries the per-datagram peer in addition to
/// the payload — see [`crate::Datagram`] for the direction-dependent
/// meaning of `peer`.
type DatagramSink = Arc<dyn Fn(Datagram) + Send + Sync + 'static>;
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
    rt: TransparentProxyAsyncRuntime,
    handler: H,
    tcp_flow_buffer_size: usize,
    tcp_channel_capacity: usize,
    udp_channel_capacity: usize,
    tcp_idle_timeout: Option<Duration>,
    tcp_paused_drain_max_wait: Option<Duration>,
    udp_max_flow_lifetime: Option<Duration>,
    udp_idle_timeout: Option<Duration>,
    decision_deadline: Duration,
    decision_deadline_action: DecisionDeadlineAction,
    /// `None` ⇒ fall back to `decision_deadline`; see the builder
    /// doc on [`TransparentProxyEngineBuilder::app_message_deadline`].
    app_message_deadline: Option<Duration>,
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

    /// Fire-and-forget notification that the system is going to
    /// sleep. Drives `TransparentProxyHandler::on_system_sleep` on
    /// the engine's runtime. Returns once the dispatch is queued
    /// — the handler's future runs detached so the Swift sleep
    /// completion isn't gated on it.
    pub fn notify_system_sleep(&self) {
        let Some(guard) = self.shutdown_guard() else {
            tracing::trace!("notify_system_sleep ignored: engine already stopped");
            return;
        };
        let exec = Executor::graceful(guard);
        let handler = self.handler.clone();
        self.rt
            .spawn(async move { handler.on_system_sleep(exec).await });
    }

    /// Symmetric counterpart of [`Self::notify_system_sleep`].
    pub fn notify_system_wake(&self) {
        let Some(guard) = self.shutdown_guard() else {
            tracing::trace!("notify_system_wake ignored: engine already stopped");
            return;
        };
        let exec = Executor::graceful(guard);
        let handler = self.handler.clone();
        self.rt
            .spawn(async move { handler.on_system_wake(exec).await });
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
        // Worst-case time we let a user-supplied app-message handler
        // run. Apple's `NETransparentProxyProvider` dispatches
        // `handleAppMessage` synchronously on its provider queue; a
        // hung handler would otherwise wedge the entire provider's
        // message dispatch indefinitely. `app_message_deadline` is
        // independent of `decision_deadline` so callers can tune
        // them separately; `None` falls back to `decision_deadline`
        // for backward-compat.
        let deadline = self.app_message_deadline.unwrap_or(self.decision_deadline);
        let message_len = message.len();
        block_on_async_task(&self.rt, async move {
            if let Ok(reply) =
                tokio::time::timeout(deadline, handler.handle_app_message(exec, message)).await
            {
                reply
            } else {
                tracing::warn!(
                    message_len,
                    deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX),
                    "transparent proxy app message handler exceeded deadline; dropping message",
                );
                None
            }
        })
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
        let tcp_paused_drain_max_wait = self.tcp_paused_drain_max_wait;
        let decision_deadline = self.decision_deadline;
        let decision_deadline_action = self.decision_deadline_action;
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
                tcp_paused_drain_max_wait,
                decision_deadline,
                decision_deadline_action,
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
        OnDatagram: Fn(Datagram) + Send + Sync + 'static,
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
        let udp_max_flow_lifetime = self.udp_max_flow_lifetime;
        let udp_idle_timeout = self.udp_idle_timeout;
        let decision_deadline = self.decision_deadline;
        let decision_deadline_action = self.decision_deadline_action;
        let exec = Executor::graceful(guard.clone());
        let handler = self.handler.clone();

        block_on_async_task(
            &self.rt,
            new_udp_session_flow_action(
                guard,
                exec,
                meta,
                udp_channel_capacity,
                udp_max_flow_lifetime,
                udp_idle_timeout,
                decision_deadline,
                decision_deadline_action,
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
    /// Shared per-flow paused flags + drain notifications.
    signals: Arc<TcpPerFlowSignals>,
    /// Rust→Swift: signal Swift it can resume reading from the intercepted flow.
    /// Fired by the ingress bridge after it drained a chunk while
    /// `signals.ingress_paused` was set.
    on_client_read_demand: DemandSink,
    /// Rust→Swift: response bytes back to the intercepted client flow.
    /// Returns a [`TcpDeliverStatus`] so the bridge can pause when Swift's
    /// writer pump is full and wait for the matching `signal_server_drain`.
    on_server_bytes: BytesStatusSink,
    /// Rust→Swift: ingress response stream done.
    on_server_closed: ClosedSink,
    /// Both ingress and egress duplex buffer size.
    tcp_flow_buffer_size: usize,
    /// Capacity of the bounded ingress and egress mpsc channels (in chunks).
    tcp_channel_capacity: usize,
    /// Optional per-flow idle timeout. `None` disables idle detection.
    tcp_idle_timeout: Option<Duration>,
    /// Optional override for [`DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT`] applied to both
    /// per-flow bridges. `None` means "use the engine default".
    tcp_paused_drain_max_wait: Option<Duration>,
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
    //
    // Shared with `promote::PromoteRegistry` so the promote fire
    // closure can drop the sender on a successful Swift cutover —
    // see `PromoteRegistry::fire`. The lock is uncontended on the
    // hot path (`on_client_bytes`) — only the promote path ever
    // contends with `on_client_bytes`, and only at cutover time.
    client_tx: Arc<parking_lot::Mutex<Option<mpsc::Sender<Bytes>>>>,
    saw_client_bytes: bool,

    // egress data path (populated by activate).
    //
    // Same `Arc<Mutex<Option<...>>>` shape as `client_tx` — and
    // for the same reason: the promote fire closure also drops
    // this sender on Ok ACK so a service using bidirectional
    // copy gets EOF on its `egress.read()` too. Without this
    // mirror, only `ingress.read()` would EOF and
    // `copy_bidirectional` (or any "both halves" reader) would
    // wedge forever after cutover.
    egress_tx: Arc<parking_lot::Mutex<Option<mpsc::Sender<Bytes>>>>,

    /// Shared paused flags + drain notifications for both directions.
    /// One allocation, used by `on_*_bytes`, the bridges, and `signal_*_drain`.
    signals: Arc<TcpPerFlowSignals>,

    // promote
    promote_registry: Arc<promote::PromoteRegistry>,

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
        // Lock window is bounded: `try_reserve` + `permit.send` are
        // both non-blocking. The lock is only contended with the
        // promote path at cutover time.
        let guard = self.client_tx.lock();
        let Some(tx) = guard.as_ref() else {
            return TcpDeliverStatus::Closed;
        };
        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(Bytes::copy_from_slice(bytes));
                TcpDeliverStatus::Accepted
            }
            Err(TrySendError::Full(())) => {
                self.signals.ingress_paused.store(true, Ordering::Release);
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
    ///
    /// If the client EOFs without ever sending a byte (`!saw_client_bytes`),
    /// route through `cancel()`: there's nothing for the service to do, and
    /// dragging the bridges through a normal half-close just adds latency
    /// before teardown. Note this is asymmetric with [`Self::on_egress_eof`]
    /// — see that method.
    pub fn on_client_eof(&mut self) {
        if !self.saw_client_bytes {
            self.cancel();
            return;
        }
        *self.client_tx.lock() = None;
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
        // Same lock-discipline rationale as `on_client_bytes` —
        // the only writer that contends is the promote fire
        // closure dropping the sender on Ok ACK.
        let guard = self.egress_tx.lock();
        let Some(tx) = guard.as_ref() else {
            return TcpDeliverStatus::Closed;
        };
        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(Bytes::copy_from_slice(bytes));
                TcpDeliverStatus::Accepted
            }
            Err(TrySendError::Full(())) => {
                self.signals.egress_paused.store(true, Ordering::Release);
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
        self.signals.ingress_drain.notify_one();
    }

    /// Symmetric counterpart of [`Self::signal_server_drain`] for the egress
    /// request direction. Called by Swift when its `NwTcpConnectionWritePump`
    /// has drained capacity after `on_write_to_egress` returned `Paused`.
    pub fn signal_egress_drain(&self) {
        self.signals.egress_drain.notify_one();
    }

    /// Called by Swift when the egress `NWConnection` closes or fails.
    ///
    /// Same channel-close pattern as [`Self::on_client_eof`], but no
    /// "no-traffic → cancel" fast path: a server closing before sending
    /// any response bytes is a normal protocol outcome (HTTP CONNECT
    /// tunnel close, idle disconnect, request-only verbs), and the
    /// service may still want to flush request bytes or run epilogue
    /// logic. Dropping `egress_tx` lets the service's `egress.read()`
    /// EOF naturally; the service decides what to do from there.
    pub fn on_egress_eof(&mut self) {
        *self.egress_tx.lock() = None;
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
            signals,
            on_client_read_demand,
            on_server_bytes,
            on_server_closed,
            tcp_flow_buffer_size,
            tcp_channel_capacity,
            tcp_idle_timeout,
            tcp_paused_drain_max_wait,
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
        // Service-initiated hand-off back to Swift; see [`PromoteHandle`].
        // The handle is backed by the session's `PromoteRegistry` so
        // `into_passthrough` fires the FFI-registered Swift callback,
        // awaits Swift's `confirm_promoted` ACK, and on success drops
        // both ingress + egress senders so the bridges EOF the
        // service after draining in-flight bytes.
        ingress_stream
            .extensions()
            .insert(self.promote_registry.clone().into_handle(rt_handle.clone()));

        // egress stream (service ↔ NWConnection)
        let (egress_user, egress_internal) = tokio::io::duplex(tcp_flow_buffer_size);
        let egress_stream = NwTcpStream::new(egress_user);

        let (egress_client_tx, egress_client_rx) = mpsc::channel::<Bytes>(tcp_channel_capacity);
        *self.egress_tx.lock() = Some(egress_client_tx);

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
        //
        // Note: we deliberately do NOT route this spawn through dial9's
        // per-future wake-tracking. `dial9_tokio_telemetry::spawn` reads
        // `TelemetryHandle::current()` from a thread-local, which is only
        // populated on dial9 worker threads. `activate` runs on a Swift
        // dispatch queue, so even with the `dial9` feature on the wrapper
        // would silently fall through to plain `tokio::spawn`. Runtime-level
        // events (poll start/end, wake, scheduling delay) are still emitted
        // on every poll because dial9 hooks the worker thread, so the loss
        // is the per-future wake graph for these two bridge tasks only.

        let paused_drain_wait =
            tcp_paused_drain_max_wait.unwrap_or(DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT);
        // spawn ingress bridge (client ↔ service)
        self.ingress_bridge_task = Some({
            let guard = flow_guard.clone();
            let meta = meta_arc.clone();
            let signals = signals.clone();
            rt_handle.spawn(async move {
                run_tcp_bridge(
                    ingress_internal,
                    client_rx,
                    signals,
                    on_client_read_demand,
                    on_server_bytes,
                    on_server_closed,
                    guard,
                    meta,
                    tcp_idle_timeout,
                    paused_drain_wait,
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
                    signals,
                    guarded_egress_demand,
                    guarded_egress_bytes,
                    guarded_egress_closed,
                    guard,
                    meta,
                    tcp_idle_timeout,
                    paused_drain_wait,
                    BridgeDirection::Egress,
                )
                .await;
            })
        });

        // deliver BridgeIo to the waiting service task
        if bridge_tx
            .send(BridgeIo(ingress_stream, egress_stream))
            .is_err()
        {
            // Same situation as the UDP path: service task ended
            // before activate (parent_guard cancelled, panic). The
            // BridgeIo we built is dropped on send failure, which
            // closes the per-flow ingress / egress channels —
            // subsequent `on_client_bytes` etc. will report
            // `Closed`.
            tracing::debug!(
                target: "rama_apple_ne::tproxy",
                "tcp activate: bridge_tx.send dropped — service task ended before activate",
            );
        }
    }

    /// Register the Swift callback fired when the per-flow service
    /// calls [`PromoteHandle::into_passthrough`].
    ///
    /// Idempotent: a later call replaces the previous registration.
    /// If no callback is registered when `into_passthrough` fires,
    /// the future resolves with [`PromoteError::EgressUnavailable`]
    /// and `PromoteLayer` falls through to the in-Rust data path.
    ///
    /// After Swift completes the cutover it MUST call
    /// [`Self::confirm_promoted`] on this session to resolve the
    /// pending future.
    pub fn register_promote_request_callback<F>(&self, on_request: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        // Rust-typed registration: the registry stores the
        // closure as `Arc<dyn Fn>`, so re-registration drops
        // the previous closure (and any sentinel it captured)
        // promptly — no leak. Mutually exclusive with the
        // FFI-shape slot; registering one clears the other.
        self.promote_registry.register_rust(on_request);
    }

    /// Engine-internal: register a raw FFI-shape promote callback.
    /// Used by `rama_transparent_proxy_tcp_session_register_promote_callbacks`.
    #[doc(hidden)]
    pub fn register_promote_request_callback_raw(
        &self,
        context: *mut std::ffi::c_void,
        on_promote_request: unsafe extern "C" fn(*mut std::ffi::c_void),
    ) {
        self.promote_registry
            .register_raw(promote::PromoteRequestCallback {
                context: context as usize,
                on_promote_request,
            });
    }

    /// Swift→Rust ACK for a pending `PromoteHandle::into_passthrough`.
    ///
    /// Resolves the future on the awaiting service task:
    /// - `Ok(())` → the in-Rust ingress sender is dropped so the
    ///   service sees EOF after draining in-flight bytes, then
    ///   `into_passthrough` returns `Ok(())`.
    /// - `Err(PromoteError::SwiftCutoverFailed { reason })` → the
    ///   layer logs the failure and the in-Rust data path keeps
    ///   running unchanged.
    ///
    /// Calling without a pending promote (e.g. duplicate confirm,
    /// or confirm before any service called `into_passthrough`) is
    /// a no-op.
    pub fn confirm_promoted(&self, result: Result<(), PromoteError>) {
        self.promote_registry.confirm(result);
    }

    pub fn cancel(&mut self) {
        // Order matters. See `guarded_datagram_sink` for the
        // callback_active contract.
        //
        //   1. callback_active = false — any in-flight bridge dispatch
        //      blocks here on the same sync mutex; further dispatches
        //      short-circuit.
        //   2. flow_stop_tx — fires `flow_guard.cancelled()` so the
        //      bridge's biased select picks the shutdown arm.
        //   3. notify_one — wake any bridge parked on Paused-wait so
        //      it observes (1) and (2).
        //   4. drop senders — natural EOF for `recv()` arms.
        //   5. detach bridge tasks (let them finish their close
        //      epilogue for dial9 / tracing); abort the service task
        //      as a fallback for user code wedged outside bridge IO.
        *self.callback_active.lock() = false;
        // The receiver lives inside `flow_shutdown`'s inner future
        // and is dropped only when that future ends — which itself
        // only ends when this `send(())` or the parent guard
        // fires. Send-then-Err therefore means "engine-level
        // shutdown raced ahead of this cancel"; trace-log so a
        // future "cancel did nothing" mystery has a breadcrumb.
        if let Some(tx) = self.flow_stop_tx.take()
            && tx.send(()).is_err()
        {
            tracing::debug!(
                target: "rama_apple_ne::tproxy",
                "tcp cancel: flow_stop_tx receiver already gone (engine shutdown raced ahead)",
            );
        }
        self.signals.ingress_drain.notify_one();
        self.signals.egress_drain.notify_one();
        *self.client_tx.lock() = None;
        *self.egress_tx.lock() = None;
        self.pending = None;
        // Abort any in-flight promote so callers of
        // `PromoteHandle::into_passthrough` resolve with
        // `EngineShuttingDown` instead of hanging on the ACK
        // forever.
        self.promote_registry.abort_pending();
        _ = self.ingress_bridge_task.take();
        _ = self.egress_bridge_task.take();
        if let Some(task) = self.service_task.take() {
            task.abort();
        }
    }
}

impl Drop for TransparentProxyTcpSession {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "internal helper threading TPROXY engine state to the per-flow handler; bundling into a struct adds noise without simplifying call sites"
)]
async fn new_tcp_session_flow_action<OnBytes, OnDemand, OnClosed, H>(
    parent_guard: ShutdownGuard,
    exec: Executor,
    meta: TransparentProxyFlowMeta,
    tcp_flow_buffer_size: usize,
    tcp_channel_capacity: usize,
    tcp_idle_timeout: Option<Duration>,
    tcp_paused_drain_max_wait: Option<Duration>,
    decision_deadline: Duration,
    decision_deadline_action: DecisionDeadlineAction,
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
    #[cfg(feature = "dial9")]
    let flow_source_pid = meta.source_app_pid;
    let Ok(flow_action) =
        tokio::time::timeout(decision_deadline, handler.match_tcp_flow(exec, meta)).await
    else {
        emit_decision_deadline_event(
            flow_id,
            flow_protocol,
            decision_deadline,
            decision_deadline_action,
        );
        #[cfg(feature = "dial9")]
        crate::tproxy::dial9::record_handler_deadline(
            flow_id,
            u64::try_from(decision_deadline.as_millis()).unwrap_or(u64::MAX),
        );
        return match decision_deadline_action {
            DecisionDeadlineAction::Block => SessionFlowAction::Blocked,
            DecisionDeadlineAction::Passthrough => SessionFlowAction::Passthrough,
        };
    };

    let (service, mut meta) = match flow_action {
        FlowAction::Intercept { service, meta } => (service, meta),
        FlowAction::Blocked => return SessionFlowAction::Blocked,
        FlowAction::Passthrough => return SessionFlowAction::Passthrough,
    };
    meta.intercept_decision = Some(crate::tproxy::types::TransparentProxyFlowAction::Intercept);

    #[cfg(feature = "dial9")]
    crate::tproxy::dial9::record_flow_opened(flow_id, flow_protocol.as_u32(), flow_source_pid);

    let (flow_stop_tx, flow_stop_rx) = oneshot::channel::<()>();
    let flow_shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = flow_stop_rx => {}
            _ = parent_guard.cancelled() => {}
        }
    });
    let flow_guard = flow_shutdown.guard();

    let (client_tx, client_rx) = mpsc::channel::<Bytes>(tcp_channel_capacity);
    let (bridge_tx, bridge_rx) = oneshot::channel::<BridgeIo<TcpFlow, NwTcpStream>>();
    let signals = Arc::new(TcpPerFlowSignals::new());

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
    //
    // Spawn through the rama `Executor` (graceful-aware) instead of
    // `flow_guard.spawn_task` directly, so that with the `dial9`
    // feature on the inner `tokio::spawn` is replaced by
    // `dial9_tokio_telemetry::spawn` — giving per-future wake-event
    // tracking on this long-lived per-flow service task.
    let meta_for_synthetic_close = meta.clone();
    let service_task = Executor::graceful(flow_guard.clone()).spawn_task(async move {
        let Ok(bridge) = bridge_rx.await else {
            // Cancelled before `activate`. Emit a synthetic close so
            // every `record_flow_opened` has a matching close in the
            // logs / dial9 trace. Mirrors the UDP path.
            let age_ms =
                u64::try_from(meta_for_synthetic_close.age().as_millis()).unwrap_or(u64::MAX);
            tracing::info!(
                target: "rama_apple_ne::tproxy",
                flow_id = meta_for_synthetic_close.flow_id,
                protocol = %meta_for_synthetic_close.protocol,
                reason = %BridgeCloseReason::Shutdown,
                age_ms,
                bytes_received = 0_u64,
                bytes_sent = 0_u64,
                pid = meta_for_synthetic_close.source_app_pid,
                bundle_id = meta_for_synthetic_close.source_app_bundle_identifier.as_deref(),
                signing_id = meta_for_synthetic_close.source_app_signing_identifier.as_deref(),
                decision = meta_for_synthetic_close
                    .intercept_decision
                    .map(|d| d.to_string()),
                "transparent proxy tcp flow closed before activate",
            );
            #[cfg(feature = "dial9")]
            crate::tproxy::dial9::record_flow_closed(
                meta_for_synthetic_close.flow_id,
                age_ms,
                0,
                0,
            );
            return;
        };
        // `serve` is `Result<(), Infallible>`; the `let Ok(())` form
        // depends on the `irrefutable_let_patterns` lint rather than
        // language-level pattern irrefutability for `Result<_,
        // Infallible>`. Drop the pattern entirely so future toolchain
        // bumps can't silently break this.
        _ = service.serve(bridge).await;
    });

    let pending = TcpSessionPendingData {
        bridge_tx,
        client_rx,
        signals: signals.clone(),
        on_client_read_demand: on_client_read_demand_guarded,
        on_server_bytes: on_server_bytes_guarded,
        on_server_closed: on_server_closed_guarded,
        tcp_flow_buffer_size,
        tcp_channel_capacity,
        tcp_idle_timeout,
        tcp_paused_drain_max_wait,
        meta,
        flow_guard,
        rt_handle,
        egress_connect_options,
    };

    let client_tx_shared = Arc::new(parking_lot::Mutex::new(Some(client_tx)));
    let egress_tx_shared: Arc<parking_lot::Mutex<Option<mpsc::Sender<Bytes>>>> =
        Arc::new(parking_lot::Mutex::new(None));
    let promote_registry = promote::PromoteRegistry::new(
        client_tx_shared.clone(),
        egress_tx_shared.clone(),
        callback_active.clone(),
    );

    SessionFlowAction::Intercept(TransparentProxyTcpSession {
        client_tx: client_tx_shared,
        saw_client_bytes: false,
        egress_tx: egress_tx_shared,
        signals,
        promote_registry,
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
    /// Delivers the completed [`UdpFlow`] to the waiting service task.
    /// UDP egress is the service's responsibility — it can pool
    /// sockets, apply platform-specific binding, or talk to a remote
    /// transport entirely; the engine just gets datagrams in and out
    /// of the intercepted client flow.
    flow_tx: oneshot::Sender<UdpFlow>,
    /// Ingress datagrams (client→service); handed to `UdpFlow` at activate.
    /// Each [`Datagram`] carries the peer the originating app addressed
    /// the datagram to.
    client_rx: mpsc::Receiver<Datagram>,
    /// service→client: datagram back to the intercepted client flow. The
    /// datagram's peer is the `sentBy` endpoint Swift uses when calling
    /// `NEAppProxyUDPFlow.writeDatagrams(_:sentBy:)`.
    on_server_datagram: DatagramSink,
    /// Demand sink captured into `UdpFlow` at activate.
    client_read_demand_sink: DemandSink,
    /// Per-flow metadata. Shared as `Arc` because the service task
    /// also needs it (close-event emission); a single refcount-bumped
    /// clone is cheaper than copying the whole struct.
    meta: Arc<TransparentProxyFlowMeta>,
}

pub struct TransparentProxyUdpSession {
    client_tx: Option<mpsc::Sender<Datagram>>,
    on_client_read_demand: DemandSink,

    flow_stop_tx: Option<oneshot::Sender<()>>,
    pending: Option<UdpSessionPendingData>,
    service_task: Option<tokio::task::JoinHandle<()>>,

    /// Soundness flag: callbacks dispatch only while this flag is
    /// `true`, with the lock held across the dispatch. `on_client_close`
    /// flips it to `false` so the Swift callback boxes (released right
    /// after `_session_free` returns) can never be reached by an
    /// in-flight Rust task. See the `guarded_*_sink` helpers for the
    /// load-bearing pattern.
    callback_active: Arc<parking_lot::Mutex<bool>>,

    /// Optional liveness signal for the engine-side UDP idle watcher.
    /// Fired on every observed ingress (`on_client_datagram`) and
    /// egress (the service's `Datagram` sink) datagram. `None` when
    /// the builder opted out via `without_udp_idle_timeout`.
    idle_notify: Option<Arc<tokio::sync::Notify>>,
}

impl TransparentProxyUdpSession {
    /// Deliver one client→service datagram. `peer` is the destination
    /// the originating app addressed it to; preserving it through the
    /// bridge is what makes multi-peer UDP (DNS, NTP, mDNS, gaming)
    /// faithfully proxied. `None` is the safety-valve for paths that
    /// lack endpoint attribution.
    pub fn on_client_datagram(&mut self, bytes: &[u8], peer: Option<SocketAddr>) {
        // Fire BEFORE the channel send: even if the channel is closed
        // (session torn down) the activity itself happened, and the
        // service task's idle watcher gets one consistent signal. The
        // watcher's `notified()` resolves at most once per
        // notify-then-notified pair, so back-to-back datagrams between
        // iterations coalesce into a single wake — no thundering herd.
        if let Some(notify) = self.idle_notify.as_ref() {
            notify.notify_one();
        }
        // Zero-length datagrams are valid per RFC 768; some protocols
        // (DTLS heartbeats, NAT-binding probes, keep-alives) rely on
        // them. Forward them through the bridge unchanged — the
        // service decides whether to filter, not the framework.
        if let Some(tx) = self.client_tx.as_mut() {
            // Bounded channel + lossy semantics: when the service can't keep up
            // we drop the datagram rather than block the FFI thread or grow the
            // queue without bound. UDP is lossy by design, so this matches what
            // the wire protocol already tolerates.
            //
            // Demand wiring: `on_client_read_demand` is the engine→Swift
            // signal that re-arms the kernel `flow.readDatagrams` cycle.
            // Swift's `requestRead` checks an internal `demandPending` flag
            // at the end of each in-flight read; if no demand call has come
            // in by then, Swift stops pumping. We therefore MUST fire
            // demand even on the `Full` arm — otherwise a saturating burst
            // that drops one datagram leaves Swift's `demandPending = false`
            // and Swift never re-issues `readDatagrams`, stalling the flow
            // permanently. Swift is already idempotent against
            // simultaneous demand calls (its `readPending` flag), so the
            // redundancy is harmless.
            //
            // Only the `Closed` arm skips the demand: the session is gone,
            // no point asking Swift to read more.
            //
            // Allocation is gated on free capacity so the overload
            // path (saturating burst that would be dropped) skips
            // the `Bytes::copy_from_slice` heap allocation entirely.
            // `Sender::capacity()` returns 0 on a closed channel too
            // — so the closed check MUST come first, otherwise a
            // closed-channel datagram would fire demand against a
            // Swift side whose session is already gone (the exact
            // contract `Closed` arm is meant to suppress).
            // `Sender::is_closed()` is a single atomic load; cheap
            // enough to do unconditionally on the hot path.
            if tx.is_closed() {
                return;
            }
            if tx.capacity() == 0 {
                (self.on_client_read_demand)();
                return;
            }
            let datagram = Datagram {
                payload: Bytes::copy_from_slice(bytes),
                peer,
            };
            match tx.try_send(datagram) {
                Ok(()) | Err(TrySendError::Full(_)) => {
                    (self.on_client_read_demand)();
                }
                Err(TrySendError::Closed(_)) => {}
            }
        }
    }

    pub fn on_client_close(&mut self) {
        // Same teardown discipline as `TransparentProxyTcpSession::cancel`:
        // flip the active-flag *first* so any callback already past
        // the active-check has its dispatch dropped instead of
        // reaching the Swift `context` after the FFI session is
        // freed and the Swift callback boxes are released.
        *self.callback_active.lock() = false;
        // Signal cooperative shutdown so the service task's
        // `flow_guard.cancelled()` arm fires; the task then runs its
        // close epilogue (`emit_udp_session_close_event`, dial9
        // `record_flow_closed`, `closed_sink()`) before returning.
        // Dropping `flow_stop_tx` triggers `flow_shutdown`'s inner
        // future to complete via the `flow_stop_rx` arm.
        if let Some(tx) = self.flow_stop_tx.take()
            && tx.send(()).is_err()
        {
            tracing::debug!(
                target: "rama_apple_ne::tproxy",
                "udp on_client_close: flow_stop_tx receiver already gone (engine shutdown raced ahead)",
            );
        }
        // Drop senders so the flow's `recv()` sees EOF. The service
        // owns egress entirely; whatever sockets / state it holds
        // are torn down inside the service future as it unwinds.
        self.client_tx = None;
        // Drop pending — drops bridge_tx so a service still parked on
        // `bridge_rx.await` returns Err and the synthetic close fires.
        self.pending = None;
        // Detach the service task without aborting. Aborting here
        // would skip the close epilogue: the future would be dropped
        // mid-`select!` and never reach
        // `emit_udp_session_close_event` / `record_flow_closed` /
        // `closed_sink`. The `flow_guard.cancelled()` arm in the
        // service task is the cooperative mechanism that lets the
        // task exit promptly while still emitting the close events.
        // The runtime keeps polling the detached task until its
        // select returns (bounded by `udp_max_flow_lifetime` if
        // configured); a service that genuinely wedges on something
        // other than bridge IO is bounded by `engine.stop()`'s
        // shutdown path.
        _ = self.service_task.take();
    }

    /// Activate the session.
    ///
    /// Hands the prepared [`UdpFlow`] to the waiting service task.
    /// The engine does not open an egress socket — the service does,
    /// using whatever transport / socket-pooling strategy fits the
    /// handler. The flow's extensions carry the per-flow
    /// [`TransparentProxyFlowMeta`] so the service can apply any
    /// platform-specific decoration before binding.
    pub fn activate(&mut self) {
        let Some(pending) = self.pending.take() else {
            tracing::warn!(
                "TransparentProxyUdpSession::activate called on already-active or cancelled session"
            );
            return;
        };

        let UdpSessionPendingData {
            flow_tx,
            client_rx,
            on_server_datagram,
            client_read_demand_sink,
            meta,
        } = pending;

        // ingress flow (client ↔ service)
        let ingress_flow = UdpFlow::new_with_io_demand(
            client_rx,
            on_server_datagram,
            Some(client_read_demand_sink),
        );
        let remote_endpoint = meta.remote_endpoint.clone();
        let protocol = meta.protocol;
        ingress_flow.extensions().insert_arc(meta);
        if let Some(remote) = remote_endpoint {
            ingress_flow.extensions().insert(ProxyTarget(remote));
        }

        tracing::debug!(protocol = ?protocol, "udp session activated");

        if flow_tx.send(ingress_flow).is_err() {
            // The service task receives via `bridge_rx` exactly once.
            // If we get here it means the task ended before activate
            // ran — `parent_guard` cancelled (engine shutting down)
            // or the task panicked. Either way the BridgeIo we just
            // built is dropped, which closes the client-ingress
            // channel from the receiver side. Log so a future
            // "everything returns Closed" mystery has a breadcrumb.
            tracing::debug!(
                target: "rama_apple_ne::tproxy",
                protocol = ?protocol,
                "udp activate: flow_tx.send dropped — service task ended before activate; per-flow ingress channel will report Closed",
            );
        }
    }
}

impl Drop for TransparentProxyUdpSession {
    fn drop(&mut self) {
        self.on_client_close();
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "internal helper threading TPROXY engine state to the per-UDP-flow handler; bundling into a struct adds noise without simplifying call sites"
)]
async fn new_udp_session_flow_action<OnDatagram, OnClosed, OnDemand, H>(
    parent_guard: ShutdownGuard,
    exec: Executor,
    meta: TransparentProxyFlowMeta,
    udp_channel_capacity: usize,
    udp_max_flow_lifetime: Option<Duration>,
    udp_idle_timeout: Option<Duration>,
    decision_deadline: Duration,
    decision_deadline_action: DecisionDeadlineAction,
    on_server_datagram: OnDatagram,
    on_client_read_demand: OnDemand,
    on_server_closed: OnClosed,
    handler: H,
) -> SessionFlowAction<TransparentProxyUdpSession>
where
    OnDatagram: Fn(Datagram) + Send + Sync + 'static,
    OnClosed: Fn() + Send + Sync + 'static,
    OnDemand: Fn() + Send + Sync + 'static,
    H: TransparentProxyHandler,
{
    let flow_id = meta.flow_id;
    let flow_protocol = meta.protocol;
    #[cfg(feature = "dial9")]
    let flow_source_pid = meta.source_app_pid;
    let Ok(flow_action) =
        tokio::time::timeout(decision_deadline, handler.match_udp_flow(exec, meta)).await
    else {
        emit_decision_deadline_event(
            flow_id,
            flow_protocol,
            decision_deadline,
            decision_deadline_action,
        );
        #[cfg(feature = "dial9")]
        crate::tproxy::dial9::record_handler_deadline(
            flow_id,
            u64::try_from(decision_deadline.as_millis()).unwrap_or(u64::MAX),
        );
        return match decision_deadline_action {
            DecisionDeadlineAction::Block => SessionFlowAction::Blocked,
            DecisionDeadlineAction::Passthrough => SessionFlowAction::Passthrough,
        };
    };
    let (service, mut meta) = match flow_action {
        FlowAction::Intercept { service, meta } => (service, meta),
        FlowAction::Blocked => return SessionFlowAction::Blocked,
        FlowAction::Passthrough => return SessionFlowAction::Passthrough,
    };
    meta.intercept_decision = Some(crate::tproxy::types::TransparentProxyFlowAction::Intercept);

    #[cfg(feature = "dial9")]
    crate::tproxy::dial9::record_flow_opened(flow_id, flow_protocol.as_u32(), flow_source_pid);

    let (flow_stop_tx, flow_stop_rx) = oneshot::channel::<()>();
    let flow_shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = flow_stop_rx => {}
            _ = parent_guard.cancelled() => {}
        }
    });
    let flow_guard = flow_shutdown.guard();

    let (client_tx, client_rx) = mpsc::channel::<Datagram>(udp_channel_capacity);
    let (flow_tx, flow_rx) = oneshot::channel::<UdpFlow>();

    // One mutex covers every Swift-bound callback for this session
    // (datagram, closed, demand). `on_client_close` flips it to false
    // (and serialises against any in-flight callback under the lock)
    // before signalling shutdown and dropping the senders, ensuring
    // the FFI box releases that happen right after `_session_free`
    // are race-free.
    let callback_active = Arc::new(parking_lot::Mutex::new(true));

    // Liveness signal for the engine-side idle watcher. Allocated
    // only when an idle timeout is configured; the wrapped sink
    // notifies on every service-emitted egress datagram, and
    // `on_client_datagram` mirrors the wake for the ingress
    // direction. The watcher races `serve_fut` in the service
    // task — see the `IdleTimeout` arm below.
    let idle_notify: Option<Arc<tokio::sync::Notify>> =
        udp_idle_timeout.map(|_| Arc::new(tokio::sync::Notify::new()));

    let on_server_datagram_with_idle: DatagramSink = if let Some(notify) = idle_notify.clone() {
        let inner: DatagramSink = Arc::new(on_server_datagram);
        Arc::new(move |d| {
            notify.notify_one();
            inner(d);
        })
    } else {
        Arc::new(on_server_datagram)
    };
    let datagram_sink: DatagramSink =
        guarded_datagram_sink(callback_active.clone(), on_server_datagram_with_idle);
    let closed_sink: ClosedSink =
        guarded_closed_sink(callback_active.clone(), Arc::new(on_server_closed));
    let user_demand_sink: DemandSink = Arc::new(on_client_read_demand);
    let client_read_demand_sink = guarded_demand_sink(callback_active.clone(), user_demand_sink);

    tracing::debug!(protocol = ?meta.protocol, "new udp session (pending egress connection)");

    // Build the meta as an Arc once and share it: the service task
    // needs it for the close-event emission paths, and `activate`
    // consumes it for the ingress flow's extension. Cloning the Arc
    // is one refcount bump; cloning the owned value would copy the
    // whole struct.
    let meta_arc = std::sync::Arc::new(meta);

    // Service task waits for BridgeIo; calls closed_sink when done.
    //
    // Spawn through the rama `Executor` so dial9 wake-event tracking
    // is applied when the feature is on (see TCP path for context).
    let meta_for_close = meta_arc.clone();
    let flow_guard_for_task = flow_guard.clone();
    let idle_notify_for_task = idle_notify.clone();
    let service_task = Executor::graceful(flow_guard).spawn_task(async move {
        let Ok(flow) = flow_rx.await else {
            // Cancelled before activate — emit a synthetic close so post-mortem
            // logs still account for the flow.
            emit_udp_session_close_event(BridgeCloseReason::Shutdown, &meta_for_close);
            #[cfg(feature = "dial9")]
            {
                let age_ms = u64::try_from(meta_for_close.age().as_millis()).unwrap_or(u64::MAX);
                crate::tproxy::dial9::record_flow_closed(meta_for_close.flow_id, age_ms, 0, 0);
            }
            return;
        };
        // Drive `service.serve(flow)` to completion, but observe up to
        // three additional terminators:
        //
        //   * `flow_guard.cancelled()` — fires when Swift calls
        //     `on_client_close` (which sends through `flow_stop_tx`) or
        //     when the engine itself is shutting down. Without this
        //     arm `on_client_close` would have to `task.abort()` the
        //     service task to reclaim it, which would skip the
        //     `closed_sink` / dial9 / structured-tracing close
        //     epilogue below — every clean Swift teardown would
        //     silently drop the close record.
        //   * `udp_idle_timeout` — when configured, the per-flow idle
        //     reaper. Resets on every datagram (ingress or egress);
        //     trips when both sides have gone quiet. This is the
        //     fast-feedback path for short-lived bursty flows
        //     (DNS, mDNS, NAT-keepalive probes) that would otherwise
        //     live until `udp_max_flow_lifetime`.
        //   * `udp_max_flow_lifetime` — when configured, a hard cap
        //     from flow start. Survives traffic; backstops a
        //     misbehaving idle reaper or a service-side wedge that
        //     keeps the idle signal alive without making real progress.
        //     See builder doc for semantics.
        let mut serve_fut = std::pin::pin!(service.serve(flow));
        let lifetime_fut = async {
            if let Some(lifetime) = udp_max_flow_lifetime {
                tokio::time::sleep(lifetime).await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let idle_fut = async {
            let (Some(timeout), Some(notify)) =
                (udp_idle_timeout, idle_notify_for_task.as_ref())
            else {
                std::future::pending::<()>().await;
                return;
            };
            loop {
                let notified = notify.notified();
                match tokio::time::timeout(timeout, notified).await {
                    Ok(()) => continue,
                    Err(_) => return,
                }
            }
        };
        let close_reason = tokio::select! {
            () = flow_guard_for_task.cancelled() => BridgeCloseReason::Shutdown,
            res = &mut serve_fut => {
                _ = res;
                BridgeCloseReason::PeerEofLeft
            }
            () = idle_fut => {
                tracing::debug!(
                    target: "rama_apple_ne::tproxy",
                    flow_id = meta_for_close.flow_id,
                    idle_ms = udp_idle_timeout
                        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                        .unwrap_or(0),
                    "transparent proxy udp flow idle; closing",
                );
                BridgeCloseReason::IdleTimeout
            }
            () = lifetime_fut => {
                tracing::warn!(
                    target: "rama_apple_ne::tproxy",
                    flow_id = meta_for_close.flow_id,
                    lifetime_ms = udp_max_flow_lifetime
                        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                        .unwrap_or(0),
                    "transparent proxy udp flow exceeded max lifetime; closing",
                );
                BridgeCloseReason::IdleTimeout
            }
        };
        emit_udp_session_close_event(close_reason, &meta_for_close);
        #[cfg(feature = "dial9")]
        {
            let age_ms = u64::try_from(meta_for_close.age().as_millis()).unwrap_or(u64::MAX);
            crate::tproxy::dial9::record_flow_closed(meta_for_close.flow_id, age_ms, 0, 0);
        }
        closed_sink();
    });

    let pending = UdpSessionPendingData {
        flow_tx,
        client_rx,
        on_server_datagram: datagram_sink,
        client_read_demand_sink: client_read_demand_sink.clone(),
        meta: meta_arc,
    };

    SessionFlowAction::Intercept(TransparentProxyUdpSession {
        client_tx: Some(client_tx),
        on_client_read_demand: client_read_demand_sink,
        flow_stop_tx: Some(flow_stop_tx),
        pending: Some(pending),
        service_task: Some(service_task),
        callback_active,
        idle_notify,
    })
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Drive `future` to completion on the engine's runtime, regardless
/// of whether the calling thread already has a Tokio runtime context.
///
/// FFI entry points are typically invoked from a Swift dispatch queue
/// (no current Tokio runtime — the bottom `_ => inner.block_on` arm
/// runs). This helper also covers the rarer cases where a caller is
/// already inside *some* runtime (e.g. an integration test, or a
/// nested FFI invocation): `block_in_place` for multi-thread, an OS
/// thread scope for current-thread.
///
/// # Cross-runtime deadlock footgun
///
/// **Do not** call FFI engine methods from inside a Tokio task on a
/// runtime that owns *shared async state* with the engine — e.g. a
/// channel whose other half is held by an engine task. The
/// block-in-place / thread-scope path parks the caller's worker until
/// the inner runtime makes progress; if the inner runtime is itself
/// awaiting wakeups that the parked outer runtime would have produced,
/// you get a future-cycle deadlock that no timeout will save you from.
///
/// In practice: don't share runtime objects between the engine and the
/// caller. The example crate uses its own runtime, kept entirely
/// separate from the engine's. FFI consumers from Swift / a C bridge
/// don't have an outer Tokio runtime to begin with, so the typical
/// case is the bottom `_ => inner.block_on` arm and is safe.
fn block_on_async_task<F>(rt: &TransparentProxyAsyncRuntime, future: F) -> F::Output
where
    F: Future<Output: Send> + Send,
{
    // We drive the inner `tokio::runtime::Runtime` directly rather than
    // the wrapper's `block_on`: non-`'static` futures can't be routed
    // through dial9's spawn-then-await instrumentation. Wake-tracking
    // on these short-lived FFI futures is sacrificed; worker-thread
    // events still fire.
    //
    // catch_unwind logs handler-future panics before the extern "C"
    // boundary forces abort.
    let inner = rt.tokio_runtime();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match tokio::runtime::Handle::try_current() {
            Ok(handle)
                if matches!(
                    handle.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread
                ) =>
            {
                tokio::task::block_in_place(|| inner.block_on(future))
            }
            Ok(handle)
                if matches!(
                    handle.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::CurrentThread
                ) =>
            {
                std::thread::scope(|scope| {
                    let join = scope.spawn(|| inner.block_on(future));
                    match join.join() {
                        Ok(output) => output,
                        Err(panic) => std::panic::resume_unwind(panic),
                    }
                })
            }
            _ => inner.block_on(future),
        }
    }));
    match result {
        Ok(output) => output,
        Err(panic) => {
            let msg = if let Some(s) = panic.downcast_ref::<&'static str>() {
                (*s).to_owned()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_owned()
            };
            tracing::error!(
                target: "rama_apple_ne::tproxy",
                panic_message = %msg,
                "tproxy FFI: handler future panicked; resuming unwind (extern \"C\" boundary aborts the process)",
            );
            std::panic::resume_unwind(panic);
        }
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
            _ = stop_trigger.send(());
        }

        let time = block_on_async_task(&self.rt, shutdown.shutdown());
        tracing::info!(?time, reason, "transparent proxy engine stopped");
    }
}

// ── Guarded callback sinks ────────────────────────────────────────────────
//
// The `callback_active` mutex is the load-bearing guarantee that bridge
// tasks never dispatch into a Swift `context` after `cancel()` returned
// and `_session_free` released the Swift callback box. The lock is held
// across the entire user closure: `cancel()` flips the flag under the
// same mutex, so a mid-dispatch callback blocks `cancel()` until it
// returns. Bind the guard to a named local (`active`) so its scope is
// the whole closure body — `let _ = lock()` drops immediately and
// reintroduces the UAF window.
//
// Why a `Mutex<bool>` rather than an `AtomicBool`. We need TWO
// invariants: (1) reads of the flag observe the latest write, and
// (2) `cancel()` only proceeds once any in-flight closure dispatch
// has finished. (1) alone is what an `AtomicBool` gives you; (2) is
// what makes the FFI-box release race-free, and it requires the
// closure body to run inside a critical section that excludes the
// flag flip. `AtomicBool` plus an "after the load, dispatch the
// closure" pattern leaks: the load can return `true`, `cancel()`
// can run + release the box, the closure then dereferences a freed
// pointer. The mutex makes "in-flight closure" and "flag flipped"
// mutually exclusive, which is the property we actually need.
//

fn guarded_bytes_status_sink(
    callback_active: Arc<parking_lot::Mutex<bool>>,
    user_bytes_sink: BytesStatusSink,
) -> BytesStatusSink {
    Arc::new(move |bytes: Bytes| -> TcpDeliverStatus {
        let active = callback_active.lock();
        if !*active {
            return TcpDeliverStatus::Closed;
        }
        user_bytes_sink(bytes)
    })
}

fn guarded_closed_sink(
    callback_active: Arc<parking_lot::Mutex<bool>>,
    user_closed_sink: ClosedSink,
) -> ClosedSink {
    // The mutex gate is load-bearing for FFI box lifetime: the
    // user closure's first act is to dispatch through the C
    // function pointer registered by Swift, which reconstructs the
    // Swift `CallbackBox` from the raw `*mut c_void` we hold via
    // `Unmanaged.fromOpaque(ptr).takeUnretainedValue()`. If
    // `_session_free` ran and Swift's `callbackBox.release()`
    // dropped the box's last retain, that reconstruction is a
    // use-after-free regardless of what the closure body does
    // afterwards (so the "closure only touches `[weak …]`
    // captures" property of the dispatcher's Swift side is
    // necessary but not sufficient).
    //
    // Serialisation contract: `cancel()` locks this same mutex to
    // flip the flag to false, so an in-flight closure either
    // finishes before cancel observes the lock (box still alive)
    // or short-circuits on the flag check (box pointer never
    // touched). The truncated-response failure mode that motivated
    // looking at this gate is fixed on the dispatcher side
    // (natural EOF goes through `on_client_eof` rather than
    // `cancel`); routing the close signal around the gate would
    // re-open the UAF.
    Arc::new(move || {
        let active = callback_active.lock();
        if !*active {
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
        let active = callback_active.lock();
        if !*active {
            return;
        }
        user_demand_sink();
    })
}

/// Guards a Swift-bound datagram callback against a teardown race:
/// `on_client_close` flips `callback_active` to `false` under the
/// same mutex, so any callback already past the active-check has
/// its dispatch dropped before reaching the freed Swift `context`.
fn guarded_datagram_sink(
    callback_active: Arc<parking_lot::Mutex<bool>>,
    user_datagram_sink: DatagramSink,
) -> DatagramSink {
    Arc::new(move |datagram: Datagram| {
        let active = callback_active.lock();
        if !*active {
            return;
        }
        user_datagram_sink(datagram);
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

impl std::fmt::Display for BridgeDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        })
    }
}

/// Per-flow backpressure flags and drain notifications, shared between the
/// session's FFI surface and its two bridge tasks via a single `Arc`. One
/// allocation instead of four (two `AtomicBool` + two `Notify`).
struct TcpPerFlowSignals {
    ingress_paused: AtomicBool,
    ingress_drain: Notify,
    egress_paused: AtomicBool,
    egress_drain: Notify,
}

impl TcpPerFlowSignals {
    fn new() -> Self {
        Self {
            ingress_paused: AtomicBool::new(false),
            ingress_drain: Notify::new(),
            egress_paused: AtomicBool::new(false),
            egress_drain: Notify::new(),
        }
    }

    fn paused(&self, dir: BridgeDirection) -> &AtomicBool {
        match dir {
            BridgeDirection::Ingress => &self.ingress_paused,
            BridgeDirection::Egress => &self.egress_paused,
        }
    }

    fn drain(&self, dir: BridgeDirection) -> &Notify {
        match dir {
            BridgeDirection::Ingress => &self.ingress_drain,
            BridgeDirection::Egress => &self.egress_drain,
        }
    }
}

#[expect(clippy::too_many_arguments)]
async fn run_tcp_bridge(
    internal: tokio::io::DuplexStream,
    mut client_rx: mpsc::Receiver<Bytes>,
    signals: Arc<TcpPerFlowSignals>,
    on_read_demand: DemandSink,
    on_server_bytes: BytesStatusSink,
    on_server_closed: ClosedSink,
    flow_guard: ShutdownGuard,
    meta: Arc<TransparentProxyFlowMeta>,
    idle_timeout: Option<Duration>,
    paused_drain_max_wait: Duration,
    direction: BridgeDirection,
) {
    let paused = signals.paused(direction);
    let server_write_notify = signals.drain(direction);
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

    // Direction-relative byte counters. See `emit_tcp_bridge_close_event`
    // for how the Ingress / Egress orientations resolve at log time.
    let mut bytes_received: u64 = 0; // FFI peer → duplex (this side received)
    let mut bytes_sent: u64 = 0; // duplex → FFI peer  (this side sent)
    let progress = Arc::new(AtomicU64::new(0));
    let mut last_progress: u64 = 0;
    let mut idle = idle_timeout.map(IdleGuard::new);

    let close_reason = loop {
        if server_closed {
            break BridgeCloseReason::PeerEofRight;
        }

        // Drain any pending replay before reading more from the duplex.
        if let Some(bytes) = pending_to_server.take() {
            let chunk_len = bytes.len() as u64;
            match on_server_bytes(bytes.clone()) {
                TcpDeliverStatus::Accepted => {
                    // Count this chunk against `bytes_sent` here, on
                    // the replay's accepted return — the original
                    // read in the main loop only counts for the first
                    // successful delivery, never for chunks that
                    // paused and were replayed.
                    bytes_sent += chunk_len;
                    progress.fetch_add(1, Ordering::Relaxed);
                }
                TcpDeliverStatus::Paused => {
                    pending_to_server = Some(bytes);
                    // Wait for drain or shutdown — never block here forever.
                    // The `paused_drain_max_wait` arm catches a stuck
                    // peer-side drain signal (lost / never invoked) so
                    // the bridge can't wedge waiting for a notification
                    // that never arrives.
                    tokio::select! {
                        biased;
                        () = flow_guard.cancelled() => {
                            break BridgeCloseReason::Shutdown;
                        }
                        () = server_write_notify.notified() => {
                            continue;
                        }
                        () = tokio::time::sleep(paused_drain_max_wait) => {
                            tracing::warn!(
                                target: "rama_apple_ne::tproxy",
                                flow_id = meta.flow_id,
                                direction = %direction,
                                wait_ms = u64::try_from(paused_drain_max_wait.as_millis()).unwrap_or(u64::MAX),
                                "transparent proxy bridge: paused-wait timeout (replay) — peer drain signal lost?",
                            );
                            break BridgeCloseReason::PausedTimeout;
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
            // Biased: shutdown + idle drain immediately, and the write
            // arm is preferred when both data arms are simultaneously
            // ready. Accepted trade-off — the read arm yields a poll to
            // the kernel buffer, which absorbs short backlog while the
            // write side bursts. Cancel determinism wins over perfect
            // read/write fairness for proxy traffic.
            biased;

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
                            tracing::trace!(direction = %direction, %err, "tcp bridge write_all conn error");
                        } else {
                            tracing::debug!(direction = %direction, %err, "tcp bridge write_all failed");
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
                        bytes_received += n;
                        progress.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    // FFI sender dropped (EOF or cancel). Drain done; close
                    // the write side so the service sees end-of-stream.
                    _ = write_half.shutdown().await;
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
                            tracing::trace!(direction = %direction, %err, "tcp bridge read_half conn error");
                        } else {
                            tracing::debug!(direction = %direction, %err, "tcp bridge read_half failed");
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
                                bytes_sent += n as u64;
                                progress.fetch_add(1, Ordering::Relaxed);
                            }
                            TcpDeliverStatus::Paused => {
                                pending_to_server = Some(bytes);
                                // See `paused_drain_max_wait` doc; mirrors
                                // the bound on the replay-side wait above.
                                tokio::select! {
                                    biased;
                                    () = flow_guard.cancelled() => {
                                        break BridgeCloseReason::Shutdown;
                                    }
                                    () = server_write_notify.notified() => {}
                                    () = tokio::time::sleep(paused_drain_max_wait) => {
                                        tracing::warn!(
                                            target: "rama_apple_ne::tproxy",
                                            flow_id = meta.flow_id,
                                            direction = %direction,
                                            wait_ms = u64::try_from(paused_drain_max_wait.as_millis()).unwrap_or(u64::MAX),
                                            "transparent proxy bridge: paused-wait timeout — peer drain signal lost?",
                                        );
                                        break BridgeCloseReason::PausedTimeout;
                                    }
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

    emit_tcp_bridge_close_event(direction, close_reason, &meta, bytes_received, bytes_sent);
    // Emit the dial9 close event only from the Ingress direction so
    // the flow appears once in the trace. The structured `tracing`
    // event above is per-direction (each bridge logs its own
    // direction-relative `bytes_received` / `bytes_sent`); dial9
    // collapses the two views into a single record using the
    // INGRESS bridge's counts, which on the ingress side mean:
    //   - bytes_received = client → service (this side received)
    //   - bytes_sent     = service → client (this side sent)
    // For a faithful relay these match the egress view modulo MITM
    // transformations.
    #[cfg(feature = "dial9")]
    if matches!(direction, BridgeDirection::Ingress) {
        let age_ms = u64::try_from(meta.age().as_millis()).unwrap_or(u64::MAX);
        crate::tproxy::dial9::record_flow_closed(meta.flow_id, age_ms, bytes_received, bytes_sent);
    }
    on_server_closed();
}

fn emit_udp_session_close_event(reason: BridgeCloseReason, meta: &TransparentProxyFlowMeta) {
    let age_ms = u64::try_from(meta.age().as_millis()).unwrap_or(u64::MAX);
    let local = meta.local_endpoint.as_ref().map(ToString::to_string);
    let remote = meta.remote_endpoint.as_ref().map(ToString::to_string);
    let decision = meta.intercept_decision.map(|d| d.to_string());

    tracing::info!(
        target: "rama_apple_ne::tproxy",
        flow_id = meta.flow_id,
        protocol = %meta.protocol,
        reason = %reason,
        age_ms,
        pid = meta.source_app_pid,
        bundle_id = meta.source_app_bundle_identifier.as_deref(),
        signing_id = meta.source_app_signing_identifier.as_deref(),
        local,
        remote,
        decision,
        "transparent proxy udp flow closed",
    );
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
        protocol = %protocol,
        deadline_ms,
        action = %action,
        reason = %BridgeCloseReason::HandlerDeadline,
        "transparent proxy flow handler exceeded decision deadline",
    );
}

fn emit_tcp_bridge_close_event(
    direction: BridgeDirection,
    reason: BridgeCloseReason,
    meta: &TransparentProxyFlowMeta,
    bytes_received: u64,
    bytes_sent: u64,
) {
    // `bytes_received` / `bytes_sent` are RELATIVE to the side this
    // bridge half is on (Ingress: client-side; Egress: server-side):
    //   * Ingress: received = client→service,  sent = service→client
    //   * Egress:  received = server→service,  sent = service→server
    // Operators reading the log MUST also read `direction` to
    // interpret the counts. The previous `bytes_in` / `bytes_out`
    // names suggested an absolute orientation that is not what the
    // bridge actually measures.
    let age_ms = u64::try_from(meta.age().as_millis()).unwrap_or(u64::MAX);
    let local = meta.local_endpoint.as_ref().map(ToString::to_string);
    let remote = meta.remote_endpoint.as_ref().map(ToString::to_string);
    let decision = meta.intercept_decision.map(|d| d.to_string());

    tracing::info!(
        target: "rama_apple_ne::tproxy",
        flow_id = meta.flow_id,
        protocol = %meta.protocol,
        direction = %direction,
        reason = %reason,
        age_ms,
        bytes_received,
        bytes_sent,
        pid = meta.source_app_pid,
        bundle_id = meta.source_app_bundle_identifier.as_deref(),
        signing_id = meta.source_app_signing_identifier.as_deref(),
        local,
        remote,
        decision,
        "transparent proxy tcp flow closed",
    );
}

#[cfg(test)]
mod tests;
