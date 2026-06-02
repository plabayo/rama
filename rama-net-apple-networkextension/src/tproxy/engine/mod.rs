use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
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
use rama_net::proxy::{BridgeCloseReason, IdleGuard, ProxyTarget};

use atomic_waker::AtomicWaker;
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};

use self::ffi_stream::{CloseReasonCell, FfiBridgeStream, TcpFlowByteCounters};

use std::net::SocketAddr;

use crate::{
    Datagram, NwTcpStream, TcpFlow, UdpFlow,
    tproxy::{TransparentProxyFlowMeta, types::NwTcpConnectOptions},
};

mod svc_context;
pub use self::svc_context::TransparentProxyServiceContext;

pub(crate) mod ffi_stream;

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

/// Default backstop on how long `engine.stop()` waits for engine-level
/// graceful guards to drop. Tuned via
/// [`TransparentProxyEngineBuilder::with_stop_drain_max_wait`].
///
/// A correct stop completes in sub-millisecond time once the trigger
/// fires: the only guards held at the engine level are the per-flow
/// signal-future parent guards (which drop immediately on cancel) and
/// any [`TransparentProxyHandler::on_system_sleep`] /
/// [`TransparentProxyHandler::on_system_wake`] hook tasks. Per-flow
/// data tasks hold per-flow guards, not engine guards, so they are not
/// awaited here. This bound therefore only bites a handler hook stuck
/// on un-timed I/O; the right fix for that is to bound the hook, not to
/// raise this. Kept short so a wedged hook cannot eat the whole Apple
/// stop grace.
pub const DEFAULT_STOP_DRAIN_MAX_WAIT: Duration = Duration::from_secs(5);

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

/// Default for the [`TransparentProxyEngineBuilder::tcp_flow_buffer_size`]
/// setter, which has no effect — per-flow buffering is bounded by
/// [`DEFAULT_TCP_CHANNEL_CAPACITY`].
const DEFAULT_TCP_FLOW_BUFFER_SIZE: usize = 16 * 1024;
/// Number of `Bytes` chunks each TCP per-flow channel (ingress and egress)
/// buffers before backpressuring Swift. Each chunk is whatever Swift hands
/// us in one `flow.readData` / `connection.receive` callback (typically
/// 4–64 KiB).
///
/// This channel is the only per-flow buffer, so deep queues just pin
/// memory; 8 suits L4 forwarding (~128 KiB/direction at 16 KiB chunks).
/// Handlers terminating HTTP/2 (or other heavy fan-in) should raise it via
/// [`TransparentProxyEngineBuilder::tcp_channel_capacity`].
const DEFAULT_TCP_CHANNEL_CAPACITY: usize = 8;
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

/// TCP response / upstream-write sink. Returns a [`TcpDeliverStatus`] so the
/// stream's write side can pause when Swift's pending queue is full and
/// resume after the matching `signal_*_drain`.
type BytesStatusSink = Arc<dyn Fn(&[u8]) -> TcpDeliverStatus + Send + Sync + 'static>;
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

impl TcpDeliverStatus {
    /// Decode a raw byte received across the FFI boundary. The FFI
    /// callbacks are declared to return `u8` (not this enum) so an
    /// out-of-range value from a foreign caller can never materialize
    /// an invalid discriminant (which would be UB). Unknown values
    /// fail safe to `Closed` — stop the pump rather than act on a
    /// corrupt status.
    #[must_use]
    pub fn from_ffi_u8(raw: u8) -> Self {
        match raw {
            0 => Self::Accepted,
            1 => Self::Paused,
            2 => Self::Closed,
            other => {
                tracing::error!(
                    raw = other,
                    "TcpDeliverStatus: invalid FFI value; treating as Closed"
                );
                Self::Closed
            }
        }
    }
}

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
    /// Backstop on `shutdown_blocking`'s wait for engine guards to
    /// drop; see [`DEFAULT_STOP_DRAIN_MAX_WAIT`].
    stop_drain_max_wait: Duration,
    /// Engine-wide [`Shutdown`] + its `oneshot` trigger, held together
    /// so they move as a unit (the trigger fires the `Shutdown`'s inner
    /// future). `None` after `shutdown_blocking` has taken them — the
    /// engine is terminally stopped.
    shutdown: parking_lot::Mutex<Option<ShutdownPair>>,
}

/// Pair of an engine-wide [`Shutdown`] and the [`oneshot::Sender`]
/// that fires its inner future.
///
/// Kept together because they must move atomically: firing the trigger
/// resolves the inner future, which lets the [`Shutdown`] propagate
/// cancellation to all outstanding [`ShutdownGuard`]s; once the trigger
/// is `send()`-ed it is consumed, and firing again would need a fresh
/// `Shutdown`.
struct ShutdownPair {
    shutdown: Shutdown,
    trigger: oneshot::Sender<()>,
}

/// Build a fresh [`ShutdownPair`] bound to the engine's runtime.
///
/// Kept private to this module — every construction site needs the
/// same `rt.enter()` ceremony so the [`Shutdown`]'s inner future is
/// spawned on the engine's runtime, not whatever runtime the caller
/// happens to be on.
fn build_shutdown_pair(rt: &TransparentProxyAsyncRuntime) -> ShutdownPair {
    let (trigger, rx) = oneshot::channel::<()>();
    let _enter = rt.enter();
    let shutdown = Shutdown::new(async move {
        _ = rx.await;
    });
    ShutdownPair { shutdown, trigger }
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
        OnBytes: Fn(&[u8]) -> TcpDeliverStatus + Send + Sync + 'static,
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
        self.shutdown
            .lock()
            .as_ref()
            .map(|pair| pair.shutdown.guard())
    }
}

// ── TCP session ──────────────────────────────────────────────────────────────

/// Data held between `new_tcp_session` and `activate`.
struct TcpSessionPendingData {
    /// Delivers the completed `BridgeIo` to the waiting service task.
    bridge_tx: oneshot::Sender<BridgeIo<TcpFlow, NwTcpStream>>,
    /// Ingress (client→Rust) bytes; becomes the `TcpFlow` read side at activate.
    client_rx: mpsc::Receiver<Bytes>,
    /// Shared per-flow paused flags + drain wakers.
    signals: Arc<TcpPerFlowSignals>,
    /// Rust→Swift: signal Swift it can resume reading from the intercepted flow.
    /// Fired by the `TcpFlow` read side after it drains a chunk while
    /// `signals.ingress_paused` was set.
    on_client_read_demand: DemandSink,
    /// Rust→Swift: response bytes back to the intercepted client flow.
    /// Returns a [`TcpDeliverStatus`] so the `TcpFlow` write side can pause
    /// when Swift's writer pump is full and wait for `signal_server_drain`.
    on_server_bytes: BytesStatusSink,
    /// Rust→Swift: ingress response stream done.
    on_server_closed: ClosedSink,
    /// Capacity of the bounded ingress and egress mpsc channels (in chunks).
    tcp_channel_capacity: usize,
    /// Optional override for [`DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT`] applied to
    /// both per-flow stream write sides. `None` means "use the engine default".
    tcp_paused_drain_max_wait: Option<Duration>,
    /// Per-flow byte tallies shared with the streams; read by the service
    /// task to emit the flow's close event.
    byte_counters: Arc<TcpFlowByteCounters>,
    /// Per-direction terminal close reason, recorded by each stream and read
    /// by the service task to label that direction's close event.
    ingress_close_reason: CloseReasonCell,
    egress_close_reason: CloseReasonCell,
    /// Per-flow metadata inserted into `TcpFlow` extensions at activate.
    meta: TransparentProxyFlowMeta,
    /// Flow-scoped guard, cloned into the per-flow stream executor.
    flow_guard: ShutdownGuard,
    /// Runtime handle, used to back the promote handle from `activate`
    /// (which Swift may call from an external, non-Tokio thread).
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

    /// Shared paused flags + drain wakers for both directions; used by
    /// `on_*_bytes`, the per-flow streams, and `signal_*_drain`.
    signals: Arc<TcpPerFlowSignals>,

    // promote
    promote_registry: Arc<promote::PromoteRegistry>,

    // lifecycle
    callback_active: Arc<parking_lot::Mutex<bool>>,
    flow_stop_tx: Option<oneshot::Sender<()>>,

    // pre-activate state
    pending: Option<TcpSessionPendingData>,

    // tasks
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
        self.try_enqueue_client(|| Bytes::copy_from_slice(bytes))
    }

    /// Owned-buffer counterpart of [`Self::on_client_bytes`]: Swift
    /// transfers ownership of the read buffer instead of lending it, so
    /// the common (`Accepted`) path enqueues a zero-copy [`Bytes`] backed
    /// by the foreign allocation rather than copying it. See
    /// [`BytesOwnedView`] for the ownership contract — crucially, the
    /// buffer is consumed only on the reserve-success path, so a
    /// `Paused`/`Closed` return leaves ownership with the caller (which
    /// must still retain+replay on `Paused`, free on `Closed`).
    ///
    /// [`BytesOwnedView`]: crate::ffi::BytesOwnedView
    #[must_use = "the caller must honor the returned backpressure / closed signal"]
    pub fn on_client_bytes_owned(&mut self, view: crate::ffi::BytesOwnedView) -> TcpDeliverStatus {
        if view.ptr.is_null() || view.len == 0 {
            // Mirror `on_client_bytes`: empty input is "no bytes observed",
            // so do NOT set `saw_client_bytes` (keeps the `on_client_eof`
            // fast-cancel applicable). We did take ownership of the (empty)
            // buffer, so release it here.
            // SAFETY: ownership was transferred to us; release exactly once.
            unsafe { view.release_now() };
            return TcpDeliverStatus::Accepted;
        }
        self.saw_client_bytes = true;
        // `view` is moved into the closure and consumed by `into_bytes`
        // ONLY when a slot is reserved. On `Paused`/`Closed` the closure
        // is dropped uncalled, leaving the foreign buffer owned by Swift.
        //
        // SAFETY: the FFI caller guarantees the buffer stays valid until
        // its `release` runs, and that `release` is thread-safe.
        self.try_enqueue_client(move || unsafe { view.into_bytes() })
    }

    /// Shared ingress (client→service) enqueue. `make` builds the chunk
    /// and is invoked ONLY when a channel slot was reserved, so no owned
    /// buffer is consumed on the `Paused` / `Closed` paths.
    ///
    /// Lock window is bounded: `try_reserve` + `permit.send` are both
    /// non-blocking. The lock is only contended with the promote path at
    /// cutover time.
    fn try_enqueue_client(&self, make: impl FnOnce() -> Bytes) -> TcpDeliverStatus {
        let guard = self.client_tx.lock();
        let Some(tx) = guard.as_ref() else {
            return TcpDeliverStatus::Closed;
        };
        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(make());
                TcpDeliverStatus::Accepted
            }
            Err(TrySendError::Full(())) => {
                // TODO(backpressure): lost-wakeup race. If the reader drains the
                // channel empty between this `try_reserve` and the store, it
                // clears `paused` before we set it, so the read-demand callback
                // never re-fires and the flow stalls until the idle backstop.
                // Pre-existing, rare at the default capacity; fix + a
                // capacity-1 test deferred (mirror in `try_enqueue_egress`).
                self.signals.ingress_paused.store(true, Ordering::Release);
                TcpDeliverStatus::Paused
            }
            Err(TrySendError::Closed(())) => TcpDeliverStatus::Closed,
        }
    }

    /// Called by Swift when the intercepted flow signals read-EOF.
    ///
    /// Drop the per-flow ingress sender: the stream's read side drains any
    /// buffered chunks then sees `None` (EOF). Dropping the sender (vs a
    /// side-channel flag) keeps the final chunk and the EOF strictly ordered.
    ///
    /// If the client EOFs without ever sending a byte (`!saw_client_bytes`),
    /// route through `cancel()` — nothing for the service to do. Asymmetric
    /// with [`Self::on_egress_eof`]; see there.
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
        self.try_enqueue_egress(|| Bytes::copy_from_slice(bytes))
    }

    /// Owned-buffer counterpart of [`Self::on_egress_bytes`]; see
    /// [`Self::on_client_bytes_owned`] and [`BytesOwnedView`] for the
    /// zero-copy ownership contract.
    ///
    /// [`BytesOwnedView`]: crate::ffi::BytesOwnedView
    #[must_use = "the caller must honor the returned backpressure / closed signal"]
    pub fn on_egress_bytes_owned(&mut self, view: crate::ffi::BytesOwnedView) -> TcpDeliverStatus {
        if view.ptr.is_null() || view.len == 0 {
            // SAFETY: ownership was transferred to us; release exactly once.
            unsafe { view.release_now() };
            return TcpDeliverStatus::Accepted;
        }
        // SAFETY: see `on_client_bytes_owned` — buffer valid until its
        // `release` runs, and consumed only on the reserve-success path.
        self.try_enqueue_egress(move || unsafe { view.into_bytes() })
    }

    /// Shared egress (upstream→service) enqueue. Same lock discipline as
    /// [`Self::try_enqueue_client`]; the only writer that contends is the
    /// promote fire closure dropping the sender on Ok ACK.
    fn try_enqueue_egress(&self, make: impl FnOnce() -> Bytes) -> TcpDeliverStatus {
        let guard = self.egress_tx.lock();
        let Some(tx) = guard.as_ref() else {
            return TcpDeliverStatus::Closed;
        };
        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(make());
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
        self.signals.ingress_drain.wake();
    }

    /// Symmetric counterpart of [`Self::signal_server_drain`] for the egress
    /// request direction. Called by Swift when its `NwTcpConnectionWritePump`
    /// has drained capacity after `on_write_to_egress` returned `Paused`.
    pub fn signal_egress_drain(&self) {
        self.signals.egress_drain.wake();
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
        OnEgressWrite: Fn(&[u8]) -> TcpDeliverStatus + Send + Sync + 'static,
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
            tcp_channel_capacity,
            tcp_paused_drain_max_wait,
            byte_counters,
            ingress_close_reason,
            egress_close_reason,
            meta,
            flow_guard,
            rt_handle,
            egress_connect_options: _,
        } = pending;

        let paused_drain_wait =
            tcp_paused_drain_max_wait.unwrap_or(DEFAULT_TCP_PAUSED_DRAIN_MAX_WAIT);
        let remote_endpoint = meta.remote_endpoint.clone();
        let meta_arc = Arc::new(meta);

        // ── ingress stream ──
        // read = client→service channel; write = service→client sink.
        let ingress_inner = FfiBridgeStream::new(
            client_rx,
            on_server_bytes,
            on_client_read_demand,
            on_server_closed,
            signals.clone(),
            byte_counters.clone(),
            ingress_close_reason,
            BridgeDirection::Ingress,
            paused_drain_wait,
        );
        let ingress_stream = TcpFlow::new(ingress_inner, Some(Executor::graceful(flow_guard)));
        ingress_stream.extensions().insert_arc(meta_arc);
        if let Some(remote) = remote_endpoint {
            ingress_stream.extensions().insert(ProxyTarget(remote));
        }
        // Service-initiated hand-off back to Swift; see [`PromoteHandle`].
        // The handle is backed by the session's `PromoteRegistry` so
        // `into_passthrough` fires the FFI-registered Swift callback,
        // awaits Swift's `confirm_promoted` ACK, and on success drops both
        // ingress + egress senders so the stream read sides EOF the service
        // after draining in-flight bytes.
        ingress_stream
            .extensions()
            .insert(self.promote_registry.clone().into_handle(rt_handle));

        // ── egress stream ──
        // read = upstream→service channel; write = service→upstream sink.
        let (egress_client_tx, egress_client_rx) = mpsc::channel::<Bytes>(tcp_channel_capacity);
        *self.egress_tx.lock() = Some(egress_client_tx);

        // guard egress callbacks against the post-cancel teardown race
        let egress_bytes_sink: BytesStatusSink = Arc::new(on_write_to_egress);
        let egress_closed_sink: ClosedSink = Arc::new(on_close_egress);
        let egress_demand_sink: DemandSink = Arc::new(on_egress_read_demand);
        let guarded_egress_bytes =
            guarded_bytes_status_sink(self.callback_active.clone(), egress_bytes_sink);
        let guarded_egress_closed =
            guarded_closed_sink(self.callback_active.clone(), egress_closed_sink);
        let guarded_egress_demand =
            guarded_demand_sink(self.callback_active.clone(), egress_demand_sink);

        let egress_inner = FfiBridgeStream::new(
            egress_client_rx,
            guarded_egress_bytes,
            guarded_egress_demand,
            guarded_egress_closed,
            signals,
            byte_counters,
            egress_close_reason,
            BridgeDirection::Egress,
            paused_drain_wait,
        );
        let egress_stream = NwTcpStream::new(egress_inner);

        // deliver BridgeIo to the waiting service task
        if bridge_tx
            .send(BridgeIo(ingress_stream, egress_stream))
            .is_err()
        {
            // Same situation as the UDP path: service task ended before
            // activate (parent_guard cancelled, panic). The BridgeIo we
            // built is dropped on send failure, which closes the per-flow
            // ingress / egress channels — subsequent `on_client_bytes` etc.
            // will report `Closed`.
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
        //   1. callback_active = false — any in-flight stream dispatch
        //      blocks here on the same sync mutex; further dispatches
        //      short-circuit.
        //   2. flow_stop_tx — fires `flow_guard.cancelled()` so the
        //      forwarder's biased select picks the shutdown arm and the
        //      flow-level idle watcher exits.
        //   3. drain wakers — wake any stream write side parked on a
        //      `Paused` so it re-polls, observes (1) via the gated sink
        //      (now `Closed`), and unwinds.
        //   4. drop senders — natural EOF for the stream read sides.
        //   5. abort the service task as a fallback for user code wedged
        //      outside stream IO (its streams' `Drop` still fires the
        //      gated close callbacks, no-op'd by (1)).
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
        self.signals.ingress_drain.wake();
        self.signals.egress_drain.wake();
        *self.client_tx.lock() = None;
        *self.egress_tx.lock() = None;
        self.pending = None;
        // Abort any in-flight promote so callers of
        // `PromoteHandle::into_passthrough` resolve with
        // `EngineShuttingDown` instead of hanging on the ACK
        // forever.
        self.promote_registry.abort_pending();
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
    // No effect; channel capacity bounds per-flow buffering.
    _tcp_flow_buffer_size: usize,
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
    OnBytes: Fn(&[u8]) -> TcpDeliverStatus + Send + Sync + 'static,
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
    let byte_counters = Arc::new(TcpFlowByteCounters::default());
    let ingress_close_reason: CloseReasonCell = Arc::new(parking_lot::Mutex::new(None));
    let egress_close_reason: CloseReasonCell = Arc::new(parking_lot::Mutex::new(None));

    let callback_active = Arc::new(parking_lot::Mutex::new(true));
    let on_server_bytes_guarded =
        guarded_bytes_status_sink(callback_active.clone(), Arc::new(on_server_bytes));
    let on_server_closed_guarded =
        guarded_closed_sink(callback_active.clone(), Arc::new(on_server_closed));
    let on_client_read_demand_guarded =
        guarded_demand_sink(callback_active.clone(), Arc::new(on_client_read_demand));

    // Capture the current runtime handle so `activate` (which Swift may
    // call from an external, non-Tokio thread) can back the promote handle.
    let rt_handle = tokio::runtime::Handle::current();

    tracing::debug!(protocol = ?meta.protocol, "new tcp session (pending egress connection)");

    // Service task waits for BridgeIo, then serves it under a flow-level
    // idle backstop + cancellation watch.
    //
    // Spawn through the rama `Executor` (graceful-aware) instead of
    // `flow_guard.spawn_task` directly, so that with the `dial9`
    // feature on the inner `tokio::spawn` is replaced by
    // `dial9_tokio_telemetry::spawn` — giving per-future wake-event
    // tracking on this long-lived per-flow service task.
    let meta_for_close = meta.clone();
    let counters_for_close = byte_counters.clone();
    let ingress_reason_cell = ingress_close_reason.clone();
    let egress_reason_cell = egress_close_reason.clone();
    let idle_guard = flow_guard.clone();
    let service_task = Executor::graceful(flow_guard.clone()).spawn_task(async move {
        let Ok(bridge) = bridge_rx.await else {
            // Cancelled before `activate`. Emit a synthetic close so
            // every `record_flow_opened` has a matching close in the
            // logs / dial9 trace. Mirrors the UDP path.
            let age_ms = u64::try_from(meta_for_close.age().as_millis()).unwrap_or(u64::MAX);
            tracing::info!(
                target: "rama_apple_ne::tproxy",
                flow_id = meta_for_close.flow_id,
                protocol = %meta_for_close.protocol,
                reason = %BridgeCloseReason::Shutdown,
                age_ms,
                bytes_received = 0_u64,
                bytes_sent = 0_u64,
                pid = meta_for_close.source_app_pid,
                bundle_id = meta_for_close.source_app_bundle_identifier.as_deref(),
                signing_id = meta_for_close.source_app_signing_identifier.as_deref(),
                decision = meta_for_close.intercept_decision.map(tracing::field::display),
                "transparent proxy tcp flow closed before activate",
            );
            #[cfg(feature = "dial9")]
            crate::tproxy::dial9::record_flow_closed(meta_for_close.flow_id, age_ms, 0, 0);
            return;
        };

        // Run the service, applying the idle timeout and watching the flow
        // guard here (the streams don't). On idle/shutdown we drop `serve`,
        // whose streams' `Drop` fires the gated close callbacks.
        let reason = {
            let mut serve = std::pin::pin!(service.serve(bridge));
            let mut idle = tcp_idle_timeout.map(IdleGuard::new);
            let mut last_progress = counters_for_close.total();
            loop {
                tokio::select! {
                    biased;
                    () = idle_guard.cancelled() => break BridgeCloseReason::Shutdown,
                    _ = async {
                        match idle.as_mut() {
                            Some(g) => g.tick().await,
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        let cur = counters_for_close.total();
                        if cur != last_progress {
                            last_progress = cur;
                            if let Some(g) = idle.as_mut() {
                                g.reset();
                            }
                            continue;
                        }
                        break BridgeCloseReason::IdleTimeout;
                    }
                    _ = serve.as_mut() => break BridgeCloseReason::PeerEofLeft,
                }
            }
        };

        let (ingress_received, ingress_sent) =
            counters_for_close.snapshot(BridgeDirection::Ingress);
        let (egress_received, egress_sent) = counters_for_close.snapshot(BridgeDirection::Egress);
        let (ingress_reason, egress_reason) = resolve_tcp_close_reasons(
            reason,
            *ingress_reason_cell.lock(),
            *egress_reason_cell.lock(),
        );
        emit_tcp_bridge_close_event(
            BridgeDirection::Ingress,
            ingress_reason,
            &meta_for_close,
            ingress_received,
            ingress_sent,
        );
        emit_tcp_bridge_close_event(
            BridgeDirection::Egress,
            egress_reason,
            &meta_for_close,
            egress_received,
            egress_sent,
        );
        // dial9 records one row per flow using the INGRESS orientation
        // (received = client→service, sent = service→client).
        #[cfg(feature = "dial9")]
        {
            let age_ms = u64::try_from(meta_for_close.age().as_millis()).unwrap_or(u64::MAX);
            crate::tproxy::dial9::record_flow_closed(
                meta_for_close.flow_id,
                age_ms,
                ingress_received,
                ingress_sent,
            );
        }
    });

    let pending = TcpSessionPendingData {
        bridge_tx,
        client_rx,
        signals: signals.clone(),
        on_client_read_demand: on_client_read_demand_guarded,
        on_server_bytes: on_server_bytes_guarded,
        on_server_closed: on_server_closed_guarded,
        tcp_channel_capacity,
        tcp_paused_drain_max_wait,
        byte_counters,
        ingress_close_reason,
        egress_close_reason,
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
            let (Some(timeout), Some(notify)) = (udp_idle_timeout, idle_notify_for_task.as_ref())
            else {
                std::future::pending::<()>().await;
                return;
            };
            loop {
                let notified = notify.notified();
                if let Err(err) = tokio::time::timeout(timeout, notified).await {
                    tracing::debug!("UDP idle notifier timed out after {err:?}");
                    return;
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
    //
    // NOTE (fail-fast vs isolate): we deliberately resume_unwind →
    // abort the whole sysext rather than swallow the panic and return
    // a fail-safe decision (`Block`). Loud + no poisoned-state class,
    // but blast radius = every flow. If a single panicking flow taking
    // the tunnel down ever proves worse than the recovery risk,
    // reconsider isolating just the decision path here.
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

/// Slack added to `stop_drain_max_wait` to form the OUTER hard cap on
/// `shutdown_blocking`. The inner [`Shutdown::shutdown_with_limit`]
/// only time-limits its guard-drop phase; its earlier
/// cancellation-propagation phase is unbounded and could wedge if the
/// runtime is starved. The outer [`tokio::time::timeout`] guarantees
/// `stop` returns regardless. Sized so the inner limit always wins in
/// every non-pathological case — the outer firing means the engine is
/// genuinely wedged.
const STOP_HARD_CAP_SLACK: Duration = Duration::from_secs(2);

impl<H> TransparentProxyEngine<H> {
    #[expect(clippy::needless_pass_by_ref_mut, reason = "contract")]
    fn shutdown_blocking(&mut self, reason: i32) {
        let Some(pair) = self.shutdown.lock().take() else {
            return;
        };

        tracing::info!(reason, "transparent proxy engine stopping");
        let ShutdownPair { shutdown, trigger } = pair;
        _ = trigger.send(());

        // Two-layer bound so teardown always returns:
        //   - INNER `shutdown_with_limit(max_wait)`: the graceful
        //     "wait for engine guards to drop, but not forever" cap. A
        //     correct stop resolves in sub-ms; this only bites a
        //     handler hook wedged on un-timed I/O (see
        //     [`DEFAULT_STOP_DRAIN_MAX_WAIT`]).
        //   - OUTER `timeout(max_wait + slack)`: a hard cap covering
        //     the inner's unbounded cancellation-propagation phase, so
        //     `stop` returns even if the runtime is starved. The inner
        //     wins in every non-pathological case.
        let max_wait = self.stop_drain_max_wait;
        let hard_cap = max_wait + STOP_HARD_CAP_SLACK;
        let outcome = block_on_async_task(&self.rt, async move {
            tokio::time::timeout(hard_cap, shutdown.shutdown_with_limit(max_wait)).await
        });
        match outcome {
            Ok(Ok(elapsed)) => {
                tracing::info!(?elapsed, reason, "transparent proxy engine stopped");
            }
            Ok(Err(_)) => tracing::warn!(
                reason,
                ?max_wait,
                "transparent proxy engine stop timed out waiting for guards to \
                 drop; proceeding (a handler hook likely holds a guard with \
                 un-timed I/O)"
            ),
            Err(_) => tracing::error!(
                reason,
                ?hard_cap,
                "transparent proxy engine stop hit its hard cap before the \
                 graceful drain returned; abandoning drain (engine runtime \
                 likely wedged)"
            ),
        }
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
    Arc::new(move |bytes: &[u8]| -> TcpDeliverStatus {
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

/// Direction tag selecting per-direction signals/counters and used in
/// close-log emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BridgeDirection {
    /// Client ↔ service direction.
    Ingress,
    /// Service ↔ NWConnection (upstream) direction.
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

/// Per-flow backpressure flags and drain wakers, shared between the
/// session's FFI surface and its two per-flow streams via a single `Arc`.
/// One allocation instead of four (two `AtomicBool` + two `AtomicWaker`).
///
/// `*_paused` is set by `on_*_bytes` when the ingress channel is full and
/// cleared (edge-triggered, firing the read-demand callback) by the
/// matching stream's `poll_read` when it drains a slot. `*_drain` is
/// registered by the matching stream's `poll_write` while parked on
/// `Paused` and woken by `signal_*_drain`.
pub(crate) struct TcpPerFlowSignals {
    ingress_paused: AtomicBool,
    ingress_drain: AtomicWaker,
    egress_paused: AtomicBool,
    egress_drain: AtomicWaker,
}

impl TcpPerFlowSignals {
    fn new() -> Self {
        Self {
            ingress_paused: AtomicBool::new(false),
            ingress_drain: AtomicWaker::new(),
            egress_paused: AtomicBool::new(false),
            egress_drain: AtomicWaker::new(),
        }
    }

    fn paused(&self, dir: BridgeDirection) -> &AtomicBool {
        match dir {
            BridgeDirection::Ingress => &self.ingress_paused,
            BridgeDirection::Egress => &self.egress_paused,
        }
    }

    fn drain(&self, dir: BridgeDirection) -> &AtomicWaker {
        match dir {
            BridgeDirection::Ingress => &self.ingress_drain,
            BridgeDirection::Egress => &self.egress_drain,
        }
    }
}

fn emit_udp_session_close_event(reason: BridgeCloseReason, meta: &TransparentProxyFlowMeta) {
    let age_ms = u64::try_from(meta.age().as_millis()).unwrap_or(u64::MAX);
    let local = meta.local_endpoint.as_ref().map(tracing::field::display);
    let remote = meta.remote_endpoint.as_ref().map(tracing::field::display);
    let decision = meta.intercept_decision.map(tracing::field::display);

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

/// Resolve the per-direction close reasons for a flow's two close events.
///
/// `flow_reason` is the service task's outcome: `Shutdown` / `IdleTimeout`
/// are flow-wide and apply to both directions; otherwise each direction
/// reports the reason its own stream recorded (defaulting to a clean
/// `PeerEofLeft` if it terminated without recording one).
fn resolve_tcp_close_reasons(
    flow_reason: BridgeCloseReason,
    ingress: Option<BridgeCloseReason>,
    egress: Option<BridgeCloseReason>,
) -> (BridgeCloseReason, BridgeCloseReason) {
    match flow_reason {
        BridgeCloseReason::Shutdown | BridgeCloseReason::IdleTimeout => (flow_reason, flow_reason),
        _ => (
            ingress.unwrap_or(BridgeCloseReason::PeerEofLeft),
            egress.unwrap_or(BridgeCloseReason::PeerEofLeft),
        ),
    }
}

#[cfg(test)]
mod close_reason_resolution {
    use super::resolve_tcp_close_reasons;
    use rama_net::proxy::BridgeCloseReason::*;

    #[test]
    fn flow_level_reasons_apply_to_both_directions() {
        assert_eq!(
            resolve_tcp_close_reasons(Shutdown, Some(PeerEofRight), None),
            (Shutdown, Shutdown)
        );
        assert_eq!(
            resolve_tcp_close_reasons(IdleTimeout, None, Some(PausedTimeout)),
            (IdleTimeout, IdleTimeout)
        );
    }

    #[test]
    fn serve_completed_uses_per_direction_recorded_reason() {
        // A write-side failure on one direction must NOT be logged as a
        // clean EOF — this is the bug the per-direction cells fix.
        assert_eq!(
            resolve_tcp_close_reasons(PeerEofLeft, Some(PausedTimeout), Some(PeerEofRight)),
            (PausedTimeout, PeerEofRight)
        );
    }

    #[test]
    fn serve_completed_defaults_unrecorded_direction_to_clean_eof() {
        assert_eq!(
            resolve_tcp_close_reasons(PeerEofLeft, None, None),
            (PeerEofLeft, PeerEofLeft)
        );
    }
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
    let local = meta.local_endpoint.as_ref().map(tracing::field::display);
    let remote = meta.remote_endpoint.as_ref().map(tracing::field::display);
    let decision = meta.intercept_decision.map(tracing::field::display);

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
