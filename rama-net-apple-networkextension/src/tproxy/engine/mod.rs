use std::{future::Future, sync::Arc};

use rama_core::{
    bytes::Bytes,
    extensions::ExtensionsRef,
    graceful::{Shutdown, ShutdownGuard},
    io::BridgeIo,
    rt::Executor,
    service::Service,
};
use rama_net::{conn::is_connection_error, proxy::ProxyTarget};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
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

const DEFAULT_TCP_FLOW_BUFFER_SIZE: usize = 64 * 1024; // 64 KiB

type BytesSink = Arc<dyn Fn(Bytes) + Send + Sync + 'static>;
type ClosedSink = Arc<dyn Fn() + Send + Sync + 'static>;
type DemandSink = Arc<dyn Fn() + Send + Sync + 'static>;

pub enum SessionFlowAction<S> {
    Intercept(S),
    Blocked,
    Passthrough,
}

pub struct TransparentProxyEngine<H> {
    rt: tokio::runtime::Runtime,
    handler: H,
    tcp_flow_buffer_size: usize,
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

    pub fn new_tcp_session<OnBytes, OnClosed>(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_bytes: OnBytes,
        on_server_closed: OnClosed,
    ) -> SessionFlowAction<TransparentProxyTcpSession>
    where
        OnBytes: Fn(Bytes) + Send + Sync + 'static,
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
        let exec = Executor::graceful(guard.clone());
        let handler = self.handler.clone();

        block_on_async_task(
            &self.rt,
            new_tcp_session_flow_action(
                guard,
                exec,
                meta,
                tcp_flow_buffer_size,
                on_server_bytes,
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

        let exec = Executor::graceful(guard.clone());
        let handler = self.handler.clone();

        block_on_async_task(
            &self.rt,
            new_udp_session_flow_action(
                guard,
                exec,
                meta,
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
    client_rx: mpsc::UnboundedReceiver<Bytes>,
    /// Ingress EOF watch; handed to the ingress bridge at activate.
    eof_rx: watch::Receiver<bool>,
    /// Rust→Swift: response bytes back to the intercepted client flow.
    on_server_bytes: BytesSink,
    /// Rust→Swift: ingress response stream done.
    on_server_closed: ClosedSink,
    /// Both ingress and egress duplex buffer size.
    tcp_flow_buffer_size: usize,
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
    client_tx: Option<mpsc::UnboundedSender<Bytes>>,
    eof_tx: watch::Sender<bool>,
    saw_client_bytes: bool,

    // egress data path (populated by activate)
    egress_tx: Option<mpsc::UnboundedSender<Bytes>>,
    egress_eof_tx: Option<watch::Sender<bool>>,

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
    pub fn on_client_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.saw_client_bytes = true;
        if let Some(tx) = self.client_tx.as_mut() {
            let _ = tx.send(Bytes::copy_from_slice(bytes));
        }
    }

    /// Called by Swift when the intercepted flow signals read-EOF.
    pub fn on_client_eof(&mut self) {
        if !self.saw_client_bytes {
            self.cancel();
            return;
        }
        let _ = self.eof_tx.send(true);
    }

    /// Called by Swift when bytes arrive from the egress `NWConnection`.
    pub fn on_egress_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(tx) = self.egress_tx.as_mut() {
            let _ = tx.send(Bytes::copy_from_slice(bytes));
        }
    }

    /// Called by Swift when the egress `NWConnection` closes or fails.
    pub fn on_egress_eof(&mut self) {
        if let Some(tx) = self.egress_eof_tx.as_mut() {
            let _ = tx.send(true);
        }
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
    /// * `on_close_egress` — Rust→Swift: egress stream is done writing.
    pub fn activate<OnEgressWrite, OnEgressClose>(
        &mut self,
        on_write_to_egress: OnEgressWrite,
        on_close_egress: OnEgressClose,
    ) where
        OnEgressWrite: Fn(Bytes) + Send + Sync + 'static,
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
            eof_rx,
            on_server_bytes,
            on_server_closed,
            tcp_flow_buffer_size,
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
        ingress_stream.extensions().insert_arc(Arc::new(meta));
        if let Some(remote) = remote_endpoint {
            ingress_stream.extensions().insert(ProxyTarget(remote));
        }

        // egress stream (service ↔ NWConnection)
        let (egress_user, egress_internal) = tokio::io::duplex(tcp_flow_buffer_size);
        let egress_stream = NwTcpStream::new(egress_user);

        let (egress_client_tx, egress_client_rx) = mpsc::unbounded_channel::<Bytes>();
        let (egress_eof_tx, egress_eof_rx) = watch::channel(false);
        self.egress_tx = Some(egress_client_tx);
        self.egress_eof_tx = Some(egress_eof_tx);

        // guard egress callbacks
        let egress_bytes_sink: BytesSink = Arc::new(on_write_to_egress);
        let egress_closed_sink: ClosedSink = Arc::new(on_close_egress);
        let guarded_egress_bytes =
            guarded_bytes_sink(self.callback_active.clone(), egress_bytes_sink);
        let guarded_egress_closed =
            guarded_closed_sink(self.callback_active.clone(), egress_closed_sink);

        // Spawn bridge tasks via the stored runtime handle so that `activate` can be
        // called from an external (non-Tokio) thread — e.g. a Swift dispatch queue.
        // We clone the flow_guard into each task to keep the shutdown barrier alive
        // until the task completes, matching the semantics of `spawn_task`.

        // spawn ingress bridge (client ↔ service)
        self.ingress_bridge_task = Some({
            let guard = flow_guard.clone();
            rt_handle.spawn(async move {
                let _guard = guard;
                run_tcp_bridge(
                    ingress_internal,
                    client_rx,
                    eof_rx,
                    on_server_bytes,
                    on_server_closed,
                )
                .await;
            })
        });

        // spawn egress bridge (service ↔ NWConnection)
        self.egress_bridge_task = Some({
            rt_handle.spawn(async move {
                let _guard = flow_guard;
                run_tcp_bridge(
                    egress_internal,
                    egress_client_rx,
                    egress_eof_rx,
                    guarded_egress_bytes,
                    guarded_egress_closed,
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
        self.client_tx = None;
        self.egress_tx = None;
        let _ = self.eof_tx.send(true);
        if let Some(tx) = self.egress_eof_tx.as_mut() {
            let _ = tx.send(true);
        }
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
async fn new_tcp_session_flow_action<OnBytes, OnClosed, H>(
    parent_guard: ShutdownGuard,
    exec: Executor,
    meta: TransparentProxyFlowMeta,
    tcp_flow_buffer_size: usize,
    on_server_bytes: OnBytes,
    on_server_closed: OnClosed,
    handler: H,
) -> SessionFlowAction<TransparentProxyTcpSession>
where
    OnBytes: Fn(Bytes) + Send + Sync + 'static,
    OnClosed: Fn() + Send + Sync + 'static,
    H: TransparentProxyHandler,
{
    let egress_connect_options = handler.egress_tcp_connect_options(&meta);
    let flow_action = handler.match_tcp_flow(exec, meta).await;

    let (service, meta) = match flow_action {
        FlowAction::Intercept { service, meta } => (service, meta),
        FlowAction::Blocked => return SessionFlowAction::Blocked,
        FlowAction::Passthrough => return SessionFlowAction::Passthrough,
    };

    let (flow_stop_tx, flow_stop_rx) = oneshot::channel::<()>();
    let flow_shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = flow_stop_rx => {}
            _ = parent_guard.cancelled() => {}
        }
    });
    let flow_guard = flow_shutdown.guard();

    let (client_tx, client_rx) = mpsc::unbounded_channel::<Bytes>();
    let (eof_tx, eof_rx) = watch::channel(false);
    let (bridge_tx, bridge_rx) = oneshot::channel::<BridgeIo<TcpFlow, NwTcpStream>>();

    let callback_active = Arc::new(parking_lot::Mutex::new(true));
    let on_server_bytes_guarded =
        guarded_bytes_sink(callback_active.clone(), Arc::new(on_server_bytes));
    let on_server_closed_guarded =
        guarded_closed_sink(callback_active.clone(), Arc::new(on_server_closed));

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
        eof_rx,
        on_server_bytes: on_server_bytes_guarded,
        on_server_closed: on_server_closed_guarded,
        tcp_flow_buffer_size,
        meta,
        flow_guard,
        rt_handle,
        egress_connect_options,
    };

    SessionFlowAction::Intercept(TransparentProxyTcpSession {
        client_tx: Some(client_tx),
        eof_tx,
        saw_client_bytes: false,
        egress_tx: None,
        egress_eof_tx: None,
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
    client_rx: mpsc::UnboundedReceiver<Bytes>,
    /// Rust→Swift: datagram back to the intercepted client flow.
    on_server_datagram: BytesSink,
    /// Demand sink captured into `UdpFlow` at activate.
    client_read_demand_sink: DemandSink,
    /// Per-flow metadata.
    meta: TransparentProxyFlowMeta,
    /// Handler-supplied egress options.
    egress_connect_options: Option<NwUdpConnectOptions>,
}

pub struct TransparentProxyUdpSession {
    client_tx: Option<mpsc::UnboundedSender<Bytes>>,
    on_client_read_demand: DemandSink,

    /// Egress datagrams (NWConnection→Rust, populated by activate).
    egress_tx: Option<mpsc::UnboundedSender<Bytes>>,

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
            let _ = tx.send(Bytes::copy_from_slice(bytes));
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
    pub fn on_egress_datagram(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if let Some(tx) = self.egress_tx.as_mut() {
            let _ = tx.send(Bytes::copy_from_slice(bytes));
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
        let (egress_client_tx, egress_client_rx) = mpsc::unbounded_channel::<Bytes>();
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

async fn new_udp_session_flow_action<OnDatagram, OnClosed, OnDemand, H>(
    parent_guard: ShutdownGuard,
    exec: Executor,
    meta: TransparentProxyFlowMeta,
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
    let flow_action = handler.match_udp_flow(exec, meta).await;
    let (service, meta) = match flow_action {
        FlowAction::Intercept { service, meta } => (service, meta),
        FlowAction::Blocked => return SessionFlowAction::Blocked,
        FlowAction::Passthrough => return SessionFlowAction::Passthrough,
    };

    let (flow_stop_tx, flow_stop_rx) = oneshot::channel::<()>();
    let flow_shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = flow_stop_rx => {}
            _ = parent_guard.cancelled() => {}
        }
    });
    let flow_guard = flow_shutdown.guard();

    let (client_tx, client_rx) = mpsc::unbounded_channel::<Bytes>();
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

fn guarded_bytes_sink(
    callback_active: Arc<parking_lot::Mutex<bool>>,
    user_bytes_sink: BytesSink,
) -> BytesSink {
    Arc::new(move |bytes: Bytes| {
        if !*callback_active.lock() {
            return;
        }
        user_bytes_sink(bytes);
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

async fn run_tcp_bridge(
    internal: tokio::io::DuplexStream,
    mut client_rx: mpsc::UnboundedReceiver<Bytes>,
    mut eof_rx: watch::Receiver<bool>,
    on_server_bytes: BytesSink,
    on_server_closed: ClosedSink,
) {
    let (mut read_half, mut write_half) = tokio::io::split(internal);
    let mut buf = vec![0u8; 16 * 1024];
    // Set to true once the write side is finished so we keep draining read_half even
    // if the service dropped its read side before the bridge had a chance to read its
    // response bytes.  Without this flag, a write failure would cause a `break` that
    // races against any already-buffered server response bytes.
    let mut write_done = false;

    loop {
        tokio::select! {
            maybe = client_rx.recv(), if !write_done => {
                if let Some(bytes) = maybe {
                     if let Err(err) = write_half.write_all(&bytes).await {
                         if is_connection_error(&err) {
                             tracing::trace!("tcp bridge write_all conn error: {err}");
                         } else {
                             tracing::debug!("tcp bridge write_all failed: {err}");
                         }
                         // The service dropped its read side (e.g. it already wrote its
                         // response and returned).  Stop writing, but keep reading so
                         // any buffered response bytes still reach the client.
                         write_done = true;
                     }
                 } else {
                     let _ = write_half.shutdown().await;
                     write_done = true;
                 }
            }
            _ = eof_rx.changed(), if !write_done => {
                if *eof_rx.borrow() {
                    let _ = write_half.shutdown().await;
                    write_done = true;
                }
            }
            read_res = read_half.read(&mut buf) => {
                match read_res {
                    Ok(0) => break,
                    Err(err) => {
                        if is_connection_error(&err) {
                            tracing::trace!("tcp bridge read_half conn error: {err}");
                        } else {
                            tracing::debug!("tcp bridge read_half failed: {err}");
                        }
                        break;
                    }
                    Ok(n) => on_server_bytes(Bytes::copy_from_slice(&buf[..n])),
                }
            }
        }
    }

    on_server_closed();
}

#[cfg(test)]
mod tests;
