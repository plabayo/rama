use rama_core::{
    bytes::Bytes,
    extensions::ExtensionsRef,
    graceful::{Shutdown, ShutdownGuard},
    rt::Executor,
    service::Service,
};
use rama_net::{conn::is_connection_error, proxy::ProxyTarget};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
};

use crate::{TcpFlow, UdpFlow, tproxy::TransparentProxyFlowMeta};

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
            new_tcp_sesson_flow_action(
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
            new_udp_sesson_flow_action(
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

#[allow(clippy::too_many_arguments)]
async fn new_tcp_sesson_flow_action<OnBytes, OnClosed, H>(
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
    let flow_action = handler.match_tcp_flow(exec, meta).await;

    let (service, meta) = match flow_action {
        FlowAction::Intercept { service, meta } => (service, meta),
        FlowAction::Blocked => return SessionFlowAction::Blocked,
        FlowAction::Passthrough => return SessionFlowAction::Passthrough,
    };

    let (flow_stop_tx, flow_stop_rx) = oneshot::channel::<()>();
    let flow_shutdown = {
        Shutdown::new(async move {
            tokio::select! {
                _ = flow_stop_rx => {}
                _ = parent_guard.cancelled() => {}
            }
        })
    };
    let flow_guard = flow_shutdown.guard();

    let (user_stream, internal_stream) = tokio::io::duplex(tcp_flow_buffer_size);
    let (client_tx, client_rx) = mpsc::unbounded_channel::<Bytes>();
    let (eof_tx, eof_rx) = watch::channel(false);

    let callback_active = Arc::new(parking_lot::Mutex::new(true));
    let user_bytes_sink: BytesSink = Arc::new(on_server_bytes);
    let user_closed_sink: ClosedSink = Arc::new(on_server_closed);
    let bytes_sink = guarded_bytes_sink(callback_active.clone(), user_bytes_sink);
    let closed_sink = guarded_closed_sink(callback_active.clone(), user_closed_sink);
    let remote_endpoint = meta.remote_endpoint.clone();

    tracing::debug!(protocol = ?meta.protocol, "new tcp session");

    let bridge_task = flow_guard.spawn_task(run_tcp_bridge(
        internal_stream,
        client_rx,
        eof_rx,
        bytes_sink,
        closed_sink,
    ));

    let stream = TcpFlow::new(user_stream, Some(Executor::graceful(flow_guard.clone())));
    stream.extensions().insert_arc(Arc::new(meta));
    if let Some(remote) = remote_endpoint {
        stream.extensions().insert(ProxyTarget(remote));
    }

    let service_task = flow_guard.spawn_task_fn(async move |guard| {
        stream.extensions().insert(guard);
        let Ok(()) = service.serve(stream).await;
    });

    SessionFlowAction::Intercept(TransparentProxyTcpSession {
        client_tx: Some(client_tx),
        eof_tx,
        callback_active,
        saw_client_bytes: false,
        bridge_task: Some(bridge_task),
        service_task: Some(service_task),
        flow_stop_tx: Some(flow_stop_tx),
    })
}

async fn new_udp_sesson_flow_action<OnDatagram, OnClosed, OnDemand, H>(
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
    let flow_action = handler.match_udp_flow(exec, meta).await;
    let (service, meta) = match flow_action {
        FlowAction::Intercept { service, meta } => (service, meta),
        FlowAction::Blocked => return SessionFlowAction::Blocked,
        FlowAction::Passthrough => return SessionFlowAction::Passthrough,
    };

    let (flow_stop_tx, flow_stop_rx) = oneshot::channel::<()>();
    let flow_shutdown = {
        Shutdown::new(async move {
            tokio::select! {
                _ = flow_stop_rx => {}
                _ = parent_guard.cancelled() => {}
            }
        })
    };
    let flow_guard = flow_shutdown.guard();

    let (client_tx, client_rx) = mpsc::unbounded_channel::<Bytes>();

    let datagram_sink: BytesSink = Arc::new(on_server_datagram);
    let user_client_read_demand_sink: DemandSink = Arc::new(on_client_read_demand);
    let closed_sink: ClosedSink = Arc::new(on_server_closed);
    let client_read_demand_sink = guarded_demand_sink(
        Arc::new(parking_lot::Mutex::new(true)),
        user_client_read_demand_sink,
    );
    let remote_endpoint = meta.remote_endpoint.clone();
    let protocol = meta.protocol;
    let flow = UdpFlow::new_with_io_demand(
        client_rx,
        datagram_sink,
        Some(client_read_demand_sink.clone()),
    );
    flow.extensions().insert(flow_guard.clone());
    flow.extensions().insert_arc(Arc::new(meta));
    if let Some(remote) = remote_endpoint {
        flow.extensions().insert(ProxyTarget(remote));
    }

    tracing::debug!(protocol = ?protocol, "new udp session");

    let service_task = flow_guard.spawn_task(async move {
        let Ok(()) = service.serve(flow).await;
        closed_sink();
    });

    SessionFlowAction::Intercept(TransparentProxyUdpSession {
        client_tx: Some(client_tx),
        on_client_read_demand: client_read_demand_sink,
        service_task: Some(service_task),
        flow_stop_tx: Some(flow_stop_tx),
    })
}

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
    user_client_read_demand_sink: DemandSink,
) -> DemandSink {
    Arc::new(move || {
        if !*callback_active.lock() {
            return;
        }
        user_client_read_demand_sink();
    })
}

pub struct TransparentProxyTcpSession {
    client_tx: Option<mpsc::UnboundedSender<Bytes>>,
    eof_tx: watch::Sender<bool>,
    callback_active: Arc<parking_lot::Mutex<bool>>,
    saw_client_bytes: bool,
    bridge_task: Option<tokio::task::JoinHandle<()>>,
    service_task: Option<tokio::task::JoinHandle<()>>,
    flow_stop_tx: Option<oneshot::Sender<()>>,
}

impl TransparentProxyTcpSession {
    pub fn on_client_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.saw_client_bytes = true;
        if let Some(tx) = self.client_tx.as_mut() {
            let _ = tx.send(Bytes::copy_from_slice(bytes));
        }
    }

    pub fn on_client_eof(&mut self) {
        if !self.saw_client_bytes {
            self.cancel();
            return;
        }
        let _ = self.eof_tx.send(true);
    }

    pub fn cancel(&mut self) {
        *self.callback_active.lock() = false;
        self.client_tx = None;
        let _ = self.eof_tx.send(true);
        if let Some(tx) = self.flow_stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.bridge_task.take() {
            task.abort();
        }
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

pub struct TransparentProxyUdpSession {
    client_tx: Option<mpsc::UnboundedSender<Bytes>>,
    on_client_read_demand: Arc<dyn Fn() + Send + Sync + 'static>,
    service_task: Option<tokio::task::JoinHandle<()>>,
    flow_stop_tx: Option<oneshot::Sender<()>>,
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
        if let Some(tx) = self.flow_stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.service_task.take() {
            task.abort();
        }
    }
}

impl Drop for TransparentProxyUdpSession {
    fn drop(&mut self) {
        self.on_client_close();
    }
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

    loop {
        tokio::select! {
            maybe = client_rx.recv() => {
                if let Some(bytes) = maybe {
                     if let Err(err) = write_half.write_all(&bytes).await {
                         if is_connection_error(&err) {
                             tracing::trace!("tcp bridge write_all conn error: {err}");
                         } else {
                             tracing::debug!("tcp bridge write_all failed: {err}");
                         }
                         break;
                     }
                 } else {
                     let _ = write_half.shutdown().await;
                     break;
                 }
            }
            _ = eof_rx.changed() => {
                if *eof_rx.borrow() {
                    let _ = write_half.shutdown().await;
                    break;
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
