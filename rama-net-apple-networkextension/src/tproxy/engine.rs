use rama_core::{
    bytes::Bytes,
    extensions::{ExtensionsMut, ExtensionsRef},
    graceful::{Shutdown, ShutdownGuard},
    rt::Executor,
    service::{BoxService, Service, service_fn},
};
use rama_net::{
    address::HostWithPort,
    proxy::{ProxyRequest, ProxyTarget, StreamForwardService},
};
use rama_tcp::client::default_tcp_connect;

use parking_lot::Mutex;
use rama_udp::bind_udp_socket_with_connect_default_dns;
use std::{convert::Infallible, future::Future, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
};

use crate::{
    TcpFlow, UdpFlow,
    tproxy::{TransparentProxyConfig, TransparentProxyFlowMeta},
};

const DEFAULT_TCP_FLOW_BUFFER_SIZE: usize = 64 * 1024; // 64 KiB

#[derive(Default)]
struct EngineState {
    running: bool,
    shutdown: Option<Shutdown>,
    stop_trigger: Option<oneshot::Sender<()>>,
}

type TcpFlowService = BoxService<TcpFlow, (), Infallible>;
type UdpFlowService = BoxService<UdpFlow, (), Infallible>;
type BytesSink = Arc<dyn Fn(Bytes) + Send + Sync + 'static>;
type ClosedSink = Arc<dyn Fn() + Send + Sync + 'static>;

pub struct TransparentProxyEngineBuilder {
    config: TransparentProxyConfig,
    tcp_service: Option<TcpFlowService>,
    tcp_flow_buffer_size: Option<usize>,
    udp_service: Option<UdpFlowService>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl TransparentProxyEngineBuilder {
    #[must_use]
    pub fn new(config: TransparentProxyConfig) -> Self {
        Self {
            config,
            tcp_service: None,
            tcp_flow_buffer_size: None,
            udp_service: None,
            runtime: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a custom [`TcpFlow`] [`Service`].
        ///
        /// Default TCP Service (if UDP is intercepted at all,
        /// forwards bytes as-is, without inspection).
        pub fn tcp_service(mut self, svc: impl Service<TcpFlow, Output = (), Error = Infallible>) -> Self
        {
            self.tcp_service = Some(svc.boxed());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Define what size to use for the TCP flow buffer (`None` will use default)
        pub fn tcp_flow_buffer_size(mut self, size: Option<usize>) -> Self
        {
            self.tcp_flow_buffer_size = size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set a custom [`UdpFlow`] [`Service`].
        ///
        /// Default UDP Service (if UDP is intercepted at all,
        /// forwards bytes as-is, without inspection).
        pub fn udp_service(mut self, svc: impl Service<UdpFlow, Output = (), Error = Infallible>) -> Self
        {
            self.udp_service = Some(svc.boxed());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// define the Tokio runtime for the transparent proxy engine.
        pub fn runtime(mut self, runtime: Option<tokio::runtime::Runtime>) -> Self {
            self.runtime = runtime;
            self
        }
    }

    #[must_use]
    pub fn build(self) -> TransparentProxyEngine {
        let tcp_service = self.tcp_service.unwrap_or_else(default_tcp_service);
        let tcp_flow_buffer_size = self
            .tcp_flow_buffer_size
            .unwrap_or(DEFAULT_TCP_FLOW_BUFFER_SIZE);
        let udp_service = self.udp_service.unwrap_or_else(default_udp_service);
        let runtime = self.runtime.unwrap_or_else(build_default_runtime);

        TransparentProxyEngine {
            rt: runtime,
            config: self.config,
            tcp_service,
            tcp_flow_buffer_size,
            udp_service,
            state: Mutex::new(EngineState::default()),
        }
    }
}

pub struct TransparentProxyEngine {
    rt: tokio::runtime::Runtime,
    config: TransparentProxyConfig,
    tcp_service: TcpFlowService,
    tcp_flow_buffer_size: usize,
    udp_service: UdpFlowService,
    state: Mutex<EngineState>,
}

impl TransparentProxyEngine {
    pub fn start(&self) {
        let mut state = self.state.lock();

        if state.running {
            tracing::trace!("transparent proxy engine already running");
            return;
        }

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let shutdown = {
            let _enter = self.rt.enter();
            Shutdown::new(async move {
                let _ = stop_rx.await;
            })
        };

        state.running = true;
        state.shutdown = Some(shutdown);
        state.stop_trigger = Some(stop_tx);
        tracing::info!("transparent proxy engine started");
    }

    pub fn stop(&self, reason: i32) {
        let (shutdown, stop_trigger) = {
            let mut state = self.state.lock();

            if !state.running {
                tracing::trace!("transparent proxy engine already stopped");
                return;
            }

            state.running = false;
            (state.shutdown.take(), state.stop_trigger.take())
        };

        tracing::info!(reason, "transparent proxy engine stopping");

        if let Some(stop_trigger) = stop_trigger {
            let _ = stop_trigger.send(());
        }

        if let Some(shutdown) = shutdown {
            self.rt.block_on(async move {
                shutdown.shutdown().await;
            });
        }

        tracing::info!(reason, "transparent proxy engine stopped");
    }

    pub fn is_running(&self) -> bool {
        let state = self.state.lock();
        state.running
    }

    pub fn new_tcp_session<F, G>(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_bytes: F,
        on_server_closed: G,
    ) -> Option<TransparentProxyTcpSession>
    where
        F: Fn(Bytes) + Send + Sync + 'static,
        G: Fn() + Send + Sync + 'static,
    {
        let guard = self.shutdown_guard()?;

        let (user_stream, internal_stream) = tokio::io::duplex(self.tcp_flow_buffer_size);
        let (client_tx, client_rx) = mpsc::unbounded_channel::<Bytes>();
        let (eof_tx, eof_rx) = watch::channel(false);

        let cfg = self.config.clone();
        let service = self.tcp_service.clone();
        let bytes_sink: BytesSink = Arc::new(on_server_bytes);
        let closed_sink: ClosedSink = Arc::new(on_server_closed);

        tracing::debug!(protocol = ?meta.protocol, "new tcp session");

        self.spawn_graceful(
            guard.clone(),
            run_tcp_bridge(internal_stream, client_rx, eof_rx, bytes_sink, closed_sink),
        );

        let mut stream = TcpFlow::new(user_stream);
        stream.extensions_mut().insert(meta.clone());
        stream.extensions_mut().insert(cfg.clone());
        if let Some(remote) = meta.remote_endpoint.clone() {
            stream.extensions_mut().insert(ProxyTarget(remote));
        }

        self.spawn_graceful(guard, async move {
            let _ = service.serve(stream).await;
        });

        Some(TransparentProxyTcpSession { client_tx, eof_tx })
    }

    pub fn new_udp_session<F, G>(
        &self,
        meta: TransparentProxyFlowMeta,
        on_server_datagram: F,
        on_server_closed: G,
    ) -> Option<TransparentProxyUdpSession>
    where
        F: Fn(Bytes) + Send + Sync + 'static,
        G: Fn() + Send + Sync + 'static,
    {
        let guard = self.shutdown_guard()?;

        let (client_tx, client_rx) = mpsc::unbounded_channel::<Bytes>();

        let cfg = self.config.clone();
        let service = self.udp_service.clone();
        let datagram_sink: BytesSink = Arc::new(on_server_datagram);
        let closed_sink: ClosedSink = Arc::new(on_server_closed);

        tracing::debug!(protocol = ?meta.protocol, "new udp session");

        let mut flow = UdpFlow::new(client_rx, datagram_sink);
        flow.extensions_mut().insert(meta.clone());
        flow.extensions_mut().insert(cfg.clone());
        if let Some(remote) = meta.remote_endpoint.clone() {
            flow.extensions_mut().insert(ProxyTarget(remote));
        }

        self.spawn_graceful(guard, async move {
            let _ = service.serve(flow).await;
            closed_sink();
        });

        Some(TransparentProxyUdpSession {
            client_tx: Some(client_tx),
        })
    }

    fn shutdown_guard(&self) -> Option<ShutdownGuard> {
        let state = self.state.lock();

        if !state.running {
            tracing::warn!("session rejected: engine not running");
            return None;
        }

        let shutdown = state.shutdown.as_ref()?;
        Some(shutdown.guard())
    }

    fn spawn_graceful<F>(&self, guard: ShutdownGuard, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let _enter = self.rt.enter();
        Executor::graceful(guard).spawn_task(future);
    }
}

fn build_default_runtime() -> tokio::runtime::Runtime {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => panic!("failed to build tokio runtime: {err}"),
    }
}

pub struct TransparentProxyTcpSession {
    client_tx: mpsc::UnboundedSender<Bytes>,
    eof_tx: watch::Sender<bool>,
}

impl TransparentProxyTcpSession {
    pub fn on_client_bytes(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let _ = self.client_tx.send(Bytes::copy_from_slice(bytes));
    }

    pub fn on_client_eof(&mut self) {
        let _ = self.eof_tx.send(true);
    }
}

pub struct TransparentProxyUdpSession {
    client_tx: Option<mpsc::UnboundedSender<Bytes>>,
}

impl TransparentProxyUdpSession {
    pub fn on_client_datagram(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        if let Some(tx) = self.client_tx.as_mut() {
            let _ = tx.send(Bytes::copy_from_slice(bytes));
        }
    }

    pub fn on_client_close(&mut self) {
        self.client_tx = None;
    }
}

fn default_tcp_service() -> TcpFlowService {
    tracing::debug!("using default tcp service (dumb L4 forward)");
    service_fn(|stream: TcpFlow| async move {
        let target = stream
            .extensions()
            .get::<ProxyTarget>()
            .cloned()
            .map(|target| target.0)
            .or_else(|| {
                stream
                    .extensions()
                    .get::<TransparentProxyFlowMeta>()
                    .and_then(|meta| meta.remote_endpoint.clone())
            });
        let Some(target) = target else {
            tracing::warn!("default tcp service missing target endpoint");
            return Ok(());
        };

        let extensions = stream.extensions().clone();
        let exec = Executor::default();
        let Ok((upstream, _sock_addr)) = default_tcp_connect(&extensions, target, exec).await
        else {
            tracing::warn!("default tcp connect failed");
            return Ok(());
        };

        let req = ProxyRequest {
            source: stream,
            target: upstream,
        };
        if let Err(err) = StreamForwardService::new().serve(req).await {
            tracing::warn!(%err, "default tcp forward failed");
        }
        Ok(())
    })
    .boxed()
}

fn udp_remote_endpoint_from_extensions(flow: &UdpFlow) -> Option<HostWithPort> {
    flow.extensions()
        .get::<ProxyTarget>()
        .cloned()
        .map(|target| target.0)
        .or_else(|| {
            flow.extensions()
                .get::<TransparentProxyFlowMeta>()
                .and_then(|meta| meta.remote_endpoint.clone())
        })
}

fn default_udp_service() -> UdpFlowService {
    tracing::debug!("using default udp service (dumb L4 forward)");
    service_fn(|mut flow: UdpFlow| async move {
        let target = udp_remote_endpoint_from_extensions(&flow);
        let Some(target_addr) = target else {
            tracing::warn!("default udp service missing target endpoint");
            while flow.recv().await.is_some() {}
            return Ok(());
        };

        let socket = match bind_udp_socket_with_connect_default_dns(
            target_addr.clone(),
            Some(flow.extensions()),
        )
        .await
        {
            Ok(socket) => socket,
            Err(err) => {
                tracing::error!(error = %err, "default udp (forward) service: udp bind failed w/ bind + connect to address: {target_addr}");
                while flow.recv().await.is_some() {}
                return Ok(());
            }
        };

        tracing::info!(
            remote = %target_addr,
            local_addr = ?socket.local_addr().ok(),
            peer_addr = ?socket.peer_addr().ok(),
            "default udp (forward) service started"
        );

        let mut buf = vec![0u8; 64 * 1024];
        loop {
            tokio::select! {
                maybe_datagram = flow.recv() => {
                    let Some(datagram) = maybe_datagram else { break; };
                    if let Err(err) = socket.send(&datagram).await {
                        tracing::warn!(%err, "default udp send failed");
                        break;
                    }
                }
                recv_result = socket.recv(&mut buf) => {
                    match recv_result {
                        Ok(0) => break,
                        Ok(n) => flow.send(Bytes::copy_from_slice(&buf[..n])),
                        Err(err) => {
                            tracing::warn!(%err, "default udp recv failed");
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    })
    .boxed()
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
                match maybe {
                    Some(bytes) => {
                        if write_half.write_all(&bytes).await.is_err() {
                            tracing::debug!("tcp bridge write_all failed");
                            break;
                        }
                    }
                    None => {
                        let _ = write_half.shutdown().await;
                    }
                }
            }
            _ = eof_rx.changed() => {
                if *eof_rx.borrow() {
                    let _ = write_half.shutdown().await;
                }
            }
            read_res = read_half.read(&mut buf) => {
                match read_res {
                    Ok(0) | Err(_) => break,
                    Ok(n) => on_server_bytes(Bytes::copy_from_slice(&buf[..n])),
                }
            }
        }
    }

    on_server_closed();
}

#[cfg(test)]
mod tests {
    use crate::tproxy::TransparentProxyFlowProtocol;

    use super::*;
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[test]
    fn engine_start_stop_state() {
        let engine = TransparentProxyEngineBuilder::new(TransparentProxyConfig::new())
            .with_runtime(
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap(),
            )
            .build();
        assert!(!engine.is_running());
        engine.start();
        assert!(engine.is_running());
        engine.stop(0);
        assert!(!engine.is_running());
    }

    #[test]
    fn session_rejected_if_not_running() {
        let engine = TransparentProxyEngineBuilder::new(TransparentProxyConfig::new())
            .with_runtime(
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap(),
            )
            .build();
        let session = engine.new_tcp_session(
            TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
            |_| {},
            || {},
        );
        assert!(session.is_none());
    }

    #[test]
    fn session_rejected_after_stop() {
        let engine = TransparentProxyEngineBuilder::new(TransparentProxyConfig::new())
            .with_runtime(
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap(),
            )
            .build();
        engine.start();
        engine.stop(0);
        let session = engine.new_tcp_session(
            TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp),
            |_| {},
            || {},
        );
        assert!(session.is_none());
    }

    #[test]
    fn tcp_bridge_delivers_server_bytes() {
        let got = Arc::new(Mutex::new(Vec::<u8>::new()));
        let got_clone = got.clone();
        let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

        let engine = TransparentProxyEngineBuilder::new(TransparentProxyConfig::new())
            .with_tcp_service(service_fn(|mut stream: TcpFlow| async move {
                let _ = stream.write_all(b"pong").await;
                Ok(())
            }))
            .with_runtime(
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap(),
            )
            .build();

        engine.start();
        let mut session = engine
            .new_tcp_session(
                TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Tcp)
                    .with_remote_endpoint(HostWithPort::example_domain_with_port(80)),
                move |bytes| {
                    let mut lock = got_clone.lock();
                    lock.extend_from_slice(&bytes);
                    let _ = notify_tx.send(());
                },
                || {},
            )
            .expect("session");

        session.on_client_bytes(b"ping");

        let _ = notify_rx.recv_timeout(std::time::Duration::from_secs(1));
        engine.stop(0);

        let lock = got.lock();
        assert_eq!(lock.as_slice(), b"pong");
    }

    #[test]
    fn udp_bridge_delivers_server_datagram() {
        let got = Arc::new(Mutex::new(Vec::<u8>::new()));
        let got_clone = got.clone();
        let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

        let engine = TransparentProxyEngineBuilder::new(TransparentProxyConfig::new())
            .with_runtime(
                tokio::runtime::Builder::new_current_thread()
                    .build()
                    .unwrap(),
            )
            .with_udp_service(service_fn(|mut flow: UdpFlow| async move {
                if let Some(datagram) = flow.recv().await {
                    flow.send(datagram);
                }
                Ok(())
            }))
            .build();

        engine.start();
        let mut session = engine
            .new_udp_session(
                TransparentProxyFlowMeta::new(TransparentProxyFlowProtocol::Udp)
                    .with_remote_endpoint(HostWithPort::local_ipv4(5353)),
                move |bytes| {
                    let mut lock = got_clone.lock();
                    lock.extend_from_slice(&bytes);
                    let _ = notify_tx.send(());
                },
                || {},
            )
            .expect("session");

        session.on_client_datagram(b"ping");

        let _ = notify_rx.recv_timeout(std::time::Duration::from_secs(1));
        engine.stop(0);

        let lock = got.lock();
        assert_eq!(lock.as_slice(), b"ping");
    }
}
