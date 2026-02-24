use crate::{TcpFlow, TransparentProxyConfig, TransparentProxyMeta, UdpFlow};
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
use std::{
    convert::Infallible,
    future::Future,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, oneshot, watch},
};

const DUPLEX_CAPACITY: usize = 64 * 1024;

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
    udp_service: Option<UdpFlowService>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl TransparentProxyEngineBuilder {
    pub fn new(config_json: impl Into<String>) -> Self {
        Self {
            config: TransparentProxyConfig::from_json(config_json),
            tcp_service: None,
            udp_service: None,
            runtime: None,
        }
    }

    pub fn with_tcp_service<S>(mut self, service: S) -> Self
    where
        S: Service<TcpFlow, Output = (), Error = Infallible>,
    {
        self.tcp_service = Some(service.boxed());
        self
    }

    pub fn with_udp_service<S>(mut self, service: S) -> Self
    where
        S: Service<UdpFlow, Output = (), Error = Infallible>,
    {
        self.udp_service = Some(service.boxed());
        self
    }

    /// Use a caller-provided Tokio runtime for the transparent proxy engine.
    pub fn with_runtime(mut self, runtime: tokio::runtime::Runtime) -> Self {
        self.runtime = Some(runtime);
        self
    }

    pub fn build(self) -> TransparentProxyEngine {
        let tcp_service = self.tcp_service.unwrap_or_else(default_tcp_service);
        let udp_service = self.udp_service.unwrap_or_else(default_udp_service);
        let runtime = self.runtime.unwrap_or_else(build_default_runtime);
        TransparentProxyEngine::new(runtime, self.config, tcp_service, udp_service)
    }
}

pub struct TransparentProxyEngine {
    rt: tokio::runtime::Runtime,
    config: TransparentProxyConfig,
    tcp_service: TcpFlowService,
    udp_service: UdpFlowService,
    state: Mutex<EngineState>,
}

impl TransparentProxyEngine {
    fn new(
        rt: tokio::runtime::Runtime,
        config: TransparentProxyConfig,
        tcp_service: TcpFlowService,
        udp_service: UdpFlowService,
    ) -> Self {
        Self {
            rt,
            config,
            tcp_service,
            udp_service,
            state: Mutex::new(EngineState::default()),
        }
    }

    pub fn start(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(err) => err.into_inner(),
        };

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
            let mut state = match self.state.lock() {
                Ok(state) => state,
                Err(err) => err.into_inner(),
            };

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
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(err) => err.into_inner(),
        };
        state.running
    }

    pub fn new_tcp_session<F, G>(
        &self,
        meta_json: impl Into<String>,
        on_server_bytes: F,
        on_server_closed: G,
    ) -> Option<TransparentProxyTcpSession>
    where
        F: Fn(Bytes) + Send + Sync + 'static,
        G: Fn() + Send + Sync + 'static,
    {
        let guard = self.shutdown_guard()?;

        let (user_stream, internal_stream) = tokio::io::duplex(DUPLEX_CAPACITY);
        let (client_tx, client_rx) = mpsc::unbounded_channel::<Bytes>();
        let (eof_tx, eof_rx) = watch::channel(false);

        let meta = TransparentProxyMeta::from_json(meta_json);
        let cfg = self.config.clone();
        let service = self.tcp_service.clone();
        let bytes_sink: BytesSink = Arc::new(on_server_bytes);
        let closed_sink: ClosedSink = Arc::new(on_server_closed);

        tracing::debug!(protocol = %meta.protocol().as_str(), "new tcp session");

        self.spawn_graceful(
            guard.clone(),
            run_tcp_bridge(internal_stream, client_rx, eof_rx, bytes_sink, closed_sink),
        );

        let mut stream = TcpFlow::new(user_stream);
        stream.extensions_mut().insert(meta.clone());
        stream.extensions_mut().insert(cfg.clone());
        if let Some(remote) = meta
            .remote_endpoint()
            .or_else(|| cfg.default_remote_endpoint())
            .cloned()
        {
            stream.extensions_mut().insert(ProxyTarget(remote));
        }

        self.spawn_graceful(guard, async move {
            let _ = service.serve(stream).await;
        });

        Some(TransparentProxyTcpSession { client_tx, eof_tx })
    }

    pub fn new_udp_session<F, G>(
        &self,
        meta_json: impl Into<String>,
        on_server_datagram: F,
        on_server_closed: G,
    ) -> Option<TransparentProxyUdpSession>
    where
        F: Fn(Bytes) + Send + Sync + 'static,
        G: Fn() + Send + Sync + 'static,
    {
        let guard = self.shutdown_guard()?;

        let (client_tx, client_rx) = mpsc::unbounded_channel::<Bytes>();

        let meta = TransparentProxyMeta::from_json(meta_json);
        let cfg = self.config.clone();
        let service = self.udp_service.clone();
        let datagram_sink: BytesSink = Arc::new(on_server_datagram);
        let closed_sink: ClosedSink = Arc::new(on_server_closed);

        tracing::debug!(protocol = %meta.protocol().as_str(), "new udp session");

        let mut flow = UdpFlow::new(client_rx, datagram_sink);
        flow.extensions_mut().insert(meta.clone());
        flow.extensions_mut().insert(cfg.clone());
        if let Some(remote) = meta
            .remote_endpoint()
            .or_else(|| cfg.default_remote_endpoint())
            .cloned()
        {
            flow.extensions_mut().insert(ProxyTarget(remote));
        }

        self.spawn_graceful(guard, async move {
            let _ = service.serve(flow).await;
            closed_sink();
        });

        Some(TransparentProxyUdpSession {
            client_tx: Mutex::new(Some(client_tx)),
        })
    }

    fn shutdown_guard(&self) -> Option<ShutdownGuard> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(err) => err.into_inner(),
        };

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
    pub fn on_client_bytes(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let _ = self.client_tx.send(Bytes::copy_from_slice(bytes));
    }

    pub fn on_client_eof(&self) {
        let _ = self.eof_tx.send(true);
    }
}

pub struct TransparentProxyUdpSession {
    client_tx: Mutex<Option<mpsc::UnboundedSender<Bytes>>>,
}

impl TransparentProxyUdpSession {
    pub fn on_client_datagram(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        let tx = {
            let lock = match self.client_tx.lock() {
                Ok(lock) => lock,
                Err(err) => err.into_inner(),
            };
            lock.clone()
        };

        if let Some(tx) = tx {
            let _ = tx.send(Bytes::copy_from_slice(bytes));
        }
    }

    pub fn on_client_close(&self) {
        let mut lock = match self.client_tx.lock() {
            Ok(lock) => lock,
            Err(err) => err.into_inner(),
        };
        *lock = None;
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
                    .get::<TransparentProxyMeta>()
                    .and_then(|meta| meta.remote_endpoint().cloned())
            })
            .or_else(|| {
                stream
                    .extensions()
                    .get::<TransparentProxyConfig>()
                    .and_then(|cfg| cfg.default_remote_endpoint().cloned())
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
                .get::<TransparentProxyMeta>()
                .and_then(|meta| meta.remote_endpoint().cloned())
        })
        .or_else(|| {
            flow.extensions()
                .get::<TransparentProxyConfig>()
                .and_then(|cfg| cfg.default_remote_endpoint().cloned())
        })
}

fn default_udp_service() -> UdpFlowService {
    tracing::debug!("using default udp service (dumb L4 forward)");
    service_fn(|mut flow: UdpFlow| async move {
        let target = udp_remote_endpoint_from_extensions(&flow);
        let Some(target) = target else {
            tracing::warn!("default udp service missing target endpoint");
            while flow.recv().await.is_some() {}
            return Ok(());
        };

        let remote = format!("{}:{}", target.host, target.port);
        let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(err) => {
                tracing::warn!(%err, "default udp bind failed");
                return Ok(());
            }
        };
        if let Err(err) = socket.connect(&remote).await {
            tracing::warn!(%err, remote = %remote, "default udp connect failed");
            while flow.recv().await.is_some() {}
            return Ok(());
        }

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
                    Ok(0) => break,
                    Ok(n) => on_server_bytes(Bytes::copy_from_slice(&buf[..n])),
                    Err(_) => break,
                }
            }
        }
    }

    on_server_closed();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn engine_start_stop_state() {
        let engine = TransparentProxyEngineBuilder::new("{}").build();
        assert!(!engine.is_running());
        engine.start();
        assert!(engine.is_running());
        engine.stop(0);
        assert!(!engine.is_running());
    }

    #[test]
    fn session_rejected_if_not_running() {
        let engine = TransparentProxyEngineBuilder::new("{}").build();
        let session = engine.new_tcp_session("{}", |_| {}, || {});
        assert!(session.is_none());
    }

    #[test]
    fn session_rejected_after_stop() {
        let engine = TransparentProxyEngineBuilder::new("{}").build();
        engine.start();
        engine.stop(0);
        let session = engine.new_tcp_session("{}", |_| {}, || {});
        assert!(session.is_none());
    }

    #[test]
    fn tcp_bridge_delivers_server_bytes() {
        let got = Arc::new(Mutex::new(Vec::<u8>::new()));
        let got_clone = got.clone();
        let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

        let engine = TransparentProxyEngineBuilder::new("{}")
            .with_tcp_service(service_fn(|mut stream: TcpFlow| async move {
                let _ = stream.write_all(b"pong").await;
                Ok(())
            }))
            .build();

        engine.start();
        let session = engine
            .new_tcp_session(
                r#"{"protocol":"tcp","remote_endpoint":"example.com:80"}"#,
                move |bytes| {
                    let mut lock = got_clone.lock().unwrap_or_else(|e| e.into_inner());
                    lock.extend_from_slice(&bytes);
                    let _ = notify_tx.send(());
                },
                || {},
            )
            .expect("session");

        session.on_client_bytes(b"ping");

        let _ = notify_rx.recv_timeout(std::time::Duration::from_secs(1));
        engine.stop(0);

        let lock = got.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(lock.as_slice(), b"pong");
    }

    #[test]
    fn udp_bridge_delivers_server_datagram() {
        let got = Arc::new(Mutex::new(Vec::<u8>::new()));
        let got_clone = got.clone();
        let (notify_tx, notify_rx) = std::sync::mpsc::channel::<()>();

        let engine = TransparentProxyEngineBuilder::new("{}")
            .with_udp_service(service_fn(|mut flow: UdpFlow| async move {
                if let Some(datagram) = flow.recv().await {
                    flow.send(datagram);
                }
                Ok(())
            }))
            .build();

        engine.start();
        let session = engine
            .new_udp_session(
                r#"{"protocol":"udp","remote_endpoint":"127.0.0.1:5353"}"#,
                move |bytes| {
                    let mut lock = got_clone.lock().unwrap_or_else(|e| e.into_inner());
                    lock.extend_from_slice(&bytes);
                    let _ = notify_tx.send(());
                },
                || {},
            )
            .expect("session");

        session.on_client_datagram(b"ping");

        let _ = notify_rx.recv_timeout(std::time::Duration::from_secs(1));
        engine.stop(0);

        let lock = got.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(lock.as_slice(), b"ping");
    }
}
