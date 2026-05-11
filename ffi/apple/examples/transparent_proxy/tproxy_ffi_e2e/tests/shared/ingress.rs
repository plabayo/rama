use std::{ffi::c_void, ptr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener as TokioTcpListener, TcpStream},
    sync::{Mutex, Notify, mpsc},
    task::JoinHandle,
};

use super::{bindings, ffi::EngineHandle};

// ── Ingress (client → service) callback context ───────────────────────────────

struct TcpServerCallbackContext {
    sender: mpsc::UnboundedSender<Vec<u8>>,
    closed: Arc<Notify>,
    /// Fired by the FFI when the per-flow ingress channel transitions from
    /// full to has-space after `on_client_bytes` returned `Paused`. The
    /// ingress reader awaits on this before retrying a rejected chunk.
    /// Without this we'd drop the chunk and corrupt the byte stream — same
    /// bug that surfaced as `tls: bad record MAC` for large h2 transfers.
    client_read_demand: Arc<Notify>,
}

unsafe extern "C" fn on_tcp_server_bytes(
    ctx: *mut c_void,
    bytes: bindings::RamaBytesView,
) -> bindings::RamaTcpDeliverStatus {
    let ctx = unsafe { &*(ctx as *const TcpServerCallbackContext) };
    let payload = if bytes.ptr.is_null() || bytes.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len).to_vec() }
    };
    _ = ctx.sender.send(payload);
    // The e2e harness uses an unbounded mpsc + tight-loop writer, so there's
    // no Swift-side backpressure to surface here.
    bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_ACCEPTED
}

unsafe extern "C" fn on_tcp_server_closed(ctx: *mut c_void) {
    let ctx = unsafe { &*(ctx as *const TcpServerCallbackContext) };
    ctx.closed.notify_waiters();
}

/// Resume signal from Rust: the per-flow ingress channel has space again.
/// Wakes the harness's ingress reader, which is parked waiting to retry a
/// chunk Rust rejected with `Paused`.
unsafe extern "C" fn on_tcp_client_read_demand(ctx: *mut c_void) {
    let ctx = unsafe { &*(ctx as *const TcpServerCallbackContext) };
    ctx.client_read_demand.notify_one();
}

unsafe extern "C" fn on_tcp_egress_read_demand(ctx: *mut c_void) {
    let ctx = unsafe { &*(ctx as *const TcpEgressCallbackContext) };
    ctx.egress_read_demand.notify_one();
}

// ── Egress (service → upstream) callback context ─────────────────────────────

struct TcpEgressCallbackContext {
    sender: mpsc::UnboundedSender<Vec<u8>>,
    closed: Arc<Notify>,
    /// See `TcpServerCallbackContext.client_read_demand` — same role for
    /// the egress (NWConnection-receive) direction.
    egress_read_demand: Arc<Notify>,
}

unsafe extern "C" fn on_tcp_write_to_egress(
    ctx: *mut c_void,
    bytes: bindings::RamaBytesView,
) -> bindings::RamaTcpDeliverStatus {
    let ctx = unsafe { &*(ctx as *const TcpEgressCallbackContext) };
    let payload = if bytes.ptr.is_null() || bytes.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len).to_vec() }
    };
    _ = ctx.sender.send(payload);
    bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_ACCEPTED
}

unsafe extern "C" fn on_tcp_close_egress(ctx: *mut c_void) {
    let ctx = unsafe { &*(ctx as *const TcpEgressCallbackContext) };
    ctx.closed.notify_waiters();
}

pub(crate) struct IngressGuard {
    local_addr: std::net::SocketAddr,
    shutdown: Arc<Notify>,
    accept_task: Option<JoinHandle<()>>,
    connection_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl IngressGuard {
    pub(crate) fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }

    pub(crate) async fn shutdown(mut self) {
        self.shutdown.notify_waiters();
        let accept_task = self.accept_task.take().expect("accept task");
        accept_task.abort();
        _ = accept_task.await;

        let mut tasks = self.connection_tasks.lock().await;
        for mut task in tasks.drain(..) {
            if tokio::time::timeout(Duration::from_millis(200), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
    }
}

impl Drop for IngressGuard {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
        if let Some(accept_task) = self.accept_task.take() {
            accept_task.abort();
        }
        let connection_tasks = self.connection_tasks.clone();
        tokio::spawn(async move {
            let mut tasks = connection_tasks.lock().await;
            for task in tasks.drain(..) {
                task.abort();
            }
        });
    }
}

pub(crate) async fn spawn_ingress_listener(
    engine: Arc<EngineHandle>,
    remote_addr: std::net::SocketAddr,
) -> IngressGuard {
    let listener = TokioTcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ingress listener");
    let local_addr = listener.local_addr().expect("ingress listener local addr");
    let shutdown = Arc::new(Notify::new());
    let shutdown_task = shutdown.clone();
    let connection_tasks = Arc::new(Mutex::new(Vec::new()));
    let connection_tasks_task = connection_tasks.clone();

    let accept_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_task.notified() => break,
                result = listener.accept() => {
                    let Ok((stream, _)) = result else {
                        break;
                    };
                    let engine = engine.clone();
                    let shutdown = shutdown_task.clone();
                    let task = tokio::spawn(async move {
                        serve_one_ingress_connection(engine, stream, remote_addr, shutdown).await;
                    });
                    connection_tasks_task.lock().await.push(task);
                }
            }
        }
    });

    IngressGuard {
        local_addr,
        shutdown,
        accept_task: Some(accept_task),
        connection_tasks,
    }
}

/// Serve one intercepted client connection end-to-end.
///
/// The Rust engine became "Swift-driven" in a recent refactor: after
/// `new_tcp_session` returns, the bridge tasks remain dormant until
/// `tcp_session_activate` is called with the egress callbacks. That mirrors
/// the production flow where Swift opens an `NWConnection` to the upstream
/// before activating the session. This test harness has no `NWConnection`,
/// so we open a plain `TcpStream` to `remote_addr` and pretend to be one:
/// `on_write_to_egress` enqueues bytes for our writer task, and we read
/// from the upstream socket and feed the bytes back via
/// `tcp_session_on_egress_bytes`.
async fn serve_one_ingress_connection(
    engine: Arc<EngineHandle>,
    stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    shutdown: Arc<Notify>,
) {
    // Open the egress side first; if the upstream rejects, there's no point
    // creating an FFI session at all.
    let Ok(egress_stream) = TcpStream::connect(remote_addr).await else {
        return;
    };

    let (client_read, mut client_write) = stream.into_split();
    let (egress_read, mut egress_write) = egress_stream.into_split();

    // Ingress (client) side: server callbacks deliver bytes from the Rust
    // service back to the client connection.
    let (server_bytes_tx, mut server_bytes_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let server_closed = Arc::new(Notify::new());
    let client_read_demand = Arc::new(Notify::new());
    let server_ctx_ptr = Box::into_raw(Box::new(TcpServerCallbackContext {
        sender: server_bytes_tx,
        closed: server_closed.clone(),
        client_read_demand: client_read_demand.clone(),
    })) as usize;

    // Egress side: callbacks deliver bytes from the Rust service to the
    // upstream socket.
    let (egress_bytes_tx, mut egress_bytes_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let egress_closed = Arc::new(Notify::new());
    let egress_read_demand = Arc::new(Notify::new());
    let egress_ctx_ptr = Box::into_raw(Box::new(TcpEgressCallbackContext {
        sender: egress_bytes_tx,
        closed: egress_closed.clone(),
        egress_read_demand: egress_read_demand.clone(),
    })) as usize;

    let session = {
        let remote_host = remote_addr.ip().to_string().into_bytes();
        let meta = bindings::RamaTransparentProxyFlowMeta {
            protocol: bindings::RamaTransparentProxyFlowProtocol_RAMA_FLOW_PROTOCOL_TCP,
            remote_endpoint: bindings::RamaTransparentProxyFlowEndpoint {
                host_utf8: remote_host.as_ptr().cast(),
                host_utf8_len: remote_host.len(),
                port: remote_addr.port(),
            },
            local_endpoint: bindings::RamaTransparentProxyFlowEndpoint {
                host_utf8: ptr::null(),
                host_utf8_len: 0,
                port: 0,
            },
            source_app_signing_identifier_utf8: ptr::null(),
            source_app_signing_identifier_utf8_len: 0,
            source_app_bundle_identifier_utf8: ptr::null(),
            source_app_bundle_identifier_utf8_len: 0,
            source_app_audit_token_bytes: ptr::null(),
            source_app_audit_token_bytes_len: 0,
            source_app_pid: 0,
            source_app_pid_is_set: false,
        };

        let result = unsafe {
            bindings::rama_transparent_proxy_engine_new_tcp_session(
                engine.raw,
                &meta,
                bindings::RamaTransparentProxyTcpSessionCallbacks {
                    context: server_ctx_ptr as *mut c_void,
                    on_server_bytes: Some(on_tcp_server_bytes),
                    on_server_closed: Some(on_tcp_server_closed),
                    on_client_read_demand: Some(on_tcp_client_read_demand),
                },
            )
        };
        assert_eq!(
            result.action,
            bindings::RamaTransparentProxyFlowAction_RAMA_FLOW_ACTION_INTERCEPT,
            "ffi tcp session decision should intercept"
        );
        let raw = result.session;
        assert!(!raw.is_null(), "ffi tcp session must allocate");
        raw as usize
    };

    // Activate the session. Until this is called, bytes pushed via
    // `on_client_bytes` queue up in the engine's pending state and never
    // reach the service.
    unsafe {
        bindings::rama_transparent_proxy_tcp_session_activate(
            session as *mut bindings::RamaTransparentProxyTcpSession,
            bindings::RamaTransparentProxyTcpEgressCallbacks {
                context: egress_ctx_ptr as *mut c_void,
                on_write_to_egress: Some(on_tcp_write_to_egress),
                on_close_egress: Some(on_tcp_close_egress),
                on_egress_read_demand: Some(on_tcp_egress_read_demand),
            },
        );
    }

    // Ingress writer: service-bound bytes → client socket.
    let server_writer = tokio::spawn(async move {
        while let Some(chunk) = server_bytes_rx.recv().await {
            if client_write.write_all(&chunk).await.is_err() {
                break;
            }
        }
        _ = client_write.shutdown().await;
    });

    // Egress writer: service-bound bytes → upstream socket.
    let egress_closed_for_writer = egress_closed.clone();
    let egress_writer = tokio::spawn(async move {
        loop {
            tokio::select! {
                next = egress_bytes_rx.recv() => {
                    match next {
                        Some(chunk) => {
                            if egress_write.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                _ = egress_closed_for_writer.notified() => break,
            }
        }
        _ = egress_write.shutdown().await;
    });

    // Egress reader: upstream socket → on_egress_bytes / on_egress_eof.
    //
    // Honours backpressure: on `Paused` we retain the rejected chunk and
    // wait for the matching `egress_read_demand` notify before retrying.
    // Without this we'd silently drop the chunk and corrupt the byte
    // stream (see `tcp_byte_stream_preserved_under_egress_backpressure`).
    let egress_session = session;
    let egress_read_demand_for_reader = egress_read_demand.clone();
    let egress_reader = tokio::spawn(async move {
        let mut reader = egress_read;
        let mut buf = [0_u8; 16 * 1024];
        let mut pending: Option<Vec<u8>> = None;
        'outer: loop {
            // Replay any pending rejected chunk before reading new data.
            while let Some(chunk) = pending.take() {
                let status = unsafe {
                    bindings::rama_transparent_proxy_tcp_session_on_egress_bytes(
                        egress_session as *mut bindings::RamaTransparentProxyTcpSession,
                        bindings::RamaBytesView {
                            ptr: chunk.as_ptr(),
                            len: chunk.len(),
                        },
                    )
                };
                match status {
                    bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_ACCEPTED => {}
                    bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_PAUSED => {
                        pending = Some(chunk);
                        egress_read_demand_for_reader.notified().await;
                    }
                    _ => break 'outer, // closed
                }
            }

            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    unsafe {
                        bindings::rama_transparent_proxy_tcp_session_on_egress_eof(
                            egress_session as *mut bindings::RamaTransparentProxyTcpSession,
                        );
                    }
                    break;
                }
                Ok(n) => {
                    let status = unsafe {
                        bindings::rama_transparent_proxy_tcp_session_on_egress_bytes(
                            egress_session as *mut bindings::RamaTransparentProxyTcpSession,
                            bindings::RamaBytesView {
                                ptr: buf.as_ptr(),
                                len: n,
                            },
                        )
                    };
                    match status {
                        bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_ACCEPTED => {}
                        bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_PAUSED => {
                            // Save the rejected chunk for replay.
                            pending = Some(buf[..n].to_vec());
                            egress_read_demand_for_reader.notified().await;
                        }
                        _ => break, // closed
                    }
                }
            }
        }
    });

    // Ingress reader: client socket → on_client_bytes / on_client_eof.
    //
    // Same backpressure-honouring shape as the egress reader above.
    let mut reader = client_read;
    let mut buf = [0_u8; 16 * 1024];
    let mut pending: Option<Vec<u8>> = None;
    'ingress: loop {
        // Replay before reading new data.
        while let Some(chunk) = pending.take() {
            let status = unsafe {
                bindings::rama_transparent_proxy_tcp_session_on_client_bytes(
                    session as *mut bindings::RamaTransparentProxyTcpSession,
                    bindings::RamaBytesView {
                        ptr: chunk.as_ptr(),
                        len: chunk.len(),
                    },
                )
            };
            match status {
                bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_ACCEPTED => {}
                bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_PAUSED => {
                    pending = Some(chunk);
                    tokio::select! {
                        _ = client_read_demand.notified() => {}
                        _ = shutdown.notified() => {
                            unsafe {
                                bindings::rama_transparent_proxy_tcp_session_on_client_eof(
                                    session as *mut bindings::RamaTransparentProxyTcpSession,
                                );
                            }
                            break 'ingress;
                        }
                        _ = server_closed.notified() => break 'ingress,
                    }
                }
                _ => break 'ingress, // closed
            }
        }

        tokio::select! {
            result = reader.read(&mut buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        unsafe {
                            bindings::rama_transparent_proxy_tcp_session_on_client_eof(
                                session as *mut bindings::RamaTransparentProxyTcpSession,
                            );
                        }
                        break;
                    }
                    Ok(n) => {
                        let status = unsafe {
                            bindings::rama_transparent_proxy_tcp_session_on_client_bytes(
                                session as *mut bindings::RamaTransparentProxyTcpSession,
                                bindings::RamaBytesView {
                                    ptr: buf.as_ptr(),
                                    len: n,
                                },
                            )
                        };
                        match status {
                            bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_ACCEPTED => {}
                            bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_PAUSED => {
                                pending = Some(buf[..n].to_vec());
                            }
                            _ => break, // closed
                        }
                    }
                }
            }
            _ = shutdown.notified() => {
                unsafe {
                    bindings::rama_transparent_proxy_tcp_session_on_client_eof(
                        session as *mut bindings::RamaTransparentProxyTcpSession,
                    );
                }
                break;
            }
            _ = server_closed.notified() => break,
        }
    }

    // Tear down the bridges. Aborting is fine because the FFI session owns
    // the underlying tokio tasks via its own shutdown guard.
    server_writer.abort();
    egress_writer.abort();
    egress_reader.abort();
    _ = server_writer.await;
    _ = egress_writer.await;
    _ = egress_reader.await;
}
