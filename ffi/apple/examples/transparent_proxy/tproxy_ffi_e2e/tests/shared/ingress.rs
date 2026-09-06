use std::{ffi::c_void, ptr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener as TokioTcpListener, TcpStream},
    sync::{Mutex, Notify, mpsc},
    task::JoinHandle,
};

use rama::utils::octets::kib;

use super::{bindings, ffi::EngineHandle};

// ── Ingress (client → service) callback context ───────────────────────────────

struct TcpServerCallbackContext {
    sender: mpsc::UnboundedSender<Option<Vec<u8>>>,
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
    _ = ctx.sender.send(Some(payload));
    // The e2e harness uses an unbounded mpsc + tight-loop writer, so there's
    // no Swift-side backpressure to surface here.
    bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_ACCEPTED
}

unsafe extern "C" fn on_tcp_server_closed(ctx: *mut c_void) {
    let ctx = unsafe { &*(ctx as *const TcpServerCallbackContext) };
    // The close marker shares the byte queue, so all accepted chunks drain first.
    _ = ctx.sender.send(None);
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
    sender: mpsc::UnboundedSender<Option<Vec<u8>>>,
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
    _ = ctx.sender.send(Some(payload));
    bindings::RamaTcpDeliverStatus_RAMA_TCP_DELIVER_ACCEPTED
}

unsafe extern "C" fn on_tcp_close_egress(ctx: *mut c_void) {
    let ctx = unsafe { &*(ctx as *const TcpEgressCallbackContext) };
    // The close marker shares the byte queue, so all accepted chunks drain first.
    _ = ctx.sender.send(None);
}

/// The connection task exclusively owns the session. Its pump futures are
/// polled together, so calls that borrow the FFI session mutably cannot overlap.
struct TcpSessionGuard {
    raw: usize,
    // Keep the callback allocations stable and live through `session_free`.
    server_context: Box<TcpServerCallbackContext>,
    egress_context: Box<TcpEgressCallbackContext>,
}

impl Drop for TcpSessionGuard {
    fn drop(&mut self) {
        // Free first: it cancels the session and waits for callbacks already
        // holding the lifetime gate. Only then may the boxed contexts drop.
        unsafe {
            bindings::rama_transparent_proxy_tcp_session_free(
                self.raw as *mut bindings::RamaTransparentProxyTcpSession,
            );
        }
    }
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
        let accept_task = self.accept_task.as_mut().expect("accept task");
        accept_task.abort();
        _ = (&mut *accept_task).await;
        self.accept_task.take();

        let mut tasks = self.connection_tasks.lock().await;
        // Retain every handle in the shared collection until it is joined.
        // If shutdown itself is cancelled, Drop can still abort and join them.
        while let Some(task) = tasks.last_mut() {
            if tokio::time::timeout(Duration::from_millis(200), &mut *task)
                .await
                .is_err()
            {
                task.abort();
                _ = (&mut *task).await;
            }
            tasks.pop();
        }
    }
}

impl Drop for IngressGuard {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
        let accept_task = self.accept_task.take();
        if let Some(task) = &accept_task {
            task.abort();
        }
        let connection_tasks = self.connection_tasks.clone();
        tokio::spawn(async move {
            if let Some(task) = accept_task {
                _ = task.await;
            }
            let mut tasks = connection_tasks.lock().await;
            while let Some(task) = tasks.last_mut() {
                task.abort();
                _ = (&mut *task).await;
                tasks.pop();
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
                    let mut tasks = connection_tasks_task.lock().await;
                    // No await between spawning and recording the handle: aborting
                    // the accept task must not orphan a connection task.
                    tasks.push(tokio::spawn(async move {
                        serve_one_ingress_connection(engine, stream, remote_addr, shutdown).await;
                    }));
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
    let (server_bytes_tx, mut server_bytes_rx) = mpsc::unbounded_channel();
    let client_read_demand = Arc::new(Notify::new());
    let (egress_bytes_tx, mut egress_bytes_rx) = mpsc::unbounded_channel();
    let egress_read_demand = Arc::new(Notify::new());
    let mut session_guard = TcpSessionGuard {
        raw: 0,
        server_context: Box::new(TcpServerCallbackContext {
            sender: server_bytes_tx,
            client_read_demand: client_read_demand.clone(),
        }),
        egress_context: Box::new(TcpEgressCallbackContext {
            sender: egress_bytes_tx,
            egress_read_demand: egress_read_demand.clone(),
        }),
    };

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
            remote_hostname_utf8: ptr::null(),
            remote_hostname_utf8_len: 0,
            local_interface_name_utf8: ptr::null(),
            local_interface_name_utf8_len: 0,
            local_interface_index: 0,
            local_interface_index_is_set: false,
            local_interface_type: 0,
            local_interface_type_is_set: false,
            is_bound: false,
            is_bound_is_set: false,
        };

        let result = unsafe {
            bindings::rama_transparent_proxy_engine_new_tcp_session(
                engine.raw,
                &meta,
                bindings::RamaTransparentProxyTcpSessionCallbacks {
                    context: ptr::from_mut(session_guard.server_context.as_mut()).cast(),
                    on_server_bytes: Some(on_tcp_server_bytes),
                    on_server_closed: Some(on_tcp_server_closed),
                    on_client_read_demand: Some(on_tcp_client_read_demand),
                },
            )
        };
        // Establish ownership before assertions or activation can fail.
        session_guard.raw = result.session as usize;
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
                context: ptr::from_mut(session_guard.egress_context.as_mut()).cast(),
                on_write_to_egress: Some(on_tcp_write_to_egress),
                on_close_egress: Some(on_tcp_close_egress),
                on_egress_read_demand: Some(on_tcp_egress_read_demand),
            },
        );
    }

    // Each close marker follows the accepted bytes on its queue. Draining
    // either writer half-closes that socket without cancelling its reader.
    let server_writer = async move {
        while let Some(Some(chunk)) = server_bytes_rx.recv().await {
            if client_write.write_all(&chunk).await.is_err() {
                break;
            }
        }
        _ = client_write.shutdown().await;
    };
    let egress_writer = async move {
        while let Some(Some(chunk)) = egress_bytes_rx.recv().await {
            if egress_write.write_all(&chunk).await.is_err() {
                break;
            }
        }
        _ = egress_write.shutdown().await;
    };

    // Egress reader: upstream socket → on_egress_bytes / on_egress_eof.
    //
    // Honours backpressure: on `Paused` we retain the rejected chunk and
    // wait for the matching `egress_read_demand` notify before retrying.
    // Without this we'd silently drop the chunk and corrupt the byte
    // stream (see `tcp_byte_stream_preserved_under_egress_backpressure`).
    let egress_session = session;
    let egress_read_demand_for_reader = egress_read_demand.clone();
    let egress_reader = async move {
        let mut reader = egress_read;
        let mut buf = [0_u8; kib(16)];
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
    };

    // Ingress reader: client socket → on_client_bytes / on_client_eof.
    //
    // Same backpressure-honouring shape as the egress reader above.
    let client_reader = async move {
        let mut reader = client_read;
        let mut buf = [0_u8; kib(16)];
        let mut pending: Option<Vec<u8>> = None;
        'ingress: loop {
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
                        client_read_demand.notified().await;
                    }
                    _ => break 'ingress,
                }
            }

            match reader.read(&mut buf).await {
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
                            client_read_demand.notified().await;
                        }
                        _ => break,
                    }
                }
            }
        }
    };

    tokio::pin!(server_writer, egress_writer, egress_reader, client_reader);
    let mut server_writer_done = false;
    let mut egress_writer_done = false;
    let mut egress_reader_done = false;
    let mut client_reader_done = false;
    while !server_writer_done || !egress_writer_done {
        tokio::select! {
            // Client EOF only completes client_reader. Continue polling the
            // sibling pumps until both directions have drained accepted bytes.
            _ = &mut server_writer, if !server_writer_done => server_writer_done = true,
            _ = &mut egress_writer, if !egress_writer_done => egress_writer_done = true,
            _ = &mut egress_reader, if !egress_reader_done => egress_reader_done = true,
            _ = &mut client_reader, if !client_reader_done => client_reader_done = true,
            _ = shutdown.notified() => break,
        }
    }
    // All four pump futures drop before session_guard, including on task
    // cancellation. No detached reader can enter the FFI during or after free.
}
