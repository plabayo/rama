use std::{ffi::c_void, ptr, sync::Arc, time::Duration};

use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener as TokioTcpListener, TcpStream},
    sync::{Mutex, Notify, mpsc},
    task::JoinHandle,
};

use super::{bindings, ffi::EngineHandle};

struct TcpCallbackContext {
    sender: mpsc::UnboundedSender<Vec<u8>>,
    closed: Arc<Notify>,
}

unsafe extern "C" fn on_tcp_server_bytes(ctx: *mut c_void, bytes: bindings::RamaBytesView) {
    let ctx = unsafe { &*(ctx as *const TcpCallbackContext) };
    let payload = if bytes.ptr.is_null() || bytes.len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(bytes.ptr, bytes.len).to_vec() }
    };
    let _ = ctx.sender.send(payload);
}

unsafe extern "C" fn on_tcp_server_closed(ctx: *mut c_void) {
    let ctx = unsafe { &*(ctx as *const TcpCallbackContext) };
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
        let _ = accept_task.await;

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

async fn serve_one_ingress_connection(
    engine: Arc<EngineHandle>,
    stream: TcpStream,
    remote_addr: std::net::SocketAddr,
    shutdown: Arc<Notify>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let closed = Arc::new(Notify::new());
    let ctx_ptr = Box::into_raw(Box::new(TcpCallbackContext {
        sender: tx,
        closed: closed.clone(),
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

        let raw = unsafe {
            bindings::rama_transparent_proxy_engine_new_tcp_session(
                engine.raw,
                &meta,
                bindings::RamaTransparentProxyTcpSessionCallbacks {
                    context: ctx_ptr as *mut c_void,
                    on_server_bytes: Some(on_tcp_server_bytes),
                    on_server_closed: Some(on_tcp_server_closed),
                },
            )
        };
        assert!(!raw.is_null(), "ffi tcp session must allocate");
        raw as usize
    };

    let writer = tokio::spawn(async move {
        while let Some(chunk) = rx.recv().await {
            if write_half.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });

    let mut reader = read_half;
    let mut buf = [0_u8; 16 * 1024];
    loop {
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
                    Ok(n) => unsafe {
                        bindings::rama_transparent_proxy_tcp_session_on_client_bytes(
                            session as *mut bindings::RamaTransparentProxyTcpSession,
                            bindings::RamaBytesView {
                                ptr: buf.as_ptr(),
                                len: n,
                            },
                        );
                    },
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
            _ = closed.notified() => break,
        }
    }

    writer.abort();
    let _ = writer.await;
}
