use std::{future::Future, sync::Arc};

use rama_core::{
    Service, error::BoxError, graceful::WeakShutdownGuard, rt::Executor, telemetry::tracing,
};

use crate::{
    ReceivedXpcMessage, XpcConnection, XpcConnectionError, XpcError, XpcEvent, XpcListener,
    XpcMessage,
};

/// A Rama-native XPC server adapter built on top of [`XpcListener`] and [`XpcConnection`].
///
/// `XpcServer` is the higher-level server layer for the crate:
///
/// - [`XpcListener`] remains the low-level primitive for binding and accepting peers
/// - `XpcServer` owns the accept / recv loop and dispatches incoming messages into a
///   regular Rama [`Service`]
///
/// The inner service receives an [`XpcMessage`] and returns an optional reply:
///
/// - `Some(reply)` attempts to reply to the incoming request
/// - `None` processes the message without replying
///
/// If the peer sent the message via [`XpcConnection::send`] rather than
/// [`XpcConnection::send_request`], replying is not possible and the server silently
/// ignores [`XpcError::ReplyNotExpected`].
///
/// A failing message (handler error, or a reply that can't be delivered) is logged
/// and, when a reply is expected, answered with an
/// [`error_envelope`](crate::router::error_envelope) — it never tears down the peer
/// connection; only a kernel [`XpcEvent::Error`] does.
///
/// This adapter is intentionally minimal. It keeps [`XpcMessage`] as the public wire
/// type, while leaving room for higher-level typed codecs and request-routing layers
/// to be built on top later.
#[derive(Debug, Clone)]
pub struct XpcServer<S> {
    service: Arc<S>,
}

impl<S> XpcServer<S> {
    /// Create a new XPC server adapter from a Rama service.
    pub fn new(service: S) -> Self {
        Self {
            service: Arc::new(service),
        }
    }

    /// Borrow the inner service.
    pub fn service(&self) -> &S {
        self.service.as_ref()
    }
}

impl<S> XpcServer<S>
where
    S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>>,
{
    /// Serve an already-bound named listener.
    ///
    /// Each accepted peer is handled concurrently on its own task.
    ///
    /// Returns an error when libxpc terminated the listener (e.g. the Mach
    /// receive right was revoked or never granted, so no peer will ever be
    /// delivered); returns `Ok` on a graceful shutdown-guard exit or an
    /// explicit [`XpcListener::cancel`].
    pub async fn serve_listener(
        self,
        mut listener: XpcListener,
        executor: Executor,
    ) -> Result<(), BoxError> {
        let weak_guard = executor.guard().map(|guard| guard.clone_weak());

        tracing::info!("xpc server listener loop started");

        while let Some(peer) =
            recv_with_optional_shutdown(weak_guard.clone(), listener.accept()).await
        {
            tracing::info!(
                pid = peer.pid(),
                asid = peer.asid(),
                "xpc server accepted peer connection"
            );
            self.spawn_peer_task(peer, &executor);
        }

        if let Some(error) = listener.termination_reason() {
            tracing::error!(
                %error,
                "xpc server listener loop stopped: listener terminated by libxpc"
            );
            return Err(error.clone().into());
        }

        tracing::warn!("xpc server listener loop stopped");

        Ok(())
    }

    /// Serve a connection-driven XPC source.
    ///
    /// This works for:
    /// - peer connections created by [`XpcConnection::connect`](crate::XpcConnection::connect)
    /// - listener-style connections such as [`crate::XpcEndpoint::anonymous_channel`],
    ///   whose first useful events are [`XpcEvent::Connection`] peer arrivals
    pub async fn serve_connection(
        self,
        mut connection: XpcConnection,
        executor: Executor,
    ) -> Result<(), BoxError> {
        let weak_guard = executor.guard().map(|guard| guard.clone_weak());

        loop {
            match recv_with_optional_shutdown(weak_guard.clone(), connection.recv()).await {
                None => break,
                Some(XpcEvent::Connection(peer)) => {
                    tracing::info!(
                        pid = peer.pid(),
                        asid = peer.asid(),
                        "xpc server accepted peer connection from event stream"
                    );
                    self.spawn_peer_task(peer, &executor);
                }
                Some(XpcEvent::Message(message)) => {
                    handle_message(self.service.as_ref(), message, None).await;
                }
                Some(XpcEvent::Error(err)) => {
                    log_connection_close(&err, "xpc server event stream closed");
                    break;
                }
            }
        }

        Ok(())
    }

    fn spawn_peer_task(&self, peer: XpcConnection, executor: &Executor) {
        let service = self.service.clone();
        let weak_guard = executor.guard().map(|guard| guard.clone_weak());
        let pid = peer.pid();
        let asid = peer.asid();

        tracing::info!(pid, asid, "xpc server spawning peer task");

        executor.spawn_cancellable_task(async move {
            if let Err(err) = serve_peer(service, peer, weak_guard, pid, asid).await {
                tracing::error!(%err, "xpc peer task failed");
            }
        });
    }
}

async fn serve_peer<S>(
    service: Arc<S>,
    mut peer: XpcConnection,
    weak_guard: Option<WeakShutdownGuard>,
    pid: i32,
    asid: i32,
) -> Result<(), BoxError>
where
    S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>>,
{
    tracing::info!(pid, asid, "xpc server peer task started");
    loop {
        match recv_with_optional_shutdown(weak_guard.clone(), peer.recv()).await {
            None => {
                tracing::info!(pid, asid, "xpc server peer task stopped");
                return Ok(());
            }
            Some(XpcEvent::Connection(_)) => {
                tracing::warn!("xpc server received unexpected nested peer connection event");
            }
            Some(XpcEvent::Message(message)) => {
                handle_message(service.as_ref(), message, Some((pid, asid))).await;
            }
            Some(XpcEvent::Error(err)) => {
                log_connection_close(&err, "xpc peer connection closed");
                return Ok(());
            }
        }
    }
}

/// Handle one message. Infallible by design: a handler error or undeliverable reply
/// is logged (and answered with an error envelope when a reply is expected), never
/// propagated, so one bad request can't tear down the peer connection.
async fn handle_message<S>(
    service: &S,
    message: ReceivedXpcMessage,
    peer_identity: Option<(i32, i32)>,
) where
    S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>>,
{
    let request = message.message().clone();
    let selector = message_selector(&request);
    let selector = selector.as_deref();
    if let Some((pid, asid)) = peer_identity {
        tracing::info!(pid, asid, selector, "xpc server handling message");
    } else {
        tracing::info!(selector, "xpc server handling message");
    }

    let reply = match service.serve(request).await {
        Ok(reply) => reply,
        Err(err) => {
            let err: BoxError = err.into();
            tracing::warn!(selector, %err, "xpc server handler failed; replying with error envelope");
            Some(crate::router::error_envelope(
                crate::router::ERROR_CODE_HANDLER_FAILED,
                err.to_string(),
            ))
        }
    };

    let Some(reply) = reply else {
        tracing::debug!(selector, "xpc server service completed without reply");
        return;
    };

    match message.reply(reply) {
        Ok(()) => {
            tracing::info!(selector, "xpc server sent reply");
        }
        // Fire-and-forget message: nothing to reply to.
        Err(XpcError::ReplyNotExpected) => {
            tracing::debug!(
                selector,
                "xpc server produced a reply for a fire-and-forget message"
            );
        }
        Err(err) => {
            tracing::warn!(selector, %err, "xpc server failed to deliver reply");
        }
    }
}

fn message_selector(message: &XpcMessage) -> Option<String> {
    let XpcMessage::Dictionary(map) = message else {
        return None;
    };
    let Some(XpcMessage::String(selector)) = map.get("$selector") else {
        return None;
    };
    Some(selector.clone())
}

fn log_connection_close(err: &XpcConnectionError, message: &'static str) {
    match err {
        XpcConnectionError::Interrupted => tracing::debug!(?err, "{message}"),
        XpcConnectionError::Invalidated(_) => tracing::debug!(?err, "{message}"),
        XpcConnectionError::PeerRequirementFailed(_) => tracing::warn!(?err, "{message}"),
    }
}

async fn recv_with_optional_shutdown<T>(
    weak_guard: Option<WeakShutdownGuard>,
    future: impl Future<Output = Option<T>>,
) -> Option<T> {
    match weak_guard {
        Some(weak_guard) => {
            let mut cancelled = std::pin::pin!(weak_guard.into_cancelled());
            tokio::select! {
                _ = cancelled.as_mut() => None,
                output = future => output,
            }
        }
        None => future.await,
    }
}
