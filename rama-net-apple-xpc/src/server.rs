use std::{future::Future, sync::Arc};

use rama_core::{
    Service, error::BoxError, graceful::WeakShutdownGuard, rt::Executor, telemetry::tracing,
};

use crate::{
    ReceivedXpcMessage, XpcConnection, XpcConnectionError, XpcError, XpcEvent, XpcListener,
    XpcListenerConfig, XpcMessage,
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
    /// Bind a named XPC listener and serve it until the listener stops.
    pub async fn serve_named(
        self,
        config: XpcListenerConfig,
        executor: Executor,
    ) -> Result<(), BoxError> {
        let listener = XpcListener::bind(config)?;
        self.serve_listener(listener, executor).await
    }

    /// Serve an already-bound named listener.
    ///
    /// Each accepted peer is handled concurrently on its own task.
    pub async fn serve_listener(
        self,
        mut listener: XpcListener,
        executor: Executor,
    ) -> Result<(), BoxError> {
        let weak_guard = executor.guard().map(|guard| guard.clone_weak());

        while let Some(peer) =
            recv_with_optional_shutdown(weak_guard.clone(), listener.accept()).await
        {
            self.spawn_peer_task(peer, &executor);
        }

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
                    tracing::debug!("xpc server accepted peer connection from event stream");
                    self.spawn_peer_task(peer, &executor);
                }
                Some(XpcEvent::Message(message)) => {
                    handle_message(self.service.as_ref(), message).await?;
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

        executor.spawn_cancellable_task(async move {
            if let Err(err) = serve_peer(service, peer, weak_guard).await {
                tracing::error!(%err, "xpc peer task failed");
            }
        });
    }
}

async fn serve_peer<S>(
    service: Arc<S>,
    mut peer: XpcConnection,
    weak_guard: Option<WeakShutdownGuard>,
) -> Result<(), BoxError>
where
    S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>>,
{
    tracing::debug!("xpc server peer task started");
    loop {
        match recv_with_optional_shutdown(weak_guard.clone(), peer.recv()).await {
            None => return Ok(()),
            Some(XpcEvent::Connection(_)) => {
                tracing::warn!("xpc server received unexpected nested peer connection event");
            }
            Some(XpcEvent::Message(message)) => {
                handle_message(service.as_ref(), message).await?;
            }
            Some(XpcEvent::Error(err)) => {
                log_connection_close(&err, "xpc peer connection closed");
                return Ok(());
            }
        }
    }
}

async fn handle_message<S>(service: &S, message: ReceivedXpcMessage) -> Result<(), BoxError>
where
    S: Service<XpcMessage, Output = Option<XpcMessage>, Error: Into<BoxError>>,
{
    let request = message.message().clone();
    tracing::trace!(request = ?request, "xpc server handling message");
    let reply = service.serve(request).await.map_err(Into::into)?;

    if let Some(reply) = reply {
        tracing::trace!(reply = ?reply, "xpc server sending reply");
        match message.reply(reply) {
            Ok(()) => {}
            Err(XpcError::ReplyNotExpected) => {
                tracing::trace!(
                    "xpc server service produced a reply for a fire-and-forget message"
                );
            }
            Err(err) => return Err(err.into()),
        }
    }

    Ok(())
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
