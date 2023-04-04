use pin_project::pin_project;
use std::{
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::sync::{broadcast, mpsc};
use tracing::error;

use crate::core::transport::shutdown::Shutdown;

#[pin_project]
pub struct Listener<S: HandlerStream, E: Future<Output = ()>> {
    #[pin]
    stream: S,

    #[pin]
    shutdown: E,

    /// Broadcasts a shutdown signal to all active connections.
    ///
    /// The initial `shutdown` trigger is provided by the `run` caller. The
    /// server is responsible for gracefully shutting down active connections.
    /// When a connection task is spawned, it is passed a broadcast receiver
    /// handle. When a graceful shutdown is initiated, a `()` value is sent via
    /// the broadcast::Sender. Each active connection receives it, reaches a
    /// safe terminal state, and completes the task.
    notify_shutdown: broadcast::Sender<()>,

    /// Used as part of the graceful shutdown process to wait for client
    /// connections to complete processing.
    ///
    /// Tokio channels are closed once all `Sender` handles go out of scope.
    /// When a channel is closed, the receiver receives `None`. This is
    /// leveraged to detect all connection handlers completing. When a
    /// connection handler is initialized, it is assigned a clone of
    /// `shutdown_complete_tx`. When the listener shuts down, it drops the
    /// sender held by this `shutdown_complete_tx` field. Once all handler tasks
    /// complete, all clones of the `Sender` are also dropped. This results in
    /// `shutdown_complete_rx.recv()` completing with `None`. At this point, it
    /// is safe to exit the server process.
    shutdown_complete_rx: mpsc::Receiver<()>,
    shutdown_complete_tx: mpsc::Sender<()>,
}

impl<S: HandlerStream, E: Future<Output = ()>> Listener<S, E> {
    pub fn new(stream: S, shutdown: E) -> Self {
        let (notify_shutdown, _) = broadcast::channel(1);
        let (shutdown_complete_tx, shutdown_complete_rx) = mpsc::channel(1);

        Self {
            stream,
            shutdown,
            notify_shutdown,
            shutdown_complete_rx,
            shutdown_complete_tx,
        }
    }
}

impl<S: HandlerStream, E: Future<Output = ()>> Future for Listener<S, E> {
    type Output = Result<(), S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        if let Poll::Ready(()) = this.shutdown.poll(cx) {
            return Poll::Ready(Ok(()));
        }

        let maybe_result = ready!(this.stream.poll_next(cx));
        let result = match maybe_result {
            Some(result) => result,
            None => return Poll::Ready(Ok(())),
        };
        let handler = result?;

        let shutdown = Shutdown::new(this.notify_shutdown.subscribe());
        let shutdown_complete_tx = this.shutdown_complete_tx.clone();

        tokio::spawn(async move {
            if let Err(e) = handler.handle(shutdown).await {
                error!(%e, "error handling connection");
            }
            let _ = shutdown_complete_tx.send(()).await;
        });

        Poll::Pending
    }
}

pub trait Handler: Send {
    type Error: Send;
    type Future: Future<Output = Result<(), Self::Error>> + Send + 'static;

    fn handle(self, shutdown: Shutdown) -> Self::Future;
}

pub trait HandlerStream {
    type Error: Send + std::error::Error + std::fmt::Debug;
    type Handler: Handler<Error = Self::Error> + 'static;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Handler, Self::Error>>>;
}
