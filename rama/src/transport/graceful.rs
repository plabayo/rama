//! Graceful shutdown utilities.

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use pin_project_lite::pin_project;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};

pin_project! {
    /// A future that resolves when a graceful shutdown is requested.
    pub struct ShutdownFuture<'a> {
        #[pin]
        maybe_future: Option<WaitForCancellationFuture<'a>>,
    }
}

impl<'a> ShutdownFuture<'a> {
    /// Create a new [`ShutdownFuture`] from a [`WaitForCancellationFuture`].
    ///
    /// [`WaitForCancellationFuture`]: https://docs.rs/tokio-util/*/tokio_util/sync/struct.WaitForCancellationFuture.html
    pub fn new(future: WaitForCancellationFuture<'a>) -> Self {
        Self {
            maybe_future: Some(future),
        }
    }

    /// Create a new [`ShutdownFuture`] that never resolves.
    pub fn pending() -> Self {
        Self { maybe_future: None }
    }
}

impl Future for ShutdownFuture<'_> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project().maybe_future.as_pin_mut() {
            Some(fut) => fut.poll(cx),
            None => Poll::Pending,
        }
    }
}

/// A service to facilitate graceful shutdown within your server.
#[derive(Debug)]
pub struct GracefulService {
    shutdown: CancellationToken,
    shutdown_complete_rx: Receiver<()>,
    shutdown_complete_tx: Sender<()>,
}

/// Create the service required to facilitate graceful shutdown within your server.
pub fn service(signal: impl Future + Send + 'static) -> GracefulService {
    GracefulService::new(signal)
}

/// The error returned in case a graceful service that was blocked on shutdown
/// using a deadline (duration) that was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutError(());

impl Display for TimeoutError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Graceful shutdown timed out")
    }
}

impl Error for TimeoutError {}

impl GracefulService {
    /// Create a new graceful service that can be used to facilitate graceful
    /// shutdown within your server, which triggers when the given future (signal)
    /// resolves.
    pub fn new(signal: impl Future + Send + 'static) -> Self {
        let service = Self::pending();

        let token = service.shutdown.clone();
        tokio::spawn(async move {
            // ensure the signal is killed even when manual triggered
            tokio::select! {
                _ = signal => {
                    token.cancel();
                },
                _ = token.cancelled() => (),
            };
        });

        service
    }

    /// Create a new graceful service that can be used to facilitate graceful
    /// shutdown within your server, which triggers when the infamous "CTRL+C" signal (future)
    /// resolves.
    pub fn ctrl_c() -> Self {
        let signal = tokio::signal::ctrl_c();
        Self::new(signal)
    }

    #[cfg(unix)]
    /// Create a new graceful service that can be used to facilitate graceful
    /// shutdown within your server, which triggers when the UNIX "SIGTERM" signal (future)
    /// resolves.
    pub fn sigterm() -> Self {
        let signal = async {
            let mut os_signal =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            os_signal.recv().await;
            std::io::Result::Ok(())
        };
        Self::new(signal)
    }

    /// Create a new graceful service that can be used to facilitate graceful
    /// shutdown without an external signal to auto-trigger graceful shutdown.
    ///
    /// This is useful when you want to ensure trigger graceful shutdown manually,
    /// using [`GracefulService::trigger_shutdown`] or do not wish to use a dummy
    /// service in case no graceful shutdown is desired at all.
    pub fn pending() -> Self {
        let shutdown = CancellationToken::new();
        let (shutdown_complete_tx, shutdown_complete_rx) = channel(1);

        Self {
            shutdown,
            shutdown_complete_rx,
            shutdown_complete_tx,
        }
    }

    /// Create a new graceful token that can be used by a graceful service's
    /// child processes to indicate it is finished as well as to interrupt itself
    /// in case a shutdown is desired.
    pub fn token(&self) -> Token {
        Token::new(
            self.shutdown.child_token(),
            self.shutdown_complete_tx.clone(),
        )
    }

    /// Trigger a manual shutdown.
    pub async fn trigger_shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Wait indefinitely until the server has its shutdown requested
    pub async fn shutdown_triggered(&self) {
        self.shutdown.cancelled().await;
    }

    /// Wait until the server can be gracefully shut down,
    /// in case `wait` is `None` it will wait indefinitely.
    pub async fn shutdown_gracefully(mut self, wait: Option<Duration>) -> Result<(), TimeoutError> {
        self.shutdown_triggered().await;
        drop(self.shutdown_complete_tx);

        let future = self.shutdown_complete_rx.recv();
        match wait {
            Some(duration) => match tokio::time::timeout(duration, future).await {
                Err(_) => Err(TimeoutError(())),
                Ok(_) => Ok(()),
            },
            None => {
                future.await;
                Ok(())
            }
        }
    }
}

impl Default for GracefulService {
    fn default() -> Self {
        let signal = tokio::signal::ctrl_c();
        Self::new(signal)
    }
}

/// A graceful shutdown token,
/// used to respect graceful shutdowns within your server's child routines.
#[derive(Debug, Clone)]
pub struct Token {
    state: Option<TokenState>,
}

impl Token {
    /// Construct a true graceful token.
    ///
    /// This token will drop the shutdown_complete
    /// when finished (to mark it went out of scope) and which can be also used
    /// to await the given shutdown cancellation token.
    pub fn new(shutdown: CancellationToken, shutdown_complete: Sender<()>) -> Self {
        Self {
            state: Some(TokenState {
                shutdown,
                shutdown_complete,
            }),
        }
    }

    /// Construct a token that will never shutdown.
    ///
    /// This is a desired solution where you need to provide a token for
    /// a service which is not graceful.
    pub fn pending() -> Self {
        Self { state: None }
    }

    /// Returns the future that resolves when the
    /// graceful shutdown has been triggered.
    pub fn shutdown(&self) -> ShutdownFuture<'_> {
        match &self.state {
            Some(state) => ShutdownFuture::new(state.shutdown.cancelled()),
            None => ShutdownFuture::pending(),
        }
    }

    /// Creates a child token that
    /// can be passed down to child procedures that
    /// wish to respect the graceful shutdown when possible.
    pub fn child_token(&self) -> Token {
        match &self.state {
            Some(state) => Token {
                state: Some(TokenState {
                    shutdown: state.shutdown.child_token(),
                    shutdown_complete: state.shutdown_complete.clone(),
                }),
            },
            None => self.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct TokenState {
    shutdown: CancellationToken,
    shutdown_complete: Sender<()>,
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use super::*;

    use tokio::{select, time::sleep};

    #[tokio::test]
    async fn test_token_pending() {
        let token = Token::pending();
        select! {
            _ = token.shutdown() => panic!("should not shutdown"),
            _ = sleep(Duration::from_millis(100)) => (),
        };
    }

    #[tokio::test]
    async fn test_graceful_service() {
        let (tx, mut rx) = channel::<()>(1);
        let (shutdown_tx, mut shutdown_rx) = channel::<()>(1);

        let service_shutdown_tx = shutdown_tx.clone();
        let service = service(async move {
            let _ = rx.recv().await.unwrap();
            drop(service_shutdown_tx);
        });

        let token = service.token();
        let process_shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            token.shutdown().await;
            drop(process_shutdown_tx);
        });

        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            tx.send(()).await.unwrap();
        });

        service.shutdown_gracefully(None).await.unwrap();

        drop(shutdown_tx);
        shutdown_rx.recv().await;
    }

    #[tokio::test]
    async fn test_graceful_service_timeout() {
        let (tx, mut rx) = channel::<()>(1);
        let (shutdown_tx, mut shutdown_rx) = channel::<()>(1);

        let service_shutdown_tx = shutdown_tx.clone();
        let service = service(async move {
            let _ = rx.recv().await.unwrap();
            drop(service_shutdown_tx);
        });

        let token = service.token();
        tokio::spawn(async move {
            pending::<()>().await;
            token.shutdown().await;
        });

        tokio::spawn(async move {
            sleep(Duration::from_millis(100)).await;
            tx.send(()).await.unwrap();
        });

        assert_eq!(
            TimeoutError(()),
            service
                .shutdown_gracefully(Some(Duration::from_millis(100)))
                .await
                .unwrap_err(),
        );

        drop(shutdown_tx);
        shutdown_rx.recv().await;
    }
}
