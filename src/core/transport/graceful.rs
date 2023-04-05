//! graceful shutdown utilities

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    time::Duration,
};

use futures::Future;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_util::sync::CancellationToken;

/// A service to facilitate graceful shutdown within your server.
pub struct GracefulService {
    shutdown: CancellationToken,
    shutdown_complete_rx: Receiver<()>,
    shutdown_complete_tx: Sender<()>,
}

/// Create the service required to facilitate graceful shutdown within your server.
pub fn service(signal: impl Future + Send + 'static) -> GracefulService {
    let shutdown = CancellationToken::new();
    let (shutdown_complete_tx, shutdown_complete_rx) = channel(1);

    let token = shutdown.clone();
    tokio::spawn(async move {
        let _ = signal.await;
        token.cancel();
    });

    GracefulService {
        shutdown,
        shutdown_complete_rx,
        shutdown_complete_tx,
    }
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
    /// Create a new graceful token that can be used by a graceful service's
    /// child processes to indicate it is finished as well as to interrupt itself
    /// in case a shutdown is desired.
    pub fn token(&self) -> Token {
        Token {
            shutdown: self.shutdown.child_token(),
            _shutdown_complete: self.shutdown_complete_tx.clone(),
        }
    }

    /// Wait indefinitely until the server can be gracefully shut down.
    pub async fn shutdown(mut self) {
        self.shutdown.cancelled().await;
        drop(self.shutdown_complete_tx);
        self.shutdown_complete_rx.recv().await;
    }

    /// Wait until the server is gracefully shutdown,
    /// but adding a max amount of time to wait since the moment
    /// a cancellation it desired.
    pub async fn shutdown_until(mut self, duration: Duration) -> Result<(), TimeoutError> {
        self.shutdown.cancelled().await;
        drop(self.shutdown_complete_tx);
        match tokio::time::timeout(duration, self.shutdown_complete_rx.recv()).await {
            Err(_) => Err(TimeoutError(())),
            Ok(_) => Ok(()),
        }
    }
}

#[derive(Debug)]
pub struct Token {
    shutdown: CancellationToken,
    _shutdown_complete: Sender<()>,
}

impl Token {
    pub async fn shutdown(self) {
        self.shutdown.cancelled().await;
    }

    pub fn child_token(&self) -> Token {
        Token {
            shutdown: self.shutdown.child_token(),
            _shutdown_complete: self._shutdown_complete.clone(),
        }
    }
}

impl Clone for Token {
    fn clone(&self) -> Self {
        Self {
            shutdown: self.shutdown.clone(),
            _shutdown_complete: self._shutdown_complete.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;

    use super::*;
    use tokio::time::sleep;

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

        service.shutdown().await;

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
                .shutdown_until(Duration::from_millis(100))
                .await
                .unwrap_err(),
        );

        drop(shutdown_tx);
        shutdown_rx.recv().await;
    }
}
