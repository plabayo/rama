use std::{future::Future, time::Duration};
use tokio::{
    select,
    sync::{broadcast, mpsc},
};

use super::shutdown::Shutdown;

pub trait GracefulListener {
    type Error: Send;
    type Handler: GracefulHandler<Error = Self::Error>;
    type Future: Future<Output = Result<Self::Handler, Self::Error>>;

    fn accept(&self) -> Self::Future;
}

pub trait GracefulHandler: Send {
    type Error: Send;
    type Future: Future<Output = Result<(), Self::Error>> + Send;

    fn handle(&mut self, shutdown: Shutdown) -> Self::Future;
}

pub struct GracefulServer<L, S> {
    listener: L,
    shutdown: S,
    timeout: Option<Duration>,
}

impl<L, S> GracefulServer<L, S>
where
    L: GracefulListener,
    <L as GracefulListener>::Handler: 'static,
    <L as GracefulListener>::Error: 'static,
    S: Future<Output = ()>,
{
    pub(super) fn new(listener: L, shutdown: S) -> Self {
        Self {
            listener,
            shutdown,
            timeout: None,
        }
    }

    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    pub async fn listen(self) -> Result<(), L::Error> {
        let (notify_shutdown, _) = broadcast::channel(1);
        let (shutdown_complete_tx, shutdown_complete_rx) = mpsc::channel(1);

        let (error_tx, mut error_rx) = mpsc::channel(1);

        let mut server = ManagedListener {
            listener: self.listener,
            error_tx,

            notify_shutdown,
            shutdown_complete_rx,
            shutdown_complete_tx,
        };

        let serve_result = tokio::select! {
            res = server.run() => res, // unexpected server err
            err = error_rx.recv() => Err(err.unwrap()), // unexpected handler err
            _ = self.shutdown => Ok(()), // graceful shutdown
        };

        let ManagedListener {
            mut shutdown_complete_rx,
            shutdown_complete_tx,
            notify_shutdown,
            ..
        } = server;

        drop(notify_shutdown);
        drop(shutdown_complete_tx);

        let shutdown_complete_rx_future = shutdown_complete_rx.recv();
        if let Some(timeout) = self.timeout {
            let _ = tokio::time::timeout(timeout, shutdown_complete_rx_future).await;
        } else {
            let _ = shutdown_complete_rx_future.await;
        }

        serve_result
    }
}

struct ManagedListener<L, E> {
    listener: L,
    error_tx: mpsc::Sender<E>,

    notify_shutdown: broadcast::Sender<()>,
    shutdown_complete_rx: mpsc::Receiver<()>,
    shutdown_complete_tx: mpsc::Sender<()>,
}

impl<L: GracefulListener> ManagedListener<L, L::Error>
where
    <L as GracefulListener>::Handler: 'static,
    <L as GracefulListener>::Error: 'static,
{
    async fn run(&mut self) -> Result<(), L::Error> {
        loop {
            let handler = self.listener.accept().await?;

            let handler = ManagedHandler {
                handler,
                shutdown: Shutdown::new(self.notify_shutdown.subscribe()),
                _shutdown_complete: self.shutdown_complete_tx.clone(),
            };

            let error_tx = self.error_tx.clone();

            tokio::spawn(async move {
                if let Err(err) = handler.run().await {
                    let _ = error_tx.send(err).await;
                }
            });
        }
    }
}

struct ManagedHandler<H> {
    handler: H,

    shutdown: Shutdown,
    _shutdown_complete: mpsc::Sender<()>,
}

impl<H: GracefulHandler> ManagedHandler<H> {
    async fn run(mut self) -> Result<(), H::Error> {
        self.handler.handle(self.shutdown).await
    }
}
