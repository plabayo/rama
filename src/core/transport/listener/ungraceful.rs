use std::future::Future;
use tokio::{select, sync::mpsc};

use super::{GracefulListener, GracefulServer};

pub trait Listener {
    type Error: Send;
    type Handler: Handler<Error = Self::Error>;
    type Future: Future<Output = Result<Self::Handler, Self::Error>>;

    fn accept(&self) -> Self::Future;
}

pub trait Handler: Send {
    type Error: Send;
    type Future: Future<Output = Result<(), Self::Error>> + Send;

    fn handle(self) -> Self::Future;
}

pub fn server<L: Listener>(listener: L) -> Server<L> {
    Server { listener }
}

pub struct Server<L> {
    listener: L,
}

impl<L: GracefulListener> Server<L>
where
    <L as GracefulListener>::Handler: 'static,
    <L as GracefulListener>::Error: 'static,
{
    pub fn graceful<S: Future<Output = ()>>(self, shutdown: S) -> GracefulServer<L, S> {
        GracefulServer::new(self.listener, shutdown)
    }

    pub fn graceful_ctrl_c(self) -> GracefulServer<L, impl Future<Output = ()>> {
        GracefulServer::new(self.listener, async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

impl<L: Listener> Server<L>
where
    <L as Listener>::Handler: 'static,
    <L as Listener>::Error: 'static,
{
    pub async fn listen(self) -> Result<(), L::Error> {
        let (tx, mut rx) = mpsc::channel(1);

        loop {
            let handler = select! {
                result = rx.recv() => Err(result.unwrap()),
                result = self.listener.accept() => result,
            }?;

            let tx = tx.clone();

            tokio::spawn(async move {
                if let Err(e) = handler.handle().await {
                    let _ = tx.send(e);
                }
            });
        }
    }
}
