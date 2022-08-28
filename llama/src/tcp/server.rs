use crate::error::Result;

use std::future::Future;
use std::pin::Pin;
use tokio::net::{TcpListener, TcpStream};
use tokio::task;
use tokio_task_manager::Task;
use tracing::{debug, error};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:4040";

pub trait Handler: Clone + Send + Sized + 'static {
    type Future: Future<Output = Result<()>> + Send + 'static;

    fn call(self, task: Task, stream: TcpStream) -> Self::Future;
}

impl<F, Fut> Handler for F
where
    F: FnOnce(Task, TcpStream) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<()>> + Send,
{
    type Future = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn call(self, task: Task, stream: TcpStream) -> Self::Future {
        Box::pin(async move { self(task, stream).await })
    }
}

#[derive(Clone)]
pub struct Server<'a, H: Handler> {
    handler: H,
    listen_addr: Option<&'a str>,
}

impl<'a, H: Handler> Server<'a, H> {
    pub fn new(handler: H) -> Self {
        Self {
            handler,
            listen_addr: None,
        }
    }

    pub fn listen_addr(mut self, listen_addr: &'a str) -> Self {
        self.listen_addr = Some(listen_addr);
        self
    }

    pub async fn serve(self, mut task: Task) -> Result<()> {
        let listen_addr = self.listen_addr.unwrap_or(DEFAULT_LISTEN_ADDR);
        let listener = TcpListener::bind(listen_addr).await?;

        debug!("starting TCP accept loop...");
        loop {
            let accept_result = tokio::select! {
                r = listener.accept() => r,
                _ = task.wait() => {
                    return Ok(());
                }
            };
            let socket = match accept_result {
                Ok((socket, _)) => socket,
                Err(err) => {
                    error!("TCP loop: accept result: {}", err);
                    continue;
                }
            };

            let task = task.clone();
            let handler = self.handler.clone();

            task::spawn(async move {
                if let Err(err) = handler.call(task, socket).await {
                    error!("tcp stream handle error = {:#}", err);
                }
            });
        }
    }
}
