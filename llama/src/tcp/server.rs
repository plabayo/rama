use crate::error::Result;

use std::future::Future;
use std::pin::Pin;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::task;
use tokio_task_manager::Task;
use tracing::{debug, error};

#[derive(Debug)]
pub struct Options<'a> {
    pub listen_addr: Option<&'a str>,
}

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:4040";

impl<'a> Default for Options<'a> {
    fn default() -> Self {
        Self {
            listen_addr: Some(DEFAULT_LISTEN_ADDR),
        }
    }
}

// TODO: how do common Http frameworks deal with handlers blocking exit,
// without requiring to expose something like a task?!
//
// asking as we probably want to implement the same thing here...

pub trait Handler<IO>: Clone + Send + Sized + 'static
where
    IO: io::AsyncRead + io::AsyncWrite + Unpin,
{
    type Future: Future<Output = Result<()>> + Send + 'static;

    fn call(self, task: Task, stream: IO) -> Self::Future;
}

impl<F, Fut, IO> Handler<IO> for F
where
    F: FnOnce(Task, IO) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<()>> + Send,
    IO: io::AsyncRead + io::AsyncWrite + Unpin + Send + 'static,
{
    type Future = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn call(self, task: Task, stream: IO) -> Self::Future {
        Box::pin(async move { self(task, stream).await })
    }
}

pub async fn serve<'a, H>(mut task: Task, handler: H, opt: Option<Options<'a>>) -> Result<()>
where
    H: Handler<TcpStream>,
{
    let opt = opt.unwrap_or_default();
    let listen_addr = opt.listen_addr.unwrap_or(DEFAULT_LISTEN_ADDR);

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
        let handler = handler.clone();

        task::spawn(async move {
            if let Err(err) = handler.call(task, socket).await {
                error!("tcp stream handle error = {:#}", err);
            }
        });
    }
}
