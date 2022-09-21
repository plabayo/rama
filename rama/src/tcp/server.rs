use crate::error::Result;
use tokio::net::TcpListener;
use tokio::task;
use tokio_task_manager::Task;
use tracing::{debug, error};

use super::TcpService;

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:4040";

#[derive(Clone)]
pub struct Server<'a, S>
where
    S: TcpService + Send + Clone + 'static,
{
    service: S,
    listen_addr: Option<&'a str>,
}

impl<'a, S> Server<'a, S>
where
    S: TcpService + Send + Clone + 'static,
    S::Future: Send,
{
    pub fn new(service: S) -> Self {
        Self {
            service,
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
            let mut service = self.service.clone();

            task::spawn(async move {
                let _ = task;
                if let Err(err) = service.call(socket).await {
                    error!("tcp stream handle error = {:#}", err.into());
                }
            });
        }
    }
}
