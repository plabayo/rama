//! rama ws client

use std::time::Duration;

use rama::{
    Service,
    error::{BoxError, ErrorContext},
    graceful::{self, Shutdown},
    http::{Request, Response},
};
use tokio::sync::oneshot;

mod client;
mod tui;

pub(super) async fn run<C>(
    req: Request,
    client: C,
    protocols: Option<Vec<String>>,
) -> Result<(), BoxError>
where
    C: Service<Request, Response = Response, Error = BoxError>,
{
    let app = tui::App::new(req, client, protocols)
        .await
        .context("create tui app")?;

    let (tx, rx) = oneshot::channel();
    let (tx_final, rx_final) = oneshot::channel();

    let shutdown = Shutdown::new(async move {
        tokio::select! {
            _ = graceful::default_signal() => {
                let _ = tx_final.send(Ok(()));
            }
            result = rx => {
                match result {
                    Ok(result) => {
                        let _ = tx_final.send(result);
                    }
                    Err(_) => {
                        let _ = tx_final.send(Ok(()));
                    }
                }
            }
        }
    });

    shutdown.spawn_task_fn(async move |guard| {
        let mut app = app;
        let result = app.run(guard).await.map_err(|err| err.into_boxed());
        let _ = tx.send(result);
    });

    let _ = shutdown.shutdown_with_limit(Duration::from_secs(1)).await;

    rx_final.await?
}
