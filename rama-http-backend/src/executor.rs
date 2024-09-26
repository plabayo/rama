//! tmp executor for http (while hyper is still third party)

use rama_core::rt::Executor;

#[derive(Default, Debug, Clone)]
/// Newtype to be able to implement Executor interface
/// from hyper
///
/// TODO: delete once http::core is hyper fork
pub struct HyperExecutor(pub(crate) Executor);

impl<F> hyper::rt::Executor<F> for HyperExecutor
where
    F: std::future::Future<Output: Send + 'static> + Send + 'static,
{
    fn execute(&self, future: F) {
        // Hyper... \_(ツ)_/
        #[allow(clippy::let_underscore_future)]
        let _ = self.0.spawn_task(future);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use hyper::rt::Executor as _;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn simple_execute() -> Result<(), Box<dyn std::error::Error>> {
        let (tx, rx) = oneshot::channel();
        let executor = HyperExecutor(Executor::new());
        executor.execute(async move {
            tx.send(()).unwrap();
        });
        rx.await.map_err(Into::into)
    }

    #[tokio::test]
    async fn graceful_execute() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let (tx, rx) = oneshot::channel();
        let shutdown = rama_core::graceful::Shutdown::new(async move {
            rx.await.unwrap();
        });

        {
            let executor = HyperExecutor(Executor::graceful(shutdown.guard()));
            let counter2 = counter.clone();
            executor.execute(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                counter2.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            });
        }

        tx.send(()).unwrap();
        shutdown
            .shutdown_with_limit(Duration::from_millis(500))
            .await
            .unwrap();

        assert_eq!(counter.load(std::sync::atomic::Ordering::Acquire), 1);
    }
}
