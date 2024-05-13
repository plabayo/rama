use crate::utils::graceful::ShutdownGuard;

/// Future executor that utilises `tokio` threads.
#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct Executor {
    guard: Option<ShutdownGuard>,
}

impl Executor {
    /// Create a new [`Executor`].
    pub fn new() -> Self {
        Self { guard: None }
    }

    /// Create a new [`Executor`] with the given shutdown guard,
    ///
    /// This will spawn tasks that are awaited gracefully
    /// in case the shutdown guard is triggered.
    pub fn graceful(guard: ShutdownGuard) -> Self {
        Self { guard: Some(guard) }
    }

    /// Spawn a future on the current executor,
    /// this is spawned gracefully in case a shutdown guard has been registered.
    pub fn spawn_task<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        match &self.guard {
            Some(guard) => guard.spawn_task(future),
            None => tokio::spawn(future),
        }
    }
}

impl Executor {
    /// Get a reference to the shutdown guard,
    /// if and only if the executor was created with [`Self::graceful`].
    pub(crate) fn guard(&self) -> Option<&ShutdownGuard> {
        self.guard.as_ref()
    }
}

impl<F> hyper::rt::Executor<F> for Executor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, future: F) {
        // Hyper... \_(ツ)_/
        #[allow(clippy::let_underscore_future)]
        let _ = self.spawn_task(future);
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
        let executor = Executor::new();
        executor.execute(async move {
            tx.send(()).unwrap();
        });
        rx.await.map_err(Into::into)
    }

    #[tokio::test]
    async fn graceful_execute() {
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let (tx, rx) = oneshot::channel();
        let shutdown = crate::utils::graceful::Shutdown::new(async move {
            rx.await.unwrap();
        });

        {
            let executor = Executor::graceful(shutdown.guard());
            let counter2 = counter.clone();
            executor.execute(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                counter2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        }

        tx.send(()).unwrap();
        shutdown
            .shutdown_with_limit(Duration::from_millis(500))
            .await
            .unwrap();

        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
