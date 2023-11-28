/// Future executor that is used to spawn futures in hyper services, such as h2 web services.
#[non_exhaustive]
#[derive(Default, Debug, Clone)]
pub struct GlobalExecutor;

impl<Fut> hyper::rt::Executor<Fut> for GlobalExecutor
where
    Fut: std::future::Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, fut: Fut) {
        crate::rt::spawn(fut);
    }
}

impl GlobalExecutor {
    /// Create new executor that relies on [`crate::rt::spawn`] to execute futures.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::GlobalExecutor;

    use crate::rt::sync::oneshot;
    use hyper::rt::Executor;

    #[crate::rt::test]
    async fn simple_execute() -> Result<(), Box<dyn std::error::Error>> {
        let (tx, rx) = oneshot::channel();
        let executor = GlobalExecutor::new();
        executor.execute(async move {
            tx.send(()).unwrap();
        });
        rx.await.map_err(Into::into)
    }
}
