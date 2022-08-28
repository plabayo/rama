use crate::error::Result;
use crate::tcp::{Handler, Server};

use std::{future::Future, pin::Pin, time::Duration};
use tokio::runtime::Builder;
use tokio_task_manager::{Task, TaskManager};

pub trait Application: Clone + Send + Sized + 'static {
    type Future: Future<Output = Result<()>> + Send + 'static;

    fn run(self, task: Task) -> Self::Future;
}

impl<H: Handler> Application for Server<'static, H> {
    type Future = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn run(self, task: Task) -> Self::Future {
        Box::pin(async move { self.serve(task).await })
    }
}

pub struct Runtime<A: Application> {
    application: A,
    num_workers: usize,
    thread_stack_size: usize,
    shutdown_wait_timeout: Duration,
}

impl<A: Application> Runtime<A> {
    pub fn new(application: A) -> Self {
        Self {
            application,
            num_workers: num_cpus::get(),
            thread_stack_size: 3145728,
            shutdown_wait_timeout: Duration::from_secs(30),
        }
    }

    pub fn num_workers(mut self, num_workers: usize) -> Self {
        self.num_workers = num_workers;
        self
    }

    pub fn thread_stack_size(mut self, thread_stack_size: usize) -> Self {
        self.thread_stack_size = thread_stack_size;
        self
    }

    pub fn shutdown_wait_timeout(mut self, shutdown_wait_timeout: Duration) -> Self {
        self.shutdown_wait_timeout = shutdown_wait_timeout;
        self
    }

    pub fn run(self) -> Result<()> {
        // build runtime
        let runtime = Builder::new_multi_thread()
            .worker_threads(self.num_workers)
            .thread_name("llama-runtime")
            .thread_stack_size(self.thread_stack_size)
            .enable_all()
            .build()?;

        let tm = TaskManager::new(self.shutdown_wait_timeout);
        let task = tm.task();

        runtime.block_on(async move {
            tokio::spawn(async move {
                if let Err(err) = self.application.run(task).await {
                    panic!("llama application exited with an error: {}", err);
                }
            });
            tm.shutdown_gracefully_on_ctrl_c().await;
        });

        Ok(())
    }
}
