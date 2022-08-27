use std::time::Duration;
use tokio::io;
use tokio::runtime::Builder;
use tokio_task_manager::{Task, TaskManager};

use llama::error::Result;
use llama::tcp::serve;

async fn handle<IO>(_task: Task, stream: IO) -> Result<()>
where
    IO: io::AsyncRead + io::AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = io::split(stream);
    io::copy(&mut reader, &mut writer).await?;
    Ok(())
}

pub fn main() -> Result<()> {
    // build runtime
    let runtime = Builder::new_multi_thread()
        .worker_threads(num_cpus::get())
        .thread_name("tcp-echo")
        .thread_stack_size(3145728)
        .enable_all()
        .build()?;

    let tm = TaskManager::new(Duration::from_secs(5));
    let task = tm.task();

    runtime.block_on(async move {
        tokio::spawn(async move {
            if let Err(err) = serve(task, handle, None).await {
                panic!("tcp-echo exited with an error: {}", err);
            }
        });
        tm.shutdown_gracefully_on_ctrl_c().await;
    });

    Ok(())
}
