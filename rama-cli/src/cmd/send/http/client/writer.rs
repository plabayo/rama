use std::sync::Arc;

use rama::{
    combinators::Either,
    error::{BoxError, ErrorContext as _},
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncWriteExt as _, Stdout},
    sync::Mutex,
};

use super::SendCommand;

#[derive(Debug, Clone)]
pub(super) struct Writer {
    inner: Arc<Mutex<Either<File, Stdout>>>,
}

impl Writer {
    pub(super) async fn write_bytes(&self, b: &[u8]) -> std::io::Result<()> {
        let mut writer = self.inner.lock().await;
        writer.write_all(b).await?;
        writer.flush().await
    }

    /// Write a chunk without flushing; pair with [`Writer::flush`] to
    /// stream a response body without buffering it all in memory.
    pub(super) async fn write_chunk(&self, b: &[u8]) -> std::io::Result<()> {
        self.inner.lock().await.write_all(b).await
    }

    pub(super) async fn flush(&self) -> std::io::Result<()> {
        self.inner.lock().await.flush().await
    }
}

pub(super) async fn try_new(cfg: &SendCommand) -> Result<Writer, BoxError> {
    let writer = if let Some(path) = cfg.output.as_deref() {
        Either::A(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .context("open file for writing")?,
        )
    } else {
        Either::B(tokio::io::stdout())
    };

    Ok(Writer {
        inner: Arc::new(Mutex::new(writer)),
    })
}
