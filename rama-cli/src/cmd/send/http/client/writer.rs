use std::sync::Arc;

use rama::{
    combinators::Either,
    error::{ErrorContext as _, OpaqueError},
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
        self.inner.lock().await.write_all(b).await
    }
}

pub(super) async fn new(cfg: &SendCommand) -> Result<Writer, OpaqueError> {
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
