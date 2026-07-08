use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
pub struct ServerController {
    pub(super) shutdown: CancellationToken,
    pub(super) abort: CancellationToken,
}

impl ServerController {
    pub fn terminate(&self) {
        self.abort.cancel();
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    pub fn new() -> Self {
        Self::default()
    }
}
