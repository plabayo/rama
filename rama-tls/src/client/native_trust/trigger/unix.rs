use rama_core::futures::Stream;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

/// Request a native trust refresh when the process receives a Unix signal.
pub struct UnixSignalTrigger(tokio::signal::unix::Signal);

impl UnixSignalTrigger {
    /// Register for SIGHUP on the current Tokio runtime. As with other Tokio
    /// signal listeners, registering replaces the process's default behavior
    /// for this signal, even after the listener is dropped.
    ///
    /// ```
    /// # async fn configure() -> std::io::Result<()> {
    /// use rama_tls::client::{TlsServerTrust, UnixSignalTrigger};
    ///
    /// let trust = TlsServerTrust::native_roots()
    ///     .with_reload_trigger(UnixSignalTrigger::sighup()?);
    /// # drop(trust);
    /// # Ok(())
    /// # }
    /// ```
    pub fn sighup() -> std::io::Result<Self> {
        Self::new(tokio::signal::unix::SignalKind::hangup())
    }

    /// Register for the specified Unix signal on the current Tokio runtime.
    ///
    /// The runtime must have I/O enabled.
    pub fn new(kind: tokio::signal::unix::SignalKind) -> std::io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(std::io::Error::other)?;
        tokio::signal::unix::signal(kind).map(Self)
    }
}

impl Stream for UnixSignalTrigger {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        self.0.poll_recv(cx)
    }
}
