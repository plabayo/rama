use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use rama_core::futures::Stream;
use tokio::{
    runtime::Handle,
    signal::unix::{Signal, SignalKind, signal},
};

/// Request a native trust refresh when the process receives a Unix signal.
pub struct UnixSignalTrigger(Signal);

impl UnixSignalTrigger {
    /// Register for SIGHUP on the current Tokio runtime. As with other Tokio
    /// signal listeners, registering replaces the process's default behavior
    /// for this signal, even after the listener is dropped.
    /// Pass the resulting trigger to the trust policy’s reload configuration.
    pub fn sighup() -> io::Result<Self> {
        Self::new(SignalKind::hangup())
    }

    /// Register for the specified Unix signal on the current Tokio runtime.
    ///
    /// The runtime must have I/O enabled.
    pub fn new(kind: SignalKind) -> io::Result<Self> {
        Handle::try_current().map_err(io::Error::other)?;
        signal(kind).map(Self)
    }
}

impl Stream for UnixSignalTrigger {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<()>> {
        self.0.poll_recv(cx)
    }
}
