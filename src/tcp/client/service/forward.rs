use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::{
    net::stream::Stream,
    service::{Context, Service},
    tcp::utils::is_connection_error,
};

/// [`Forwarder`] using [`Forwarder::dynamic`] requires this struct
/// to be present in the [`Context`].
#[derive(Debug, Clone)]
pub struct ForwardAddress {
    target: SocketAddr,
}

impl ForwardAddress {
    /// Create a new [`ForwardAddress`] for the given target [`SocketAddr`].
    pub fn new(target: SocketAddr) -> Self {
        Self { target }
    }
}

impl From<SocketAddr> for ForwardAddress {
    fn from(target: SocketAddr) -> Self {
        Self::new(target)
    }
}

#[derive(Debug, Clone)]
enum ForwarderKind {
    Static(SocketAddr),
    Dynamic,
}

/// A TCP forwarder.
#[derive(Debug, Clone)]
pub struct Forwarder {
    kind: ForwarderKind,
}

impl Forwarder {
    /// Create a new [`Forwarder::dynamic`] forwarder.
    pub fn new() -> Self {
        Self::dynamic()
    }

    /// Create a new static forwarder for the given target [`SocketAddr`]
    pub fn target(target: SocketAddr) -> Self {
        Self {
            kind: ForwarderKind::Static(target),
        }
    }

    /// Create a new dynamic forwarder.
    ///
    /// # Panics
    ///
    /// Panics if the [`Context`] does not contain a [`ForwardAddress`].
    pub fn dynamic() -> Self {
        Self {
            kind: ForwarderKind::Dynamic,
        }
    }
}

impl Default for Forwarder {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, T> Service<S, T> for Forwarder
where
    S: Send + Sync + 'static,
    T: Stream + Unpin,
{
    type Response = ();
    type Error = std::io::Error;

    async fn serve(&self, ctx: Context<S>, mut source: T) -> Result<Self::Response, Self::Error> {
        let mut target = match &self.kind {
            ForwarderKind::Static(target) => TcpStream::connect(target).await?,
            ForwarderKind::Dynamic => {
                let addr: &ForwardAddress = ctx.get().unwrap();
                TcpStream::connect(addr.target).await?
            }
        };

        match tokio::io::copy_bidirectional(&mut source, &mut target).await {
            Ok(_) => Ok(()),
            Err(err) => {
                if is_connection_error(&err) {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }
}
