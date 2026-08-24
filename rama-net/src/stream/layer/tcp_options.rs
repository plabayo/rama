use crate::socket::{AsSocketRef, SocketOptions, opts::TcpKeepAlive};
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
};
use rama_utils::macros::define_inner_service_accessors;
use std::sync::Arc;

/// Options that are meaningful on an accepted or connected TCP stream.
///
/// Addressing, multicast, reuse, transparent-proxy, and other socket-creation
/// fields deliberately do not exist here, so callers cannot mistake silently
/// ignored [`SocketOptions`] fields for applied settings.
#[derive(Debug, Clone, Default)]
pub struct TcpStreamOptions {
    pub keep_alive: Option<bool>,
    pub recv_buffer_size: Option<usize>,
    pub send_buffer_size: Option<usize>,
    pub tcp_keep_alive: Option<TcpKeepAlive>,
    pub tcp_no_delay: Option<bool>,
}

impl TcpStreamOptions {
    /// Apply these options to an accepted or connected TCP stream.
    pub fn try_apply(&self, stream: &impl AsSocketRef) -> std::io::Result<()> {
        let socket = stream.as_socket_ref();
        if let Some(keep_alive) = self.keep_alive {
            socket.set_keepalive(keep_alive)?;
        }
        if let Some(size) = self.recv_buffer_size {
            socket.set_recv_buffer_size(size)?;
        }
        if let Some(size) = self.send_buffer_size {
            socket.set_send_buffer_size(size)?;
        }
        if let Some(keep_alive) = self.tcp_keep_alive.clone() {
            socket.set_tcp_keepalive(&keep_alive.into_socket_keep_alive())?;
        }
        if let Some(no_delay) = self.tcp_no_delay {
            socket.set_tcp_nodelay(no_delay)?;
        }
        Ok(())
    }
}

impl From<&SocketOptions> for TcpStreamOptions {
    fn from(options: &SocketOptions) -> Self {
        Self {
            keep_alive: options.keep_alive,
            recv_buffer_size: options.recv_buffer_size,
            send_buffer_size: options.send_buffer_size,
            tcp_keep_alive: options.tcp_keep_alive.clone(),
            tcp_no_delay: options.tcp_no_delay,
        }
    }
}

impl From<SocketOptions> for TcpStreamOptions {
    fn from(options: SocketOptions) -> Self {
        Self::from(&options)
    }
}

impl From<Arc<SocketOptions>> for TcpStreamOptions {
    fn from(options: Arc<SocketOptions>) -> Self {
        Self::from(options.as_ref())
    }
}

/// Apply connected [`TcpStreamOptions`] before delegating a TCP stream.
///
/// This layer is suitable for accepted and connected streams. It deliberately
/// exposes only settings that can be applied at this point in the lifecycle.
#[derive(Debug, Clone)]
pub struct TcpStreamOptionsLayer {
    options: Arc<TcpStreamOptions>,
}

impl TcpStreamOptionsLayer {
    /// Create a layer backed by the supplied socket options.
    #[must_use]
    pub fn new(options: impl Into<TcpStreamOptions>) -> Self {
        Self {
            options: Arc::new(options.into()),
        }
    }
}

impl<S> Layer<S> for TcpStreamOptionsLayer {
    type Service = TcpStreamOptionsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TcpStreamOptionsService {
            inner,
            options: self.options.clone(),
        }
    }
}

/// Service produced by [`TcpStreamOptionsLayer`].
#[derive(Debug, Clone)]
pub struct TcpStreamOptionsService<S> {
    inner: S,
    options: Arc<TcpStreamOptions>,
}

impl<S> TcpStreamOptionsService<S> {
    /// Create a service that tunes each TCP stream before calling `inner`.
    #[must_use]
    pub fn new(inner: S, options: impl Into<TcpStreamOptions>) -> Self {
        Self {
            inner,
            options: Arc::new(options.into()),
        }
    }

    define_inner_service_accessors!();
}

impl<S, IO> Service<IO> for TcpStreamOptionsService<S>
where
    S: Service<IO>,
    S::Error: Into<BoxError>,
    IO: AsSocketRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        self.options
            .try_apply(&stream)
            .context("apply connected TCP stream options")?;
        self.inner.serve(stream).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::service::service_fn;
    use std::convert::Infallible;

    #[tokio::test]
    async fn applies_options_before_dispatch_without_mutating_the_peer() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(tokio::net::TcpStream::connect(address));
        let (server, _) = listener.accept().await.unwrap();
        let client = client.await.unwrap().unwrap();
        let service = TcpStreamOptionsLayer::new(SocketOptions {
            keep_alive: Some(true),
            tcp_no_delay: Some(true),
            ..SocketOptions::default_tcp()
        })
        .into_layer(service_fn(|stream: tokio::net::TcpStream| async move {
            let socket = stream.as_socket_ref();
            Ok::<_, Infallible>((socket.keepalive().unwrap(), socket.tcp_nodelay().unwrap()))
        }));

        assert_eq!(service.serve(server).await.unwrap(), (true, true));
        assert!(!client.nodelay().unwrap());
    }
}
