use crate::socket::{AsSocketRef, SocketOptions};
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
};
use rama_utils::macros::define_inner_service_accessors;
use std::sync::Arc;

/// Apply connection-oriented [`SocketOptions`] before delegating a TCP stream.
///
/// This layer is suitable for accepted and connected streams. It deliberately
/// ignores addressing, multicast, reuse, and socket-creation options, which
/// must be configured before bind or connect.
#[derive(Debug, Clone)]
pub struct TcpStreamOptionsLayer {
    options: Arc<SocketOptions>,
}

impl TcpStreamOptionsLayer {
    /// Create a layer backed by the supplied socket options.
    #[must_use]
    pub fn new(options: impl Into<Arc<SocketOptions>>) -> Self {
        Self {
            options: options.into(),
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
    options: Arc<SocketOptions>,
}

impl<S> TcpStreamOptionsService<S> {
    /// Create a service that tunes each TCP stream before calling `inner`.
    #[must_use]
    pub fn new(inner: S, options: impl Into<Arc<SocketOptions>>) -> Self {
        Self {
            inner,
            options: options.into(),
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
        apply_tcp_stream_options(&self.options, &stream)
            .context("apply connected TCP stream options")?;
        self.inner.serve(stream).await.map_err(Into::into)
    }
}

fn apply_tcp_stream_options(
    options: &SocketOptions,
    stream: &impl AsSocketRef,
) -> std::io::Result<()> {
    let socket = stream.as_socket_ref();
    if let Some(keep_alive) = options.keep_alive {
        socket.set_keepalive(keep_alive)?;
    }
    if let Some(size) = options.recv_buffer_size {
        socket.set_recv_buffer_size(size)?;
    }
    if let Some(size) = options.send_buffer_size {
        socket.set_send_buffer_size(size)?;
    }
    if let Some(keep_alive) = options.tcp_keep_alive.clone() {
        socket.set_tcp_keepalive(&keep_alive.into_socket_keep_alive())?;
    }
    if let Some(no_delay) = options.tcp_no_delay {
        socket.set_tcp_nodelay(no_delay)?;
    }
    Ok(())
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
