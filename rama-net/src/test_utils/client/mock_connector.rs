use std::{convert::Infallible, fmt, net::Ipv4Addr};

use rama_core::{
    Service,
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, duplex};

use crate::{client::EstablishedClientConnection, stream::Socket};

/// Mock connector can be used in tests to simulate connectors so we can test client and servers
/// without opening actuall connections
pub struct MockConnectorService<S> {
    create_server: S,
    max_buffer_size: usize,
}

impl<S: fmt::Debug> fmt::Debug for MockConnectorService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockConnectorService")
            .field("create_server", &self.create_server)
            .finish()
    }
}

impl<S> MockConnectorService<S> {
    pub fn new(create_server: S) -> Self {
        Self {
            create_server,
            max_buffer_size: 1024,
        }
    }

    /// Set `max_buffer_size` that will be used when creating DuplexStream
    pub fn set_max_buffer_size(&mut self, size: usize) -> &mut Self {
        self.max_buffer_size = size;
        self
    }

    /// [`MockConnectorService`] with `max_buffer_size` that will be used when creating DuplexStream
    #[must_use]
    pub fn with_max_buffer_size(self, size: usize) -> Self {
        Self {
            max_buffer_size: size,
            ..self
        }
    }
}

impl<S, Request, Error, Server> Service<Request> for MockConnectorService<S>
where
    S: Fn() -> Server + Send + Sync + 'static,
    Server: Service<MockSocket, Error = Error>,
    Request: Send + 'static,
    Error: std::fmt::Debug + 'static,
{
    type Error = Infallible;
    type Response = EstablishedClientConnection<MockSocket, Request>;

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        let (client, server) = duplex(self.max_buffer_size);
        let client_socket = MockSocket::new(client);
        let server_socket = MockSocket::new(server);

        let server = (self.create_server)();

        tokio::spawn(async move {
            server.serve(server_socket).await.unwrap();
        });

        Ok(EstablishedClientConnection {
            req,
            conn: client_socket,
        })
    }
}

#[derive(Debug)]
pub struct MockSocket {
    stream: DuplexStream,
    extensions: Extensions,
}

impl MockSocket {
    #[must_use]
    pub fn new(stream: DuplexStream) -> Self {
        Self {
            stream,
            extensions: Extensions::new(),
        }
    }
}

impl ExtensionsRef for MockSocket {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl ExtensionsMut for MockSocket {
    fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }
}

#[warn(clippy::missing_trait_methods)]
impl AsyncRead for MockSocket {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

#[warn(clippy::missing_trait_methods)]
impl AsyncWrite for MockSocket {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }
}

impl Socket for MockSocket {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            0,
        )))
    }

    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            0,
        )))
    }
}
