use std::convert::Infallible;

use rama_core::{
    Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsMut, ExtensionsRef},
    rt::Executor,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, duplex};

use crate::{address::SocketAddress, client::EstablishedClientConnection, stream::Socket};

#[derive(Debug, Clone)]
/// Mock connector can be used in tests to simulate connectors so we can test client and servers
/// without opening actuall connections
pub struct MockConnectorService<S> {
    create_server: S,
    max_buffer_size: usize,
    executor: Option<Executor>,
}

impl<S> MockConnectorService<S> {
    pub fn new(create_server: S) -> Self {
        Self {
            create_server,
            max_buffer_size: 1024,
            executor: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set `max_buffer_size` that will be used when creating DuplexStream
        pub fn max_buffer_size(mut self, size: usize) -> Self {
            self.max_buffer_size = size;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set `Executor` used for child tasks.
        pub fn executor(mut self, executor: Option<Executor>) -> Self {
            self.executor = executor;
            self
        }
    }
}

impl<S, Input, Server> Service<Input> for MockConnectorService<S>
where
    S: Fn() -> Server + Send + Sync + 'static,
    Server: Service<MockSocket, Error: Into<BoxError>>,
    Input: Send + 'static,
{
    type Error = Infallible;
    type Output = EstablishedClientConnection<MockSocket, Input>;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let (client, server) = duplex(self.max_buffer_size);
        let client_socket = MockSocket::new(client);
        let server_socket = MockSocket::new(server);

        let server = (self.create_server)();

        self.executor
            .clone()
            .unwrap_or_default()
            .into_spawn_task(async move {
                if let Err(err) = server.serve(server_socket).await {
                    panic!("created mock server failed: {}", err.into())
                }
            });

        Ok(EstablishedClientConnection {
            input,
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
    fn local_addr(&self) -> std::io::Result<SocketAddress> {
        Ok(SocketAddress::local_ipv4(0))
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddress> {
        Ok(SocketAddress::local_ipv4(0))
    }
}
