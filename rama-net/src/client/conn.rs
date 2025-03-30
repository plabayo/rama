use crate::stream::Socket;
use rama_core::{Context, Service, error::BoxError};
use std::{convert::Infallible, fmt, net::Ipv4Addr};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, duplex};

/// The established connection to a server returned for the http client to be used.
pub struct EstablishedClientConnection<S, State, Request> {
    /// The [`Context`] of the `Request` for which a connection was established.
    pub ctx: Context<State>,
    /// The `Request` for which a connection was established.
    pub req: Request,
    /// The established connection stream/service/... to the server.
    pub conn: S,
}

impl<S: fmt::Debug, State: fmt::Debug, Request: fmt::Debug> fmt::Debug
    for EstablishedClientConnection<S, State, Request>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedClientConnection")
            .field("ctx", &self.ctx)
            .field("req", &self.req)
            .field("conn", &self.conn)
            .finish()
    }
}

impl<S: Clone, State: Clone, Request: Clone> Clone
    for EstablishedClientConnection<S, State, Request>
{
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            req: self.req.clone(),
            conn: self.conn.clone(),
        }
    }
}

/// Glue trait that is used as the Connector trait bound for
/// clients establishing a connection on one layer or another.
///
/// Can also be manually implemented as an alternative [`Service`] trait,
/// but from a Rama POV it is mostly used for UX trait bounds.
pub trait ConnectorService<State, Request>: Send + Sync + 'static {
    /// Connection returned by the [`ConnectorService`]
    type Connection;
    /// Error returned in case of connection / setup failure
    type Error: Into<BoxError>;

    /// Establish a connection, which often involves some kind of handshake,
    /// or connection revival.
    fn connect(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, State, Request>, Self::Error>,
    > + Send
    + '_;
}

impl<S, State, Request, Connection> ConnectorService<State, Request> for S
where
    S: Service<
            State,
            Request,
            Response = EstablishedClientConnection<Connection, State, Request>,
            Error: Into<BoxError>,
        >,
{
    type Connection = Connection;
    type Error = S::Error;

    fn connect(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> impl Future<
        Output = Result<EstablishedClientConnection<Self::Connection, State, Request>, Self::Error>,
    > + Send
    + '_ {
        self.serve(ctx, req)
    }
}

/// Mock connector can be used in tests to simulate connectors so we can test client and servers
/// without opening actuall connections
pub struct MockConnectorService<S> {
    create_server: S,
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
        Self { create_server }
    }
}

impl<State, S, Request, Error, Server> Service<State, Request> for MockConnectorService<S>
where
    S: Fn() -> Server + Send + Sync + 'static,
    Server: Service<State, MockSocket, Error = Error>,
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
    Error: std::fmt::Debug + 'static,
{
    type Error = Infallible;
    type Response = EstablishedClientConnection<MockSocket, State, Request>;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let (client, server) = duplex(1024);
        let client_socket = MockSocket { stream: client };
        let server_socket = MockSocket { stream: server };

        let server = (self.create_server)();
        let server_ctx = ctx.clone();

        tokio::spawn(async move {
            server.serve(server_ctx, server_socket).await.unwrap();
        });

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: client_socket,
        })
    }
}

#[derive(Debug)]
pub struct MockSocket {
    stream: DuplexStream,
}

impl AsyncRead for MockSocket {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

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
