use crate::http::RequestContext;
use crate::service::Service;
use crate::tcp::service::TcpConnector;
use crate::tls::rustls::verify::NoServerCertVerifier;
use crate::tls::rustls::{
    dep::pki_types,
    dep::rustls::{ClientConfig, RootCertStore},
    dep::tokio_rustls::{client::TlsStream, TlsConnector},
    dep::webpki_roots,
};
use crate::{http::Request, service::Context};
use pin_project_lite::pin_project;
use std::sync::{Arc, OnceLock};
use std::{fmt, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// The established connection to a server returned for the http client to be used.
pub struct EstablishedClientConnection<S, Body, State> {
    /// The [`Context`] of the [`Request`] for which a connection was established.
    pub ctx: Context<State>,
    /// The [`Request`] for which a connection was established.
    pub req: Request<Body>,
    /// The established [`ClientConnection`] to the server.
    pub conn: ClientConnection<S>,
}

impl<S: fmt::Debug, Body: fmt::Debug, State: fmt::Debug> fmt::Debug
    for EstablishedClientConnection<S, Body, State>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedClientConnection")
            .field("ctx", &self.ctx)
            .field("req", &self.req)
            .field("conn", &self.conn)
            .finish()
    }
}

impl<S: Clone, Body: Clone, State> Clone for EstablishedClientConnection<S, Body, State> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            req: self.req.clone(),
            conn: self.conn.clone(),
        }
    }
}

pin_project! {
    /// A connection to a server.
    pub struct ClientConnection<S> {
        // The R/W stream that can be used to communicate with the server.
        #[pin]
        stream: S,

        // The target address connected to.
        addr: SocketAddr,
    }
}

impl<S: fmt::Debug> fmt::Debug for ClientConnection<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConnection")
            .field("addr", &self.addr)
            .field("stream", &self.stream)
            .finish()
    }
}

impl<S: Clone> Clone for ClientConnection<S> {
    fn clone(&self) -> Self {
        Self {
            addr: self.addr,
            stream: self.stream.clone(),
        }
    }
}

impl<S> ClientConnection<S> {
    /// Create a new [`ClientConnection`] for the given target [`SocketAddr`] and stream.
    pub fn new(addr: SocketAddr, stream: S) -> Self {
        Self { addr, stream }
    }

    /// Get the target [`SocketAddr`] of this [`ClientConnection`].
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    /// Consume the [`ClientConnection`] and return the inner stream and target [`SocketAddr`].
    pub fn into_parts(self) -> (SocketAddr, S) {
        (self.addr, self.stream)
    }

    /// Consume the [`ClientConnection`] and return the inner stream.
    pub fn into_stream(self) -> S {
        self.stream
    }
}

impl<S> AsyncRead for ClientConnection<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().stream.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for ClientConnection<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.project().stream.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().stream.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().stream.poll_shutdown(cx)
    }
}

pin_project! {
    #[derive(Debug)]
    /// Default [`Stream`] used by the default [`HttpClient`] as
    /// the [`EstablishedClientConnection`] stream.
    ///
    /// This stream can be either a plain TCP stream or a secure TLS stream.
    ///
    /// [`Stream`]: crate::stream::Stream
    /// [`HttpClient`]: crate::http::client::HttpClient
    pub struct DefaultClientStream {
        #[pin]
        stream: InnerClientStream,
    }
}

pin_project! {
    #[derive(Debug)]
    #[project = InnerClientStreamProj]
    enum InnerClientStream {
        Plain { #[pin] pinned: TcpStream },
        Secure { #[pin] pinned: TlsStream<TcpStream> },
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Default connector [`Service`] used by the default [`HttpClient`].
///
/// [`HttpClient`]: crate::http::client::HttpClient
pub struct DefaultClientConnector;

impl DefaultClientConnector {
    /// Create a new [`DefaultClientConnector`].
    pub fn new() -> Self {
        Self
    }
}

impl Default for DefaultClientConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn default_tls_client_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut root_storage = RootCertStore::empty();
            root_storage.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = ClientConfig::builder()
                .with_root_certificates(root_storage)
                .with_no_client_auth();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoServerCertVerifier::default()));
            Arc::new(config)
        })
        .clone()
}

impl<State, Body> Service<State, Request<Body>> for DefaultClientConnector
where
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = EstablishedClientConnection<DefaultClientStream, Body, State>;
    type Error = std::io::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { mut ctx, req, conn } =
            TcpConnector::default().serve(ctx, req).await?;

        let (addr, stream) = conn.into_parts();
        let request_ctx = ctx.get_or_insert_with(|| RequestContext::new(&req));

        if !request_ctx.scheme.secure() {
            return Ok(EstablishedClientConnection {
                ctx,
                req,
                conn: ClientConnection::new(
                    addr,
                    DefaultClientStream {
                        stream: InnerClientStream::Plain { pinned: stream },
                    },
                ),
            });
        }

        let host = match request_ctx.host.as_deref() {
            Some(host) => host,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "missing http host",
                ))
            }
        };
        let domain = pki_types::ServerName::try_from(host)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid DNS Name"))?
            .to_owned();

        let config = match ctx.get::<Arc<ClientConfig>>() {
            Some(config) => config.clone(),
            None => default_tls_client_config(),
        };
        let connector = TlsConnector::from(config);
        let stream = TcpStream::connect(&addr).await?;

        let stream = connector.connect(domain, stream).await?;

        Ok(EstablishedClientConnection {
            ctx,
            req,
            conn: ClientConnection::new(
                addr,
                DefaultClientStream {
                    stream: InnerClientStream::Secure { pinned: stream },
                },
            ),
        })
    }
}

impl AsyncRead for DefaultClientStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project().stream.project() {
            InnerClientStreamProj::Plain { ref mut pinned } => pinned.as_mut().poll_read(cx, buf),
            InnerClientStreamProj::Secure { ref mut pinned } => pinned.as_mut().poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for DefaultClientStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.project().stream.project() {
            InnerClientStreamProj::Plain { ref mut pinned } => pinned.as_mut().poll_write(cx, buf),
            InnerClientStreamProj::Secure { ref mut pinned } => pinned.as_mut().poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project().stream.project() {
            InnerClientStreamProj::Plain { ref mut pinned } => pinned.as_mut().poll_flush(cx),
            InnerClientStreamProj::Secure { ref mut pinned } => pinned.as_mut().poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project().stream.project() {
            InnerClientStreamProj::Plain { ref mut pinned } => pinned.as_mut().poll_shutdown(cx),
            InnerClientStreamProj::Secure { ref mut pinned } => pinned.as_mut().poll_shutdown(cx),
        }
    }
}
