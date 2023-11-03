use std::{
    io,
    net::{self, SocketAddr},
};

use tokio::net::{TcpListener as TokioTcpListener, ToSocketAddrs};

use super::TcpStream;

pub struct TcpListener {
    inner: TokioTcpListener,
}

impl TcpListener {
    /// Creates a new TcpListener, which will be bound to the specified address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<TcpListener> {
        let inner = TokioTcpListener::bind(addr).await?;
        Ok(TcpListener { inner })
    }

    /// Creates new `TcpListener` from a `std::net::TcpListener`.
    ///
    /// This function is intended to be used to wrap a TCP listener from the
    /// standard library in the Tokio equivalent.
    ///
    /// This API is typically paired with the `socket2` crate and the `Socket`
    /// type to build up and customize a listener before it's shipped off to the
    /// backing event loop. This allows configuration of options like
    /// `SO_REUSEPORT`, binding to multiple addresses, etc.
    ///
    /// # Notes
    ///
    /// The caller is responsible for ensuring that the listener is in
    /// non-blocking mode. Otherwise all I/O operations on the listener
    /// will block the thread, which will cause unexpected behavior.
    /// Non-blocking mode can be set using [`set_nonblocking`].
    ///
    /// [`set_nonblocking`]: std::net::TcpListener::set_nonblocking
    pub fn from_std(listener: net::TcpListener) -> io::Result<TcpListener> {
        let inner = TokioTcpListener::from_std(listener)?;
        Ok(TcpListener { inner })
    }

    /// Returns the local address that this listener is bound to.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out
    /// which port was actually bound.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see [`set_ttl`].
    ///
    /// [`set_ttl`]: method@Self::set_ttl
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Serve connections from this listener with the given service.
    ///
    /// This method will block the current listener for each incoming connection,
    /// the underlying service can choose to spawn a task to handle the accepted stream.
    pub async fn serve<S, E>(self, mut service: S) -> TcpServeResult<E>
    where
        S: tower_async_service::Service<TcpStream, Response = (), Error = E>,
    {
        loop {
            let (stream, _) = self.inner.accept().await?;
            let stream = TcpStream::new(stream);
            service.call(stream).await.map_err(TcpServeError::Service)?;
        }
    }
}

pub type TcpServeResult<E> = Result<(), TcpServeError<E>>;

#[derive(Debug)]
pub enum TcpServeError<E> {
    Io(io::Error),
    Service(E),
}

impl<E> From<io::Error> for TcpServeError<E> {
    fn from(e: io::Error) -> Self {
        TcpServeError::Io(e)
    }
}

impl<E> std::fmt::Display for TcpServeError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpServeError::Io(e) => write!(f, "IO error: {}", e),
            TcpServeError::Service(e) => write!(f, "Service error: {}", e),
        }
    }
}

impl<E> std::error::Error for TcpServeError<E> where E: std::error::Error {}
