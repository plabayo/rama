use rama_core::Service;
use rama_core::extensions::ExtensionsMut;
use rama_core::rt::Executor;
use rama_core::telemetry::tracing::{self, Instrument};
use std::io;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::RawFd;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::Path;
use std::path::PathBuf;
use std::pin::pin;
use tokio::net::UnixListener as TokioUnixListener;
use tokio::net::unix::SocketAddr;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use rama_net::socket::SocketOptions;

use crate::UnixSocketAddress;
use crate::UnixSocketInfo;
use crate::UnixStream;

#[derive(Clone, Debug)]
/// Builder for `UnixListener`.
pub struct UnixListenerBuilder {
    exec: Executor,
}

impl UnixListenerBuilder {
    /// Create a new `UnixListenerBuilder`.
    #[must_use]
    pub fn new(exec: Executor) -> Self {
        Self { exec }
    }

    pub fn default_with_executor(exec: Executor) -> Self {
        Self::new(exec)
    }
}

impl Default for UnixListenerBuilder {
    fn default() -> Self {
        Self::default_with_executor(Executor::default())
    }
}

impl UnixListenerBuilder {
    /// Creates a new [`UnixListener`], which will be bound to the specified path.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_path(self, path: impl AsRef<Path>) -> Result<UnixListener, io::Error> {
        let path = path.as_ref();

        if tokio::fs::try_exists(path).await.unwrap_or_default() {
            tracing::trace!(file.path = ?path, "try delete existing UNIX socket path");
            // some errors might lead to false positives (e.g. no permissions),
            // this is ok as this is a best-effort cleanup to anyway only be of use
            // if we have permission to do so
            tokio::fs::remove_file(path).await?;
        }

        let inner = TokioUnixListener::bind(path)?;
        let cleanup = Some(UnixSocketCleanup {
            path: path.to_owned(),
        });

        Ok(UnixListener {
            inner,
            exec: self.exec,
            _cleanup: cleanup,
        })
    }

    /// Creates a new [`UnixListener`], which will be bound to the specified socket.
    ///
    /// The returned listener is ready for accepting connections.
    pub fn bind_socket(
        self,
        socket: rama_net::socket::core::Socket,
    ) -> Result<UnixListener, io::Error> {
        let std_listener: StdUnixListener = socket.into();
        std_listener.set_nonblocking(true)?;
        let inner = TokioUnixListener::from_std(std_listener)?;
        Ok(UnixListener {
            inner,
            exec: self.exec,
            _cleanup: None,
        })
    }

    /// Creates a new TcpListener, which will be bound to the specified interface.
    ///
    /// The returned listener is ready for accepting connections.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub async fn bind_socket_opts(
        self,
        opts: SocketOptions,
    ) -> Result<UnixListener, rama_core::error::BoxError> {
        let socket = tokio::task::spawn_blocking(move || opts.try_build_socket()).await??;
        Ok(self.bind_socket(socket)?)
    }
}

#[derive(Debug)]
/// A Unix (domain) socket server, listening for incoming connections once served
/// using one of the `serve` methods such as [`UnixListener::serve`].
///
/// Note that the underlying socket (file) is only cleaned up
/// by this listener's [`Drop`] implementation if the listener
/// was created using the `bind_path` constructor. Otherwise
/// it is assumed that the creator of this listener is in charge
/// of that cleanup.
pub struct UnixListener {
    inner: TokioUnixListener,
    exec: Executor,
    _cleanup: Option<UnixSocketCleanup>,
}

impl UnixListener {
    #[inline]
    /// Create a new [`UnixListenerBuilder`] without a state,
    /// which can be used to configure a [`UnixListener`].
    #[must_use]
    pub fn build(exec: Executor) -> UnixListenerBuilder {
        UnixListenerBuilder::new(exec)
    }

    #[inline]
    /// Creates a new [`UnixListener`], which will be bound to the specified path.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_path(path: impl AsRef<Path>, exec: Executor) -> Result<Self, io::Error> {
        UnixListenerBuilder::new(exec).bind_path(path).await
    }

    #[inline]
    /// Creates a new [`UnixListener`], which will be bound to the specified socket.
    ///
    /// The returned listener is ready for accepting connections.
    pub fn bind_socket(
        socket: rama_net::socket::core::Socket,
        exec: Executor,
    ) -> Result<Self, io::Error> {
        UnixListenerBuilder::new(exec).bind_socket(socket)
    }

    #[inline]
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    /// Creates a new TcpListener, which will be bound to the specified (interface) device name.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_socket_opts(
        opts: SocketOptions,
        exec: Executor,
    ) -> Result<Self, rama_core::error::BoxError> {
        UnixListenerBuilder::new(exec).bind_socket_opts(opts).await
    }
}

impl UnixListener {
    /// Returns the local address that this listener is bound to.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out
    /// which port was actually bound.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn from_tokio_unix_listener(listener: TokioUnixListener, exec: Executor) -> Self {
        Self {
            inner: listener,
            exec,
            _cleanup: None,
        }
    }

    pub fn try_from_socket(
        socket: rama_net::socket::core::Socket,
        exec: Executor,
    ) -> Result<Self, io::Error> {
        Self::bind_socket(socket, exec)
    }

    pub fn try_from_std_unix_listener(
        listener: StdUnixListener,
        exec: Executor,
    ) -> Result<Self, io::Error> {
        listener.set_nonblocking(true)?;
        let inner = TokioUnixListener::from_std(listener)?;

        Ok(Self {
            inner,
            exec,
            _cleanup: None,
        })
    }
}

impl AsRawFd for UnixListener {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl AsFd for UnixListener {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl UnixListener {
    /// Accept a single connection from this listener,
    /// what you can do with whatever you want.
    #[inline]
    pub async fn accept(&self) -> io::Result<(UnixStream, UnixSocketAddress)> {
        let (stream, addr) = self.inner.accept().await?;
        Ok((stream.into(), addr.into()))
    }

    /// Serve connections from this listener with the given service.
    ///
    /// This listener will spawn a task in which the inner service will
    /// handle the incomming connection. Connections will be served
    /// gracefully if the [`UnixListener`] is configured with a graceful [`Executor`].
    pub async fn serve<S>(self, service: S)
    where
        S: Service<UnixStream> + Clone,
    {
        let guard = self.exec.guard().cloned();
        let cancelled_fut = async {
            if let Some(guard) = guard {
                guard.cancelled().await;
            } else {
                // If there is no executor/guard, we never trigger shutdown this way
                std::future::pending::<()>().await;
            }
        };
        let mut cancelled_fut = pin!(cancelled_fut);

        loop {
            tokio::select! {
                _ = cancelled_fut.as_mut() => {
                    tracing::trace!("signal received: initiate graceful shutdown");
                    break;
                }
                result = self.inner.accept() => {
                    match result {
                        Ok((socket, peer_addr)) => {
                            let service = service.clone();

                            let peer_addr: UnixSocketAddress = peer_addr.into();
                            let local_addr: Option<UnixSocketAddress> = socket.local_addr().ok().map(Into::into);

                            let serve_span = tracing::trace_root_span!(
                                "unix::serve_graceful",
                                otel.kind = "server",
                                network.local.address = ?local_addr,
                                network.peer.address = ?peer_addr,
                                network.protocol.name = "uds",
                            );

                            let mut socket = UnixStream::new(socket);
                            socket.extensions_mut().insert(UnixSocketInfo::new(local_addr, peer_addr));

                            self.exec.spawn_task(async move {
                                let _ = service.serve(socket).await;
                            }.instrument(serve_span));
                        }
                        Err(err) => {
                            handle_accept_err(err).await;
                        }
                    }
                }
            }
        }
    }
}

async fn handle_accept_err(err: io::Error) {
    if rama_net::conn::is_connection_error(&err) {
        tracing::trace!("unix accept error: connect error: {err:?}");
    } else {
        tracing::error!("unix accept error: {err:?}");
    }
}

#[derive(Debug)]
struct UnixSocketCleanup {
    path: PathBuf,
}

impl Drop for UnixSocketCleanup {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.path) {
            tracing::debug!(file.path = ?self.path, "failed to remove unix listener's file socket {err:?}");
        }
    }
}
