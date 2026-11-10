use rama_core::Service;
use rama_core::extensions::ExtensionsRef;
use rama_core::graceful::WeakScope;
use rama_core::graceful::attach_scope;
use rama_core::telemetry::tracing::{self, Instrument};
use rama_net::conn::AcceptBackoff;
use std::io;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::os::fd::RawFd;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::{UnixDatagram, UnixListener as StdUnixListener};
use std::path::Path;
use std::path::PathBuf;
use std::pin::pin;
use tokio::net::UnixListener as TokioUnixListener;
use tokio::net::unix::SocketAddr;

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
use rama_net::socket::{SocketOptions, opts::Domain};

use crate::UnixSocketAddress;
use crate::UnixSocketInfo;
use crate::UnixStream;

#[derive(Clone, Debug)]
/// Builder for `UnixListener`.
pub struct UnixListenerBuilder {
    scope: WeakScope,
}

impl UnixListenerBuilder {
    /// Create a new `UnixListenerBuilder`.
    #[must_use]
    pub fn new(scope: impl Into<WeakScope>) -> Self {
        let scope = scope.into();
        Self { scope }
    }

    pub fn default_with_scope(scope: impl Into<WeakScope>) -> Self {
        let scope = scope.into();
        Self::new(scope)
    }
}

impl Default for UnixListenerBuilder {
    fn default() -> Self {
        Self::default_with_scope(WeakScope::detached())
    }
}

impl UnixListenerBuilder {
    /// Creates a new [`UnixListener`], which will be bound to the specified path.
    ///
    /// A socket file left at `path` by a listener that is gone is replaced. The bind fails with
    /// [`io::ErrorKind::AddrInUse`] while a listener still serves `path`, and with
    /// [`io::ErrorKind::AlreadyExists`] if `path` is anything but a socket (symlinks included),
    /// which is left untouched.
    ///
    /// The socket file is removed when the listener drops, unless it was replaced since.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_path(self, path: impl AsRef<Path>) -> Result<UnixListener, io::Error> {
        let path = path.as_ref();

        remove_stale_socket(path).await?;
        let inner = TokioUnixListener::bind(path)?;
        let cleanup = Some(UnixSocketCleanup::new(path)?);

        Ok(UnixListener {
            inner,
            scope: self.scope,
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
            scope: self.scope,
            _cleanup: None,
        })
    }

    /// Creates a new UnixListener, which will be bound to the specified interface.
    ///
    /// The returned listener is ready for accepting connections.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
    )]
    pub async fn bind_socket_opts(
        self,
        opts: SocketOptions,
    ) -> Result<UnixListener, rama_core::error::BoxError> {
        let socket = opts.try_build_socket(Domain::Unix)?;
        Ok(self.bind_socket(socket)?)
    }
}

#[derive(Debug)]
/// A Unix (domain) socket server, listening for incoming connections once served
/// using one of the `serve` methods such as [`UnixListener::serve`].
///
/// Note that the underlying socket (file) is only cleaned up
/// by this listener's [`Drop`] implementation if the listener
/// was created using the `bind_path` constructor, and only while
/// the path still refers to the socket it bound. Otherwise
/// it is assumed that the creator of this listener is in charge
/// of that cleanup.
pub struct UnixListener {
    inner: TokioUnixListener,
    scope: WeakScope,
    _cleanup: Option<UnixSocketCleanup>,
}

impl UnixListener {
    #[inline]
    /// Create a new [`UnixListenerBuilder`] without a state,
    /// which can be used to configure a [`UnixListener`].
    #[must_use]
    pub fn build(scope: impl Into<WeakScope>) -> UnixListenerBuilder {
        let scope = scope.into();
        UnixListenerBuilder::new(scope)
    }

    #[inline]
    /// Creates a new [`UnixListener`], which will be bound to the specified path.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_path(path: impl AsRef<Path>, scope: WeakScope) -> Result<Self, io::Error> {
        UnixListenerBuilder::new(scope).bind_path(path).await
    }

    #[inline]
    /// Creates a new [`UnixListener`], which will be bound to the specified socket.
    ///
    /// The returned listener is ready for accepting connections.
    pub fn bind_socket(
        socket: rama_net::socket::core::Socket,
        scope: impl Into<WeakScope>,
    ) -> Result<Self, io::Error> {
        let scope = scope.into();
        UnixListenerBuilder::new(scope).bind_socket(socket)
    }

    #[inline]
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(
        docsrs,
        doc(cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))
    )]
    /// Creates a new UnixListener, which will be bound to the specified (interface) device name.
    ///
    /// The returned listener is ready for accepting connections.
    pub async fn bind_socket_opts(
        opts: SocketOptions,
        scope: WeakScope,
    ) -> Result<Self, rama_core::error::BoxError> {
        UnixListenerBuilder::new(scope).bind_socket_opts(opts).await
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

    pub fn from_tokio_unix_listener(
        listener: TokioUnixListener,
        scope: impl Into<WeakScope>,
    ) -> Self {
        let scope = scope.into();
        Self {
            inner: listener,
            scope,
            _cleanup: None,
        }
    }

    pub fn try_from_socket(
        socket: rama_net::socket::core::Socket,
        scope: impl Into<WeakScope>,
    ) -> Result<Self, io::Error> {
        let scope = scope.into();
        Self::bind_socket(socket, scope)
    }

    pub fn try_from_std_unix_listener(
        listener: StdUnixListener,
        scope: impl Into<WeakScope>,
    ) -> Result<Self, io::Error> {
        let scope = scope.into();
        listener.set_nonblocking(true)?;
        let inner = TokioUnixListener::from_std(listener)?;

        Ok(Self {
            inner,
            scope,
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
    /// gracefully if the [`UnixListener`] is configured with a graceful [`WeakScope`].
    pub async fn serve<S>(self, service: S)
    where
        S: Service<UnixStream> + Clone,
    {
        // Serving holds the scope, so every connection accepted until the cancel is admitted.
        let Ok(scope) = self.scope.try_hold() else {
            tracing::debug!("scope closed: not serving");
            return;
        };
        let mut cancelled_fut = pin!(self.scope.cancelled());
        let mut accept_backoff = AcceptBackoff::new();

        loop {
            tokio::select! {
                _ = cancelled_fut.as_mut() => {
                    tracing::trace!("signal received: initiate graceful shutdown");
                    break;
                }
                result = self.inner.accept() => {
                    match result {
                        Ok((socket, peer_addr)) => {
                            accept_backoff.reset();
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

                            let socket = UnixStream::new(socket);
                            socket.extensions().insert(UnixSocketInfo::new(local_addr, peer_addr));
                            attach_scope(socket.extensions(), &scope);

                            // Ended at the hard phase, whatever the service does by then.
                            scope.spawn_task(async move {
                                _ = service.serve(socket).await;
                            }.instrument(serve_span));
                        }
                        Err(err) => match accept_backoff.on_error(&err) {
                            None => tracing::trace!("unix accept error: connection error: {err:?}"),
                            Some(delay) => {
                                // Running out of file descriptors keeps the listener readable, so retrying at once spins.
                                tracing::error!("unix accept error: {err:?}; pausing accept for {delay:?}");
                                tokio::select! {
                                    _ = cancelled_fut.as_mut() => {
                                        tracing::trace!("signal received: initiate graceful shutdown");
                                        break;
                                    }
                                    () = tokio::time::sleep(delay) => {}
                                }
                            }
                        },
                    }
                }
            }
        }
    }
}

/// Removes a socket file at `path` that no listener serves anymore.
async fn remove_stale_socket(path: &Path) -> io::Result<()> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unix socket path exists and is not a socket",
        ));
    }
    // A stream connect is refused by a live listener with a full backlog on BSDs;
    // a datagram connect is refused only when nothing is bound to the path.
    let probe = UnixDatagram::unbound()?;
    probe.set_nonblocking(true)?;
    match probe.connect(path) {
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            tracing::trace!(file.path = ?path, "remove stale unix socket file");
            match tokio::fs::remove_file(path).await {
                Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err),
                _ => Ok(()),
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "unix socket path is served by a live listener",
        )),
    }
}

/// Removes the socket file a listener bound, if it is still that file.
#[derive(Debug)]
struct UnixSocketCleanup {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl UnixSocketCleanup {
    fn new(path: &Path) -> io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        Ok(Self {
            path: path.to_owned(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        })
    }
}

impl Drop for UnixSocketCleanup {
    fn drop(&mut self) {
        // a listener bound to this path since then keeps its socket file
        let ours = std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.dev() == self.dev && metadata.ino() == self.ino);
        if !ours {
            return;
        }
        if let Err(err) = std::fs::remove_file(&self.path) {
            tracing::debug!(file.path = ?self.path, "failed to remove unix listener's file socket {err:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, time::Duration};

    use rama_core::{
        graceful::{Cause, Scope},
        service::service_fn,
    };
    use tokio::{sync::mpsc, time::timeout};

    use super::*;

    const LIMIT: Duration = Duration::from_secs(10);

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rama-unix-{name}-{}", std::process::id()));
        _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn bind_replaces_a_stale_socket_file() {
        let dir = temp_dir("stale");
        let path = dir.join("stale.sock");
        // std listeners leave their socket file behind
        drop(StdUnixListener::bind(&path).unwrap());
        assert!(path.exists());

        let listener = UnixListener::bind_path(&path, WeakScope::detached())
            .await
            .unwrap();
        tokio::net::UnixStream::connect(&path).await.unwrap();
        drop(listener);
        assert!(!path.exists());
        _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bind_refuses_a_path_a_live_listener_serves() {
        let dir = temp_dir("live");
        let path = dir.join("live.sock");
        let live = StdUnixListener::bind(&path).unwrap();
        let live_datagram_path = dir.join("live-datagram.sock");
        let _live_datagram = UnixDatagram::bind(&live_datagram_path).unwrap();

        for path in [&path, &live_datagram_path] {
            let err = UnixListener::bind_path(path, WeakScope::detached())
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{path:?}");
        }
        // the live listener still owns its path
        std::os::unix::net::UnixStream::connect(&path).unwrap();
        live.accept().unwrap();
        _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bind_leaves_other_files_untouched() {
        let dir = temp_dir("other");
        let file = dir.join("file.sock");
        std::fs::write(&file, "data").unwrap();
        let stale = dir.join("stale.sock");
        drop(StdUnixListener::bind(&stale).unwrap());
        let link = dir.join("link.sock");
        std::os::unix::fs::symlink(&stale, &link).unwrap();

        for path in [&file, &link, &dir] {
            let err = UnixListener::bind_path(path, WeakScope::detached())
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::AlreadyExists, "{path:?}");
        }
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "data");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bind_refuses_a_path_with_a_nul_byte() {
        // abstract names bind through `bind_socket`; a path cannot carry one
        let err = UnixListener::bind_path("\0rama", WeakScope::detached())
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn drop_keeps_a_socket_file_bound_since() {
        let dir = temp_dir("rebound");
        let path = dir.join("rebound.sock");
        let first = UnixListener::bind_path(&path, WeakScope::detached())
            .await
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        let second = StdUnixListener::bind(&path).unwrap();

        drop(first);
        std::os::unix::net::UnixStream::connect(&path).unwrap();
        second.accept().unwrap();
        _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_served_connection_ends_at_the_hard_phase() {
        let scope = Scope::new();
        let weak = scope.clone_weak();
        let dir = std::env::temp_dir().join(format!("rama-unix-hard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("served.sock");
        _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind_path(&path, scope.clone_weak())
            .await
            .unwrap();
        let (accepted, mut accepted_rx) = mpsc::unbounded_channel();
        let serving = tokio::spawn(listener.serve(service_fn(move |stream: UnixStream| {
            accepted.send(()).unwrap();
            async move {
                std::future::pending::<()>().await;
                drop(stream);
                Ok::<_, Infallible>(())
            }
        })));
        let _client = tokio::net::UnixStream::connect(&path).await.unwrap();
        accepted_rx.recv().await.unwrap();

        scope.cancel(Cause::Owner);
        timeout(LIMIT, serving).await.unwrap().unwrap();
        assert!(
            timeout(Duration::from_millis(100), weak.drained())
                .await
                .is_err(),
            "the served connection drains in the graceful phase"
        );
        scope.abort(Cause::Owner);
        drop(scope);
        timeout(LIMIT, weak.drained())
            .await
            .expect("the served task ends at the hard phase");
        _ = std::fs::remove_dir_all(&dir);
    }
}
