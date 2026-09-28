//! Keep data that arrives right before a TCP reset.
//!
//! When a peer sends data and then resets the connection before the
//! application read that data, Windows discards it: the next read fails with
//! `WSAECONNRESET`, or `WSAECONNABORTED` after a send to a peer that already
//! closed. Linux, FreeBSD and macOS hand over the queued bytes first and only
//! then report the reset.
//!
//! Tokio on Windows waits for readiness and reads afterwards, so it never has
//! a read with a real buffer waiting on the socket. A server that replies and
//! resets right away can therefore lose its whole reply.
//!
//! [`PostedRecv`] closes that gap. On Windows it keeps overlapped receives
//! with their own buffers posted on the socket, so bytes land in user space as
//! they arrive, and only reports the end of the stream or the reset once every
//! received byte was read. On every other platform it passes reads straight
//! through, with the same API.
//!
//! Only raw TCP streams can be wrapped (see [`RawTcpStream`]): wrapping the
//! socket under a TLS or peek layer would bypass that layer.
//!
//! # Limits
//!
//! Bytes are kept when a receive is posted as they arrive. A receive
//! completes with whatever has arrived, and the completion thread posts it
//! again right away, normally within microseconds. Only if that thread is
//! held up until every posted receive completed and the reset arrived can
//! bytes still be lost; more [`slots`](PostedRecvConfig::slots) make that
//! less likely.
//!
//! No receive is posted while more than
//! [`max_buffered`](PostedRecvConfig::max_buffered) bytes wait for the
//! reader, so a reader that falls further behind is exposed again. Each
//! posted receive keeps its buffer locked by the kernel for as long as it is
//! posted.
//!
//! All receives of the process complete on one dedicated thread. That caps
//! bulk receive throughput below what tokio reaches on its own, while
//! round-trip latency stays the same.
//!
//! # Example
//!
//! ```no_run
//! use rama_tcp::{TcpStream, posted_recv::PostedRecv};
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! # async fn example() -> std::io::Result<()> {
//! let stream = tokio::net::TcpStream::connect("127.0.0.1:88").await?;
//! let mut stream = PostedRecv::new(TcpStream::new(stream))?;
//! stream.write_all(b"request").await?;
//! let mut reply = Vec::new();
//! stream.read_to_end(&mut reply).await?;
//! # Ok(())
//! # }
//! ```

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use rama_core::extensions::{Extensions, ExtensionsRef};
#[cfg(any(target_os = "windows", target_family = "unix"))]
use rama_net::conn::ConnectionAbort;
use rama_net::{address::SocketAddress, stream::Socket};
use rama_utils::{macros::generate_set_and_with, octets::kib};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{TcpStream, TokioTcpStream};

#[cfg(any(target_os = "windows", target_family = "unix"))]
mod abort;

#[cfg(target_os = "windows")]
mod iocp;

mod layer;
#[doc(inline)]
pub use layer::{PostedRecvConnector, PostedRecvLayer};

const DEFAULT_SLOTS: usize = 2;
const DEFAULT_SLOT_SIZE: usize = kib(16);
const DEFAULT_MAX_BUFFERED: usize = kib(64);

/// Configuration of a [`PostedRecv`].
///
/// Only used on Windows; other platforms accept and ignore it.
#[derive(Debug, Clone)]
pub struct PostedRecvConfig {
    slots: usize,
    slot_size: usize,
    max_buffered: usize,
}

impl Default for PostedRecvConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PostedRecvConfig {
    /// Create the default configuration: two receives of 16 KiB each, and up
    /// to 64 KiB of received bytes waiting for the reader.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: DEFAULT_SLOTS,
            slot_size: DEFAULT_SLOT_SIZE,
            max_buffered: DEFAULT_MAX_BUFFERED,
        }
    }

    generate_set_and_with! {
        /// Number of receives kept posted on the socket (at least 1).
        ///
        /// More slots keep more receives waiting while completed ones are
        /// posted again, see the [module docs](crate::posted_recv#limits).
        pub fn slots(mut self, slots: usize) -> Self {
            self.slots = slots.max(1);
            self
        }
    }

    generate_set_and_with! {
        /// Buffer size of each posted receive, in bytes (at least 1).
        pub fn slot_size(mut self, size: usize) -> Self {
            self.slot_size = size.max(1);
            self
        }
    }

    generate_set_and_with! {
        /// How far, in bytes, the reader may fall behind while receives stay
        /// posted.
        ///
        /// Received bytes are queued until they are read; once more than this
        /// is queued no new receive is posted until the reader catches up.
        pub fn max_buffered(mut self, bytes: usize) -> Self {
            self.max_buffered = bytes;
            self
        }
    }

    /// Number of receives kept posted on the socket.
    #[must_use]
    pub const fn slots(&self) -> usize {
        self.slots
    }

    /// Buffer size of each posted receive, in bytes.
    #[must_use]
    pub const fn slot_size(&self) -> usize {
        self.slot_size
    }

    /// How far, in bytes, the reader may fall behind while receives stay posted.
    #[must_use]
    pub const fn max_buffered(&self) -> usize {
        self.max_buffered
    }
}

mod sealed {
    pub trait Sealed {
        #[cfg(target_os = "windows")]
        fn raw_socket(&self) -> std::os::windows::io::RawSocket;

        #[cfg(target_family = "unix")]
        fn raw_fd(&self) -> std::os::fd::RawFd;

        /// Take the socket back from tokio, so its registration is gone
        /// before the socket is closed.
        #[cfg(target_os = "windows")]
        fn into_std(self) -> std::io::Result<std::net::TcpStream>
        where
            Self: Sized;

        fn extensions_of(&self) -> Option<&rama_core::extensions::Extensions>;
    }
}

/// A raw TCP stream that [`PostedRecv`] can take over reading from.
///
/// Sealed, and only implemented for [`TcpStream`] and [`TokioTcpStream`]:
/// the posted receives read the socket directly, so wrapping a stream that
/// transforms its bytes (TLS, a peek buffer, ...) would bypass it.
pub trait RawTcpStream:
    sealed::Sealed + AsyncRead + AsyncWrite + Socket + Unpin + Send + 'static
{
}

impl sealed::Sealed for TokioTcpStream {
    #[cfg(target_os = "windows")]
    fn raw_socket(&self) -> std::os::windows::io::RawSocket {
        std::os::windows::io::AsRawSocket::as_raw_socket(self)
    }

    #[cfg(target_family = "unix")]
    fn raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(self)
    }

    #[cfg(target_os = "windows")]
    fn into_std(self) -> io::Result<std::net::TcpStream> {
        Self::into_std(self)
    }

    fn extensions_of(&self) -> Option<&Extensions> {
        None
    }
}

impl RawTcpStream for TokioTcpStream {}

impl sealed::Sealed for TcpStream {
    #[cfg(target_os = "windows")]
    fn raw_socket(&self) -> std::os::windows::io::RawSocket {
        std::os::windows::io::AsRawSocket::as_raw_socket(&self.stream)
    }

    #[cfg(target_family = "unix")]
    fn raw_fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.stream)
    }

    #[cfg(target_os = "windows")]
    fn into_std(self) -> io::Result<std::net::TcpStream> {
        self.stream.into_std()
    }

    fn extensions_of(&self) -> Option<&Extensions> {
        Some(&self.extensions)
    }
}

impl RawTcpStream for TcpStream {}

/// A raw TCP stream whose reads keep the data that arrives right before a
/// reset.
///
/// See the [module docs](self) for why this is needed on Windows. Writes,
/// socket addresses, socket options and extensions all go to the inner
/// stream; only reading is taken over.
///
/// Dropping it never blocks. On Windows the socket is closed once the
/// cancelled receives have completed, so that the close stays graceful
/// instead of going out as a reset.
///
/// A socket stays attached to the internal completion port for its whole
/// life, so a [`PostedRecv`] cannot be unwrapped again.
///
/// It also hands out a [`ConnectionAbort`] for its socket, see
/// [`PostedRecv::connection_abort`], and puts it in the extensions of a
/// [`TcpStream`], where a bridge such as
/// [`PassResetsForwardService`](rama_net::proxy::PassResetsForwardService)
/// finds it.
pub struct PostedRecv<S: RawTcpStream> {
    // Declared before `inner`, so that it is dropped before the socket is.
    #[cfg(any(target_os = "windows", target_family = "unix"))]
    abort: abort::AbortGuard,
    #[cfg(target_os = "windows")]
    inner: std::mem::ManuallyDrop<S>,
    #[cfg(target_os = "windows")]
    reader: iocp::Reader,
    #[cfg(not(target_os = "windows"))]
    inner: S,
}

impl<S: RawTcpStream> std::fmt::Debug for PostedRecv<S>
where
    S: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostedRecv")
            .field("inner", self.get_ref())
            .finish_non_exhaustive()
    }
}

impl<S: RawTcpStream> PostedRecv<S> {
    /// Take over reading from `stream`, with the default [`PostedRecvConfig`].
    ///
    /// Wrap the stream right after it connected or was accepted: bytes read
    /// through `stream` before are not seen by the wrapper.
    ///
    /// # Errors
    ///
    /// Fails on Windows if the socket cannot be attached to the completion
    /// port, for instance because it already is attached to another one.
    pub fn new(stream: S) -> io::Result<Self> {
        Self::with_config(stream, &PostedRecvConfig::default())
    }

    /// Take over reading from `stream` with the given configuration.
    ///
    /// # Errors
    ///
    /// See [`PostedRecv::new`].
    #[cfg(target_os = "windows")]
    pub fn with_config(stream: S, config: &PostedRecvConfig) -> io::Result<Self> {
        let reader = iocp::Reader::new(stream.raw_socket(), config)?;
        Ok(Self {
            abort: abort::AbortGuard::new(stream.raw_socket(), stream.extensions_of()),
            inner: std::mem::ManuallyDrop::new(stream),
            reader,
        })
    }

    /// Take over reading from `stream` with the given configuration.
    ///
    /// # Errors
    ///
    /// See [`PostedRecv::new`].
    #[cfg(not(target_os = "windows"))]
    pub fn with_config(stream: S, config: &PostedRecvConfig) -> io::Result<Self> {
        _ = config;
        Ok(Self {
            #[cfg(target_family = "unix")]
            abort: abort::AbortGuard::new(stream.raw_fd(), stream.extensions_of()),
            inner: stream,
        })
    }

    /// A capability to abort this connection: once it is closed, it goes
    /// out as a reset instead of a clean end, discarding what is still
    /// queued to be sent.
    ///
    /// It can be used from anywhere and outlive the stream; after the stream
    /// is dropped it does nothing.
    #[cfg(any(target_os = "windows", target_family = "unix"))]
    #[must_use]
    pub fn connection_abort(&self) -> ConnectionAbort {
        self.abort.handle()
    }

    /// Borrow the inner stream.
    ///
    /// Reading from it directly bypasses the posted receives and reorders the
    /// stream, and no overlapped I/O may be issued on its socket.
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    #[cfg(all(test, target_os = "windows"))]
    fn reader(&self) -> &iocp::Reader {
        &self.reader
    }
}

#[cfg(target_os = "windows")]
impl<S: RawTcpStream> Drop for PostedRecv<S> {
    fn drop(&mut self) {
        // The socket may be closed before the fields are dropped.
        self.abort.release();
        self.reader.stop();
        // SAFETY: `inner` is never used again after this.
        let stream = unsafe { std::mem::ManuallyDrop::take(&mut self.inner) };
        self.reader.close(stream.into_std());
    }
}

impl<S: RawTcpStream> AsyncRead for PostedRecv<S> {
    #[cfg(target_os = "windows")]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.reader.poll_read(cx, buf)
    }

    #[cfg(not(target_os = "windows"))]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: RawTcpStream> AsyncWrite for PostedRecv<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.inner_mut()).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.inner_mut()).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.inner_mut()).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.inner_mut()).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<S: RawTcpStream + ExtensionsRef> ExtensionsRef for PostedRecv<S> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

impl<S: RawTcpStream> Socket for PostedRecv<S> {
    #[inline]
    fn local_addr(&self) -> io::Result<SocketAddress> {
        self.inner.local_addr()
    }

    #[inline]
    fn peer_addr(&self) -> io::Result<SocketAddress> {
        self.inner.peer_addr()
    }
}

#[cfg(any(target_os = "windows", target_family = "unix"))]
impl<S: RawTcpStream + rama_net::socket::AsSocketRef> rama_net::socket::AsSocketRef
    for PostedRecv<S>
{
    #[inline]
    fn as_socket_ref(&self) -> rama_net::socket::core::SockRef<'_> {
        self.inner.as_socket_ref()
    }
}

#[cfg(target_family = "unix")]
mod unix {
    use super::{PostedRecv, RawTcpStream};
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

    impl<S: RawTcpStream + AsFd> AsFd for PostedRecv<S> {
        #[inline]
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.inner.as_fd()
        }
    }

    impl<S: RawTcpStream + AsRawFd> AsRawFd for PostedRecv<S> {
        #[inline]
        fn as_raw_fd(&self) -> RawFd {
            self.inner.as_raw_fd()
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::{PostedRecv, RawTcpStream};
    use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, RawSocket};

    impl<S: RawTcpStream + AsSocket> AsSocket for PostedRecv<S> {
        #[inline]
        fn as_socket(&self) -> BorrowedSocket<'_> {
            self.inner.as_socket()
        }
    }

    impl<S: RawTcpStream + AsRawSocket> AsRawSocket for PostedRecv<S> {
        #[inline]
        fn as_raw_socket(&self) -> RawSocket {
            self.inner.as_raw_socket()
        }
    }
}

#[cfg(test)]
mod tests;
