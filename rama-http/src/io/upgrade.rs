//! HTTP Upgrades
//!
//! This module deals with managing [HTTP Upgrades][mdn] in rama_http_core. Since
//! several concepts in HTTP allow for first talking HTTP, and then converting
//! to a different protocol, this module conflates them into a single API.
//! Those include:
//!
//! - HTTP/1.1 Upgrades
//! - HTTP `CONNECT`
//!
//! You are responsible for any other pre-requisites to establish an upgrade,
//! such as sending the appropriate headers, methods, and status codes. You can
//! then use [`on`][] to grab a `Future` which will resolve to the upgraded
//! connection object, or an error if the upgrade fails.
//!
//! [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Protocol_upgrade_mechanism
//!
//! # Client
//!
//! Sending an HTTP upgrade from the [`client`](super::client) involves setting
//! either the appropriate method, if wanting to `CONNECT`, or headers such as
//! `Upgrade` and `Connection`, on the `http::Request`. Once receiving the
//! `http::Response` back, you must check for the specific information that the
//! upgrade is agreed upon by the server (such as a `101` status code), and then
//! get the `Future` from the `Response`.
//!
//! # Server
//!
//! Receiving upgrade requests in a server requires you to check the relevant
//! headers in a `Request`, and if an upgrade should be done, you then send the
//! corresponding headers in a response. To then wait for rama_http_core to finish the
//! upgrade, you call `on()` with the `Request`, and then can spawn a task
//! awaiting it.

use std::any::TypeId;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use rama_core::bytes::Bytes;
use rama_core::error::OpaqueError;
use rama_core::telemetry::tracing::trace;
use rama_net::stream::Stream;
use rama_net::stream::rewind::Rewind;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

/// An upgraded HTTP connection.
///
/// This type holds a trait object internally of the original IO that
/// was used to speak HTTP before the upgrade. It can be used directly
/// as a [`Read`] or [`Write`] for convenience.
///
/// Alternatively, if the exact type is known, this can be deconstructed
/// into its parts.
pub struct Upgraded {
    io: Rewind<Box<dyn Io>>,
}

/// A future for a possible HTTP upgrade.
///
/// If no upgrade was available, or it doesn't succeed, yields an `Error`.
#[derive(Clone)]
pub struct OnUpgrade {
    rx: Option<Arc<Mutex<oneshot::Receiver<Result<Upgraded, OpaqueError>>>>>,
}

/// The deconstructed parts of an [`Upgraded`] type.
///
/// Includes the original IO type, and a read buffer of bytes that the
/// HTTP state machine may have already read before completing an upgrade.
#[derive(Debug)]
#[non_exhaustive]
pub struct Parts<T> {
    /// The original IO object used before the upgrade.
    pub io: T,
    /// A buffer of bytes that have been read but not processed as HTTP.
    ///
    /// For instance, if the `Connection` is used for an HTTP upgrade request,
    /// it is possible the server sent back the first bytes of the new protocol
    /// along with the response upgrade.
    ///
    /// You will want to check for any existing bytes if you plan to continue
    /// communicating on the IO object.
    pub read_buf: Bytes,
}

/// Gets a pending HTTP upgrade from this message.
///
/// This can be called on the following types:
///
/// - `http::Request<B>`
/// - `http::Response<B>`
/// - `&mut rama_http::Request<B>`
/// - `&mut rama_http::Response<B>`
pub fn on<T: sealed::CanUpgrade>(msg: T) -> OnUpgrade {
    msg.on_upgrade()
}

/// A pending upgrade, created with [`pending`].
pub struct Pending {
    tx: oneshot::Sender<Result<Upgraded, OpaqueError>>,
}

/// Initiate an upgrade.
#[must_use]
pub fn pending() -> (Pending, OnUpgrade) {
    let (tx, rx) = oneshot::channel();
    (
        Pending { tx },
        OnUpgrade {
            rx: Some(Arc::new(Mutex::new(rx))),
        },
    )
}

// ===== impl Upgraded =====

impl Upgraded {
    /// Create a new [`Upgraded`] from an IO stream and existing buffer.
    pub fn new<T>(io: T, read_buf: Bytes) -> Self
    where
        T: Stream + Unpin,
    {
        Self {
            io: Rewind::new_buffered(Box::new(io), read_buf),
        }
    }

    /// Tries to downcast the internal trait object to the type passed.
    ///
    /// On success, returns the downcasted parts. On error, returns the
    /// `Upgraded` back.
    pub fn downcast<T: Stream + Unpin>(self) -> Result<Parts<T>, Self> {
        let (io, buf) = self.io.into_inner();
        match io.__downcast() {
            Ok(t) => Ok(Parts {
                io: *t,
                read_buf: buf,
            }),
            Err(io) => Err(Self {
                io: Rewind::new_buffered(io, buf),
            }),
        }
    }
}

trait Io: Stream + Unpin {
    fn __type_id(&self) -> TypeId {
        TypeId::of::<Self>()
    }
}

impl<T: Stream + Unpin> Io for T {}

impl dyn Io {
    fn __is<T: Io>(&self) -> bool {
        let t = TypeId::of::<T>();
        self.__type_id() == t
    }

    fn __downcast<T: Io>(self: Box<Self>) -> Result<Box<T>, Box<Self>> {
        if self.__is::<T>() {
            // Taken from `std::error::Error::downcast()`.
            unsafe {
                let raw: *mut dyn Io = Box::into_raw(self);
                Ok(Box::from_raw(raw as *mut T))
            }
        } else {
            Err(self)
        }
    }
}

impl AsyncRead for Upgraded {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Upgraded {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

impl fmt::Debug for Upgraded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upgraded").finish()
    }
}

// ===== impl OnUpgrade =====

impl OnUpgrade {
    pub(super) fn none() -> Self {
        Self { rx: None }
    }

    /// Returns true if no upgrade is in progress.
    #[must_use]
    pub fn is_none(&self) -> bool {
        self.rx.is_none()
    }
}

impl Future for OnUpgrade {
    type Output = Result<Upgraded, OpaqueError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.rx {
            Some(ref rx) => Pin::new(&mut *rx.lock().unwrap())
                .poll(cx)
                .map(|res| match res {
                    Ok(Ok(upgraded)) => Ok(upgraded),
                    Ok(Err(err)) => Err(err),
                    Err(_oneshot_canceled) => Err(OpaqueError::from_display(
                        "OnUpgrade: cancelled while expecting upgrade",
                    )),
                }),
            None => Poll::Ready(Err(OpaqueError::from_display(
                "OnUpgrade: polled for upgrade while none was expected",
            ))),
        }
    }
}

impl fmt::Debug for OnUpgrade {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnUpgrade").finish()
    }
}

// ===== impl Pending =====

impl Pending {
    /// fulfill the pending upgrade with the given [`Upgraded`] stream.
    pub fn fulfill(self, upgraded: Upgraded) {
        trace!("pending upgrade fulfill");
        let _ = self.tx.send(Ok(upgraded));
    }

    /// Don't fulfill the pending Upgrade, but instead signal that
    /// upgrades are handled manually.
    pub fn manual(self) {
        trace!("pending upgrade handled manually");
        let _ = self.tx.send(Err(OpaqueError::from_display(
            "OnUpgrade: manual upgrade failed",
        )));
    }
}

mod sealed {
    use rama_http_types::{Request, Response};

    use super::OnUpgrade;

    pub trait CanUpgrade {
        fn on_upgrade(self) -> OnUpgrade;
    }

    impl<B> CanUpgrade for Request<B> {
        fn on_upgrade(mut self) -> OnUpgrade {
            self.extensions_mut()
                .remove::<OnUpgrade>()
                .unwrap_or_else(OnUpgrade::none)
        }
    }

    impl<B> CanUpgrade for &'_ mut Request<B> {
        fn on_upgrade(self) -> OnUpgrade {
            self.extensions_mut()
                .remove::<OnUpgrade>()
                .unwrap_or_else(OnUpgrade::none)
        }
    }

    impl<B> CanUpgrade for Response<B> {
        fn on_upgrade(mut self) -> OnUpgrade {
            self.extensions_mut()
                .remove::<OnUpgrade>()
                .unwrap_or_else(OnUpgrade::none)
        }
    }

    impl<B> CanUpgrade for &'_ mut Response<B> {
        fn on_upgrade(self) -> OnUpgrade {
            self.extensions_mut()
                .remove::<OnUpgrade>()
                .unwrap_or_else(OnUpgrade::none)
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio_test::io::{Builder, Mock};

    use super::*;

    #[test]
    fn upgraded_downcast() {
        let upgraded = Upgraded::new(Builder::default().build(), Bytes::new());
        let upgraded = upgraded.downcast::<std::io::Cursor<Vec<u8>>>().unwrap_err();
        upgraded.downcast::<Mock>().unwrap();
    }
}
