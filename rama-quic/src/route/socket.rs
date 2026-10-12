use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io::{self, IoSliceMut},
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use rama_net::{
    address::{SocketAddress, ip::IntoCanonicalIpAddr as _},
    stream::Socket,
};
use rama_udp::{
    DatagramCapabilities, DatagramError, DatagramMetadata, DatagramSender, DatagramSocket,
    SendDatagram,
};
use tokio::{
    sync::{Notify, futures::OwnedNotified},
    time::{Instant, Sleep, sleep},
};

use super::{
    AssociationPermit,
    router::{RouteContext, validate_metadata},
};

pub(super) struct BufferedDatagram {
    pub(super) payload: Vec<u8>,
    pub(super) metadata: DatagramMetadata,
}

struct Lifetime {
    closed: AtomicBool,
    notify: Arc<Notify>,
    _permit: AssociationPermit,
}

impl Lifetime {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

/// Consumes the retained prefix once, before later socket input. The tuple stays
/// fixed in both directions; rebinding and CID-based migration are unsupported.
/// Drop or idle expiry closes every send handle and retains admission ownership
/// until all handles have been released.
pub struct AssociationSocket<S> {
    inner: S,
    context: RouteContext,
    prefix: VecDeque<BufferedDatagram>,
    lifetime: Arc<Lifetime>,
    idle: Pin<Box<Sleep>>,
    idle_timeout: Duration,
    cancelled: Pin<Box<OwnedNotified>>,
}
impl<S: fmt::Debug> fmt::Debug for AssociationSocket<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssociationSocket")
            .field("inner", &self.inner)
            .field("context", &self.context)
            .field("buffered_datagrams", &self.prefix.len())
            .finish_non_exhaustive()
    }
}
impl<S> AssociationSocket<S> {
    pub(super) fn new(
        inner: S,
        context: RouteContext,
        permit: AssociationPermit,
        prefix: VecDeque<BufferedDatagram>,
        idle_timeout: Duration,
    ) -> Self {
        let lifetime = Arc::new(Lifetime {
            closed: AtomicBool::new(false),
            notify: Arc::new(Notify::new()),
            _permit: permit,
        });
        let cancelled = Box::pin(lifetime.notify.clone().notified_owned());
        Self {
            inner,
            context,
            prefix,
            idle: Box::pin(sleep(idle_timeout)),
            idle_timeout,
            lifetime,
            cancelled,
        }
    }
    fn fail(&self, error: DatagramError) -> Poll<Result<usize, DatagramError>> {
        self.lifetime.close();
        Poll::Ready(Err(error))
    }
}
impl<S> Drop for AssociationSocket<S> {
    fn drop(&mut self) {
        self.lifetime.close();
    }
}
impl<S: Socket> Socket for AssociationSocket<S> {
    fn local_addr(&self) -> io::Result<SocketAddress> {
        self.inner.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddress> {
        Ok(self.context.key.peer)
    }
}
impl<S: DatagramSocket> DatagramSocket for AssociationSocket<S> {
    type Sender = AssociationSender<S::Sender>;
    fn create_sender(&self) -> Self::Sender {
        AssociationSender {
            inner: self.inner.create_sender(),
            peer: self.context.key.peer,
            local: self.context.key.ingress.ip_addr,
            force_source: self.inner.capabilities().send_source_ip,
            lifetime: self.lifetime.clone(),
            cancelled: Box::pin(self.lifetime.notify.clone().notified_owned()),
        }
    }
    fn capabilities(&self) -> DatagramCapabilities {
        self.inner.capabilities()
    }
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>> {
        if buffers.len() != metadata.len() {
            return Poll::Ready(Err(DatagramError::ReceiveSlotMismatch {
                buffers: buffers.len(),
                metadata: metadata.len(),
            }));
        }
        if buffers.is_empty() {
            return Poll::Ready(Err(DatagramError::EmptyReceiveBatch));
        }
        let _closed_notification = self.cancelled.as_mut().poll(cx);
        if self.lifetime.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(DatagramError::Closed));
        }
        if self.idle.as_mut().poll(cx).is_ready() {
            return self.fail(DatagramError::Io(io::Error::new(
                io::ErrorKind::TimedOut,
                "QUIC route ingress idle deadline",
            )));
        }
        if let Some(first) = self.prefix.front() {
            if first.payload.len() > buffers[0].len() {
                return self.fail(DatagramError::PayloadTooLarge {
                    len: first.payload.len(),
                    max: buffers[0].len(),
                });
            }
            buffers[0][..first.payload.len()].copy_from_slice(&first.payload);
            metadata[0] = first.metadata;
            let _consumed = self.prefix.pop_front();
            return Poll::Ready(Ok(1));
        }
        let count = match self.inner.poll_recv(cx, buffers, metadata) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return self.fail(error),
            Poll::Ready(Ok(count)) => count,
        };
        if count == 0 || count > buffers.len() {
            return self.fail(DatagramError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid socket receive count",
            )));
        }
        for index in 0..count {
            if let Err(error) =
                validate_metadata(&self.context, &metadata[index], buffers[index].len())
            {
                return self.fail(DatagramError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    error,
                )));
            }
        }
        let Some(deadline) = Instant::now().checked_add(self.idle_timeout) else {
            return self.fail(DatagramError::Closed);
        };
        self.idle.as_mut().reset(deadline);
        Poll::Ready(Ok(count))
    }
}

/// Independently wakeable output handle confined to its association's peer.
/// Receiver closure wakes a pending sender even when the underlying transport
/// never becomes writable again.
pub struct AssociationSender<S> {
    inner: S,
    peer: SocketAddress,
    local: IpAddr,
    force_source: bool,
    lifetime: Arc<Lifetime>,
    cancelled: Pin<Box<OwnedNotified>>,
}
impl<S: fmt::Debug> fmt::Debug for AssociationSender<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssociationSender")
            .field("inner", &self.inner)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}
impl<S: DatagramSender> DatagramSender for AssociationSender<S> {
    fn capabilities(&self) -> DatagramCapabilities {
        self.inner.capabilities()
    }
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>> {
        // Register before checking closure, so receiver cancellation cannot be
        // lost between the flag check and a pending underlying send.
        let _closed_notification = self.cancelled.as_mut().poll(cx);
        if self.lifetime.closed.load(Ordering::Acquire) {
            return Poll::Ready(Err(DatagramError::Closed));
        }
        if datagram.destination().into_canonical_ip_addr() != self.peer
            || datagram
                .source_ip()
                .is_some_and(|source| source.into_canonical_ip_addr() != self.local)
        {
            self.lifetime.close();
            return Poll::Ready(Err(DatagramError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "QUIC route cannot send to a different peer",
            ))));
        }
        let effective = if self.force_source {
            (*datagram).maybe_with_source_ip(Some(self.local))
        } else {
            *datagram
        };
        self.inner.poll_send(cx, &effective)
    }
}
