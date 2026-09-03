//! Runtime-neutral packet-oriented datagram traits.

use std::{
    fmt::Debug,
    future::{Future, poll_fn},
    io::IoSliceMut,
    task::{Context, Poll},
};

use crate::{DatagramCapabilities, DatagramError, DatagramMetadata, SendDatagram};

/// Receive side of an asynchronous packet-oriented datagram socket.
///
/// This deliberately does not implement stream-oriented `AsyncRead` or
/// `AsyncWrite`: a successful operation always preserves datagram boundaries,
/// and a zero-length datagram is data rather than end-of-file.
///
/// Async convenience methods live on [`DatagramSocketExt`]. Receive polling is
/// a single-logical-consumer operation: at most one task may poll a socket's
/// receive side at a time.
pub trait DatagramSocket: rama_net::stream::Socket + Debug {
    /// Independently wakeable send handle created by this socket.
    type Sender: DatagramSender;

    /// Create a send handle with independent readiness registration.
    ///
    /// Separate handles let several tasks wait for send readiness without one
    /// task replacing another task's waker.
    fn create_sender(&self) -> Self::Sender;

    /// Receive one or more datagrams, or register for readiness.
    ///
    /// `buffers` and `metadata` must have equal, non-zero lengths. On success,
    /// the returned count is in `1..=buffers.len()`, and only that many entries
    /// have been filled. Cancelling a pending call never consumes a datagram.
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [DatagramMetadata],
    ) -> Poll<Result<usize, DatagramError>>;

    /// Current runtime-detected capabilities.
    fn capabilities(&self) -> DatagramCapabilities;
}

/// Independently wakeable send side of a [`DatagramSocket`].
///
/// The base trait is object-safe. Each handle must use an independent
/// readiness registration or an equivalent multi-waker mechanism.
pub trait DatagramSender: Send + Debug + 'static {
    /// Send one descriptor, or register for readiness.
    ///
    /// A descriptor with segmentation metadata represents several UDP
    /// datagrams atomically at this API boundary.
    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        datagram: &SendDatagram<'_>,
    ) -> Poll<Result<(), DatagramError>>;

    /// Send as many descriptors as can be accepted now.
    ///
    /// The default is a correct per-datagram fallback. A ready `Ok(n)` means
    /// the first `n` descriptors were accepted in order. An empty batch returns
    /// `Ok(0)`. When the first descriptor is pending, this returns `Pending`.
    fn poll_send_batch(
        &mut self,
        cx: &mut Context<'_>,
        datagrams: &[SendDatagram<'_>],
    ) -> Poll<Result<usize, DatagramError>> {
        let mut sent = 0;
        for datagram in datagrams {
            match self.poll_send(cx, datagram) {
                Poll::Ready(Ok(())) => sent += 1,
                Poll::Ready(Err(error)) => {
                    return if sent == 0 {
                        Poll::Ready(Err(error))
                    } else {
                        Poll::Ready(Ok(sent))
                    };
                }
                Poll::Pending => {
                    return if sent == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(sent))
                    };
                }
            }
        }
        Poll::Ready(Ok(sent))
    }

    /// Current runtime-detected capabilities.
    fn capabilities(&self) -> DatagramCapabilities;
}

mod private {
    pub trait DatagramSenderExtSealed {}
    impl<T: super::DatagramSender + ?Sized> DatagramSenderExtSealed for T {}

    pub trait DatagramSocketExtSealed {}
    impl<T: super::DatagramSocket + ?Sized> DatagramSocketExtSealed for T {}
}

/// Async convenience methods for [`DatagramSender`].
pub trait DatagramSenderExt: DatagramSender + private::DatagramSenderExtSealed {
    /// Send one descriptor.
    fn send<'a>(
        &'a mut self,
        datagram: SendDatagram<'a>,
    ) -> impl Future<Output = Result<(), DatagramError>> + Send + 'a
    where
        Self: Sized,
    {
        poll_fn(move |cx| self.poll_send(cx, &datagram))
    }

    /// Send a batch, returning the accepted prefix length.
    fn send_batch<'a>(
        &'a mut self,
        datagrams: &'a [SendDatagram<'a>],
    ) -> impl Future<Output = Result<usize, DatagramError>> + Send + 'a
    where
        Self: Sized,
    {
        poll_fn(move |cx| self.poll_send_batch(cx, datagrams))
    }
}

impl<T> DatagramSenderExt for T where T: DatagramSender + ?Sized {}

/// Async convenience methods for [`DatagramSocket`].
pub trait DatagramSocketExt: DatagramSocket + private::DatagramSocketExtSealed {
    /// Receive one datagram into `buffer`.
    fn recv<'a>(
        &'a mut self,
        buffer: &'a mut [u8],
    ) -> impl Future<Output = Result<DatagramMetadata, DatagramError>> + Send + 'a
    where
        Self: Sized,
    {
        async move {
            let mut metadata = [DatagramMetadata::empty()];
            let mut buffers = [IoSliceMut::new(buffer)];
            poll_fn(|cx| self.poll_recv(cx, &mut buffers, &mut metadata)).await?;
            Ok(metadata[0])
        }
    }

    /// Receive one or more datagrams into parallel buffer and metadata slices.
    fn recv_batch<'a, 'buffer>(
        &'a mut self,
        buffers: &'a mut [IoSliceMut<'buffer>],
        metadata: &'a mut [DatagramMetadata],
    ) -> impl Future<Output = Result<usize, DatagramError>> + Send + 'a
    where
        Self: Sized,
        'buffer: 'a,
    {
        poll_fn(move |cx| self.poll_recv(cx, buffers, metadata))
    }
}

impl<T> DatagramSocketExt for T where T: DatagramSocket + ?Sized {}

#[cfg(test)]
mod tests {
    use std::{io, task::Waker};

    use super::*;

    #[derive(Debug)]
    struct CountingSender {
        remaining: usize,
    }

    impl DatagramSender for CountingSender {
        fn poll_send(
            &mut self,
            _cx: &mut Context<'_>,
            _datagram: &SendDatagram<'_>,
        ) -> Poll<Result<(), DatagramError>> {
            if self.remaining == 0 {
                Poll::Pending
            } else {
                self.remaining -= 1;
                Poll::Ready(Ok(()))
            }
        }

        fn capabilities(&self) -> DatagramCapabilities {
            DatagramCapabilities::portable()
        }
    }

    #[derive(Debug)]
    struct FailingSender {
        remaining: usize,
    }

    impl DatagramSender for FailingSender {
        fn poll_send(
            &mut self,
            _cx: &mut Context<'_>,
            _datagram: &SendDatagram<'_>,
        ) -> Poll<Result<(), DatagramError>> {
            if self.remaining == 0 {
                Poll::Ready(Err(io::Error::other("send failed").into()))
            } else {
                self.remaining -= 1;
                Poll::Ready(Ok(()))
            }
        }

        fn capabilities(&self) -> DatagramCapabilities {
            DatagramCapabilities::portable()
        }
    }

    #[test]
    fn default_batch_returns_accepted_prefix() {
        let datagrams = [
            SendDatagram::new(([127, 0, 0, 1], 1), b"a"),
            SendDatagram::new(([127, 0, 0, 1], 1), b"b"),
            SendDatagram::new(([127, 0, 0, 1], 1), b"c"),
        ];
        let mut context = Context::from_waker(Waker::noop());

        let mut sender = CountingSender { remaining: 2 };
        assert!(matches!(
            sender.poll_send_batch(&mut context, &datagrams),
            Poll::Ready(Ok(2))
        ));

        let mut sender = CountingSender { remaining: 0 };
        assert!(matches!(
            sender.poll_send_batch(&mut context, &datagrams),
            Poll::Pending
        ));
        assert!(matches!(
            sender.poll_send_batch(&mut context, &[]),
            Poll::Ready(Ok(0))
        ));

        let mut sender = FailingSender { remaining: 0 };
        assert!(matches!(
            sender.poll_send_batch(&mut context, &datagrams),
            Poll::Ready(Err(DatagramError::Io(_)))
        ));

        let mut sender = FailingSender { remaining: 1 };
        assert!(matches!(
            sender.poll_send_batch(&mut context, &datagrams),
            Poll::Ready(Ok(1))
        ));
    }
}
