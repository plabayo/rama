use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_channel::{mpsc, oneshot};
use rama_core::bytes::Bytes;
use rama_core::futures::{Stream, stream::FusedStream}; // for mpsc::Receiver
use rama_http_types::HeaderMap;
use rama_http_types::dep::http_body::{Body, Frame, SizeHint};
use std::task::ready;

use super::DecodedLength;
use crate::common::watch;
use crate::h2;
use crate::proto::h2::ping;

type BodySender = mpsc::Sender<Result<Bytes, crate::Error>>;
type TrailersSender = oneshot::Sender<HeaderMap>;

/// A stream of `Bytes`, used when receiving bodies from the network.
///
/// Note that Users should not instantiate this struct directly. When working with the client,
/// `Incoming` is returned to you in responses. Similarly, when operating with the server,
/// it is provided within requests.
#[must_use = "streams do nothing unless polled"]
pub struct Incoming {
    kind: Kind,
}

enum Kind {
    Empty,
    Chan {
        content_length: DecodedLength,
        want_tx: watch::Sender,
        data_rx: mpsc::Receiver<Result<Bytes, crate::Error>>,
        trailers_rx: oneshot::Receiver<HeaderMap>,
    },
    H2 {
        content_length: DecodedLength,
        data_done: bool,
        ping: ping::Recorder,
        recv: h2::RecvStream,
    },
}

/// A sender half created through [`Body::channel()`].
///
/// Useful when wanting to stream chunks from another thread.
///
/// ## Body Closing
///
/// Note that the request body will always be closed normally when the sender is dropped (meaning
/// that the empty terminating chunk will be sent to the remote). If you desire to close the
/// connection with an incomplete response (e.g. in the case of an error during asynchronous
/// processing), call the [`Sender::abort()`] method to abort the body in an abnormal fashion.
///
/// [`Body::channel()`]: struct.Body.html#method.channel
/// [`Sender::abort()`]: struct.Sender.html#method.abort
#[must_use = "Sender does nothing unless sent on"]
pub(crate) struct Sender {
    want_rx: watch::Receiver,
    data_tx: BodySender,
    trailers_tx: Option<TrailersSender>,
}

const WANT_PENDING: usize = 1;
const WANT_READY: usize = 2;

impl Incoming {
    /// Create a `Body` stream with an associated sender half.
    ///
    /// Useful when wanting to stream chunks from another thread.
    #[inline]
    #[cfg(test)]
    pub(crate) fn channel() -> (Sender, Self) {
        Self::new_channel(DecodedLength::CHUNKED, /*wanter =*/ false)
    }

    pub(crate) fn new_channel(content_length: DecodedLength, wanter: bool) -> (Sender, Self) {
        let (data_tx, data_rx) = mpsc::channel(0);
        let (trailers_tx, trailers_rx) = oneshot::channel();

        // If wanter is true, `Sender::poll_ready()` won't becoming ready
        // until the `Body` has been polled for data once.
        let want = if wanter { WANT_PENDING } else { WANT_READY };

        let (want_tx, want_rx) = watch::channel(want);

        let tx = Sender {
            want_rx,
            data_tx,
            trailers_tx: Some(trailers_tx),
        };
        let rx = Self::new(Kind::Chan {
            content_length,
            want_tx,
            data_rx,
            trailers_rx,
        });

        (tx, rx)
    }

    fn new(kind: Kind) -> Self {
        Self { kind }
    }

    #[allow(dead_code)]
    pub(crate) fn empty() -> Self {
        Self::new(Kind::Empty)
    }

    pub(crate) fn h2(
        recv: h2::RecvStream,
        mut content_length: DecodedLength,
        ping: ping::Recorder,
    ) -> Self {
        // If the stream is already EOS, then the "unknown length" is clearly
        // actually ZERO.
        if !content_length.is_exact() && recv.is_end_stream() {
            content_length = DecodedLength::ZERO;
        }

        Self::new(Kind::H2 {
            data_done: false,
            ping,
            content_length,
            recv,
        })
    }
}

impl Body for Incoming {
    type Data = Bytes;
    type Error = crate::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.kind {
            Kind::Empty => Poll::Ready(None),
            Kind::Chan {
                content_length: ref mut len,
                ref mut data_rx,
                ref mut want_tx,
                ref mut trailers_rx,
            } => {
                want_tx.send(WANT_READY);

                if !data_rx.is_terminated() {
                    if let Some(chunk) = ready!(Pin::new(data_rx).poll_next(cx)?) {
                        len.sub_if(chunk.len() as u64);
                        return Poll::Ready(Some(Ok(Frame::data(chunk))));
                    }
                }

                // check trailers after data is terminated
                match ready!(Pin::new(trailers_rx).poll(cx)) {
                    Ok(t) => Poll::Ready(Some(Ok(Frame::trailers(t)))),
                    Err(_) => Poll::Ready(None),
                }
            }
            Kind::H2 {
                ref mut data_done,
                ref ping,
                recv: ref mut h2,
                content_length: ref mut len,
            } => {
                if !*data_done {
                    match ready!(h2.poll_data(cx)) {
                        Some(Ok(bytes)) => {
                            let _ = h2.flow_control().release_capacity(bytes.len());
                            len.sub_if(bytes.len() as u64);
                            ping.record_data(bytes.len());
                            return Poll::Ready(Some(Ok(Frame::data(bytes))));
                        }
                        Some(Err(e)) => {
                            return match e.reason() {
                                // These reasons should cause the body reading to stop, but not fail it.
                                // The same logic as for `Read for H2Upgraded` is applied here.
                                Some(h2::Reason::NO_ERROR | h2::Reason::CANCEL) => {
                                    Poll::Ready(None)
                                }
                                _ => Poll::Ready(Some(Err(crate::Error::new_body(e)))),
                            };
                        }
                        None => {
                            *data_done = true;
                            // fall through to trailers
                        }
                    }
                }

                // after data, check trailers
                match ready!(h2.poll_trailers(cx)) {
                    Ok(t) => {
                        ping.record_non_data();
                        Poll::Ready(Ok(t.map(Frame::trailers)).transpose())
                    }
                    Err(e) => Poll::Ready(Some(Err(crate::Error::new_h2(e)))),
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self.kind {
            Kind::Empty => true,
            Kind::Chan { content_length, .. } => content_length == DecodedLength::ZERO,
            Kind::H2 { recv: ref h2, .. } => h2.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        fn opt_len(decoded_length: DecodedLength) -> SizeHint {
            if let Some(content_length) = decoded_length.into_opt() {
                SizeHint::with_exact(content_length)
            } else {
                SizeHint::default()
            }
        }

        match self.kind {
            Kind::Empty => SizeHint::with_exact(0),
            Kind::Chan { content_length, .. } | Kind::H2 { content_length, .. } => {
                opt_len(content_length)
            }
        }
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[derive(Debug)]
        struct Streaming;
        #[derive(Debug)]
        struct Empty;

        let mut builder = f.debug_tuple("Body");
        match self.kind {
            Kind::Empty => builder.field(&Empty),
            _ => builder.field(&Streaming),
        };

        builder.finish()
    }
}

impl Sender {
    /// Check to see if this `Sender` can send more data.
    pub(crate) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        // Check if the receiver end has tried polling for the body yet
        ready!(self.poll_want(cx)?);
        self.data_tx
            .poll_ready(cx)
            .map_err(|_| crate::Error::new_closed())
    }

    fn poll_want(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        match self.want_rx.load(cx) {
            WANT_READY => Poll::Ready(Ok(())),
            WANT_PENDING => Poll::Pending,
            watch::CLOSED => Poll::Ready(Err(crate::Error::new_closed())),
            unexpected => unreachable!("want_rx value: {}", unexpected),
        }
    }

    #[cfg(test)]
    async fn ready(&mut self) -> crate::Result<()> {
        use std::future::poll_fn;

        poll_fn(|cx| self.poll_ready(cx)).await
    }

    /// Send data on data channel when it is ready.
    #[cfg(test)]
    #[allow(unused)]
    pub(crate) async fn send_data(&mut self, chunk: Bytes) -> crate::Result<()> {
        self.ready().await?;
        self.data_tx
            .try_send(Ok(chunk))
            .map_err(|_| crate::Error::new_closed())
    }

    /// Send trailers on trailers channel.
    #[allow(unused)]
    pub(crate) async fn send_trailers(&mut self, trailers: HeaderMap) -> crate::Result<()> {
        let Some(tx) = self.trailers_tx.take() else {
            return Err(crate::Error::new_closed());
        };
        tx.send(trailers).map_err(|_| crate::Error::new_closed())
    }

    /// Try to send data on this channel.
    ///
    /// # Errors
    ///
    /// Returns `Err(Bytes)` if the channel could not (currently) accept
    /// another `Bytes`.
    ///
    /// # Note
    ///
    /// This is mostly useful for when trying to send from some other thread
    /// that doesn't have an async context. If in an async context, prefer
    /// `send_data()` instead.
    pub(crate) fn try_send_data(&mut self, chunk: Bytes) -> Result<(), Bytes> {
        self.data_tx
            .try_send(Ok(chunk))
            .map_err(|err| err.into_inner().expect("just sent Ok"))
    }

    pub(crate) fn try_send_trailers(
        &mut self,
        trailers: HeaderMap,
    ) -> Result<(), Option<HeaderMap>> {
        let Some(tx) = self.trailers_tx.take() else {
            return Err(None);
        };

        tx.send(trailers).map_err(Some)
    }

    #[cfg(test)]
    pub(crate) fn abort(mut self) {
        self.send_error(crate::Error::new_body_write_aborted());
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn send_error(&mut self, err: crate::Error) {
        let _ = self
            .data_tx
            // clone so the send works even if buffer is full
            .clone()
            .try_send(Err(err));
    }
}

impl fmt::Debug for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[derive(Debug)]
        struct Open;
        #[derive(Debug)]
        struct Closed;

        let mut builder = f.debug_tuple("Sender");
        match self.want_rx.peek() {
            watch::CLOSED => builder.field(&Closed),
            _ => builder.field(&Open),
        };

        builder.finish()
    }
}

#[cfg(test)]
mod tests {
    use std::mem;
    use std::task::Poll;

    use super::{Body, DecodedLength, Incoming, Sender, SizeHint};
    use rama_http_types::dep::http_body_util::BodyExt;

    #[test]
    fn test_size_of() {
        // These are mostly to help catch *accidentally* increasing
        // the size by too much.

        let body_size = mem::size_of::<Incoming>();
        let body_expected_size = mem::size_of::<u64>() * 5;
        assert!(
            body_size <= body_expected_size,
            "Body size = {body_size} <= {body_expected_size}",
        );

        //assert_eq!(body_size, mem::size_of::<Option<Incoming>>(), "Option<Incoming>");

        assert_eq!(
            mem::size_of::<Sender>(),
            mem::size_of::<usize>() * 5,
            "Sender"
        );

        assert_eq!(
            mem::size_of::<Sender>(),
            mem::size_of::<Option<Sender>>(),
            "Option<Sender>"
        );
    }

    #[test]
    fn size_hint() {
        #[allow(clippy::needless_pass_by_value)]
        fn eq(body: Incoming, b: SizeHint, note: &str) {
            let a = body.size_hint();
            assert_eq!(a.lower(), b.lower(), "lower for {note:?}");
            assert_eq!(a.upper(), b.upper(), "upper for {note:?}");
        }

        eq(Incoming::empty(), SizeHint::with_exact(0), "empty");

        eq(Incoming::channel().1, SizeHint::new(), "channel");

        eq(
            Incoming::new_channel(DecodedLength::new(4), /*wanter =*/ false).1,
            SizeHint::with_exact(4),
            "channel with length",
        );
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn channel_abort() {
        let (tx, mut rx) = Incoming::channel();

        tx.abort();

        let err = rx.frame().await.unwrap().unwrap_err();
        assert!(err.is_body_write_aborted(), "{err:?}");
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn channel_abort_when_buffer_is_full() {
        let (mut tx, mut rx) = Incoming::channel();

        tx.try_send_data("chunk 1".into()).expect("send 1");
        // buffer is full, but can still send abort
        tx.abort();

        let chunk1 = rx
            .frame()
            .await
            .expect("item 1")
            .expect("chunk 1")
            .into_data()
            .unwrap();
        assert_eq!(chunk1, "chunk 1");

        let err = rx.frame().await.unwrap().unwrap_err();
        assert!(err.is_body_write_aborted(), "{err:?}");
    }

    #[test]
    fn channel_buffers_one() {
        let (mut tx, _rx) = Incoming::channel();

        tx.try_send_data("chunk 1".into()).expect("send 1");

        // buffer is now full
        let chunk2 = tx.try_send_data("chunk 2".into()).expect_err("send 2");
        assert_eq!(chunk2, "chunk 2");
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn channel_empty() {
        let (_, mut rx) = Incoming::channel();

        assert!(rx.frame().await.is_none());
    }

    #[test]
    fn channel_ready() {
        let (mut tx, _rx) = Incoming::new_channel(DecodedLength::CHUNKED, /*wanter = */ false);

        let mut tx_ready = tokio_test::task::spawn(tx.ready());

        assert!(tx_ready.poll().is_ready(), "tx is ready immediately");
    }

    #[test]
    fn channel_wanter() {
        let (mut tx, mut rx) =
            Incoming::new_channel(DecodedLength::CHUNKED, /*wanter = */ true);

        let mut tx_ready = tokio_test::task::spawn(tx.ready());
        let mut rx_data = tokio_test::task::spawn(rx.frame());

        assert!(
            tx_ready.poll().is_pending(),
            "tx isn't ready before rx has been polled"
        );

        assert!(rx_data.poll().is_pending(), "poll rx.data");
        assert!(tx_ready.is_woken(), "rx poll wakes tx");

        assert!(
            tx_ready.poll().is_ready(),
            "tx is ready after rx has been polled"
        );
    }

    #[test]
    fn channel_notices_closure() {
        let (mut tx, rx) = Incoming::new_channel(DecodedLength::CHUNKED, /*wanter = */ true);

        let mut tx_ready = tokio_test::task::spawn(tx.ready());

        assert!(
            tx_ready.poll().is_pending(),
            "tx isn't ready before rx has been polled"
        );

        drop(rx);
        assert!(tx_ready.is_woken(), "dropping rx wakes tx");

        match tx_ready.poll() {
            Poll::Ready(Err(ref e)) if e.is_closed() => (),
            unexpected => panic!("tx poll ready unexpected: {unexpected:?}"),
        }
    }
}
