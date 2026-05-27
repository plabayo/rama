//! [`BytesFreeze`] — adapter that freezes [`BytesMut`] decoder output to
//! [`Bytes`] without disturbing the [`Sink`] side.
//!
//! Most byte-oriented codecs in `tokio-util` (`BytesCodec`,
//! `LengthDelimitedCodec`, …) decode to [`BytesMut`] but encode [`Bytes`].
//! That asymmetry surfaces whenever you want to bridge two such
//! [`Stream`] + [`Sink`] pairs through
//! [`super::StreamForwardService`] — the symmetric item-type bound `T`
//! forces both sides to agree on one type for stream items *and* sink
//! input. Wrapping each side in [`BytesFreeze`] aligns them on `T = Bytes`.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream};

/// Wraps a duplex [`Stream`] + [`Sink`] that decodes to [`BytesMut`] and
/// accepts [`Bytes`] in its sink, exposing a uniform `Stream<Bytes>` +
/// `Sink<Bytes>` on top.
///
/// Cheap zero-copy: [`BytesMut::freeze`] converts in place. The sink path
/// is a direct pass-through.
///
/// # Example
///
/// ```no_run
/// use rama_core::stream::BytesFreeze;
/// use rama_core::stream::codec::{Framed, LengthDelimitedCodec};
/// use tokio::net::TcpStream;
///
/// # async fn _example(tcp: TcpStream) {
/// let framed = Framed::new(tcp, LengthDelimitedCodec::builder()
///     .length_field_type::<u16>()
///     .new_codec());
/// // `framed`'s Stream yields BytesMut, its Sink takes Bytes.
/// // BytesFreeze unifies both onto Bytes.
/// let aligned = BytesFreeze::new(framed);
/// # let _ = aligned;
/// # }
/// ```
#[derive(Debug)]
pub struct BytesFreeze<S> {
    inner: S,
}

impl<S> BytesFreeze<S> {
    /// Wrap `inner` in a [`BytesFreeze`] adapter.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    /// Borrow the wrapped duplex.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    /// Mutably borrow the wrapped duplex.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Unwrap and return the inner duplex.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S, E> Stream for BytesFreeze<S>
where
    S: Stream<Item = Result<BytesMut, E>> + Unpin,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner)
            .poll_next(cx)
            .map(|opt| opt.map(|res| res.map(BytesMut::freeze)))
    }
}

impl<S, E> Sink<Bytes> for BytesFreeze<S>
where
    S: Sink<Bytes, Error = E> + Unpin,
{
    type Error = E;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
