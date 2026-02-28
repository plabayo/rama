use rama_core::bytes::{BufMut, BytesMut};
use rama_core::futures::Sink;
use rama_core::futures::Stream;
use rama_core::stream::codec::{Decoder, Encoder};
use std::borrow::Borrow;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::ReadBuf;
use tokio::net::UnixDatagram;

use super::UnixSocketAddress;

/// A unified [`Stream`] and [`Sink`] interface to an underlying [`UnixDatagram`], using
/// the `Encoder` and `Decoder` traits to encode and decode frames.
///
/// Raw Unix datagram sockets work with datagrams, but higher-level code usually wants to
/// batch these into meaningful chunks, called "frames". This method layers
/// framing on top of this socket by using the `Encoder` and `Decoder` traits to
/// handle encoding and decoding of messages frames. Note that the incoming and
/// outgoing frame types may be distinct.
///
/// This function returns a *single* object that is both [`Stream`] and [`Sink`];
/// grouping this into a single object is often useful for layering things which
/// require both read and write access to the underlying object.
///
/// If you want to work more directly with the streams and sink, consider
/// calling [`split`] on the `UnixDatagramFramed` returned by this method, which will break
/// them into separate objects, allowing them to interact more easily.
///
/// [`split`]: rama_core::futures::StreamExt::split
#[must_use = "sinks do nothing unless polled"]
#[derive(Debug)]
pub struct UnixDatagramFramed<C, T = UnixDatagram> {
    socket: T,
    codec: C,
    rd: BytesMut,
    wr: BytesMut,
    out_addr: Option<UnixSocketAddress>,
    flushed: bool,
    current_addr: Option<UnixSocketAddress>,
}

const INITIAL_RD_CAPACITY: usize = 64 * 1024;
const INITIAL_WR_CAPACITY: usize = 8 * 1024;

impl<C, T> Unpin for UnixDatagramFramed<C, T> {}

impl<C, T> Stream for UnixDatagramFramed<C, T>
where
    T: Borrow<UnixDatagram>,
    C: Decoder,
{
    type Item = Result<(C::Item, UnixSocketAddress), C::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let pin = self.get_mut();

        pin.rd.reserve(INITIAL_RD_CAPACITY);

        loop {
            // Are there still bytes left in the read buffer to decode?
            if let Some(current_addr) = pin.current_addr.clone() {
                if let Some(frame) = pin.codec.decode_eof(&mut pin.rd)? {
                    return Poll::Ready(Some(Ok((frame, current_addr))));
                }

                // if this line has been reached then decode has returned `None`.
                pin.current_addr = None;
                pin.rd.clear();
            }

            // We're out of data. Try and fetch more data to decode
            let addr = {
                // Safety: `chunk_mut()` returns a `&mut UninitSlice`, and `UninitSlice` is a
                // transparent wrapper around `[MaybeUninit<u8>]`.
                let buf = unsafe { pin.rd.chunk_mut().as_uninit_slice_mut() };
                let mut read = ReadBuf::uninit(buf);
                let ptr = read.filled().as_ptr();
                let res = ready!(pin.socket.borrow().poll_recv_from(cx, &mut read));

                assert_eq!(ptr, read.filled().as_ptr());
                let addr = res?;

                let filled = read.filled().len();
                // Safety: This is guaranteed to be the number of initialized (and read) bytes due
                // to the invariants provided by `ReadBuf::filled`.
                unsafe { pin.rd.advance_mut(filled) };

                addr
            };

            pin.current_addr = Some(addr.into());
        }
    }
}

impl<I, C, T> Sink<(I, UnixSocketAddress)> for UnixDatagramFramed<C, T>
where
    T: Borrow<UnixDatagram>,
    C: Encoder<I>,
{
    type Error = C::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.flushed {
            match self.poll_flush(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: (I, UnixSocketAddress)) -> Result<(), Self::Error> {
        let (frame, out_addr) = item;

        let pin = self.get_mut();

        pin.codec.encode(frame, &mut pin.wr)?;
        pin.out_addr = Some(out_addr);
        pin.flushed = false;

        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.flushed {
            return Poll::Ready(Ok(()));
        }

        let Self {
            ref socket,
            ref mut out_addr,
            ref mut wr,
            ..
        } = *self;

        let n = ready!(match out_addr.as_ref().and_then(|a| a.as_pathname()) {
            Some(path) => socket.borrow().poll_send_to(cx, wr, path),
            None => socket.borrow().poll_send(cx, wr),
        })?;

        let wrote_all = n == self.wr.len();
        self.wr.clear();
        self.flushed = true;

        let res = if wrote_all {
            Ok(())
        } else {
            Err(io::Error::other("failed to write entire datagram to socket").into())
        };

        Poll::Ready(res)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl<C, T> UnixDatagramFramed<C, T>
where
    T: Borrow<UnixDatagram>,
{
    /// Create a new `UnixDatagramFramed` backed by the given socket and codec.
    ///
    /// See struct level documentation for more details.
    pub fn new(socket: T, codec: C) -> Self {
        Self {
            socket,
            codec,
            out_addr: None,
            rd: BytesMut::with_capacity(INITIAL_RD_CAPACITY),
            wr: BytesMut::with_capacity(INITIAL_WR_CAPACITY),
            flushed: true,
            current_addr: None,
        }
    }

    /// Returns a reference to the underlying I/O stream wrapped by `Framed`.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_ref(&self) -> &T {
        &self.socket
    }

    /// Returns a mutable reference to the underlying I/O stream wrapped by `Framed`.
    ///
    /// # Note
    ///
    /// Care should be taken to not tamper with the underlying stream of data
    /// coming in as it may corrupt the stream of frames otherwise being worked
    /// with.
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.socket
    }

    /// Returns a reference to the underlying codec wrapped by
    /// `Framed`.
    ///
    /// Note that care should be taken to not tamper with the underlying codec
    /// as it may corrupt the stream of frames otherwise being worked with.
    pub fn codec(&self) -> &C {
        &self.codec
    }

    /// Returns a mutable reference to the underlying codec wrapped by
    /// `UnixDatagramFramed`.
    ///
    /// Note that care should be taken to not tamper with the underlying codec
    /// as it may corrupt the stream of frames otherwise being worked with.
    pub fn codec_mut(&mut self) -> &mut C {
        &mut self.codec
    }

    /// Returns a reference to the read buffer.
    pub fn read_buffer(&self) -> &BytesMut {
        &self.rd
    }

    /// Returns a mutable reference to the read buffer.
    pub fn read_buffer_mut(&mut self) -> &mut BytesMut {
        &mut self.rd
    }

    /// Consumes the `Framed`, returning its underlying I/O stream.
    pub fn into_inner(self) -> T {
        self.socket
    }
}
