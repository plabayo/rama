//! Contains a [`UdpStream`] implementation for udp connections.

use bytes::Bytes;
use futures_core::Stream;
use futures_util::TryStreamExt;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use pin_project_lite::pin_project;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::io::{SinkWriter, StreamReader};
use tokio_util::udp::UdpFramed;

use crate::UdpSocket;
use crate::codec::{BytesCodec, Decoder, Encoder};

pin_project! {
    pub struct UdpStream<C = BytesCodec> {
        #[pin]
        r: StreamReader<UdpByteStream<C>, Bytes>,
        #[pin]
        w: SinkWriter<SplitSink<UdpFramed<C>, (Bytes, SocketAddr)>>,
    }
}

pin_project! {
    #[derive(Debug)]
    struct UdpByteStream<C>{
        #[pin]
        stream: SplitStream<UdpFramed<C>>,
    }
}

impl<C> Stream for UdpByteStream<C>
where
    C: Decoder<Item = Bytes, Error: Into<std::io::Error>>,
{
    type Item = Result<Bytes, C::Error>;

    #[inline]
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().stream.poll_next(cx) {
            Poll::Ready(Some(Ok((bytes, _)))) => Poll::Ready(Some(Ok(bytes))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.stream.size_hint()
    }
}

impl<C: fmt::Debug> fmt::Debug for UdpStream<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpStream")
            .field("r", &self.r)
            .field("w", &self.w)
            .finish()
    }
}

impl<C> UdpStream<C> {
    pub fn new(socket: UdpSocket, codec: C) -> Self
    where
        C: Encoder<Bytes, Error: Into<std::io::Error>>
            + Decoder<Item = Bytes, Error: Into<std::io::Error>>,
    {
        let f = UdpFramed::new(socket, codec);
        let (sink, stream) = f.split();

        let r = StreamReader::new(UdpByteStream { stream });
        let w = SinkWriter::new(sink);

        Self { r, w }
    }
}

impl<C> AsyncRead for UdpStream<C>
where
    C: Decoder<Item = Bytes, Error: Into<std::io::Error>>,
{
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().r.poll_read(cx, buf)
    }
}

impl<C> AsyncWrite for UdpStream<C>
where
    C: Encoder<Bytes, Error: Into<std::io::Error>>,
{
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        self.project().w.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }

    #[inline]
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let buf = bufs
            .iter()
            .find(|b| !b.is_empty())
            .map_or(&[][..], |b| &**b);
        self.poll_write(cx, buf)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        false
    }
}
