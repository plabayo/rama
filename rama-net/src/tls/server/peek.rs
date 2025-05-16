use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext},
    service::RejectService,
};
use std::{fmt, io::IoSlice, pin::Pin, task::Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// A [`Service`] router that can be used to support
/// tls traffic as well as non-tls traffic.
///
/// By default non-tls traffic is rejected using [`RejectService`].
/// Use [`TlsPeekRouter::with_fallback`] to configure the fallback service.
pub struct TlsPeekRouter<T, F = RejectService<(), NoTlsRejectError>> {
    tls_acceptor: T,
    fallback: F,
}

rama_utils::macros::error::static_str_error! {
    #[doc = "non-tls connection is rejected"]
    pub struct NoTlsRejectError;
}

impl<T> TlsPeekRouter<T> {
    /// Create a new [`TlsPeekRouter`].
    pub fn new(tls_acceptor: T) -> Self {
        Self {
            tls_acceptor,
            fallback: RejectService::new(NoTlsRejectError),
        }
    }

    /// Attach a fallback [`Service`] tp this [`TlsPeekRouter`].
    pub fn with_fallback<F>(self, fallback: F) -> TlsPeekRouter<T, F> {
        TlsPeekRouter {
            tls_acceptor: self.tls_acceptor,
            fallback,
        }
    }
}

impl<T: Clone, F: Clone> Clone for TlsPeekRouter<T, F> {
    fn clone(&self) -> Self {
        Self {
            tls_acceptor: self.tls_acceptor.clone(),
            fallback: self.fallback.clone(),
        }
    }
}

impl<T: fmt::Debug, F: fmt::Debug> fmt::Debug for TlsPeekRouter<T, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsPeekRouter")
            .field("tls_acceptor", &self.tls_acceptor)
            .field("fallback", &self.fallback)
            .finish()
    }
}

impl<State, Stream, Response, T, F> Service<State, Stream> for TlsPeekRouter<T, F>
where
    State: Clone + Send + Sync + 'static,
    Stream: crate::stream::Stream + Unpin,
    Response: Send + 'static,
    T: Service<State, TlsPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
    F: Service<State, TlsPeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        mut stream: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let mut peek_buf = [0u8; TLS_HEADER_PEEK_LEN];
        let n = stream
            .read(&mut peek_buf)
            .await
            .context("try to read tls prefix header")?;

        let is_tls = n == TLS_HEADER_PEEK_LEN && matches!(peek_buf, [0x16, 0x03, 0x00..=0x04, ..]);
        tracing::trace!(%is_tls, "tls prefix header read");

        let offset = TLS_HEADER_PEEK_LEN - n;
        if offset > 0 {
            peek_buf.copy_within(..n, offset);
        }

        let stream = TlsPeekStream {
            prefix: peek_buf,
            offset,
            inner: stream,
        };

        if is_tls {
            self.tls_acceptor
                .serve(ctx, stream)
                .await
                .map_err(Into::into)
        } else {
            self.fallback.serve(ctx, stream).await.map_err(Into::into)
        }
    }
}

const TLS_HEADER_PEEK_LEN: usize = 5;
type TlsPrefixHeader = [u8; TLS_HEADER_PEEK_LEN];

pub struct TlsPeekStream<S> {
    prefix: TlsPrefixHeader,
    offset: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for TlsPeekStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < TLS_HEADER_PEEK_LEN - 1 {
            let remaining = &self.prefix[self.offset..];
            let to_copy = remaining.len().min(buf.remaining());

            if to_copy > 0 {
                buf.put_slice(&self.prefix[..to_copy]);
                self.offset += to_copy;
                return Poll::Ready(Ok(()));
            }
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TlsPeekStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod test {
    use rama_core::service::service_fn;
    use std::convert::Infallible;
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn test_peek_router() {
        let tls_service = service_fn(async |_, _| Ok::<_, Infallible>("tls"));
        let plain_service = service_fn(async |_, _| Ok::<_, Infallible>("plain"));

        let peek_tls_svc = TlsPeekRouter::new(tls_service).with_fallback(plain_service);

        let response = peek_tls_svc
            .serve(Context::default(), std::io::Cursor::new(b"".to_vec()))
            .await
            .unwrap();
        assert_eq!("plain", response);

        let response = peek_tls_svc
            .serve(
                Context::default(),
                std::io::Cursor::new(b"\x16\x03\x03\x00\x2afoo".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!("tls", response);

        let response = peek_tls_svc
            .serve(Context::default(), std::io::Cursor::new(b"foo".to_vec()))
            .await
            .unwrap();
        assert_eq!("plain", response);

        let response = peek_tls_svc
            .serve(Context::default(), std::io::Cursor::new(b"foobar".to_vec()))
            .await
            .unwrap();
        assert_eq!("plain", response);
    }

    #[tokio::test]
    async fn test_peek_stream() -> std::io::Result<()> {
        let prefix = b"\x16\x03\x01\x00\x2a";
        let payload = b"actual application data";

        let (mut client, server) = duplex(64);

        let mut input_data = prefix.to_vec();
        input_data.extend_from_slice(payload);

        let w_input_data = input_data.clone();
        tokio::spawn(async move {
            client.write_all(&w_input_data).await.unwrap();
            client.shutdown().await.unwrap();
        });

        let mut peek_buf = [0u8; 5];
        let mut sniff_stream = server;
        sniff_stream.read_exact(&mut peek_buf).await?;
        assert_eq!(&peek_buf, prefix);

        let mut buffered = TlsPeekStream {
            prefix: peek_buf,
            offset: 0,
            inner: sniff_stream,
        };

        let mut all_data = Vec::new();
        buffered.read_to_end(&mut all_data).await?;
        assert_eq!(all_data, input_data);

        Ok(())
    }
}
