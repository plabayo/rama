use std::fmt;

use rama_core::telemetry::tracing;
use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext},
    service::RejectService,
};
use tokio::io::AsyncReadExt;

use crate::stream::{PeekStream, StackReader};

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
        tracing::trace!(%is_tls, "tls prefix header read: is tls: {is_tls}");

        let offset = TLS_HEADER_PEEK_LEN - n;
        if offset > 0 {
            tracing::trace!("move tls peek buffer cursor due to reading not enough: (read: {n})");
            peek_buf.copy_within(0..n, offset);
        }

        let mut peek = StackReader::new(peek_buf);
        peek.skip(offset);

        let stream = PeekStream::new(peek, stream);

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

/// [`PeekStream`] alias used by [`TlsPeekRouter`].
pub type TlsPeekStream<S> = PeekStream<StackReader<TLS_HEADER_PEEK_LEN>, S>;

#[cfg(test)]
mod test {
    use rama_core::service::{RejectError, service_fn};
    use std::convert::Infallible;

    use crate::stream::Stream;

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
    async fn test_peek_router_read_eof() {
        const CONTENT: &[u8] = b"\x16\x03\x03\x00\x2afoo";

        async fn tls_service_fn(mut stream: impl Stream + Unpin) -> Result<&'static str, BoxError> {
            let mut v = Vec::default();
            let _ = stream.read_to_end(&mut v).await?;
            assert_eq!(CONTENT, v);

            Ok("ok")
        }
        let tls_service = service_fn(tls_service_fn);

        let peek_tls_svc =
            TlsPeekRouter::new(tls_service).with_fallback(
                RejectService::<&'static str, RejectError>::new(RejectError::default()),
            );

        let response = peek_tls_svc
            .serve(Context::default(), std::io::Cursor::new(CONTENT.to_vec()))
            .await
            .unwrap();
        assert_eq!("ok", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_no_tls_eof() {
        let cases = ["", "foo", "abcd", "abcde", "foobarbazbananas"];
        for content in cases {
            async fn tls_service_fn() -> Result<Vec<u8>, BoxError> {
                Ok("tls".as_bytes().to_vec())
            }
            let tls_service = service_fn(tls_service_fn);

            async fn plain_service_fn(
                mut stream: impl Stream + Unpin,
            ) -> Result<Vec<u8>, BoxError> {
                let mut v = Vec::default();
                let _ = stream.read_to_end(&mut v).await?;
                Ok(v)
            }
            let plain_service = service_fn(plain_service_fn);

            let peek_tls_svc = TlsPeekRouter::new(tls_service).with_fallback(plain_service);

            let response = peek_tls_svc
                .serve(
                    Context::default(),
                    std::io::Cursor::new(content.as_bytes().to_vec()),
                )
                .await
                .unwrap();

            assert_eq!(content.as_bytes(), &response[..]);
        }
    }
}
