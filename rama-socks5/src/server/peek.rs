use std::fmt;

use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext},
    service::RejectService,
    telemetry::tracing,
};
use rama_net::stream::{PeekStream, StackReader};
use tokio::io::AsyncReadExt;

use crate::proto::{ProtocolVersion, SocksMethod};

/// A [`Service`] router that can be used to support
/// socks5 traffic as well as non-socks5 traffic.
///
/// By default non-socks5 traffic is rejected using [`RejectService`].
/// Use [`Socks5PeekRouter::with_fallback`] to configure the fallback service.
///
/// This kind of router can be useful in case you want to have a proxy
/// which supports for example both HTTP proxy requests as well socks5 proxy requests.
pub struct Socks5PeekRouter<T, F = RejectService<(), NoSocks5RejectError>> {
    socks5_acceptor: T,
    fallback: F,
}

rama_utils::macros::error::static_str_error! {
    #[doc = "non-socks5 connection is rejected"]
    pub struct NoSocks5RejectError;
}

impl<T> Socks5PeekRouter<T> {
    /// Create a new [`Socks5PeekRouter`].
    pub fn new(socks5_acceptor: T) -> Self {
        Self {
            socks5_acceptor,
            fallback: RejectService::new(NoSocks5RejectError),
        }
    }

    /// Attach a fallback [`Service`] tp this [`Socks5PeekRouter`].
    pub fn with_fallback<F>(self, fallback: F) -> Socks5PeekRouter<T, F> {
        Socks5PeekRouter {
            socks5_acceptor: self.socks5_acceptor,
            fallback,
        }
    }
}

impl<T: Clone, F: Clone> Clone for Socks5PeekRouter<T, F> {
    fn clone(&self) -> Self {
        Self {
            socks5_acceptor: self.socks5_acceptor.clone(),
            fallback: self.fallback.clone(),
        }
    }
}

impl<T: fmt::Debug, F: fmt::Debug> fmt::Debug for Socks5PeekRouter<T, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socks5PeekRouter")
            .field("socks5_acceptor", &self.socks5_acceptor)
            .field("fallback", &self.fallback)
            .finish()
    }
}

impl<State, Stream, Response, T, F> Service<State, Stream> for Socks5PeekRouter<T, F>
where
    State: Clone + Send + Sync + 'static,
    Stream: rama_net::stream::Stream + Unpin,
    Response: Send + 'static,
    T: Service<State, Socks5PeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
    F: Service<State, Socks5PeekStream<Stream>, Response = Response, Error: Into<BoxError>>,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        mut stream: Stream,
    ) -> Result<Self::Response, Self::Error> {
        let mut peek_buf = [0u8; SOCKS5_HEADER_PEEK_LEN];
        let n = stream
            .read(&mut peek_buf)
            .await
            .context("try to read socks5 prefix header")?;

        let is_socks5 = n >= 2
            && ProtocolVersion::from(peek_buf[0]) == ProtocolVersion::Socks5
            && !(0..(peek_buf[1] as usize + 2).min(SOCKS5_HEADER_PEEK_LEN))
                .any(|i| matches!(SocksMethod::from(peek_buf[i]), SocksMethod::Unknown(_)));

        tracing::trace!("socks5 prefix header read (is socks5: {is_socks5}");

        let offset = SOCKS5_HEADER_PEEK_LEN - n;
        if offset > 0 {
            tracing::trace!(
                %n,
                "move socks5 peek buffer cursor due to reading not enough"
            );
            for i in (0..n).rev() {
                peek_buf[i + offset] = peek_buf[i];
            }
        }

        let mut peek = StackReader::new(peek_buf);
        peek.skip(offset);

        let stream = PeekStream::new(peek, stream);

        if is_socks5 {
            self.socks5_acceptor
                .serve(ctx, stream)
                .await
                .map_err(Into::into)
        } else {
            self.fallback.serve(ctx, stream).await.map_err(Into::into)
        }
    }
}

const SOCKS5_HEADER_PEEK_LEN: usize = 5;

/// [`PeekStream`] alias used by [`Socks5PeekRouter`].
pub type Socks5PeekStream<S> = PeekStream<StackReader<SOCKS5_HEADER_PEEK_LEN>, S>;

#[cfg(test)]
mod test {
    use rama_core::service::{RejectError, service_fn};
    use std::convert::Infallible;

    use rama_net::stream::Stream;

    use super::*;

    #[tokio::test]
    async fn test_peek_router() {
        let socks5_service = service_fn(async |_, _| Ok::<_, Infallible>("socks5"));
        let other_service = service_fn(async |_, _| Ok::<_, Infallible>("other"));

        let peek_socks5_svc = Socks5PeekRouter::new(socks5_service).with_fallback(other_service);

        let response = peek_socks5_svc
            .serve(Context::default(), std::io::Cursor::new(b"".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_socks5_svc
            .serve(
                Context::default(),
                std::io::Cursor::new(b"\x05\x01\x00".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!("socks5", response);

        let response = peek_socks5_svc
            .serve(
                Context::default(),
                std::io::Cursor::new(b"\x05\x01\x00foobar".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!("socks5", response);

        let response = peek_socks5_svc
            .serve(
                Context::default(),
                std::io::Cursor::new(b"\x05\x02\x01\x00".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!("socks5", response);

        let response = peek_socks5_svc
            .serve(Context::default(), std::io::Cursor::new(b"fo".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_socks5_svc
            .serve(Context::default(), std::io::Cursor::new(b"foo".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_socks5_svc
            .serve(Context::default(), std::io::Cursor::new(b"foobar".to_vec()))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_eof() {
        const CONTENT: &[u8] = b"\x05\x01\x00";

        async fn socks5_service_fn(
            mut stream: impl Stream + Unpin,
        ) -> Result<&'static str, BoxError> {
            let mut v = Vec::default();
            let _ = stream.read_to_end(&mut v).await?;
            assert_eq!(CONTENT, v);

            Ok("ok")
        }
        let tls_service = service_fn(socks5_service_fn);

        let peek_socks5_svc = Socks5PeekRouter::new(tls_service).with_fallback(RejectService::<
            &'static str,
            RejectError,
        >::new(
            RejectError::default(),
        ));

        let response = peek_socks5_svc
            .serve(Context::default(), std::io::Cursor::new(CONTENT.to_vec()))
            .await
            .unwrap();
        assert_eq!("ok", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_no_socks5_eof() {
        let cases = [
            "",
            "a",
            "f",
            "fo",
            "foo",
            "abcd",
            "abcde",
            "foobarbazbananas",
        ];
        for content in cases {
            async fn socks5_service_fn() -> Result<Vec<u8>, BoxError> {
                Ok("socks5".as_bytes().to_vec())
            }
            let socks5_service = service_fn(socks5_service_fn);

            async fn other_service_fn(
                mut stream: impl Stream + Unpin,
            ) -> Result<Vec<u8>, BoxError> {
                let mut v = Vec::default();
                let _ = stream.read_to_end(&mut v).await?;
                Ok(v)
            }
            let other_service = service_fn(other_service_fn);

            let peek_socks5_svc =
                Socks5PeekRouter::new(socks5_service).with_fallback(other_service);

            let response = peek_socks5_svc
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
