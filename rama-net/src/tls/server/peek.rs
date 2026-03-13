use std::time::Duration;

use rama_core::{
    Service,
    error::{BoxError, ErrorContext},
    io::{
        PeekIoProvider, PrefixedIo, StackReader,
        peek::{PeekOutput, peek_input_until},
    },
    service::RejectService,
    telemetry::tracing,
};

/// A [`Service`] router that can be used to support
/// tls traffic as well as non-tls traffic.
///
/// By default non-tls traffic is rejected using [`RejectService`].
/// Use [`TlsPeekRouter::with_fallback`] to configure the fallback service.
#[derive(Debug, Clone)]
pub struct TlsPeekRouter<T, F = RejectService<(), NoTlsRejectError>> {
    tls_acceptor: T,
    fallback: F,
    peek_timeout: Option<Duration>,
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
            peek_timeout: None,
        }
    }

    /// Attach a fallback [`Service`] tp this [`TlsPeekRouter`].
    pub fn with_fallback<F>(self, fallback: F) -> TlsPeekRouter<T, F> {
        TlsPeekRouter {
            tls_acceptor: self.tls_acceptor,
            fallback,
            peek_timeout: self.peek_timeout,
        }
    }
}

impl<T, F> TlsPeekRouter<T, F> {
    rama_utils::macros::generate_set_and_with! {
        /// Set the peek window to timeout on
        pub fn peek_timeout(mut self, peek_timeout: Option<Duration>) -> Self {
            self.peek_timeout = peek_timeout;
            self
        }
    }
}

impl<PeekableInput, Output, T, F> Service<PeekableInput> for TlsPeekRouter<T, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<TlsPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<TlsPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, mut input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let mut peek_buf = [0u8; TLS_HEADER_PEEK_LEN];
        let peek_reader = input.peek_io_mut();

        let PeekOutput { data, peek_size } =
            peek_input_until(peek_reader, &mut peek_buf, self.peek_timeout, |buffer| {
                if buffer.len() == TLS_HEADER_PEEK_LEN
                    && matches!(buffer, [0x16, 0x03, 0x00..=0x04, ..])
                {
                    Some(())
                } else {
                    None
                }
            })
            .await;
        let is_tls = data.is_some();

        tracing::trace!(%is_tls, "tls prefix header read: is tls: {is_tls}");

        let offset = TLS_HEADER_PEEK_LEN - peek_size;
        if offset > 0 {
            tracing::trace!(
                "move tls peek buffer cursor due to reading not enough: (read: {peek_size})"
            );
            peek_buf.copy_within(0..peek_size, offset);
        }

        let mut peek_stack_data = StackReader::new(peek_buf);
        peek_stack_data.skip(offset);

        let mapped_input = input.map_peek_io(|io| PrefixedIo::new(peek_stack_data, io));

        if is_tls {
            self.tls_acceptor.serve(mapped_input).await.into_box_error()
        } else {
            self.fallback.serve(mapped_input).await.into_box_error()
        }
    }
}

const TLS_HEADER_PEEK_LEN: usize = 5;

/// [`PrefixedIo`] alias used by [`TlsPeekRouter`].
pub type TlsPrefixedIo<S> = PrefixedIo<StackReader<TLS_HEADER_PEEK_LEN>, S>;

#[cfg(test)]
mod test {
    use rama_core::{
        ServiceInput,
        service::{RejectError, service_fn},
    };
    use std::convert::Infallible;
    use tokio::io::AsyncReadExt as _;

    use rama_core::io::Io;

    use super::*;

    #[tokio::test]
    async fn test_peek_router() {
        let tls_service = service_fn(async || Ok::<_, Infallible>("tls"));
        let plain_service = service_fn(async || Ok::<_, Infallible>("plain"));

        let peek_tls_svc = TlsPeekRouter::new(tls_service).with_fallback(plain_service);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("plain", response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"\x16\x03\x03\x00\x2afoo".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("tls", response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("plain", response);

        let response = peek_tls_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("plain", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_eof() {
        const CONTENT: &[u8] = b"\x16\x03\x03\x00\x2afoo";

        async fn tls_service_fn(mut stream: impl Io + Unpin) -> Result<&'static str, BoxError> {
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
            .serve(ServiceInput::new(std::io::Cursor::new(CONTENT.to_vec())))
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

            async fn plain_service_fn(mut stream: impl Io + Unpin) -> Result<Vec<u8>, BoxError> {
                let mut v = Vec::default();
                let _ = stream.read_to_end(&mut v).await?;
                Ok(v)
            }
            let plain_service = service_fn(plain_service_fn);

            let peek_tls_svc = TlsPeekRouter::new(tls_service).with_fallback(plain_service);

            let response = peek_tls_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    content.as_bytes().to_vec(),
                )))
                .await
                .unwrap();

            assert_eq!(content.as_bytes(), &response[..]);
        }
    }
}
