use std::time::Duration;

use rama_core::{
    Service,
    error::{BoxError, ErrorContext},
    io::{
        PeekIoProvider, PrefixedIo, StackReader,
        peek::{PeekOutput, PeekVerdict, peek_input_until_verdict_with_options},
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

        let PeekOutput { data, peek_size } = peek_input_until_verdict_with_options(
            peek_reader,
            &mut peek_buf,
            0,
            self.peek_timeout,
            // No attempt cap: non-TLS prefixes are rejected fast (see
            // `tls_record_header_verdict`), so the only reads that continue are
            // for a still-plausible TLS record header arriving fragmented. Those
            // are bounded by the 5-byte buffer, EOF, and the optional peek timeout.
            None,
            tls_record_header_verdict,
        )
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

pub(crate) const TLS_HEADER_PEEK_LEN: usize = 5;

/// Fail-fast [`PeekVerdict`] predicate for a TLS record header.
///
/// A TLS record opens with `content_type(0x16 = handshake) version_major(0x03)
/// version_minor(0x00..=0x04)`. It rejects as soon as an already-seen byte
/// cannot belong to that header, so peeking fails fast on a non-TLS prefix
/// instead of blocking until the full 5-byte window arrives; it only asks for
/// more bytes while the prefix is still a valid partial header. Shared by
/// [`TlsPeekRouter`] and the TLS ClientHello peeker.
pub(crate) fn tls_record_header_verdict(buffer: &[u8]) -> PeekVerdict<()> {
    if buffer.first() != Some(&0x16) {
        return PeekVerdict::Reject;
    }
    if buffer.len() >= 2 && buffer[1] != 0x03 {
        return PeekVerdict::Reject;
    }
    if buffer.len() >= 3 && !matches!(buffer[2], 0x00..=0x04) {
        return PeekVerdict::Reject;
    }
    if buffer.len() >= TLS_HEADER_PEEK_LEN {
        PeekVerdict::Match(())
    } else {
        PeekVerdict::NeedMore
    }
}

/// [`PrefixedIo`] alias used by [`TlsPeekRouter`].
pub type TlsPrefixedIo<S> = PrefixedIo<StackReader<TLS_HEADER_PEEK_LEN>, S>;

#[cfg(test)]
mod test {
    use rama_core::{
        ServiceInput,
        service::{RejectError, service_fn},
    };
    use std::{
        collections::VecDeque,
        convert::Infallible,
        io,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};

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
            _ = stream.read_to_end(&mut v).await?;
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
                _ = stream.read_to_end(&mut v).await?;
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

    #[tokio::test]
    async fn non_tls_prefix_then_idle_falls_back_without_blocking() {
        // A peer that opens with a short non-TLS prefix (e.g. a 4-byte `PING`)
        // and then stays connected without sending more must fall through to the
        // fallback, not block while the router waits for a 5th TLS-header byte.
        let tls_service = service_fn(async || Ok::<_, Infallible>("tls"));
        let plain_service = service_fn(async || Ok::<_, Infallible>("plain"));
        let peek_tls_svc = TlsPeekRouter::new(tls_service).with_fallback(plain_service);

        let stream = ScriptedReader::new([b"PING".as_slice()], true);

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            peek_tls_svc.serve(ServiceInput::new(stream)),
        )
        .await
        .expect("tls peek must fail fast on a non-TLS prefix, not block")
        .unwrap();
        assert_eq!("plain", response);
    }

    #[tokio::test]
    async fn fragmented_tls_record_header_is_detected() {
        // The 5-byte TLS record header arriving one byte per read must still be
        // routed to the TLS service; the old buffer-derived 2-attempt budget
        // would have given up after two reads and misrouted it as non-TLS.
        let tls_service = service_fn(async || Ok::<_, Infallible>("tls"));
        let plain_service = service_fn(async || Ok::<_, Infallible>("plain"));
        let peek_tls_svc = TlsPeekRouter::new(tls_service).with_fallback(plain_service);

        let stream = ScriptedReader::new(
            [
                b"\x16".as_slice(),
                b"\x03".as_slice(),
                b"\x03".as_slice(),
                b"\x00".as_slice(),
                b"\x2a".as_slice(),
            ],
            false,
        );

        let response = peek_tls_svc.serve(ServiceInput::new(stream)).await.unwrap();
        assert_eq!("tls", response);
    }

    /// A test stream that yields scripted chunks (one per read), then either
    /// EOFs or idles forever (pending) — modelling a peer that sends a prefix
    /// and then either closes or stays connected without sending more.
    struct ScriptedReader {
        chunks: VecDeque<&'static [u8]>,
        idle_after: bool,
    }

    impl ScriptedReader {
        fn new(chunks: impl IntoIterator<Item = &'static [u8]>, idle_after: bool) -> Self {
            Self {
                chunks: chunks.into_iter().collect(),
                idle_after,
            }
        }
    }

    impl AsyncRead for ScriptedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(chunk) = self.chunks.pop_front() {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                Poll::Ready(Ok(()))
            } else if self.idle_after {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for ScriptedReader {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
