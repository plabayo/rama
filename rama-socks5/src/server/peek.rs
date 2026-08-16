use std::time::Duration;

use rama_core::{
    Service,
    error::{BoxError, ErrorContext},
    io::{
        PeekIoProvider, PrefixedIo, StackReader,
        peek::{
            PeekOutput, PeekStopReason, PeekTimeoutError, PeekTimeoutPolicy, PeekVerdict,
            peek_input_until_verdict_with_options,
        },
    },
    service::RejectService,
    telemetry::tracing,
};

use crate::proto::{ProtocolVersion, SocksMethod};

/// A [`Service`] router that can be used to support
/// socks5 traffic as well as non-socks5 traffic.
///
/// By default non-socks5 traffic is rejected using [`RejectService`].
/// Use [`Socks5PeekRouter::with_fallback`] to configure the fallback service.
/// A definitive non-SOCKS5 prefix invokes that fallback under either timeout
/// policy; an inconclusive timeout is fail-open by default and can be made
/// fail-closed with [`Socks5PeekRouter::with_peek_timeout_policy`].
///
/// This kind of router can be useful in case you want to have a proxy
/// which supports for example both HTTP proxy requests as well socks5 proxy requests.
#[derive(Debug, Clone)]
pub struct Socks5PeekRouter<T, F = RejectService<(), NoSocks5RejectError>> {
    socks5_acceptor: T,
    fallback: F,
    peek_timeout: Option<Duration>,
    peek_timeout_policy: PeekTimeoutPolicy,
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
            peek_timeout: None,
            peek_timeout_policy: PeekTimeoutPolicy::default(),
        }
    }

    /// Attach a fallback [`Service`] tp this [`Socks5PeekRouter`].
    pub fn with_fallback<F>(self, fallback: F) -> Socks5PeekRouter<T, F> {
        Socks5PeekRouter {
            socks5_acceptor: self.socks5_acceptor,
            fallback,
            peek_timeout: self.peek_timeout,
            peek_timeout_policy: self.peek_timeout_policy,
        }
    }
}

impl<T, F> Socks5PeekRouter<T, F> {
    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum time spent peeking for a SOCKS5 greeting.
        ///
        /// A timeout is inconclusive. Use
        /// [`Socks5PeekRouter::with_peek_timeout_policy`] to choose whether it
        /// invokes the fallback or rejects the connection.
        pub fn peek_timeout(mut self, peek_timeout: Option<Duration>) -> Self {
            self.peek_timeout = peek_timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set how an inconclusive peek timeout is handled.
        ///
        /// Defaults to [`PeekTimeoutPolicy::FailOpen`]. A definitive non-SOCKS5
        /// prefix invokes the fallback under either policy.
        pub fn peek_timeout_policy(mut self, peek_timeout_policy: PeekTimeoutPolicy) -> Self {
            self.peek_timeout_policy = peek_timeout_policy;
            self
        }
    }
}

impl<PeekableInput, Output, T, F> Service<PeekableInput> for Socks5PeekRouter<T, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<Socks5PrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<Socks5PrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, mut input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let mut peek_buf = [0u8; SOCKS5_HEADER_PEEK_LEN];
        let peekable_io = input.peek_io_mut();

        let PeekOutput {
            data: socks5_method,
            peek_size,
            stop_reason,
        } = peek_input_until_verdict_with_options(
            peekable_io,
            &mut peek_buf,
            0,
            self.peek_timeout,
            None,
            |buffer| {
                // A SOCKS5 greeting opens with the version byte 0x05. Reject any
                // other first byte immediately instead of waiting for a second
                // byte that a non-SOCKS5 peer may never send.
                if ProtocolVersion::from(buffer[0]) != ProtocolVersion::Socks5 {
                    return PeekVerdict::Reject;
                }
                if buffer.len() < 2 {
                    return PeekVerdict::NeedMore;
                }
                match SocksMethod::from(buffer[1]) {
                    SocksMethod::Unknown(_) => PeekVerdict::Reject,
                    known_method => PeekVerdict::Match(known_method),
                }
            },
        )
        .await;

        if stop_reason == PeekStopReason::Timeout
            && self.peek_timeout_policy == PeekTimeoutPolicy::FailClosed
        {
            return Err(PeekTimeoutError::new().into());
        }

        let is_socks5 = socks5_method.is_some();

        tracing::trace!(
            "socks5 prefix header read (is socks5: {is_socks5}; method = {socks5_method:?})"
        );

        let offset = SOCKS5_HEADER_PEEK_LEN - peek_size;
        if offset > 0 {
            tracing::trace!(
                %peek_size,
                "move socks5 peek buffer cursor due to reading not enough"
            );
            peek_buf.copy_within(0..peek_size, offset);
        }

        let mut peek = StackReader::new(peek_buf);
        peek.skip(offset);

        let peeked_input = input.map_peek_io(|io| PrefixedIo::new(peek, io));

        if is_socks5 {
            self.socks5_acceptor
                .serve(peeked_input)
                .await
                .into_box_error()
        } else {
            self.fallback.serve(peeked_input).await.into_box_error()
        }
    }
}

const SOCKS5_HEADER_PEEK_LEN: usize = 2;

/// [`PrefixedIo`] alias used by [`Socks5PeekRouter`].
pub type Socks5PrefixedIo<S> = PrefixedIo<StackReader<SOCKS5_HEADER_PEEK_LEN>, S>;

#[cfg(test)]
mod test {
    use rama_core::{ServiceInput, io::Io, service::service_fn};
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};

    use std::{
        collections::VecDeque,
        convert::Infallible,
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use super::*;

    #[tokio::test]
    async fn test_peek_router() {
        let socks5_service = service_fn(async || Ok::<_, Infallible>("socks5"));
        let other_service = service_fn(async || Ok::<_, Infallible>("other"));

        let peek_socks5_svc = Socks5PeekRouter::new(socks5_service).with_fallback(other_service);

        let response = peek_socks5_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_socks5_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"\x05\x01\x00".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("socks5", response);

        let response = peek_socks5_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"\x05\x01\x00foobar".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("socks5", response);

        let response = peek_socks5_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"\x05\x02\x01\x00".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("socks5", response);

        let response = peek_socks5_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"fo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_socks5_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_socks5_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);
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

            async fn other_service_fn(mut stream: impl Io + Unpin) -> Result<Vec<u8>, BoxError> {
                let mut v = Vec::default();
                _ = stream.read_to_end(&mut v).await?;
                Ok(v)
            }
            let other_service = service_fn(other_service_fn);

            let peek_socks5_svc =
                Socks5PeekRouter::new(socks5_service).with_fallback(other_service);

            let response = peek_socks5_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    content.as_bytes().to_vec(),
                )))
                .await
                .unwrap();

            assert_eq!(content.as_bytes(), &response[..]);
        }
    }

    #[tokio::test]
    async fn non_socks5_prefix_then_idle_falls_back_without_blocking() {
        // A peer that opens with a non-SOCKS5 byte and then stays connected
        // without sending a second byte must fall through to the fallback, not
        // block while the router waits for the greeting's method byte.
        let socks5_service = service_fn(async || Ok::<_, Infallible>("socks5"));
        let other_service = service_fn(async || Ok::<_, Infallible>("other"));
        let peek_socks5_svc = Socks5PeekRouter::new(socks5_service).with_fallback(other_service);

        let stream = ScriptedReader::new([b"f".as_slice()], true);

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            peek_socks5_svc.serve(ServiceInput::new(stream)),
        )
        .await
        .expect("socks5 peek must fail fast on a non-SOCKS5 prefix, not block")
        .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn fragmented_socks5_greeting_is_detected() {
        // The 2-byte greeting arriving one byte per read must still be routed to
        // the SOCKS5 service.
        let socks5_service = service_fn(async || Ok::<_, Infallible>("socks5"));
        let other_service = service_fn(async || Ok::<_, Infallible>("other"));
        let peek_socks5_svc = Socks5PeekRouter::new(socks5_service).with_fallback(other_service);

        let stream = ScriptedReader::new([b"\x05".as_slice(), b"\x01".as_slice()], false);

        let response = peek_socks5_svc
            .serve(ServiceInput::new(stream))
            .await
            .unwrap();
        assert_eq!("socks5", response);
    }

    #[tokio::test]
    async fn partial_socks5_greeting_timeout_defaults_to_fail_open_and_replays() {
        async fn fallback_service_fn(
            mut stream: impl Io + Unpin,
        ) -> Result<&'static str, io::Error> {
            let mut prefix = [0_u8; 1];
            stream.read_exact(&mut prefix).await?;
            assert_eq!(b"\x05", &prefix);
            Ok("fallback")
        }

        let router = Socks5PeekRouter::new(service_fn(async || Ok::<_, Infallible>("socks5")))
            .with_peek_timeout(Duration::from_millis(10))
            .with_fallback(service_fn(fallback_service_fn));
        let input = ServiceInput::new(ScriptedReader::new([b"\x05".as_slice()], true));

        let response = router.serve(input).await.unwrap();
        assert_eq!("fallback", response);
    }

    #[tokio::test]
    async fn partial_socks5_greeting_fail_closed_returns_error_without_fallback() {
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls_for_service = Arc::clone(&fallback_calls);
        let fallback = service_fn(move || {
            fallback_calls_for_service.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, Infallible>("fallback") }
        });
        let router = Socks5PeekRouter::new(service_fn(async || Ok::<_, Infallible>("socks5")))
            .with_peek_timeout(Duration::from_millis(10))
            .with_peek_timeout_policy(PeekTimeoutPolicy::FailClosed)
            .with_fallback(fallback);
        let input = ServiceInput::new(ScriptedReader::new([b"\x05".as_slice()], true));

        let error = router.serve(input).await.unwrap_err();
        assert!(error.downcast_ref::<PeekTimeoutError>().is_some());
        assert_eq!(0, fallback_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn definitive_non_socks5_prefix_falls_back_under_both_timeout_policies() {
        for policy in [PeekTimeoutPolicy::FailOpen, PeekTimeoutPolicy::FailClosed] {
            let router = Socks5PeekRouter::new(service_fn(async || Ok::<_, Infallible>("socks5")))
                .with_peek_timeout(Duration::from_millis(10))
                .with_peek_timeout_policy(policy)
                .with_fallback(service_fn(async || Ok::<_, Infallible>("fallback")));

            let response = router
                .serve(ServiceInput::new(std::io::Cursor::new(vec![4])))
                .await
                .unwrap();
            assert_eq!("fallback", response);
        }
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
