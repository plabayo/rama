use std::num::NonZeroUsize;

use rama_core::{
    Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    graceful::scope_context,
    io::{
        PeekIoProvider, PrefixedIo, ReplayReader, StackReader,
        peek::{
            PeekEgressPredicate, PeekMapped, PeekOptions, PeekOutput, PeekPolicy,
            PeekPolicyProvider, PeekVerdict, default_egress_peek_max_size,
            peek_input_until_verdict_with_options,
        },
    },
    service::RejectService,
    telemetry::tracing,
};

/// A [`Service`] router that can be used to support
/// tls traffic as well as non-tls traffic.
///
/// By default non-tls traffic is rejected using [`RejectService`].
/// Use [`TlsPeekRouter::with_fallback`] to configure the fallback service.
/// A definitive non-TLS prefix invokes that fallback under any policy; an
/// inconclusive cutoff is handled by the [`PeekPolicy`], see
/// [`TlsPeekRouter::with_peek_policy`].
///
/// On a [`BridgeIo`] the server's first bytes are judged by [`TlsEgressPredicate`].
///
/// [`BridgeIo`]: rama_core::io::BridgeIo
#[derive(Debug, Clone)]
pub struct TlsPeekRouter<T, F = RejectService<(), NoTlsRejectError>, Pol = PeekPolicy> {
    tls_acceptor: T,
    fallback: F,
    peek_policy: Pol,
    max_egress_peek_size: NonZeroUsize,
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
            peek_policy: PeekPolicy::FAIL_OPEN,
            max_egress_peek_size: default_egress_peek_max_size(),
        }
    }
}

impl<T, Pol> TlsPeekRouter<T, RejectService<(), NoTlsRejectError>, Pol> {
    /// Attach a fallback [`Service`] tp this [`TlsPeekRouter`].
    pub fn with_fallback<F>(self, fallback: F) -> TlsPeekRouter<T, F, Pol> {
        TlsPeekRouter {
            tls_acceptor: self.tls_acceptor,
            fallback,
            peek_policy: self.peek_policy,
            max_egress_peek_size: self.max_egress_peek_size,
        }
    }
}

impl<T, F, Pol> TlsPeekRouter<T, F, Pol> {
    rama_utils::macros::generate_set_and_with! {
        /// Set the byte limit for peeking the egress.
        pub fn max_egress_peek_size(mut self, max_egress_peek_size: NonZeroUsize) -> Self {
            self.max_egress_peek_size = max_egress_peek_size;
            self
        }
    }

    /// Set how a peek cutoff is handled, using a static [`PeekPolicy`]
    /// or a [`PeekPolicyProvider`] that selects one per input.
    ///
    /// Defaults to [`PeekPolicy::FAIL_OPEN`]. A definitive non-TLS
    /// prefix invokes the fallback under any policy.
    pub fn with_peek_policy<Pol2>(self, peek_policy: Pol2) -> TlsPeekRouter<T, F, Pol2> {
        TlsPeekRouter {
            tls_acceptor: self.tls_acceptor,
            fallback: self.fallback,
            peek_policy,
            max_egress_peek_size: self.max_egress_peek_size,
        }
    }
}

impl<PeekableInput, Output, T, F, Pol> Service<PeekableInput> for TlsPeekRouter<T, F, Pol>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin, PeekEgressIo: Unpin> + ExtensionsRef,
    Output: Send + 'static,
    Pol: PeekPolicyProvider<PeekableInput>,
    T: Service<
            PeekMapped<PeekableInput, TlsPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekMapped<PeekableInput, TlsPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, mut input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let options = PeekOptions::new()
            .with_policy(self.peek_policy.peek_policy(&input))
            .maybe_with_scope(scope_context(input.extensions()))
            .with_max_egress_peek_size(self.max_egress_peek_size);
        let (peek_reader, egress) = input.peek_ios_mut();
        let mut waiter = options.waiter(egress, &TlsEgressPredicate);
        let mut peek_buf = [0u8; TLS_HEADER_PEEK_LEN];

        let PeekOutput {
            data, peek_size, ..
        } = peek_input_until_verdict_with_options(
            peek_reader,
            &mut peek_buf,
            0,
            &mut waiter,
            // No attempt cap: non-TLS prefixes are rejected fast (see
            // `tls_record_header_verdict`), so the only reads that continue are
            // for a still-plausible TLS record header arriving fragmented. Those
            // are bounded by the 5-byte buffer, EOF, and the waiter.
            None,
            tls_record_header_verdict,
        )
        .await;

        waiter.check::<BoxError>()?;

        let is_tls = data.is_some();
        let egress_prefix = waiter.into_egress_prefix();

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

        let mapped_input = input.map_peek_io(
            |io| PrefixedIo::new(peek_stack_data, io),
            |io| PrefixedIo::new(ReplayReader::new(egress_prefix), io),
        );

        if is_tls {
            self.tls_acceptor.serve(mapped_input).await.into_box_error()
        } else {
            self.fallback.serve(mapped_input).await.into_box_error()
        }
    }
}

/// [`PeekEgressPredicate`] for the first bytes a TLS server sends.
///
/// Checks a complete record header (content type `0x14..=0x16`, major
/// version `03`, a length within the record limit); plaintext application
/// data is refused by a client before the handshake, while the record minor
/// version is ignored (RFC 8446 5.1). For a handshake
/// record also the handshake type (`ServerHello` / `HelloRetryRequest`) and
/// a sane handshake length. Dummy ChangeCipherSpec records before a handshake
/// record are accepted (TLS 1.3 middlebox compatibility), as is an
/// empty HelloRequest or empty handshake record, which clients skip up to a
/// bound; an alert record matches, as a
/// client reads it as TLS. Decides within the egress limit.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct TlsEgressPredicate;

impl PeekEgressPredicate for TlsEgressPredicate {
    fn egress(&self, bytes: &[u8]) -> PeekVerdict<()> {
        tls_server_flight_verdict(bytes)
    }

    fn peeks_egress(&self) -> bool {
        true
    }
}

const CONTENT_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CONTENT_ALERT: u8 = 0x15;
const CONTENT_HANDSHAKE: u8 = 0x16;
const HANDSHAKE_HELLO_REQUEST: u8 = 0x00;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
/// Dummy ChangeCipherSpec records, empty handshake records and HelloRequests
/// skipped before judging stops with no verdict.
const MAX_SKIPPED_EMPTY_MESSAGES: usize = 4;
/// RFC 8446 5.2 / RFC 5246 6.2.3: 2^14 plus the largest expansion.
const MAX_RECORD_LEN: usize = (1 << 14) + 2048;
/// version, random, session id length, cipher suite and compression method.
const MIN_SERVER_HELLO_LEN: usize = 38;
const MAX_SERVER_HELLO_LEN: usize = 1 << 16;

fn tls_server_flight_verdict(mut bytes: &[u8]) -> PeekVerdict<()> {
    let mut skipped = 0;
    loop {
        let Some(&content_type) = bytes.first() else {
            return PeekVerdict::NeedMore;
        };
        match content_type {
            CONTENT_ALERT | CONTENT_HANDSHAKE | CONTENT_CHANGE_CIPHER_SPEC => {}
            // a client refuses anything else before the handshake, plaintext application data included
            _ => return PeekVerdict::Reject,
        }
        // RFC 8446 5.1: the record minor version is ignored for all purposes
        if bytes.get(1).is_some_and(|&b| b != 0x03) {
            return PeekVerdict::Reject;
        }
        let [_, _, _, hi, lo, ..] = *bytes else {
            return PeekVerdict::NeedMore;
        };
        let record_len = usize::from(u16::from_be_bytes([hi, lo]));
        // RFC 5246 6.2.1: alerts may be fragmented or coalesced before TLS 1.3
        let len_valid = if content_type == CONTENT_CHANGE_CIPHER_SPEC {
            record_len == 1
        } else {
            record_len <= MAX_RECORD_LEN
        };
        if !len_valid {
            return PeekVerdict::Reject;
        }
        let mut body = &bytes[TLS_HEADER_PEEK_LEN..];
        match content_type {
            CONTENT_ALERT => return PeekVerdict::Match(()),
            CONTENT_CHANGE_CIPHER_SPEC => match body {
                [] => return PeekVerdict::NeedMore,
                [0x01, rest @ ..] => {
                    // RFC 8446 5: clients drop dummy ChangeCipherSpec records
                    skipped += 1;
                    if skipped > MAX_SKIPPED_EMPTY_MESSAGES {
                        return PeekVerdict::NeedMore;
                    }
                    bytes = rest;
                }
                _ => return PeekVerdict::Reject,
            },
            _ => {
                let mut remaining = record_len;
                if remaining == 0 {
                    // clients tolerate a bounded number of empty handshake records
                    skipped += 1;
                    if skipped > MAX_SKIPPED_EMPTY_MESSAGES {
                        return PeekVerdict::NeedMore;
                    }
                }
                while remaining > 0 {
                    let Some(&handshake_type) = body.first() else {
                        return PeekVerdict::NeedMore;
                    };
                    if !matches!(
                        handshake_type,
                        HANDSHAKE_HELLO_REQUEST | HANDSHAKE_SERVER_HELLO
                    ) {
                        return PeekVerdict::Reject;
                    }
                    // only bytes of this record belong to the handshake header
                    let header_in_record = remaining.min(4);
                    if handshake_type == HANDSHAKE_HELLO_REQUEST
                        && body.iter().take(header_in_record).skip(1).any(|&b| b != 0)
                    {
                        // a HelloRequest is empty
                        return PeekVerdict::Reject;
                    }
                    if remaining < 4 {
                        // the handshake header continues in a later record: stop judging
                        return if body.len() >= remaining {
                            PeekVerdict::Match(())
                        } else {
                            PeekVerdict::NeedMore
                        };
                    }
                    let [_, a, b, c, ..] = *body else {
                        return PeekVerdict::NeedMore;
                    };
                    if handshake_type == HANDSHAKE_SERVER_HELLO {
                        let hs_len = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
                        return if (MIN_SERVER_HELLO_LEN..=MAX_SERVER_HELLO_LEN).contains(&hs_len) {
                            PeekVerdict::Match(())
                        } else {
                            PeekVerdict::Reject
                        };
                    }
                    // clients skip an empty HelloRequest during the handshake
                    skipped += 1;
                    if skipped > MAX_SKIPPED_EMPTY_MESSAGES {
                        return PeekVerdict::NeedMore;
                    }
                    body = &body[4..];
                    remaining -= 4;
                }
                bytes = body;
            }
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
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf};

    use rama_core::io::Io;

    use super::*;
    use rama_core::{
        extensions::ExtensionsRef,
        graceful::{Scope, attach_scope},
        io::peek::{PeekCutoff, PeekCutoffError},
    };

    fn scoped<I: ExtensionsRef>(input: I) -> I {
        attach_scope(
            input.extensions(),
            &Scope::new().with_timeout(Duration::from_millis(10)),
        );
        input
    }

    fn cutoff_of(error: &BoxError) -> Option<PeekCutoff> {
        error
            .downcast_ref::<PeekCutoffError>()
            .map(PeekCutoffError::cutoff)
    }

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

    #[tokio::test]
    async fn partial_tls_header_cancel_defaults_to_fail_open_and_replays() {
        async fn fallback_service_fn(
            mut stream: impl Io + Unpin,
        ) -> Result<&'static str, io::Error> {
            let mut prefix = [0_u8; 2];
            stream.read_exact(&mut prefix).await?;
            assert_eq!(b"\x16\x03", &prefix);
            Ok("fallback")
        }

        let router = TlsPeekRouter::new(service_fn(async || Ok::<_, Infallible>("tls")))
            .with_fallback(service_fn(fallback_service_fn));
        let input = scoped(ServiceInput::new(tokio::io::join(
            ScriptedReader::new([b"\x16\x03".as_slice()], true),
            tokio::io::sink(),
        )));

        let response = router.serve(input).await.unwrap();
        assert_eq!("fallback", response);
    }

    #[derive(Debug, Clone, rama_core::extensions::Extension)]
    struct Strict;

    #[tokio::test]
    async fn peek_policy_is_selected_per_input() {
        let router = TlsPeekRouter::new(service_fn(async || Ok::<_, Infallible>("tls")))
            .with_peek_policy(|input: &ServiceInput<ScriptedReader>| {
                if input.extensions().contains::<Strict>() {
                    PeekPolicy::FAIL_CLOSED
                } else {
                    PeekPolicy::FAIL_OPEN
                }
            })
            .with_fallback(service_fn(async || Ok::<_, Infallible>("fallback")));
        let partial = || {
            scoped(ServiceInput::new(ScriptedReader::new(
                [b"\x16\x03".as_slice()],
                true,
            )))
        };

        assert_eq!("fallback", router.serve(partial()).await.unwrap());
        let strict = partial();
        strict.extensions().insert(Strict);
        let error = router.serve(strict).await.unwrap_err();
        assert_eq!(Some(PeekCutoff::Cancelled), cutoff_of(&error));
    }

    #[tokio::test]
    async fn partial_tls_header_fail_closed_returns_error_without_fallback() {
        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls_for_service = Arc::clone(&fallback_calls);
        let fallback = service_fn(move || {
            fallback_calls_for_service.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, Infallible>("fallback") }
        });
        let router = TlsPeekRouter::new(service_fn(async || Ok::<_, Infallible>("tls")))
            .with_peek_policy(PeekPolicy::FAIL_CLOSED)
            .with_fallback(fallback);
        let input = scoped(ServiceInput::new(ScriptedReader::new(
            [b"\x16\x03".as_slice()],
            true,
        )));

        let error = router.serve(input).await.unwrap_err();
        assert_eq!(Some(PeekCutoff::Cancelled), cutoff_of(&error));
        assert_eq!(0, fallback_calls.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn definitive_non_tls_prefix_falls_back_under_both_policies() {
        for policy in [PeekPolicy::FAIL_OPEN, PeekPolicy::FAIL_CLOSED] {
            let router = TlsPeekRouter::new(service_fn(async || Ok::<_, Infallible>("tls")))
                .with_peek_policy(policy)
                .with_fallback(service_fn(async || Ok::<_, Infallible>("fallback")));

            let response = router
                .serve(ServiceInput::new(std::io::Cursor::new(b"P".to_vec())))
                .await
                .unwrap();
            assert_eq!("fallback", response);
        }
    }

    #[tokio::test]
    #[cfg(feature = "http")]
    async fn fail_closed_tls_cancel_does_not_cascade_to_http_or_raw_fallbacks() {
        use rama_net::http::server::HttpPeekRouter;

        let http_calls = Arc::new(AtomicUsize::new(0));
        let http_calls_for_service = Arc::clone(&http_calls);
        let http = service_fn(move || {
            http_calls_for_service.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, Infallible>("http") }
        });
        let raw_calls = Arc::new(AtomicUsize::new(0));
        let raw_calls_for_service = Arc::clone(&raw_calls);
        let raw = service_fn(move || {
            raw_calls_for_service.fetch_add(1, Ordering::SeqCst);
            async { Ok::<_, Infallible>("raw") }
        });
        let http_then_raw = HttpPeekRouter::new(http).with_fallback(raw);
        let router = TlsPeekRouter::new(service_fn(async || Ok::<_, Infallible>("tls")))
            .with_peek_policy(PeekPolicy::FAIL_CLOSED)
            .with_fallback(http_then_raw);
        let input = scoped(ServiceInput::new(ScriptedReader::new(
            [b"\x16\x03".as_slice()],
            true,
        )));

        let error = router.serve(input).await.unwrap_err();
        assert_eq!(Some(PeekCutoff::Cancelled), cutoff_of(&error));
        assert_eq!(0, http_calls.load(Ordering::SeqCst));
        assert_eq!(0, raw_calls.load(Ordering::SeqCst));
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

#[cfg(test)]
mod egress_test {
    use super::*;

    fn verdict(bytes: &[u8]) -> PeekVerdict<()> {
        TlsEgressPredicate.egress(bytes)
    }

    /// Every strict prefix is `NeedMore` and the full opening is `Match`.
    fn assert_opening(opening: &[u8]) {
        for end in 1..opening.len() {
            assert_eq!(
                PeekVerdict::NeedMore,
                verdict(&opening[..end]),
                "{opening:x?}[..{end}]"
            );
        }
        assert_eq!(PeekVerdict::Match(()), verdict(opening), "{opening:x?}");
    }

    #[test]
    fn valid_server_openings_match_and_their_prefixes_need_more() {
        // ServerHello TLS 1.2 and 1.3 (legacy 1.2 record version), HelloRetryRequest
        assert_opening(&[0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56]);
        assert_opening(&[0x16, 0x03, 0x01, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76]);
        assert_opening(&[0x16, 0x03, 0x03, 0x00, 0x58, 0x02, 0x00, 0x00, 0x54]);
        // CCS then ServerHello
        assert_opening(&[
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00,
            0x56,
        ]);
        // alert
        assert_opening(&[0x15, 0x03, 0x03, 0x00, 0x02]);
    }

    #[test]
    fn invalid_server_openings_reject() {
        for bytes in [
            &[0x16, 0x03, 0x03, 0x48, 0x01][..],
            &[0x13],
            &[0x18],
            &[0x16, 0x03, 0x03, 0x00, 0x5a, 0x01],
            &[0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x04],
            &[0x14, 0x03, 0x03, 0x00, 0x02],
            &[0x14, 0x03, 0x03, 0x00, 0x01, 0x02],
            &[0x17],
            &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17],
        ] {
            assert_eq!(PeekVerdict::Reject, verdict(bytes), "{bytes:x?}");
        }
    }

    #[test]
    fn handshake_header_split_across_records_is_not_rejected() {
        for split in 1..4u8 {
            let mut bytes = vec![0x16, 0x03, 0x03, 0x00, split, 0x02];
            bytes.extend(std::iter::repeat_n(0x00, usize::from(split) - 1));
            assert_opening(&bytes);
            bytes.extend([0x16, 0x03, 0x03, 0x00, 0x5a]);
            assert_eq!(PeekVerdict::Match(()), verdict(&bytes), "split at {split}");
        }
        assert_eq!(
            PeekVerdict::Reject,
            verdict(&[0x16, 0x03, 0x03, 0x00, 0x01, 0x01])
        );
    }

    #[test]
    fn decides_at_its_bound_and_one_byte_past_it() {
        let ccs_then_hello = [
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00,
            0x56, 0xff,
        ];
        assert_eq!(PeekVerdict::Match(()), verdict(&ccs_then_hello[..15]));
        assert_eq!(PeekVerdict::Match(()), verdict(&ccs_then_hello));
        let garbage = [0x16, 0x03, 0x03, 0x00, 0x5a, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f];
        assert_eq!(PeekVerdict::Reject, verdict(&garbage[..9]));
        assert_eq!(PeekVerdict::Reject, verdict(&garbage));
    }

    #[test]
    fn other_server_first_protocols_reject() {
        for greeting in SERVER_FIRST_GREETINGS {
            assert_eq!(PeekVerdict::Reject, verdict(greeting), "{greeting:x?}");
        }
    }

    #[test]
    fn empty_hello_request_before_the_server_hello_is_skipped() {
        // own record, then the ServerHello record
        assert_opening(&[
            0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x5a,
            0x02, 0x00, 0x00, 0x56,
        ]);
        // same record as the ServerHello
        assert_opening(&[
            0x16, 0x03, 0x03, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x56,
        ]);
        for bytes in [
            // not empty
            &[0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01][..],
            // followed by something that is not a record
            &[0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x32],
            // followed in its record by something that is not a ServerHello
            &[0x16, 0x03, 0x03, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x00, 0x01],
        ] {
            assert_eq!(PeekVerdict::Reject, verdict(bytes), "{bytes:x?}");
        }
    }

    #[test]
    fn tolerated_openings_are_not_rejected() {
        // repeated dummy ChangeCipherSpec records, then the ServerHello
        assert_opening(&[
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03,
            0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56,
        ]);
        let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert_eq!(
            PeekVerdict::NeedMore,
            verdict(&ccs.repeat(MAX_SKIPPED_EMPTY_MESSAGES + 1))
        );
        // any record minor version, empty handshake records before the ServerHello
        assert_opening(&[0x16, 0x03, 0x05, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56]);
        assert_opening(&[
            0x16, 0x03, 0x03, 0x00, 0x00, 0x16, 0x03, 0x03, 0x00, 0x5a, 0x02, 0x00, 0x00, 0x56,
        ]);
        let empty = [0x16, 0x03, 0x03, 0x00, 0x00];
        let bytes = empty.repeat(MAX_SKIPPED_EMPTY_MESSAGES + 1);
        assert_eq!(PeekVerdict::NeedMore, verdict(&bytes));
        assert_eq!(
            PeekVerdict::Reject,
            verdict(&[0x14, 0x03, 0x03, 0x00, 0x00])
        );
        // alerts of any length a client may reassemble, fragmented across records
        assert_eq!(
            PeekVerdict::Match(()),
            verdict(&[0x15, 0x03, 0x03, 0x00, 0x00])
        );
        assert_opening(&[0x15, 0x03, 0x03, 0x00, 0x01]);
        assert_eq!(
            PeekVerdict::Match(()),
            verdict(&[
                0x15, 0x03, 0x03, 0x00, 0x01, 0x01, 0x15, 0x03, 0x03, 0x00, 0x01, 0x70
            ])
        );
    }

    #[test]
    fn hello_requests_beyond_the_cap_give_no_verdict() {
        let hello_request = [0x16, 0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];
        let bytes = hello_request.repeat(MAX_SKIPPED_EMPTY_MESSAGES + 1);
        assert_eq!(PeekVerdict::NeedMore, verdict(&bytes));
        assert_eq!(
            PeekVerdict::NeedMore,
            verdict(&[bytes.as_slice(), b"\x16"].concat())
        );
    }

    #[test]
    fn verdicts_are_prefix_closed() {
        assert_prefix_closed(
            verdict,
            &[0x14, 0x15, 0x16, 0x17, 0x03, 0x01, 0x00, 0x02, 0x5a],
        );
    }

    pub(super) const SERVER_FIRST_GREETINGS: &[&[u8]] = &[
        b"SSH-2.0-OpenSSH_9.6\r\n",
        b"220 mail.example.com ESMTP\r\n",
        b"220 FTP server ready\r\n",
        b"+OK POP3 ready\r\n",
        b"* OK IMAP4rev1 ready\r\n",
        // MySQL handshake v10: 3-byte length, sequence id, protocol version 10
        b"\x4a\x00\x00\x00\x0a8.0.36\x00",
        b"RFB 003.008\n",
        b"\xff\xfd\x18",
        b"\x00",
    ];

    /// For random inputs over `alphabet`, `Match` and `Reject` stay stable under extension.
    pub(super) fn assert_prefix_closed(
        verdict: impl Fn(&[u8]) -> PeekVerdict<()>,
        alphabet: &[u8],
    ) {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..4096 {
            let mut bytes = Vec::new();
            let mut settled = None;
            for _ in 0..24 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let pick = (state % 4) as usize;
                let byte = if pick == 0 {
                    (state >> 8) as u8
                } else {
                    alphabet[(state >> 16) as usize % alphabet.len()]
                };
                bytes.push(byte);
                let now = verdict(&bytes);
                if let Some(settled) = settled {
                    assert_eq!(settled, now, "{bytes:x?}");
                } else if now != PeekVerdict::NeedMore {
                    settled = Some(now);
                }
            }
        }
    }
}
