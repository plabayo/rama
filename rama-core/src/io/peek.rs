use core::num::NonZeroUsize;
use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    time::Instant,
};

/// Result of a [`peek_input_until`] call.
///
/// `peek_size` reports how many bytes were copied into the caller-provided
/// buffer before peeking stopped. `data` is only populated when the predicate
/// matched those bytes.
#[derive(Debug)]
pub struct PeekOutput<D> {
    pub data: Option<D>,
    pub peek_size: usize,
}

#[inline(always)]
/// Read into `buffer` until `predicate` matches, peeking stops, or the optional
/// `timeout` expires.
///
/// This helper is intended for protocol sniffing and similar cases where a
/// caller needs to inspect a small prefix without committing to a full parser.
///
/// Peeking stops when one of the following happens:
/// - `predicate` returns `Some(_)`;
/// - the reader returns EOF;
/// - the reader returns an error;
/// - the optional timeout elapses;
/// - the internal read-attempt budget is exhausted.
///
/// The attempt budget defaults to `max(buffer.len() / 4, 1) + 1` reads. This keeps
/// peeking bounded even for slow or fragmented inputs, but it also means this
/// function can return partial data before the buffer is full. For protocol
/// sniffing on small buffers (e.g. a 5-byte TLS-record buffer), the buffer-derived
/// default can be too small under TCP fragmentation; prefer
/// [`peek_input_until_with_options`] and pass an explicit `max_attempts`.
pub fn peek_input_until<R, O, P>(
    reader: &mut R,
    buffer: &mut [u8],
    timeout: Option<Duration>,
    predicate: P,
) -> impl Future<Output = PeekOutput<O>>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> Option<O>,
{
    peek_input_until_with_offset(reader, buffer, 0, timeout, predicate)
}

/// Same as [`peek_input_until`] but with a starting offset as peek-size.
///
/// It is assumed that the offst is within the buffer boundaries,
/// but it will be clamped to the `buffer.len()` regardless.
///
/// Uses the buffer-derived attempt budget; see [`peek_input_until_with_options`]
/// when you need an explicit budget.
#[inline]
pub fn peek_input_until_with_offset<R, O, P>(
    reader: &mut R,
    buffer: &mut [u8],
    offset: usize,
    timeout: Option<Duration>,
    predicate: P,
) -> impl Future<Output = PeekOutput<O>>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> Option<O>,
{
    let default_budget =
        NonZeroUsize::new(buffer.len().saturating_div(4).max(1) + 1).unwrap_or(NonZeroUsize::MIN);
    peek_input_until_with_options(
        reader,
        buffer,
        offset,
        timeout,
        Some(default_budget),
        predicate,
    )
}

/// Verdict returned by a fail-fast peek predicate, used with
/// [`peek_input_until_verdict`] and [`peek_input_until_verdict_with_options`].
///
/// The plain [`peek_input_until`] predicate returns `Option<O>`, where `None`
/// always means "read more". That is fine when the input is expected to match
/// or hit EOF, but it cannot express "these bytes can *never* match" — so a
/// peer that sends a short non-matching prefix and then goes quiet keeps the
/// peek loop blocked on a read for a byte that never arrives (e.g. waiting for
/// a 5th TLS-record byte after 4 bytes of some other protocol). A `PeekVerdict`
/// predicate can `Reject` such a prefix immediately, so peeking fails fast and
/// dispatch falls through to the next protocol/fallback without blocking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeekVerdict<O> {
    /// The peeked bytes match; stop and surface `Some(data)`.
    Match(O),
    /// The peeked bytes can never match; stop now, surface no data, and do not
    /// issue another read.
    Reject,
    /// Not enough bytes to decide yet; keep reading (subject to the timeout,
    /// EOF, and attempt budget).
    NeedMore,
}

/// Same as [`peek_input_until`] but with explicit control over the starting offset
/// and the read-attempt budget.
///
/// `max_attempts`:
/// - `Some(n)` — stop after `n` read attempts even if the predicate did not match.
/// - `None` — no attempt cap; rely on the reader's EOF and the optional `timeout`.
///
/// The default budget used by [`peek_input_until`] and [`peek_input_until_with_offset`]
/// is derived from the buffer length (`max(buffer.len() / 4, 1) + 1`), which is a
/// reasonable fallback for sizable buffers but can be too tight for small protocol-
/// sniffing buffers under TCP fragmentation. Prefer this function with an explicit
/// budget when reading from untrusted/proxied peers.
///
/// This is an `Option`-predicate wrapper over
/// [`peek_input_until_verdict_with_options`]: `Some` maps to
/// [`PeekVerdict::Match`] and `None` to [`PeekVerdict::NeedMore`] (it never
/// rejects). Use the verdict variant directly when you want fail-fast rejection.
pub fn peek_input_until_with_options<R, O, P>(
    reader: &mut R,
    buffer: &mut [u8],
    offset: usize,
    timeout: Option<Duration>,
    max_attempts: Option<NonZeroUsize>,
    predicate: P,
) -> impl Future<Output = PeekOutput<O>>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> Option<O>,
{
    peek_input_until_verdict_with_options(
        reader,
        buffer,
        offset,
        timeout,
        max_attempts,
        move |buf| match predicate(buf) {
            Some(data) => PeekVerdict::Match(data),
            None => PeekVerdict::NeedMore,
        },
    )
}

/// Fail-fast variant of [`peek_input_until`] using a [`PeekVerdict`] predicate.
///
/// Uses the same buffer-derived attempt budget as [`peek_input_until`]; prefer
/// [`peek_input_until_verdict_with_options`] with an explicit budget for small
/// protocol-sniffing buffers under TCP fragmentation.
#[inline]
pub fn peek_input_until_verdict<R, O, P>(
    reader: &mut R,
    buffer: &mut [u8],
    timeout: Option<Duration>,
    predicate: P,
) -> impl Future<Output = PeekOutput<O>>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> PeekVerdict<O>,
{
    let default_budget =
        NonZeroUsize::new(buffer.len().saturating_div(4).max(1) + 1).unwrap_or(NonZeroUsize::MIN);
    peek_input_until_verdict_with_options(
        reader,
        buffer,
        0,
        timeout,
        Some(default_budget),
        predicate,
    )
}

/// Same as [`peek_input_until_with_options`] but with a fail-fast three-way
/// [`PeekVerdict`] predicate. This is the core peek loop; the `Option`-based
/// helpers are thin wrappers that never reject.
///
/// In addition to the stop conditions of [`peek_input_until`], peeking also
/// stops immediately when the predicate returns [`PeekVerdict::Reject`], in
/// which case no further read is issued and `data` is `None`.
pub async fn peek_input_until_verdict_with_options<R, O, P>(
    reader: &mut R,
    buffer: &mut [u8],
    offset: usize,
    timeout: Option<Duration>,
    max_attempts: Option<NonZeroUsize>,
    predicate: P,
) -> PeekOutput<O>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> PeekVerdict<O>,
{
    let mut output = PeekOutput {
        data: None,
        peek_size: offset.min(buffer.len()),
    };

    if buffer[output.peek_size..].is_empty() {
        return output;
    }

    let peek_deadline = timeout.map(|d| Instant::now() + d);
    let attempt_cap = max_attempts.map(NonZeroUsize::get).unwrap_or(usize::MAX);

    for _ in 0..attempt_cap {
        let read_fut = reader.read(&mut buffer[output.peek_size..]);

        let n = match peek_deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    tracing::debug!("I/O peek: abort: deadline reached");
                    return output;
                }

                let remaining = deadline - now;
                match tokio::time::timeout(remaining, read_fut).await {
                    Err(err) => {
                        tracing::debug!("I/O peek: time-fenced peek read timeout error: {err}");
                        return output;
                    }
                    Ok(Err(err)) => {
                        tracing::debug!("I/O peek: time-fenced peek read error: {err}");
                        return output;
                    }
                    Ok(Ok(n)) => n,
                }
            }
            None => match read_fut.await {
                Err(err) => {
                    tracing::debug!("I/O peek: peek read error: {err}");
                    return output;
                }
                Ok(n) => n,
            },
        };

        if n == 0 {
            tracing::trace!("I/O peek: break loop: no new data read...");
            return output;
        }

        output.peek_size = (output.peek_size + n).min(buffer.len());

        match predicate(&buffer[..output.peek_size]) {
            PeekVerdict::Match(data) => {
                output.data = Some(data);
                tracing::trace!("I/O peek: data matched by predicate: return it...");
                return output;
            }
            PeekVerdict::Reject => {
                tracing::trace!("I/O peek: predicate rejected prefix: stop peeking...");
                return output;
            }
            PeekVerdict::NeedMore => {}
        }
    }

    output
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unreachable,
        reason = "test fixture: closure is wired up but never invoked on the tested path"
    )]

    use super::*;

    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::ReadBuf;

    #[tokio::test]
    async fn returns_immediately_for_empty_buffer() {
        let mut reader = tokio_test::io::Builder::new().build();
        let mut buffer = [];

        let output =
            peek_input_until::<_, (), _>(&mut reader, &mut buffer, None, |_| unreachable!()).await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 0);
    }

    #[tokio::test]
    async fn returns_data_when_predicate_matches_on_first_read() {
        let mut reader = tokio_test::io::Builder::new().read(b"hello").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hello").then_some("hello")
        })
        .await;

        assert_eq!(output.data, Some("hello"));
        assert_eq!(output.peek_size, 5);
        assert_eq!(&buffer[..output.peek_size], b"hello");
    }

    #[tokio::test]
    async fn accumulates_across_multiple_reads_until_predicate_matches() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"he")
            .read(b"llo")
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hello").then_some(buf.len())
        })
        .await;

        assert_eq!(output.data, Some(5));
        assert_eq!(output.peek_size, 5);
        assert_eq!(&buffer[..output.peek_size], b"hello");
    }

    #[tokio::test]
    async fn returns_partial_bytes_when_reader_hits_eof_before_match() {
        let mut reader = tokio_test::io::Builder::new().read(b"he").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hello").then_some(())
        })
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn returns_partial_bytes_when_reader_errors_after_progress() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"he")
            .read_error(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hello").then_some(())
        })
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn returns_no_data_when_first_read_errors() {
        let mut reader = tokio_test::io::Builder::new()
            .read_error(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (!buf.is_empty()).then_some(())
        })
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 0);
    }

    #[tokio::test]
    async fn timeout_returns_partial_bytes_already_peeked() {
        let mut reader = TwoPhaseReader {
            first_chunk: Some(b"he".to_vec()),
            sleep: Some(Box::pin(tokio::time::sleep(Duration::from_millis(50)))),
        };
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(
            &mut reader,
            &mut buffer,
            Some(Duration::from_millis(10)),
            |buf| (buf == b"hello").then_some(()),
        )
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn stops_when_attempt_budget_is_exhausted() {
        let mut reader = tokio_test::io::Builder::new().read(b"h").read(b"e").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hel").then_some(())
        })
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
        assert_eq!(&buffer[..output.peek_size], b"he");
    }

    #[tokio::test]
    async fn explicit_max_attempts_overrides_buffer_derived_budget() {
        // Buffer-derived budget for an 8-byte buffer is 3 attempts; this reader
        // would normally exhaust the budget before "hel" is seen. With an explicit
        // max_attempts of 5 the predicate matches.
        let mut reader = tokio_test::io::Builder::new()
            .read(b"h")
            .read(b"e")
            .read(b"l")
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until_with_options(
            &mut reader,
            &mut buffer,
            0,
            None,
            NonZeroUsize::new(5),
            |buf| (buf == b"hel").then_some(()),
        )
        .await;

        assert_eq!(output.data, Some(()));
        assert_eq!(output.peek_size, 3);
    }

    #[tokio::test]
    async fn explicit_max_attempts_none_means_no_cap() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"h")
            .read(b"e")
            .read(b"l")
            .read(b"l")
            .read(b"o")
            .build();
        let mut buffer = [0_u8; 8];

        let output =
            peek_input_until_with_options(&mut reader, &mut buffer, 0, None, None, |buf| {
                (buf == b"hello").then_some(buf.len())
            })
            .await;

        assert_eq!(output.data, Some(5));
        assert_eq!(output.peek_size, 5);
    }

    #[tokio::test]
    async fn verdict_match_returns_data() {
        let mut reader = tokio_test::io::Builder::new().read(b"hello").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until_verdict(&mut reader, &mut buffer, None, |buf| {
            if buf == b"hello" {
                PeekVerdict::Match("hello")
            } else {
                PeekVerdict::NeedMore
            }
        })
        .await;

        assert_eq!(output.data, Some("hello"));
        assert_eq!(output.peek_size, 5);
    }

    #[tokio::test]
    async fn verdict_need_more_accumulates_across_reads_until_match() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"he")
            .read(b"llo")
            .build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until_verdict(&mut reader, &mut buffer, None, |buf| {
            if buf == b"hello" {
                PeekVerdict::Match(buf.len())
            } else if b"hello".starts_with(buf) {
                PeekVerdict::NeedMore
            } else {
                PeekVerdict::Reject
            }
        })
        .await;

        assert_eq!(output.data, Some(5));
        assert_eq!(output.peek_size, 5);
    }

    #[tokio::test]
    async fn verdict_reject_returns_without_blocking_on_idle_peer() {
        // A peer that sends a short non-matching prefix and then stays connected
        // without sending more (never EOF). A rejecting predicate must return
        // immediately; otherwise the next read would block forever and only the
        // timeout below would end it.
        let mut reader = IdleAfterReader::new(b"PING");

        let output = tokio::time::timeout(
            Duration::from_secs(5),
            peek_input_until_verdict(&mut reader, &mut [0_u8; 5], None, |buf: &[u8]| {
                if buf.first() == Some(&0x16) {
                    PeekVerdict::Match(())
                } else {
                    PeekVerdict::Reject
                }
            }),
        )
        .await
        .expect("reject must stop peeking without waiting for a full buffer");

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 4);
    }

    #[tokio::test]
    async fn verdict_without_attempt_cap_assembles_fragmented_prefix() {
        // Under TCP fragmentation the small buffer-derived budget could give up
        // before the prefix is complete; with no attempt cap and a `NeedMore`
        // verdict the predicate keeps reading (one byte per read here) until it
        // can decide.
        let mut reader = tokio_test::io::Builder::new()
            .read(b"\x16")
            .read(b"\x03")
            .read(b"\x03")
            .read(b"\x00")
            .read(b"\x2a")
            .build();
        let mut buffer = [0_u8; 5];

        let output = peek_input_until_verdict_with_options(
            &mut reader,
            &mut buffer,
            0,
            None,
            None,
            |buf: &[u8]| {
                if buf.first() != Some(&0x16) {
                    PeekVerdict::Reject
                } else if buf.len() >= 5 {
                    PeekVerdict::Match(())
                } else {
                    PeekVerdict::NeedMore
                }
            },
        )
        .await;

        assert!(output.data.is_some());
        assert_eq!(output.peek_size, 5);
    }

    #[tokio::test]
    async fn option_wrapper_never_rejects_and_reads_until_eof() {
        // The Option-based wrapper must preserve the old semantics: `None` keeps
        // reading (it is mapped to `NeedMore`, never `Reject`).
        let mut reader = tokio_test::io::Builder::new().read(b"he").build();
        let mut buffer = [0_u8; 8];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"hello").then_some(())
        })
        .await;

        assert!(output.data.is_none());
        assert_eq!(output.peek_size, 2);
    }

    #[tokio::test]
    async fn default_budget_is_len_div_4_plus_one_attempts() {
        // Documented default budget for a 4-byte buffer is `(4/4).max(1) + 1 = 2`
        // reads. The predicate matches exactly on the second read; a budget off
        // by one (the `+ 1` dropped) would stop after the first and miss it.
        let mut reader = tokio_test::io::Builder::new().read(b"a").read(b"b").build();
        let mut buffer = [0_u8; 4];

        let output = peek_input_until(&mut reader, &mut buffer, None, |buf| {
            (buf == b"ab").then_some(())
        })
        .await;

        assert_eq!(output.data, Some(()));
        assert_eq!(output.peek_size, 2);
    }

    #[tokio::test]
    async fn verdict_default_budget_is_len_div_4_plus_one_attempts() {
        // Same documented default budget for the verdict variant.
        let mut reader = tokio_test::io::Builder::new().read(b"a").read(b"b").build();
        let mut buffer = [0_u8; 4];

        let output = peek_input_until_verdict(&mut reader, &mut buffer, None, |buf: &[u8]| {
            if buf == b"ab" {
                PeekVerdict::Match(())
            } else if b"ab".starts_with(buf) {
                PeekVerdict::NeedMore
            } else {
                PeekVerdict::Reject
            }
        })
        .await;

        assert_eq!(output.data, Some(()));
        assert_eq!(output.peek_size, 2);
    }

    /// A reader that yields a fixed prefix on the first read, then never
    /// produces more data nor EOF — it simply pends, modelling a peer that sent
    /// a short prefix and then went idle while keeping the connection open.
    struct IdleAfterReader {
        prefix: Option<&'static [u8]>,
    }

    impl IdleAfterReader {
        fn new(prefix: &'static [u8]) -> Self {
            Self {
                prefix: Some(prefix),
            }
        }
    }

    impl AsyncRead for IdleAfterReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(prefix) = self.prefix.take() {
                let n = prefix.len().min(buf.remaining());
                buf.put_slice(&prefix[..n]);
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }

    struct TwoPhaseReader {
        first_chunk: Option<Vec<u8>>,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    }

    impl AsyncRead for TwoPhaseReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(chunk) = self.first_chunk.take() {
                buf.put_slice(&chunk[..chunk.len().min(buf.remaining())]);
                return Poll::Ready(Ok(()));
            }

            match self.sleep.as_mut() {
                Some(sleep) => sleep.as_mut().poll(cx).map(|_| Ok(())),
                None => Poll::Ready(Ok(())),
            }
        }
    }
}
