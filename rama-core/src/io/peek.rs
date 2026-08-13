use core::num::NonZeroUsize;
use std::time::Duration;

use rama_utils::octets::kib;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    time::Instant,
};

use super::{PeekIoProvider, PrefixedIo, ReplayReader};
use crate::{
    Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext},
    service::{RejectError, RejectService},
};

/// Default maximum number of bytes inspected by [`PeekRouter`].
pub const DEFAULT_PEEK_MAX_SIZE: usize = kib(8);

/// Default number of bytes requested per read by [`PeekRouter`].
pub const DEFAULT_PEEK_READ_CHUNK_SIZE: usize = 64;

/// A generic [`Service`] router driven by a fail-fast [`PeekVerdict`] predicate.
///
/// Peeking uses a grow-on-demand heap buffer and replays all read bytes. Any
/// outcome other than [`PeekVerdict::Match`] dispatches to the fallback.
#[derive(Debug, Clone)]
pub struct PeekRouter<P, T, F = RejectService<(), RejectError>> {
    predicate: P,
    acceptor: T,
    fallback: F,
    peek_timeout: Option<Duration>,
    max_peek_size: usize,
    peek_read_chunk_size: NonZeroUsize,
}

impl<P, T> PeekRouter<P, T, RejectService<(), RejectError>> {
    /// Create a router that rejects non-matching input by default.
    #[must_use]
    pub fn new(predicate: P, acceptor: T) -> Self {
        Self {
            predicate,
            acceptor,
            fallback: RejectService::default(),
            peek_timeout: None,
            max_peek_size: DEFAULT_PEEK_MAX_SIZE,
            peek_read_chunk_size: NonZeroUsize::new(DEFAULT_PEEK_READ_CHUNK_SIZE)
                .unwrap_or(NonZeroUsize::MIN),
        }
    }

    /// Attach a fallback [`Service`].
    #[must_use]
    pub fn with_fallback<F>(self, fallback: F) -> PeekRouter<P, T, F> {
        PeekRouter {
            predicate: self.predicate,
            acceptor: self.acceptor,
            fallback,
            peek_timeout: self.peek_timeout,
            max_peek_size: self.max_peek_size,
            peek_read_chunk_size: self.peek_read_chunk_size,
        }
    }
}

impl<P, T, F> PeekRouter<P, T, F> {
    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum time spent peeking into the input.
        pub fn peek_timeout(mut self, peek_timeout: Option<Duration>) -> Self {
            self.peek_timeout = peek_timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the byte limit for peeking; this does not impose a time limit.
        pub fn max_peek_size(mut self, max_peek_size: NonZeroUsize) -> Self {
            self.max_peek_size = max_peek_size.get();
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum number of bytes requested per read.
        pub fn peek_read_chunk_size(mut self, peek_read_chunk_size: NonZeroUsize) -> Self {
            self.peek_read_chunk_size = peek_read_chunk_size;
            self
        }
    }
}

impl<T> PeekRouter<(), T> {
    /// Create a router matching a fixed prefix.
    ///
    /// Peeking is limited to the prefix length unless overridden.
    ///
    /// # Panics
    ///
    /// Panics when `prefix` is empty.
    #[must_use]
    pub fn from_prefix(
        prefix: &'static [u8],
        acceptor: T,
    ) -> PeekRouter<impl Clone + Fn(&[u8]) -> PeekVerdict<()>, T> {
        assert!(!prefix.is_empty(), "PeekRouter prefix must not be empty");
        let mut router = PeekRouter::new(
            move |buffer: &[u8]| prefix_peek_verdict(buffer, prefix),
            acceptor,
        );
        router.max_peek_size = prefix.len();
        router
    }
}

impl<PeekableInput, Output, P, T, F> Service<PeekableInput> for PeekRouter<P, T, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    P: Fn(&[u8]) -> PeekVerdict<()> + Send + Sync + 'static,
    T: Service<
            PeekableInput::Mapped<PeekPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<PeekPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, mut input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let mut peek_buffer = Vec::new();
        let data = peek_input_until_verdict_growing(
            input.peek_io_mut(),
            &mut peek_buffer,
            self.max_peek_size,
            self.peek_read_chunk_size,
            self.peek_timeout,
            &self.predicate,
        )
        .await;

        let replay = ReplayReader::new(Bytes::from(peek_buffer));
        let input = input.map_peek_io(|io| PrefixedIo::new(replay, io));

        if data.is_some() {
            self.acceptor.serve(input).await.into_box_error()
        } else {
            self.fallback.serve(input).await.into_box_error()
        }
    }
}

fn prefix_peek_verdict(buffer: &[u8], prefix: &[u8]) -> PeekVerdict<()> {
    let compared_len = buffer.len().min(prefix.len());
    if buffer[..compared_len] != prefix[..compared_len] {
        PeekVerdict::Reject
    } else if buffer.len() >= prefix.len() {
        PeekVerdict::Match(())
    } else {
        PeekVerdict::NeedMore
    }
}

/// [`PrefixedIo`] alias used by [`PeekRouter`].
pub type PeekPrefixedIo<S> = PrefixedIo<ReplayReader, S>;

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
/// It is assumed that the offset is within the buffer boundaries,
/// but it will be clamped to the `buffer.len()` regardless.
/// The predicate is evaluated against the prefilled prefix before reading.
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
/// The predicate is evaluated against the prefilled prefix before reading.
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

    if output.peek_size > 0 {
        match predicate(&buffer[..output.peek_size]) {
            PeekVerdict::Match(data) => {
                output.data = Some(data);
                return output;
            }
            PeekVerdict::Reject => return output,
            PeekVerdict::NeedMore => {}
        }
    }

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

/// Fail-fast peek that **grows** its buffer on demand up to `max_len`, instead
/// of reading into a fixed caller-provided slice like
/// [`peek_input_until_verdict_with_options`].
///
/// Use this for a variable-length prefix (e.g. a TLS ClientHello) so the buffer
/// tracks the bytes actually received rather than being pre-sized to a length
/// the peer declared: memory stays proportional to real input, while `max_len`
/// still bounds a very large — or lying — peer. Once the buffer reaches
/// `max_len` without a verdict, peeking stops with no match.
///
/// `buffer` is caller-owned and may already hold an earlier peek (e.g. a record
/// header); a non-empty existing prefix is classified first and preserved for
/// replay. The predicate is never called with an empty slice. The buffer grows
/// in `read_chunk`-sized steps. Returns the matched value, or `None` on reject /
/// EOF / timeout / reaching `max_len` without a match; either way `buffer` is
/// left holding exactly the peeked bytes.
pub async fn peek_input_until_verdict_growing<R, O, P>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
    max_len: usize,
    read_chunk: NonZeroUsize,
    timeout: Option<Duration>,
    predicate: P,
) -> Option<O>
where
    R: AsyncRead + Unpin,
    P: Fn(&[u8]) -> PeekVerdict<O>,
{
    if !buffer.is_empty() {
        match predicate(buffer) {
            PeekVerdict::Match(data) => return Some(data),
            PeekVerdict::Reject => return None,
            PeekVerdict::NeedMore => {}
        }
    }

    let peek_deadline = timeout.map(|d| Instant::now() + d);
    let chunk = read_chunk.get();

    while buffer.len() < max_len {
        let start = buffer.len();
        let want = chunk.min(max_len - start);
        buffer.resize(start + want, 0);

        let read_fut = reader.read(&mut buffer[start..]);
        let n = match peek_deadline {
            Some(deadline) => {
                let now = Instant::now();
                if now >= deadline {
                    buffer.truncate(start);
                    tracing::debug!("I/O peek(grow): abort: deadline reached");
                    return None;
                }
                match tokio::time::timeout(deadline - now, read_fut).await {
                    Err(err) => {
                        buffer.truncate(start);
                        tracing::debug!("I/O peek(grow): time-fenced read timeout: {err}");
                        return None;
                    }
                    Ok(Err(err)) => {
                        buffer.truncate(start);
                        tracing::debug!("I/O peek(grow): time-fenced read error: {err}");
                        return None;
                    }
                    Ok(Ok(n)) => n,
                }
            }
            None => match read_fut.await {
                Err(err) => {
                    buffer.truncate(start);
                    tracing::debug!("I/O peek(grow): read error: {err}");
                    return None;
                }
                Ok(n) => n,
            },
        };

        buffer.truncate(start + n);
        if n == 0 {
            tracing::trace!("I/O peek(grow): break loop: no new data read...");
            return None;
        }

        match predicate(buffer) {
            PeekVerdict::Match(data) => return Some(data),
            PeekVerdict::Reject => return None,
            PeekVerdict::NeedMore => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unreachable,
        reason = "test fixture: closure is wired up but never invoked on the tested path"
    )]

    use super::*;

    use std::{
        convert::Infallible,
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use crate::{io::Io, service::service_fn};
    use tokio::io::ReadBuf;

    async fn collect_accepted(
        mut stream: impl Io + Unpin,
    ) -> Result<(&'static str, Vec<u8>), io::Error> {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await?;
        Ok(("accepted", bytes))
    }

    async fn collect_fallback(
        mut stream: impl Io + Unpin,
    ) -> Result<(&'static str, Vec<u8>), io::Error> {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await?;
        Ok(("fallback", bytes))
    }

    #[tokio::test]
    async fn peek_router_dispatches_and_replays_all_input() {
        const PREFIXES: &[&[u8]] = &[b"MAGIC", b"SPELL"];

        let router = PeekRouter::new(
            |buffer: &[u8]| {
                if PREFIXES.iter().any(|prefix| buffer.starts_with(prefix)) {
                    PeekVerdict::Match(())
                } else if PREFIXES.iter().any(|prefix| prefix.starts_with(buffer)) {
                    PeekVerdict::NeedMore
                } else {
                    PeekVerdict::Reject
                }
            },
            service_fn(collect_accepted),
        )
        .with_max_peek_size(NonZeroUsize::new(5).unwrap())
        .with_peek_read_chunk_size(NonZeroUsize::new(2).unwrap())
        .with_fallback(service_fn(collect_fallback));

        let matched = router
            .serve(std::io::Cursor::new(b"MAGIC payload".to_vec()))
            .await
            .unwrap();
        assert_eq!(("accepted", b"MAGIC payload".to_vec()), matched);

        let second_match = router
            .serve(std::io::Cursor::new(b"SPELL payload".to_vec()))
            .await
            .unwrap();
        assert_eq!(("accepted", b"SPELL payload".to_vec()), second_match);

        let rejected = router
            .serve(std::io::Cursor::new(b"OTHER payload".to_vec()))
            .await
            .unwrap();
        assert_eq!(("fallback", b"OTHER payload".to_vec()), rejected);
    }

    #[tokio::test]
    async fn peek_router_never_calls_predicate_with_empty_input() {
        let router = PeekRouter::new(
            |buffer: &[u8]| {
                if buffer[0] == 5 {
                    PeekVerdict::Match(())
                } else {
                    PeekVerdict::Reject
                }
            },
            service_fn(collect_accepted),
        )
        .with_fallback(service_fn(collect_fallback));

        let result = router
            .serve(std::io::Cursor::new(b"\x05payload".to_vec()))
            .await
            .unwrap();
        assert_eq!(("accepted", b"\x05payload".to_vec()), result);
    }

    #[tokio::test]
    async fn peek_router_configured_limit_falls_back_and_replays() {
        let router = PeekRouter::new(
            |_buffer: &[u8]| PeekVerdict::NeedMore,
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::new()))),
        )
        .with_max_peek_size(NonZeroUsize::new(4).unwrap())
        .with_peek_read_chunk_size(NonZeroUsize::new(2).unwrap())
        .with_fallback(service_fn(collect_fallback));

        let result = router
            .serve(std::io::Cursor::new(b"eight123".to_vec()))
            .await
            .unwrap();
        assert_eq!(("fallback", b"eight123".to_vec()), result);
    }

    #[tokio::test]
    async fn peek_router_limit_does_not_read_from_idle_peer_again() {
        async fn read_limit(
            mut stream: impl Io + Unpin,
        ) -> Result<(&'static str, Vec<u8>), io::Error> {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            Ok(("fallback", bytes.to_vec()))
        }

        let router = PeekRouter::new(
            |_buffer: &[u8]| PeekVerdict::NeedMore,
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::new()))),
        )
        .with_max_peek_size(NonZeroUsize::new(4).unwrap())
        .with_fallback(service_fn(read_limit));
        let input = tokio::io::join(IdleAfterReader::new(b"four"), tokio::io::sink());

        let result = tokio::time::timeout(Duration::from_secs(1), router.serve(input))
            .await
            .expect("reaching the peek limit must not issue another read")
            .unwrap();
        assert_eq!(("fallback", b"four".to_vec()), result);
    }

    #[tokio::test]
    async fn peek_router_timeout_falls_back_and_replays_partial_input() {
        async fn read_partial(
            mut stream: impl Io + Unpin,
        ) -> Result<(&'static str, Vec<u8>), io::Error> {
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes).await?;
            Ok(("fallback", bytes.to_vec()))
        }

        let router = PeekRouter::new(
            |buffer: &[u8]| {
                if buffer.starts_with(b"MAGIC") {
                    PeekVerdict::Match(())
                } else if b"MAGIC".starts_with(buffer) {
                    PeekVerdict::NeedMore
                } else {
                    PeekVerdict::Reject
                }
            },
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::new()))),
        )
        .with_peek_timeout(Duration::from_millis(10))
        .with_fallback(service_fn(read_partial));

        let input = tokio::io::join(IdleAfterReader::new(b"MA"), tokio::io::sink());
        let result = router.serve(input).await.unwrap();
        assert_eq!(("fallback", b"MA".to_vec()), result);
    }

    #[tokio::test]
    async fn peek_router_read_error_falls_back_and_replays_partial_input() {
        async fn read_partial(
            mut stream: impl Io + Unpin,
        ) -> Result<(&'static str, Vec<u8>), io::Error> {
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes).await?;
            Ok(("fallback", bytes.to_vec()))
        }

        let router = PeekRouter::new(
            |_buffer: &[u8]| PeekVerdict::NeedMore,
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::new()))),
        )
        .with_fallback(service_fn(read_partial));
        let reader = tokio_test::io::Builder::new()
            .read(b"MA")
            .read_error(io::Error::new(io::ErrorKind::BrokenPipe, "boom"))
            .build();
        let input = tokio::io::join(reader, tokio::io::sink());

        let result = router.serve(input).await.unwrap();
        assert_eq!(("fallback", b"MA".to_vec()), result);
    }

    #[tokio::test]
    async fn prefix_peek_router_decides_before_idle_peer_blocks() {
        async fn read_ping(mut stream: impl Io + Unpin) -> Result<&'static str, io::Error> {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            assert_eq!(b"PING", &bytes);
            Ok("accepted")
        }

        async fn read_pong(mut stream: impl Io + Unpin) -> Result<&'static str, io::Error> {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            assert_eq!(b"PONG", &bytes);
            Ok("fallback")
        }

        let matched = PeekRouter::from_prefix(b"PING", service_fn(read_ping))
            .with_fallback(service_fn(read_pong));
        let matched_input = tokio::io::join(IdleAfterReader::new(b"PING"), tokio::io::sink());
        let result = tokio::time::timeout(Duration::from_secs(1), matched.serve(matched_input))
            .await
            .expect("matching prefix must not wait for more input")
            .unwrap();
        assert_eq!("accepted", result);

        let rejected = PeekRouter::from_prefix(b"PING", service_fn(read_ping))
            .with_fallback(service_fn(read_pong));
        let rejected_input = tokio::io::join(IdleAfterReader::new(b"PONG"), tokio::io::sink());
        let result = tokio::time::timeout(Duration::from_secs(1), rejected.serve(rejected_input))
            .await
            .expect("diverging prefix must not wait for more input")
            .unwrap();
        assert_eq!("fallback", result);
    }

    #[tokio::test]
    async fn prefix_peek_router_replays_eof_mid_prefix() {
        let router = PeekRouter::from_prefix(b"PING", service_fn(collect_accepted))
            .with_fallback(service_fn(collect_fallback));

        let result = router
            .serve(std::io::Cursor::new(b"PI".to_vec()))
            .await
            .unwrap();
        assert_eq!(("fallback", b"PI".to_vec()), result);
    }

    #[tokio::test]
    async fn prefix_peek_router_falls_back_when_limit_is_shorter_than_prefix() {
        let router = PeekRouter::from_prefix(b"PING", service_fn(collect_accepted))
            .with_max_peek_size(NonZeroUsize::new(2).unwrap())
            .with_fallback(service_fn(collect_fallback));
        let result = router
            .serve(std::io::Cursor::new(b"PING payload".to_vec()))
            .await
            .unwrap();
        assert_eq!(("fallback", b"PING payload".to_vec()), result);
    }

    #[test]
    #[should_panic(expected = "PeekRouter prefix must not be empty")]
    fn prefix_peek_router_rejects_empty_prefix() {
        let _router = PeekRouter::from_prefix(
            b"",
            service_fn(async || Ok::<_, Infallible>(("accepted", Vec::<u8>::new()))),
        );
    }

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
    async fn verdict_classifies_the_prefilled_offset_before_reading() {
        let mut reader = tokio_test::io::Builder::new().build();
        let mut buffer = *b"hello";
        let offset = buffer.len();

        let output = peek_input_until_verdict_with_options(
            &mut reader,
            &mut buffer,
            offset,
            None,
            None,
            |buf: &[u8]| {
                if buf == b"hello" {
                    PeekVerdict::Match(buf.len())
                } else {
                    PeekVerdict::Reject
                }
            },
        )
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

    #[tokio::test]
    async fn verdict_growing_grows_across_reads_until_match() {
        let mut reader = tokio_test::io::Builder::new()
            .read(b"he")
            .read(b"llo")
            .build();
        let mut buffer = Vec::new();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            64,
            NonZeroUsize::new(4).unwrap(),
            None,
            |buf: &[u8]| {
                if buf == b"hello" {
                    PeekVerdict::Match(buf.len())
                } else if b"hello".starts_with(buf) {
                    PeekVerdict::NeedMore
                } else {
                    PeekVerdict::Reject
                }
            },
        )
        .await;

        assert_eq!(data, Some(5));
        assert_eq!(buffer, b"hello");
    }

    #[tokio::test]
    async fn verdict_growing_does_not_classify_empty_buffer_at_eof() {
        let mut reader = tokio_test::io::Builder::new().build();
        let mut buffer = Vec::new();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            8,
            NonZeroUsize::new(8).unwrap(),
            None,
            |_buf: &[u8]| -> PeekVerdict<()> { unreachable!() },
        )
        .await;

        assert!(data.is_none());
        assert!(buffer.is_empty());
    }

    #[tokio::test]
    async fn verdict_growing_never_grows_past_max_len() {
        // `max_len` (5) is deliberately NOT a multiple of the chunk (2), so the
        // final read is clamped to the remaining-to-cap; the buffer must land
        // exactly on `max_len` and never past it, even with data still available.
        let mut reader = FillReader { remaining: 100 };
        let mut buffer = Vec::new();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            5,
            NonZeroUsize::new(2).unwrap(),
            None,
            |_buf: &[u8]| PeekVerdict::<()>::NeedMore,
        )
        .await;

        assert!(data.is_none());
        assert_eq!(buffer.len(), 5, "buffer must land exactly on max_len");
    }

    #[tokio::test]
    async fn verdict_growing_matches_within_a_generous_timeout() {
        // With a generous timeout and data available, the peek must complete
        // (exercises the timeout-fenced read path: the deadline is in the future
        // and the not-timed-out check lets the read proceed).
        let mut reader = tokio_test::io::Builder::new().read(b"hello").build();
        let mut buffer = Vec::new();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            64,
            NonZeroUsize::new(8).unwrap(),
            Some(Duration::from_secs(5)),
            |buf: &[u8]| {
                if buf == b"hello" {
                    PeekVerdict::Match(())
                } else if b"hello".starts_with(buf) {
                    PeekVerdict::NeedMore
                } else {
                    PeekVerdict::Reject
                }
            },
        )
        .await;

        assert!(data.is_some());
        assert_eq!(buffer, b"hello");
    }

    #[tokio::test]
    async fn verdict_growing_matches_preseeded_buffer_without_reading() {
        // The pre-seeded buffer already satisfies the predicate, so no read may
        // happen — an empty mock reader panics on any unexpected read.
        let mut reader = tokio_test::io::Builder::new().build();
        let mut buffer = b"hello".to_vec();

        let data = peek_input_until_verdict_growing(
            &mut reader,
            &mut buffer,
            64,
            NonZeroUsize::new(8).unwrap(),
            None,
            |buf: &[u8]| {
                if buf == b"hello" {
                    PeekVerdict::Match(())
                } else {
                    PeekVerdict::NeedMore
                }
            },
        )
        .await;

        assert!(data.is_some());
        assert_eq!(buffer, b"hello");
    }

    #[tokio::test]
    async fn verdict_growing_rejects_without_blocking_on_idle_peer() {
        // A non-matching prefix then an idle-but-open peer: the reject must
        // return without blocking on the byte that never arrives.
        let mut reader = IdleAfterReader::new(b"PING");
        let mut buffer = Vec::new();

        let data = tokio::time::timeout(
            Duration::from_secs(5),
            peek_input_until_verdict_growing(
                &mut reader,
                &mut buffer,
                64,
                NonZeroUsize::new(8).unwrap(),
                None,
                |buf: &[u8]| {
                    if buf.is_empty() {
                        PeekVerdict::NeedMore
                    } else if buf[0] == 0x16 {
                        PeekVerdict::Match(())
                    } else {
                        PeekVerdict::Reject
                    }
                },
            ),
        )
        .await
        .expect("reject must stop without blocking");

        assert!(data.is_none());
        assert_eq!(buffer, b"PING");
    }

    /// A reader that fully fills the provided buffer until a byte budget is
    /// exhausted, then EOFs — deterministic (each read yields exactly the
    /// requested amount) for exercising the grow loop's sizing arithmetic.
    struct FillReader {
        remaining: usize,
    }

    impl AsyncRead for FillReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = buf.remaining().min(self.remaining);
            if n > 0 {
                buf.put_slice(&vec![0xAA_u8; n]);
                self.remaining -= n;
            }
            Poll::Ready(Ok(()))
        }
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
