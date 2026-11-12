use std::cmp;
use std::fmt;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Sleep;

use rama_core::bytes::{Buf, BufMut, Bytes, BytesMut};
use rama_core::extensions::ExtensionsRef;
use rama_core::io::poll_read_limited;
use rama_core::telemetry::tracing::{debug, trace};
use rama_utils::octets::kib;
use std::task::ready;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;

use super::{Http1Transaction, ParseContext, ParsedMessage};
use crate::common::buf::BufList;

/// The initial buffer size allocated before trying to read from IO.
pub(crate) const INIT_BUFFER_SIZE: usize = 8192;

/// The minimum value that can be set to max buffer size.
pub(crate) const MINIMUM_MAX_BUFFER_SIZE: usize = INIT_BUFFER_SIZE;

/// The buffer size for input that is only dropped, as nginx uses while
/// lingering.
const DISCARD_BUF_SIZE: usize = 4096;

/// The default maximum read buffer size. If the buffer gets this big and
/// a message is still not complete, a `TooLarge` error is triggered.
// Note: if this changes, update server::conn::Http::max_buf_size docs.
pub(crate) const DEFAULT_MAX_BUFFER_SIZE: usize = 8192 + 4096 * 100;

/// Flatten-mode chunks at least this large are written from their own buffer
/// after a prefix copy; one TLS record of plaintext, so the first write stays a single record.
const FLATTEN_COPY_LIMIT: usize = kib(16);

/// A drained buffer above this capacity is released instead of kept for the idle connection.
const MAX_RETAINED_BUF_SIZE: usize = kib(128);
/// Reuse moderately large buffers across a burst, then return to the idle cap.
const MAX_WARM_READ_BUF_SIZE: usize = kib(512);
const WARM_READ_BUF_IDLE: Duration = Duration::from_millis(100);

/// The maximum number of distinct `Buf`s to hold in a list before requiring
/// a flush. Only affects when the buffer strategy is to queue buffers.
///
/// Note that a flush can happen before reaching the maximum. This simply
/// forces a flush if the queue gets this big.
const MAX_BUF_LIST_BUFFERS: usize = 16;

#[derive(ExtensionsRef)]
pub(crate) struct Buffered<T, B> {
    flush_pipeline: bool,
    #[extensions_ref]
    io: T,
    partial_len: Option<usize>,
    read_blocked: bool,
    /// The peer ended its stream: a read with room returned nothing.
    read_eof: bool,
    /// A read failed, so the peer is gone or the transport is broken.
    read_failed: bool,
    read_buf: BytesMut,
    read_buf_strategy: ReadStrategy,
    idle_read_timer: Option<Pin<Box<Sleep>>>,
    write_buf: WriteBuf<B>,
}

impl<T, B> fmt::Debug for Buffered<T, B>
where
    B: Buf,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffered")
            .field("read_buf", &self.read_buf)
            .field("write_buf", &self.write_buf)
            .finish()
    }
}

impl<T, B> Buffered<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin + ExtensionsRef,
    B: Buf,
{
    pub(crate) fn new(io: T) -> Self {
        let strategy = if io.is_write_vectored() {
            WriteStrategy::Queue
        } else {
            WriteStrategy::Flatten
        };
        let write_buf = WriteBuf::new(strategy);
        Self {
            flush_pipeline: false,
            io,
            partial_len: None,
            read_blocked: false,
            read_eof: false,
            read_failed: false,
            read_buf: BytesMut::with_capacity(0),
            read_buf_strategy: ReadStrategy::default(),
            idle_read_timer: None,
            write_buf,
        }
    }

    pub(crate) fn set_flush_pipeline(&mut self, enabled: bool) {
        debug_assert!(!self.write_buf.has_remaining());
        self.flush_pipeline = enabled;
        if enabled {
            self.set_write_strategy_flatten();
        }
    }

    pub(crate) fn set_max_buf_size(&mut self, max: usize) {
        assert!(
            max >= MINIMUM_MAX_BUFFER_SIZE,
            "The max_buf_size cannot be smaller than {MINIMUM_MAX_BUFFER_SIZE}.",
        );
        self.read_buf_strategy = ReadStrategy::with_max(max);
        self.write_buf.max_buf_size = max;
    }

    pub(crate) fn set_read_buf_exact_size(&mut self, sz: usize) {
        self.read_buf_strategy = ReadStrategy::Exact(sz);
    }

    pub(crate) fn set_write_strategy_flatten(&mut self) {
        // this should always be called only at construction time,
        // so this assert is here to catch myself
        debug_assert_eq!(self.write_buf.queue.bufs_cnt(), 0);
        self.write_buf.set_strategy(WriteStrategy::Flatten);
    }

    pub(crate) fn set_write_strategy_queue(&mut self) {
        // this should always be called only at construction time,
        // so this assert is here to catch myself
        debug_assert_eq!(self.write_buf.queue.bufs_cnt(), 0);
        self.write_buf.set_strategy(WriteStrategy::Queue);
    }

    pub(crate) fn read_buf(&self) -> &[u8] {
        self.read_buf.as_ref()
    }

    /// Drop what was read but not parsed yet, returning how many bytes.
    pub(crate) fn discard_read_buf(&mut self, max: usize) -> usize {
        let len = self.read_buf.len().min(max);
        if len == self.read_buf.len() {
            self.read_buf.clear();
        } else {
            self.read_buf.advance(len);
        }
        len
    }

    /// Read in small reads into a small buffer: from here on input is only
    /// dropped, and may keep coming for a while.
    pub(crate) fn read_to_discard(&mut self) {
        // Abandoned input cannot become another pipelined HTTP request.
        // Even if the byte limit leaves some buffered, flush the final response.
        self.flush_pipeline = false;
        self.idle_read_timer = None;
        self.read_buf_strategy = ReadStrategy::Exact(DISCARD_BUF_SIZE);
        if self.read_buf.is_empty() && self.read_buf.capacity() > DISCARD_BUF_SIZE {
            self.read_buf = BytesMut::new();
        }
    }

    /// Between messages, drop a read buffer a large message grew so an idle connection holds little.
    pub(crate) fn release_idle_read_buf(&mut self) {
        self.idle_read_timer = None;
        if self.read_buf.is_empty() && self.read_buf.capacity() > MAX_RETAINED_BUF_SIZE {
            self.read_buf = BytesMut::new();
        }
        self.read_buf_strategy.reset_next();
    }

    /// Keep a warm allocation briefly between requests, with a wakeup to
    /// release it even if the peer sends nothing else. Buffered/pipelined data
    /// is never discarded, and oversized allocations are released immediately.
    pub(crate) fn retain_idle_read_buf(&mut self, cx: &mut Context<'_>) {
        if self.read_buf.is_empty()
            && self.read_buf.capacity() > MAX_RETAINED_BUF_SIZE
            && self.read_buf.capacity() <= MAX_WARM_READ_BUF_SIZE
        {
            self.read_buf_strategy.reset_next();
            let timer = self
                .idle_read_timer
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(WARM_READ_BUF_IDLE)));
            if timer.as_mut().poll(cx).is_ready() {
                self.release_idle_read_buf();
            }
        } else {
            self.release_idle_read_buf();
        }
    }

    /// Whether the peer ended its stream or reading from it failed.
    pub(crate) fn is_read_finished(&self) -> bool {
        self.read_eof || self.read_failed
    }

    /// Return the "allocated" available space, not the potential space
    /// that could be allocated in the future.
    fn read_buf_remaining_mut(&self) -> usize {
        self.read_buf.capacity() - self.read_buf.len()
    }

    /// Return whether we can append to the headers buffer.
    ///
    /// Reasons we can't:
    /// - The write buf is in queue mode, and some of the past body is still
    ///   needing to be flushed.
    pub(crate) fn can_headers_buf(&self) -> bool {
        !self.write_buf.queue.has_remaining()
    }

    pub(crate) fn headers_buf(&mut self) -> &mut Vec<u8> {
        let buf = self.write_buf.headers_mut();
        &mut buf.bytes
    }

    pub(super) fn write_buf(&mut self) -> &mut WriteBuf<B> {
        &mut self.write_buf
    }

    pub(crate) fn buffer<BB: Buf + Into<B>>(&mut self, buf: BB) {
        self.write_buf.buffer(buf);
    }

    /// Whether there are bytes waiting in the write buffer to be flushed.
    pub(crate) fn has_buffered_write(&self) -> bool {
        self.write_buf.remaining() > 0
    }

    pub(crate) fn can_buffer(&self) -> bool {
        self.flush_pipeline || self.write_buf.can_buffer()
    }

    pub(crate) fn consume_leading_lines(&mut self) {
        if !self.read_buf.is_empty() {
            let mut i = 0;
            while i < self.read_buf.len() {
                match self.read_buf[i] {
                    b'\r' | b'\n' => i += 1,
                    _ => break,
                }
            }
            self.read_buf.advance(i);
        }
    }

    pub(super) fn parse<S>(
        &mut self,
        cx: &mut Context<'_>,
        mut parse_ctx: ParseContext<'_>,
    ) -> Poll<crate::Result<ParsedMessage<S::Incoming>>>
    where
        S: Http1Transaction,
    {
        loop {
            if let Some(msg) = super::role::parse_headers::<S>(
                &mut self.read_buf,
                self.partial_len,
                ParseContext {
                    req_method: parse_ctx.req_method,
                    h1_parser_config: parse_ctx.h1_parser_config.clone(),
                    h1_max_headers: parse_ctx.h1_max_headers,
                    h1_max_header_size: parse_ctx.h1_max_header_size,
                    h09_responses: parse_ctx.h09_responses,
                    on_informational: parse_ctx.on_informational,
                    informational_left: parse_ctx.informational_left.as_deref_mut(),
                    prepared_extensions: parse_ctx.prepared_extensions,
                },
            )? {
                debug!("parsed {} headers", msg.head.headers.len());
                self.partial_len = None;
                return Poll::Ready(Ok(msg));
            } else {
                let curr_len = self.read_buf.len();
                // A partial head that already holds the limit can only end up past it.
                if curr_len > 0
                    && let Some(max_header_size) = parse_ctx.h1_max_header_size
                    && curr_len >= max_header_size
                {
                    debug!("max_header_size ({max_header_size}) reached, closing");
                    return Poll::Ready(Err(crate::Error::new_too_large()));
                }
                let max = self.read_buf_strategy.max();
                if curr_len >= max {
                    debug!("max_buf_size ({}) reached, closing", max);
                    return Poll::Ready(Err(crate::Error::new_too_large()));
                }
                if curr_len > 0 {
                    trace!("partial headers; {} bytes so far", curr_len);
                    self.partial_len = Some(curr_len);
                } else {
                    // 1xx gobled some bytes
                    self.partial_len = None;
                }
            }
            if ready!(self.poll_read_from_io(cx)).map_err(crate::Error::new_io)? == 0 {
                trace!("parse eof");
                return Poll::Ready(Err(crate::Error::new_incomplete()));
            }
        }
    }

    pub(crate) fn poll_read_from_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        self.poll_read_from_io_limited(cx, usize::MAX)
    }

    pub(crate) fn poll_read_from_io_limited(
        &mut self,
        cx: &mut Context<'_>,
        max: usize,
    ) -> Poll<io::Result<usize>> {
        self.read_blocked = false;
        if self
            .idle_read_timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
        {
            self.release_idle_read_buf();
        }
        // Get the next amount to allocate, but make sure we don't go over
        // the max read buf size configured.
        let next = cmp::min(
            self.read_buf_strategy.next(),
            self.read_buf_strategy
                .max()
                .saturating_sub(self.read_buf.len()),
        );
        if self.read_buf_remaining_mut() < next {
            self.read_buf.reserve(next);
        }

        // SAFETY: `as_uninit_slice_mut` requires that the slice is neither read nor
        // written with uninitialized bytes. It is only wrapped in `buf`, a tokio
        // `ReadBuf`, whose safe API writes only initialized bytes and reads only the
        // bytes it filled, and which must never be de-initialized (tokio docs).
        let dst = unsafe { self.read_buf.chunk_mut().as_uninit_slice_mut() };
        let had_room = dst.len().min(max) > 0;
        let mut buf = ReadBuf::uninit(dst);
        match poll_read_limited(Pin::new(&mut self.io), cx, &mut buf, max) {
            Poll::Ready(Ok(n)) => {
                // Once input resumes this is an active message, not idle memory.
                self.idle_read_timer = None;
                self.read_eof |= n == 0 && had_room;
                trace!("received {n} bytes");
                // SAFETY: `advance_mut(n)` needs the next `n` bytes of `chunk_mut()`
                // initialized. `buf` wrapped that chunk with nothing filled, so by
                // `poll_read_limited`'s safety-usable invariant its first `n` bytes
                // are initialized; `read_buf` was not touched in between.
                unsafe { self.read_buf.advance_mut(n) };
                self.read_buf_strategy.record(n);
                Poll::Ready(Ok(n))
            }
            Poll::Pending => {
                self.read_blocked = true;
                Poll::Pending
            }
            Poll::Ready(Err(e)) => {
                self.read_failed = true;
                Poll::Ready(Err(e))
            }
        }
    }

    pub(crate) fn into_inner(self) -> (T, Bytes) {
        (self.io, self.read_buf.freeze())
    }

    pub(crate) fn is_read_blocked(&self) -> bool {
        self.read_blocked
    }

    pub(crate) fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flush_pipeline && !self.read_buf.is_empty() {
            Poll::Ready(Ok(()))
        } else if self.write_buf.remaining() == 0 {
            Pin::new(&mut self.io).poll_flush(cx)
        } else {
            if matches!(self.write_buf.strategy, WriteStrategy::Flatten) {
                return self.poll_flush_flattened(cx);
            }

            const MAX_WRITEV_BUFS: usize = 64;
            loop {
                let n = {
                    let mut iovs = [IoSlice::new(&[]); MAX_WRITEV_BUFS];
                    let len = self.write_buf.chunks_vectored(&mut iovs);
                    ready!(Pin::new(&mut self.io).poll_write_vectored(cx, &iovs[..len]))?
                };
                // TODO(eliza): we have to do this manually because
                // `poll_write_buf` doesn't exist in Tokio 0.3 yet...when
                // `poll_write_buf` comes back, the manual advance will need to leave!
                self.write_buf.advance(n);
                debug!("flushed {} bytes", n);
                if self.write_buf.remaining() == 0 {
                    break;
                } else if n == 0 {
                    trace!(
                        "write returned zero, but {} bytes remaining",
                        self.write_buf.remaining()
                    );
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
            }
            Pin::new(&mut self.io).poll_flush(cx)
        }
    }

    /// Specialized version of `flush` when strategy is Flatten: one slice per write.
    fn poll_flush_flattened(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_buf.has_remaining() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, self.write_buf.chunk()))?;
            debug!("flushed {} bytes", n);
            if n == 0 {
                trace!(
                    "write returned zero, but {} bytes remaining",
                    self.write_buf.remaining()
                );
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_buf.advance(n);
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    pub(crate) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_flush(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    #[cfg(test)]
    fn flush(&mut self) -> impl Future<Output = io::Result<()>> + '_ {
        std::future::poll_fn(move |cx| self.poll_flush(cx))
    }
}

// The `B` is a `Buf`, we never project a pin to it
impl<T: Unpin, B> Unpin for Buffered<T, B> {}

// TODO: This trait is old... at least rename to PollBytes or something...
pub(crate) trait MemRead {
    /// Reads one byte, or `None` once the transport reached EOF.
    fn read_byte(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<u8>>>;

    fn read_mem(&mut self, cx: &mut Context<'_>, len: usize) -> Poll<io::Result<Bytes>>;
}

impl<T, B> MemRead for Buffered<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin + ExtensionsRef,
    B: Buf,
{
    #[inline]
    fn read_byte(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<u8>>> {
        if self.read_buf.is_empty() && ready!(self.poll_read_from_io(cx))? == 0 {
            return Poll::Ready(Ok(None));
        }
        let byte = self.read_buf[0];
        self.read_buf.advance(1);
        Poll::Ready(Ok(Some(byte)))
    }

    fn read_mem(&mut self, cx: &mut Context<'_>, len: usize) -> Poll<io::Result<Bytes>> {
        if !self.read_buf.is_empty() {
            let n = std::cmp::min(len, self.read_buf.len());
            Poll::Ready(Ok(self.read_buf.split_to(n).freeze()))
        } else {
            let n = ready!(self.poll_read_from_io(cx))?;
            Poll::Ready(Ok(self.read_buf.split_to(::std::cmp::min(len, n)).freeze()))
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ReadStrategy {
    Adaptive {
        decrease_now: bool,
        next: usize,
        max: usize,
    },
    Exact(usize),
}

impl ReadStrategy {
    fn with_max(max: usize) -> Self {
        Self::Adaptive {
            decrease_now: false,
            next: INIT_BUFFER_SIZE,
            max,
        }
    }

    fn reset_next(&mut self) {
        if let Self::Adaptive {
            decrease_now, next, ..
        } = self
        {
            *next = INIT_BUFFER_SIZE;
            *decrease_now = false;
        }
    }

    fn next(&self) -> usize {
        match *self {
            Self::Adaptive { next, .. } => next,
            Self::Exact(exact) => exact,
        }
    }

    fn max(&self) -> usize {
        match *self {
            Self::Adaptive { max, .. } => max,
            Self::Exact(exact) => exact,
        }
    }

    fn record(&mut self, bytes_read: usize) {
        match self {
            Self::Adaptive {
                decrease_now,
                next,
                max,
                ..
            } => {
                if bytes_read >= *next {
                    *next = cmp::min(incr_power_of_two(*next), *max);
                    *decrease_now = false;
                } else {
                    let decr_to = prev_power_of_two(*next);
                    if bytes_read < decr_to {
                        if *decrease_now {
                            *next = cmp::max(decr_to, INIT_BUFFER_SIZE);
                            *decrease_now = false;
                        } else {
                            // Decreasing is a two "record" process.
                            *decrease_now = true;
                        }
                    } else {
                        // A read within the current range should cancel
                        // a potential decrease, since we just saw proof
                        // that we still need this size.
                        *decrease_now = false;
                    }
                }
            }
            Self::Exact(_) => (),
        }
    }
}

fn incr_power_of_two(n: usize) -> usize {
    n.saturating_mul(2)
}

fn prev_power_of_two(n: usize) -> usize {
    // Only way this shift can underflow is if n is less than 4.
    // (Which would means `usize::MAX >> 64` and underflowed!)
    debug_assert!(n >= 4);
    (usize::MAX >> (n.leading_zeros() + 2)) + 1
}

impl Default for ReadStrategy {
    fn default() -> Self {
        Self::with_max(DEFAULT_MAX_BUFFER_SIZE)
    }
}

#[derive(Clone)]
pub(crate) struct Cursor<T> {
    bytes: T,
    pos: usize,
}

impl<T: AsRef<[u8]>> Cursor<T> {
    #[inline]
    pub(crate) fn new(bytes: T) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl Cursor<Vec<u8>> {
    /// If we've advanced the position a bit in this cursor, and wish to
    /// extend the underlying vector, we may wish to unshift the "read" bytes
    /// off, and move everything else over.
    fn maybe_unshift(&mut self, additional: usize) {
        if self.pos == 0 {
            // nothing to do
            return;
        }

        if self.bytes.capacity() - self.bytes.len() >= additional {
            // there's room!
            return;
        }

        self.bytes.drain(0..self.pos);
        self.pos = 0;
    }

    fn reset(&mut self) {
        self.pos = 0;
        if self.bytes.capacity() > MAX_RETAINED_BUF_SIZE {
            self.bytes = Vec::with_capacity(INIT_BUFFER_SIZE);
        } else {
            self.bytes.clear();
        }
    }
}

impl<T: AsRef<[u8]>> fmt::Debug for Cursor<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cursor")
            .field("pos", &self.pos)
            .field("len", &self.bytes.as_ref().len())
            .finish()
    }
}

impl<T: AsRef<[u8]>> Buf for Cursor<T> {
    #[inline]
    fn remaining(&self) -> usize {
        self.bytes.as_ref().len() - self.pos
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        &self.bytes.as_ref()[self.pos..]
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        debug_assert!(self.pos + cnt <= self.bytes.as_ref().len());
        self.pos += cnt;
    }
}

// an internal buffer to collect writes before flushes
pub(super) struct WriteBuf<B> {
    /// Re-usable buffer that holds message headers.
    headers: Cursor<Vec<u8>>,
    max_buf_size: usize,
    /// Deque of user buffers if strategy is `Queue`.
    queue: BufList<B>,
    strategy: WriteStrategy,
}

impl<B: Buf> WriteBuf<B> {
    fn new(strategy: WriteStrategy) -> Self {
        Self {
            headers: Cursor::new(Vec::with_capacity(INIT_BUFFER_SIZE)),
            max_buf_size: DEFAULT_MAX_BUFFER_SIZE,
            queue: BufList::new(),
            strategy,
        }
    }
}

impl<B> WriteBuf<B>
where
    B: Buf,
{
    fn set_strategy(&mut self, strategy: WriteStrategy) {
        self.strategy = strategy;
    }

    pub(super) fn buffer<BB: Buf + Into<B>>(&mut self, mut buf: BB) {
        debug_assert!(buf.has_remaining());
        match self.strategy {
            // Bytes already queued go out first, so later ones may not jump ahead into the headers.
            WriteStrategy::Flatten if self.queue.has_remaining() => self.queue.push(buf.into()),
            // Only contiguous chunks: a chunked frame split here would cost extra tiny writes.
            WriteStrategy::Flatten
                if buf.remaining() >= FLATTEN_COPY_LIMIT
                    && buf.chunk().len() == buf.remaining() =>
            {
                let head = self.headers_mut();
                if head.has_remaining() {
                    // Top up pending head bytes so they leave together with the body's start.
                    let room = FLATTEN_COPY_LIMIT.saturating_sub(head.remaining());
                    head.maybe_unshift(room);
                    head.bytes.extend_from_slice(&buf.chunk()[..room]);
                    buf.advance(room);
                }
                trace!(
                    "buffer.flatten: head.remaining = {}; queued remaining: {}",
                    head.remaining(),
                    buf.remaining(),
                );
                self.queue.push(buf.into());
            }
            WriteStrategy::Flatten => {
                let head = self.headers_mut();

                head.maybe_unshift(buf.remaining());
                trace!(
                    "buffer.flatten: head.remaining = {}; buf.remaining: {}",
                    head.remaining(),
                    buf.remaining(),
                );
                //perf: This is a little faster than <Vec as BufMut>>::put,
                //but accomplishes the same result.
                loop {
                    let adv = {
                        let slice = buf.chunk();
                        if slice.is_empty() {
                            return;
                        }
                        head.bytes.extend_from_slice(slice);
                        slice.len()
                    };
                    buf.advance(adv);
                }
            }
            WriteStrategy::Queue => {
                trace!(
                    "buffer.queue: head.remaining = {}; buf.remaining: {}",
                    self.remaining(),
                    buf.remaining(),
                );
                self.queue.push(buf.into());
            }
        }
    }

    fn can_buffer(&self) -> bool {
        match self.strategy {
            // A queued chunk drains before more body is polled, bounding what one connection holds.
            WriteStrategy::Flatten => {
                !self.queue.has_remaining() && self.remaining() < self.max_buf_size
            }
            WriteStrategy::Queue => {
                self.queue.bufs_cnt() < MAX_BUF_LIST_BUFFERS && self.remaining() < self.max_buf_size
            }
        }
    }

    fn headers_mut(&mut self) -> &mut Cursor<Vec<u8>> {
        debug_assert!(!self.queue.has_remaining());
        &mut self.headers
    }
}

impl<B: Buf> fmt::Debug for WriteBuf<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteBuf")
            .field("remaining", &self.remaining())
            .field("strategy", &self.strategy)
            .finish()
    }
}

impl<B: Buf> Buf for WriteBuf<B> {
    #[inline]
    fn remaining(&self) -> usize {
        self.headers.remaining() + self.queue.remaining()
    }

    #[inline]
    fn has_remaining(&self) -> bool {
        self.headers.has_remaining() || self.queue.has_remaining()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        let headers = self.headers.chunk();
        if !headers.is_empty() {
            headers
        } else {
            self.queue.chunk()
        }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        let hrem = self.headers.remaining();

        match hrem.cmp(&cnt) {
            cmp::Ordering::Equal => self.headers.reset(),
            cmp::Ordering::Greater => self.headers.advance(cnt),
            cmp::Ordering::Less => {
                let qcnt = cnt - hrem;
                self.headers.reset();
                self.queue.advance(qcnt);
            }
        }
    }

    #[inline]
    fn chunks_vectored<'t>(&'t self, dst: &mut [IoSlice<'t>]) -> usize {
        let n = self.headers.chunks_vectored(dst);
        self.queue.chunks_vectored(&mut dst[n..]) + n
    }
}

#[derive(Debug)]
enum WriteStrategy {
    Flatten,
    Queue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use rama_utils::octets::mib;
    use tokio_test::io::Builder as Mock;

    #[tokio::test]
    #[ignore = "needs vectored writes in the mock"]
    async fn iobuf_write_empty_slice() {
        // TODO(eliza): can i have writev back pls T_T
        // // First, let's just check that the Mock would normally return an
        // // error on an unexpected write, even if the buffer is empty...
        // let mut mock = Mock::new().build();
        // std::future::poll_fn(|cx| {
        //     Pin::new(&mut mock).poll_write_buf(cx, &mut Cursor::new(&[]))
        // })
        // .await
        // .expect_err("should be a broken pipe");

        // // underlying io will return the logic error upon write,
        // // so we are testing that the io_buf does not trigger a write
        // // when there is nothing to flush
        // let mock = Mock::new().build();
        // let mut io_buf = Buffered::<_, Cursor<Vec<u8>>>::new(mock);
        // io_buf.flush().await.expect("should short-circuit flush");
    }

    /// Keeps the replacement buffers reachable, so leak checkers do not report them.
    static REPLACEMENT: std::sync::atomic::AtomicPtr<u8> =
        std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

    /// IO whose reads replace their `ReadBuf` with one over 16 filled bytes of its own.
    struct Replacer;

    impl AsyncRead for Replacer {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let own: &'static mut [u8] = Box::leak(vec![7u8; 64].into_boxed_slice());
            REPLACEMENT.store(own.as_mut_ptr(), std::sync::atomic::Ordering::Relaxed);
            let mut other = ReadBuf::new(own);
            other.advance(16);
            *buf = other;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Replacer {
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

    #[test]
    #[should_panic(expected = "replaced the ReadBuf")]
    fn read_from_io_rejects_replaced_read_buf() {
        let io = rama_core::ServiceInput::new(Replacer);
        let mut buffered = Buffered::<_, Cursor<Vec<u8>>>::new(io);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let res = buffered.poll_read_from_io(&mut cx);
        assert!(res.is_ready());
        let sum: u32 = buffered.read_buf.iter().copied().map(u32::from).sum();
        assert!(sum < u32::MAX);
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn parse_reads_until_blocked() {
        use rama_core::ServiceInput;
        use rama_core::extensions::Extensions;

        use crate::proto::h1::ClientTransaction;

        let mock = Mock::new()
            // Split over multiple reads will read all of it
            .read(b"HTTP/1.1 200 OK\r\n")
            .read(b"Server: rama\r\n")
            // missing last line ending
            .wait(Duration::from_secs(1))
            .build();

        let mock = ServiceInput::new(mock);

        let mut buffered = Buffered::<_, Cursor<Vec<u8>>>::new(mock);

        // We expect a `parse` to be not ready, and so can't await it directly.
        // Rather, this `poll_fn` will wrap the `Poll` result.
        std::future::poll_fn(|cx| {
            let parse_ctx = ParseContext {
                req_method: &mut None,
                h1_parser_config: Default::default(),
                h1_max_headers: None,
                h1_max_header_size: None,
                h09_responses: false,
                on_informational: &mut None,
                informational_left: None,
                prepared_extensions: &mut Some(Extensions::default()),
            };
            assert!(
                buffered
                    .parse::<ClientTransaction>(cx, parse_ctx)
                    .is_pending()
            );
            Poll::Ready(())
        })
        .await;

        assert_eq!(
            buffered.read_buf,
            b"HTTP/1.1 200 OK\r\nServer: rama\r\n"[..]
        );
    }

    #[test]
    fn read_strategy_adaptive_increments() {
        let mut strategy = ReadStrategy::default();
        assert_eq!(strategy.next(), 8192);

        // Grows if record == next
        strategy.record(8192);
        assert_eq!(strategy.next(), 16384);

        strategy.record(16384);
        assert_eq!(strategy.next(), 32768);

        // Enormous records still increment at same rate
        strategy.record(usize::MAX);
        assert_eq!(strategy.next(), 65536);

        let max = strategy.max();
        while strategy.next() < max {
            strategy.record(max);
        }

        assert_eq!(strategy.next(), max, "never goes over max");
        strategy.record(max + 1);
        assert_eq!(strategy.next(), max, "never goes over max");
    }

    #[test]
    fn read_strategy_adaptive_decrements() {
        let mut strategy = ReadStrategy::default();
        strategy.record(8192);
        assert_eq!(strategy.next(), 16384);

        strategy.record(1);
        assert_eq!(
            strategy.next(),
            16384,
            "first smaller record doesn't decrement yet"
        );
        strategy.record(8192);
        assert_eq!(strategy.next(), 16384, "record was with range");

        strategy.record(1);
        assert_eq!(
            strategy.next(),
            16384,
            "in-range record should make this the 'first' again"
        );

        strategy.record(1);
        assert_eq!(strategy.next(), 8192, "second smaller record decrements");

        strategy.record(1);
        assert_eq!(strategy.next(), 8192, "first doesn't decrement");
        strategy.record(1);
        assert_eq!(strategy.next(), 8192, "doesn't decrement under minimum");
    }

    #[test]
    fn read_strategy_adaptive_stays_the_same() {
        let mut strategy = ReadStrategy::default();
        strategy.record(8192);
        assert_eq!(strategy.next(), 16384);

        strategy.record(8193);
        assert_eq!(
            strategy.next(),
            16384,
            "first smaller record doesn't decrement yet"
        );

        strategy.record(8193);
        assert_eq!(
            strategy.next(),
            16384,
            "with current step does not decrement"
        );
    }

    #[test]
    fn read_strategy_adaptive_max_fuzz() {
        fn fuzz(max: usize) {
            let mut strategy = ReadStrategy::with_max(max);
            while strategy.next() < max {
                strategy.record(usize::MAX);
            }
            let mut next = strategy.next();
            while next > 8192 {
                strategy.record(1);
                strategy.record(1);
                next = strategy.next();
                assert!(
                    next.is_power_of_two(),
                    "decrement should be powers of two: {next} (max = {max})",
                );
            }
        }

        let mut max = 8192;
        while max < usize::MAX {
            fuzz(max);
            max = (max / 2).saturating_mul(3);
        }
        fuzz(usize::MAX);
    }

    #[test]
    #[should_panic]
    #[cfg(debug_assertions)] // needs to trigger a debug_assert
    fn write_buf_requires_non_empty_bufs() {
        use rama_core::ServiceInput;

        let mock = Mock::new().build();
        let mock = ServiceInput::new(mock);
        let mut buffered = Buffered::<_, Cursor<Vec<u8>>>::new(mock);

        buffered.buffer(Cursor::new(Vec::new()));
    }

    /*
    TODO: needs tokio_test::io to allow configure write_buf calls
    #[test]
    fn write_buf_queue() {
        _ = pretty_env_logger::try_init();

        let mock = AsyncIo::new_buf(vec![], 1024);
        let mut buffered = Buffered::<_, Cursor<Vec<u8>>>::new(mock);


        buffered.headers_buf().extend(b"hello ");
        buffered.buffer(Cursor::new(b"world, ".to_vec()));
        buffered.buffer(Cursor::new(b"it's ".to_vec()));
        buffered.buffer(Cursor::new(b"rama!".to_vec()));
        assert_eq!(buffered.write_buf.queue.bufs_cnt(), 3);
        buffered.flush().unwrap();

        assert_eq!(buffered.io, b"hello world, it's rama!");
        assert_eq!(buffered.io.num_writes(), 1);
        assert_eq!(buffered.write_buf.queue.bufs_cnt(), 0);
    }
    */

    fn flatten_buffered(
        mock: tokio_test::io::Mock,
    ) -> Buffered<rama_core::ServiceInput<tokio_test::io::Mock>, Cursor<Vec<u8>>> {
        let mut buffered = Buffered::new(rama_core::ServiceInput::new(mock));
        buffered.write_buf.set_strategy(WriteStrategy::Flatten);
        buffered
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn write_buf_flatten_large_chunk_is_not_copied() {
        let head = b"HTTP/1.1 200 OK\r\ncontent-length: 4194304\r\n\r\n";
        let body = pattern(mib(4));
        let mut wire = head.to_vec();
        wire.extend_from_slice(&body);
        let (first, rest) = wire.split_at(FLATTEN_COPY_LIMIT);
        let mut buffered = flatten_buffered(Mock::new().write(first).write(rest).build());

        buffered.headers_buf().extend_from_slice(head);
        buffered.buffer(Cursor::new(body));
        assert_eq!(buffered.write_buf.headers.remaining(), FLATTEN_COPY_LIMIT);
        assert_eq!(buffered.write_buf.queue.bufs_cnt(), 1);
        assert!(
            !buffered.can_buffer(),
            "a queued chunk drains before more is buffered"
        );

        buffered.flush().await.expect("flush");
        assert!(!buffered.has_buffered_write());
        assert!(buffered.write_buf.headers.bytes.capacity() <= 2 * FLATTEN_COPY_LIMIT);
        assert!(buffered.can_buffer());
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn write_buf_flatten_large_chunk_without_pending_head_is_written_directly() {
        let body = pattern(kib(64));
        let mut buffered = flatten_buffered(Mock::new().write(&body).build());

        buffered.buffer(Cursor::new(body.clone()));
        assert_eq!(buffered.write_buf.headers.remaining(), 0);
        assert_eq!(buffered.write_buf.queue.bufs_cnt(), 1);

        buffered.flush().await.expect("flush");
        assert_eq!(
            buffered.write_buf.headers.bytes.capacity(),
            INIT_BUFFER_SIZE
        );
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn write_buf_flatten_releases_oversized_buffer_after_flush() {
        let mut wire = Vec::new();
        let mut buffered = flatten_buffered({
            for i in 0..64u8 {
                wire.extend(std::iter::repeat_n(i, kib(4)));
            }
            Mock::new().write(&wire).build()
        });
        for i in 0..64u8 {
            buffered.buffer(Cursor::new(vec![i; kib(4)]));
        }
        assert!(buffered.write_buf.headers.bytes.capacity() > MAX_RETAINED_BUF_SIZE);

        buffered.flush().await.expect("flush");
        assert_eq!(
            buffered.write_buf.headers.bytes.capacity(),
            INIT_BUFFER_SIZE
        );
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn write_buf_flatten_keeps_order_behind_queued_chunk() {
        let head = b"HTTP/1.1 200 OK\r\n\r\n";
        let large = pattern(kib(32));
        let mut wire = head.to_vec();
        wire.extend_from_slice(&large);
        wire.extend_from_slice(b"tail");
        let (first, rest) = wire.split_at(FLATTEN_COPY_LIMIT);
        let (middle, tail) = rest.split_at(rest.len() - 4);
        let mut buffered =
            flatten_buffered(Mock::new().write(first).write(middle).write(tail).build());

        buffered.headers_buf().extend_from_slice(head);
        buffered.buffer(Cursor::new(large));
        buffered.buffer(Cursor::new(b"tail".to_vec()));
        assert_eq!(buffered.write_buf.queue.bufs_cnt(), 2);

        buffered.flush().await.expect("flush");
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn write_buf_flatten_survives_partial_and_pending_writes() {
        let head = b"HTTP/1.1 200 OK\r\n\r\n";
        let body = pattern(kib(40));
        let mut wire = head.to_vec();
        wire.extend_from_slice(&body);

        // Each mock write accepts at most its piece, so every write is partial.
        let mut mock = Mock::new();
        mock.wait(Duration::from_millis(1));
        for piece in wire.chunks(1000) {
            mock.write(piece);
        }
        let mut buffered = flatten_buffered(mock.build());

        buffered.headers_buf().extend_from_slice(head);
        buffered.buffer(Cursor::new(body));
        buffered.flush().await.expect("flush");
        assert!(!buffered.has_buffered_write());
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn idle_read_buf_is_released_after_large_upload() {
        let chunk = vec![7u8; kib(512)];
        let mut mock = Mock::new();
        for _ in 0..16 {
            mock.read(&chunk);
        }
        let mut buffered =
            Buffered::<_, Cursor<Vec<u8>>>::new(rama_core::ServiceInput::new(mock.build()));
        let mut total = 0;
        while total < 16 * chunk.len() {
            total += std::future::poll_fn(|cx| buffered.read_mem(cx, usize::MAX))
                .await
                .unwrap()
                .len();
        }
        assert!(buffered.read_buf.capacity() > MAX_RETAINED_BUF_SIZE);

        buffered.release_idle_read_buf();
        assert_eq!(buffered.read_buf.capacity(), 0);
        assert_eq!(buffered.read_buf_strategy.next(), INIT_BUFFER_SIZE);
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn alternating_large_and_small_uploads_survive_idle_release() {
        let chunk = vec![7u8; kib(512)];
        let small = b"next small upload";
        let mut mock = Mock::new();
        for _ in 0..4 {
            for _ in 0..16 {
                mock.read(&chunk);
            }
            mock.read(small);
        }
        let mut buffered =
            Buffered::<_, Cursor<Vec<u8>>>::new(rama_core::ServiceInput::new(mock.build()));
        let mut retained = Vec::new();
        for _ in 0..4 {
            let mut total = 0;
            while total < 16 * chunk.len() {
                let data = std::future::poll_fn(|cx| buffered.read_mem(cx, usize::MAX))
                    .await
                    .unwrap();
                assert!(!data.is_empty());
                assert!(data.iter().all(|b| *b == 7));
                total += data.len();
            }
            assert_eq!(total, 16 * chunk.len());
            buffered.release_idle_read_buf();
            assert_eq!(buffered.read_buf.capacity(), 0);
            assert_eq!(buffered.read_buf_strategy.next(), INIT_BUFFER_SIZE);
            let data = std::future::poll_fn(|cx| buffered.read_mem(cx, small.len()))
                .await
                .unwrap();
            assert_eq!(data.as_ref(), small);
            retained.push(data);
            buffered.release_idle_read_buf();
        }
        // Consumer-held slices remain valid across later growth and releases.
        assert!(retained.iter().all(|data| data.as_ref() == small));
    }

    #[tokio::test(start_paused = true)]
    async fn warm_read_buffer_expires_without_new_input() {
        let (_peer, io) = tokio::io::duplex(1024);
        let mut buffered = Buffered::<_, Cursor<Vec<u8>>>::new(rama_core::ServiceInput::new(io));
        buffered.read_buf = BytesMut::with_capacity(kib(256));
        let mut task = tokio_test::task::spawn(());
        task.enter(|cx, _| buffered.retain_idle_read_buf(cx));
        assert!(buffered.idle_read_timer.is_some());
        assert!(buffered.read_buf.capacity() >= kib(256));
        tokio::time::advance(Duration::from_millis(50)).await;
        // Repeated idle observations must not postpone expiry.
        task.enter(|cx, _| buffered.retain_idle_read_buf(cx));
        tokio::time::advance(Duration::from_millis(51)).await;
        assert!(task.is_woken());
        task.enter(|cx, _| assert!(buffered.poll_read_from_io(cx).is_pending()));
        assert!(buffered.idle_read_timer.is_none());
        assert!(buffered.read_buf.capacity() <= MAX_RETAINED_BUF_SIZE);
        assert!(!buffered.is_read_finished());
    }

    #[tokio::test(start_paused = true)]
    async fn resumed_input_cancels_buffer_expiry_and_preserves_partial_heads() {
        use tokio::io::AsyncWriteExt as _;
        let (mut peer, io) = tokio::io::duplex(1024);
        let mut buffered = Buffered::<_, Cursor<Vec<u8>>>::new(rama_core::ServiceInput::new(io));
        buffered.read_buf = BytesMut::with_capacity(kib(256));
        let mut task = tokio_test::task::spawn(());
        task.enter(|cx, _| buffered.retain_idle_read_buf(cx));
        tokio::time::advance(Duration::from_millis(50)).await;
        peer.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        task.enter(|cx, _| {
            assert!(matches!(
                buffered.poll_read_from_io(cx),
                Poll::Ready(Ok(16))
            ))
        });
        assert!(buffered.idle_read_timer.is_none());
        tokio::time::advance(Duration::from_millis(100)).await;
        task.enter(|cx, _| assert!(buffered.poll_read_from_io(cx).is_pending()));
        assert_eq!(buffered.read_buf(), b"GET / HTTP/1.1\r\n");
        assert!(buffered.read_buf.capacity() >= kib(256));
        buffered.read_buf.clear();
        task.enter(|cx, _| buffered.retain_idle_read_buf(cx));
        tokio::time::advance(Duration::from_millis(50)).await;
        task.enter(|cx, _| assert!(buffered.poll_read_from_io(cx).is_pending()));
        assert!(buffered.idle_read_timer.is_some());
        tokio::time::advance(Duration::from_millis(51)).await;
        task.enter(|cx, _| assert!(buffered.poll_read_from_io(cx).is_pending()));
        assert!(buffered.idle_read_timer.is_none());
        assert!(buffered.read_buf.capacity() <= MAX_RETAINED_BUF_SIZE);
    }

    #[tokio::test]
    async fn small_and_oversized_idle_buffers_need_no_expiry_timer() {
        for capacity in [
            INIT_BUFFER_SIZE,
            MAX_RETAINED_BUF_SIZE,
            2 * MAX_WARM_READ_BUF_SIZE,
        ] {
            let (_peer, io) = tokio::io::duplex(1024);
            let mut buffered =
                Buffered::<_, Cursor<Vec<u8>>>::new(rama_core::ServiceInput::new(io));
            buffered.read_buf = BytesMut::with_capacity(capacity);
            tokio_test::task::spawn(()).enter(|cx, _| buffered.retain_idle_read_buf(cx));
            assert!(buffered.idle_read_timer.is_none());
            assert!(buffered.read_buf.capacity() <= MAX_RETAINED_BUF_SIZE);
        }
    }

    #[tokio::test]
    async fn pipelined_input_is_never_expired() {
        let (_peer, io) = tokio::io::duplex(1024);
        let mut buffered = Buffered::<_, Cursor<Vec<u8>>>::new(rama_core::ServiceInput::new(io));
        buffered.read_buf = BytesMut::with_capacity(MAX_WARM_READ_BUF_SIZE);
        buffered.read_buf.extend_from_slice(b"next request");
        tokio_test::task::spawn(()).enter(|cx, _| buffered.retain_idle_read_buf(cx));
        assert!(buffered.idle_read_timer.is_none());
        assert_eq!(buffered.read_buf(), b"next request");
    }

    #[test]
    fn idle_read_buf_keeps_pipelined_bytes() {
        let mut buffered =
            Buffered::<_, Cursor<Vec<u8>>>::new(rama_core::ServiceInput::new(Mock::new().build()));
        buffered.read_buf = BytesMut::with_capacity(4 * MAX_RETAINED_BUF_SIZE);
        buffered.read_buf.extend_from_slice(b"GET / HTTP/1.1\r\n");

        buffered.release_idle_read_buf();
        assert_eq!(buffered.read_buf(), b"GET / HTTP/1.1\r\n");
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn write_buf_flatten() {
        use rama_core::ServiceInput;

        let mock = Mock::new().write(b"hello world, it's rama!").build();
        let mock = ServiceInput::new(mock);

        let mut buffered = Buffered::<_, Cursor<Vec<u8>>>::new(mock);
        buffered.write_buf.set_strategy(WriteStrategy::Flatten);

        buffered.headers_buf().extend(b"hello ");
        buffered.buffer(Cursor::new(b"world, ".to_vec()));
        buffered.buffer(Cursor::new(b"it's ".to_vec()));
        buffered.buffer(Cursor::new(b"rama!".to_vec()));
        assert_eq!(buffered.write_buf.queue.bufs_cnt(), 0);

        buffered.flush().await.expect("flush");
    }

    #[test]
    fn write_buf_flatten_partially_flushed() {
        let b = |s: &str| Cursor::new(s.as_bytes().to_vec());

        let mut write_buf = WriteBuf::<Cursor<Vec<u8>>>::new(WriteStrategy::Flatten);

        write_buf.buffer(b("hello "));
        write_buf.buffer(b("world, "));

        assert_eq!(write_buf.chunk(), b"hello world, ");

        // advance most of the way, but not all
        write_buf.advance(11);

        assert_eq!(write_buf.chunk(), b", ");
        assert_eq!(write_buf.headers.pos, 11);
        assert_eq!(write_buf.headers.bytes.capacity(), INIT_BUFFER_SIZE);

        // there's still room in the headers buffer, so just push on the end
        write_buf.buffer(b("it's rama!"));

        assert_eq!(write_buf.chunk(), b", it's rama!");
        assert_eq!(write_buf.headers.pos, 11);

        let rem1 = write_buf.remaining();
        let cap = write_buf.headers.bytes.capacity();

        // but when this would go over capacity, don't copy the old bytes
        write_buf.buffer(Cursor::new(vec![b'X'; cap]));
        assert_eq!(write_buf.remaining(), cap + rem1);
        assert_eq!(write_buf.headers.pos, 0);
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn write_buf_queue_disable_auto() {
        use rama_core::ServiceInput;

        let mock = Mock::new()
            .write(b"hello ")
            .write(b"world, ")
            .write(b"it's ")
            .write(b"rama!")
            .build();

        let mock = ServiceInput::new(mock);

        let mut buffered = Buffered::<_, Cursor<Vec<u8>>>::new(mock);
        buffered.write_buf.set_strategy(WriteStrategy::Queue);

        // we have 4 buffers, and vec IO disabled, but explicitly said
        // don't try to auto detect (via setting strategy above)

        buffered.headers_buf().extend(b"hello ");
        buffered.buffer(Cursor::new(b"world, ".to_vec()));
        buffered.buffer(Cursor::new(b"it's ".to_vec()));
        buffered.buffer(Cursor::new(b"rama!".to_vec()));
        assert_eq!(buffered.write_buf.queue.bufs_cnt(), 3);

        buffered.flush().await.expect("flush");

        assert_eq!(buffered.write_buf.queue.bufs_cnt(), 0);
    }
}
