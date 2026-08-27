use crate::sse::event_data::EventDataLineReader;

use super::parser::{RawEventLine, parse_line};
use super::{Event, EventBuildError, EventDataRead};

use memchr::{memchr2, memchr2_iter};
use pin_project_lite::pin_project;
use rama_core::error::{BoxError, ErrorContext as _, ErrorExt as _};
use rama_core::futures::stream::Stream;
use rama_core::futures::task::{Context, Poll};
use rama_core::telemetry::tracing;
use rama_utils::str::smol_str::SmolStr;
use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;

struct EventBuilder<T: EventDataRead> {
    reader: T::Reader,
    event: Event<T>,
    is_complete: bool,
}

impl<T> fmt::Debug for EventBuilder<T>
where
    T: EventDataRead + fmt::Debug,
    T::Reader: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBuilder")
            .field("reader", &self.reader)
            .field("event", &self.event)
            .field("is_complete", &self.is_complete)
            .finish()
    }
}

impl<T: EventDataRead> Default for EventBuilder<T> {
    fn default() -> Self {
        Self {
            reader: T::line_reader(),
            event: Default::default(),
            is_complete: false,
        }
    }
}

impl<T: EventDataRead> EventBuilder<T> {
    /// From the HTML spec
    ///
    /// -> If the field name is "event"
    ///    Set the event type buffer to field value.
    ///
    /// -> If the field name is "data"
    ///    Append the field value to the data buffer, then append a single U+000A LINE FEED (LF)
    ///    character to the data buffer.
    ///
    /// -> If the field name is "id"
    ///    If the field value does not contain U+0000 NULL, then set the last event ID buffer
    ///    to the field value. Otherwise, ignore the field.
    ///
    /// -> If the field name is "retry"
    ///    If the field value consists of only ASCII digits, then interpret the field value as
    ///    an integer in base ten, and set the event stream's reconnection time to that integer.
    ///    Otherwise, ignore the field.
    ///
    /// -> Otherwise
    ///    The field is ignored.
    #[inline]
    fn add(&mut self, line: RawEventLine<'_>) -> Result<(), BoxError> {
        match line {
            RawEventLine::Field(field, val) => match field {
                "data" => {
                    self.reader.read_line(val.unwrap_or(""))?;
                }
                "event" => {
                    // WHATWG: bare `event` (no value) sets the event-type buffer
                    // to the empty string, which then dispatches as the default
                    // `message` event. Modelling that as `None` so the dispatch
                    // path treats it identically to "no event field present".
                    if let Some(v) = val {
                        self.event.try_set_event(v).context("set event value")?;
                    } else {
                        self.event.event = None;
                    }
                }
                "id" => {
                    // WHATWG: bare `id` (no value) sets the last-event-ID buffer
                    // to the empty string; NUL in the id makes the field ignored.
                    if let Some(v) = val {
                        if !v.contains('\u{0000}') {
                            self.event.try_set_id(v).context("set event id")?;
                        }
                    } else {
                        self.event.id = Some(SmolStr::default());
                    }
                }
                "retry" => {
                    // WHATWG: retry value MUST consist of only ASCII digits.
                    // `u64::parse` would otherwise accept a leading `+`.
                    if let Some(v) = val
                        && !v.is_empty()
                        && v.bytes().all(|b| b.is_ascii_digit())
                        && let Ok(ms) = v.parse::<u64>()
                    {
                        self.event.set_retry(ms);
                    }
                }
                _ => {
                    tracing::debug!("ignore unknown SSE field {field}: value = {val:?}",)
                }
            },
            RawEventLine::Comment(comment) => {
                self.event
                    .try_set_comment(comment)
                    .context("set event comment")?;
            }
            RawEventLine::Empty => self.is_complete = true,
        }
        Ok(())
    }

    /// From the HTML spec
    ///
    /// 1. Set the last event ID string of the event source to the value of the last event ID
    ///    buffer. The buffer does not get reset, so the last event ID string of the event source
    ///    remains set to this value until the next time it is set by the server.
    /// 2. If the data buffer is an empty string, set the data buffer and the event type buffer
    ///    to the empty string and return.
    /// 3. If the data buffer's last character is a U+000A LINE FEED (LF) character, then remove
    ///    the last character from the data buffer.
    /// 4. Let event be the result of creating an event using MessageEvent, in the relevant Realm
    ///    of the EventSource object.
    /// 5. Initialize event's type attribute to message, its data attribute to data, its origin
    ///    attribute to the serialization of the origin of the event stream's final URL (i.e., the
    ///    URL after redirects), and its lastEventId attribute to the last event ID string of the
    ///    event source.
    /// 6. If the event type buffer has a value other than the empty string, change the type of
    ///    the newly created event to equal the value of the event type buffer.
    /// 7. Set the data buffer and the event type buffer to the empty string.
    /// 8. Queue a task which, if the readyState attribute is set to a value other than CLOSED,
    ///    dispatches the newly created event at the EventSource object.
    fn try_dispatch(&mut self) -> Result<Event<T>, BoxError> {
        self.is_complete = false;
        let mut event = std::mem::take(&mut self.event);
        if let Some(data) = self.reader.data(event.event.as_deref())? {
            event.set_data(data);
        }
        Ok(event)
    }
}

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Decoding pauses once this many events are queued but not yet yielded:
/// a single upstream chunk full of tiny events would otherwise be decoded
/// in one `poll_next` call, an input-controlled memory amplification
/// (and executor monopolization) the chunk size does not bound.
const READY_EVENTS_SOFT_CAP: usize = 16;

/// At most this many bytes are decoded per `scan` call.
/// Real HTTP/1 bodies arrive in chunks well below this, so the regular
/// path is unaffected.
const SCAN_BYTES_SOFT_CAP: usize = rama_utils::octets::mib(1);

/// Start each scan in a fixed-size block, then grow blocks exponentially.
/// If dense events hit the ready cap, at most this fixed prefix was inspected;
/// sparse input reaches large SIMD-friendly blocks after only a few steps.
const SCAN_INITIAL_BLOCK_SIZE: usize = 1024;

/// Cooperative budget for parser bytes consumed by one `poll_next` call.
const POLL_BYTES_SOFT_CAP: usize = SCAN_BYTES_SOFT_CAP;

/// Byte accounting alone cannot bound a stream of ready empty/tiny chunks.
const POLL_UPSTREAM_ITEMS_SOFT_CAP: usize = 64;

/// Incremental SSE decoder state.
///
/// Consumes raw body chunks as bytes: complete lines are parsed directly out
/// of each scan block (one UTF-8 validation pass and one line-terminator scan,
/// zero allocations per line); only a line or UTF-8 sequence that
/// crosses a chunk boundary is buffered in `carry`.
struct DecodeState<T: EventDataRead> {
    /// partial line (possibly ending in a partial UTF-8 sequence) from prior chunks
    carry: Vec<u8>,
    /// valid UTF-8 prefix of `carry`, always ending at a character boundary;
    /// the remaining suffix is an incomplete sequence of at most three bytes
    carry_valid_up_to: usize,
    /// a CR was the last byte seen: an LF at the start of the next chunk
    /// belongs to that terminator and must be skipped
    pending_cr: bool,
    /// leading BOM check has been resolved
    started: bool,
    builder: EventBuilder<T>,
    /// events decoded but not yet yielded (a single chunk can complete several)
    ready: VecDeque<Event<T>>,
    last_event_id: Option<SmolStr>,
}

impl<T> fmt::Debug for DecodeState<T>
where
    T: EventDataRead + fmt::Debug,
    T::Reader: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodeState")
            .field("carry", &self.carry)
            .field("carry_valid_up_to", &self.carry_valid_up_to)
            .field("pending_cr", &self.pending_cr)
            .field("started", &self.started)
            .field("builder", &self.builder)
            .field("ready", &self.ready)
            .field("last_event_id", &self.last_event_id)
            .finish()
    }
}

impl<T: EventDataRead> Default for DecodeState<T> {
    fn default() -> Self {
        Self {
            carry: Vec::new(),
            carry_valid_up_to: 0,
            pending_cr: false,
            started: false,
            builder: EventBuilder::default(),
            ready: VecDeque::new(),
            last_event_id: None,
        }
    }
}

impl<T: EventDataRead> DecodeState<T> {
    /// Feed one body chunk into the decoder; completed events queue up in
    /// `ready`. Returns the number of bytes consumed: decoding pauses once
    /// `ready` holds [`READY_EVENTS_SOFT_CAP`] events, and the caller is
    /// expected to re-offer the unconsumed remainder once drained.
    fn feed(&mut self, mut input: &[u8]) -> Result<usize, BoxError> {
        let full_len = input.len();
        if input.is_empty() {
            return Ok(0);
        }
        if !self.started {
            if self.carry.is_empty() && input.len() >= UTF8_BOM.len() {
                self.started = true;
                if input[..UTF8_BOM.len()] == UTF8_BOM {
                    input = &input[UTF8_BOM.len()..];
                }
            } else {
                // tiny first chunk(s): buffer bytes until the BOM question is decided
                while !self.started {
                    let Some((&byte, rest)) = input.split_first() else {
                        return Ok(full_len);
                    };
                    input = rest;
                    self.carry.push(byte);
                    if self.carry[..] == UTF8_BOM {
                        self.carry.clear();
                        self.started = true;
                    } else if self.carry[..] != UTF8_BOM[..self.carry.len()] {
                        self.started = true;
                        // non-BOM prefix: replay it through the regular scanner,
                        // as it may itself contain line terminators
                        let mut replay = [0u8; UTF8_BOM.len()];
                        let n = self.carry.len();
                        replay[..n].copy_from_slice(&self.carry);
                        self.carry.clear();
                        self.carry_valid_up_to = 0;
                        let consumed = self.scan(&replay[..n])?;
                        debug_assert_eq!(
                            consumed, n,
                            "a replay of at most 3 bytes cannot hit the ready-event cap"
                        );
                    }
                }
            }
        }
        let consumed = self.scan(input)?;
        Ok(full_len - input.len() + consumed)
    }

    /// The underlying stream is exhausted: validate and discard any
    /// unterminated trailing line, per the WHATWG event stream model.
    fn finish(&mut self) -> Result<(), BoxError> {
        if self.carry.is_empty() {
            return Ok(());
        }
        // `scan` validates carried bytes incrementally. Only the possible
        // incomplete UTF-8 suffix remains to check at EOF, rather than
        // re-validating an attacker-sized unterminated line in one poll.
        std::str::from_utf8(&self.carry[self.carry_valid_up_to..])
            .map_err(|err| err.context("utf8 error: invalid trailing sse bytes"))?;
        self.carry.clear();
        self.carry_valid_up_to = 0;
        Ok(())
    }

    /// Extend `carry` while validating only bytes not already known valid.
    fn extend_carry(&mut self, bytes: &[u8]) -> Result<(), BoxError> {
        let validate_from = self.carry_valid_up_to;
        self.carry.extend_from_slice(bytes);
        match std::str::from_utf8(&self.carry[validate_from..]) {
            Ok(_) => self.carry_valid_up_to = self.carry.len(),
            Err(err) => {
                self.carry_valid_up_to = validate_from + err.valid_up_to();
                if err.error_len().is_some() {
                    return Err(err.context("utf8 error: invalid sse bytes"));
                }
            }
        }
        debug_assert!(self.carry.len() - self.carry_valid_up_to <= 3);
        Ok(())
    }

    /// Scan the input for complete lines; returns the number of bytes
    /// consumed, which is less than `input.len()` when one of the soft
    /// caps ([`READY_EVENTS_SOFT_CAP`], [`SCAN_BYTES_SOFT_CAP`]) pauses
    /// decoding mid-chunk. Every pause point is also a valid chunk
    /// boundary, so resuming later with the remainder is state-safe.
    fn scan(&mut self, input: &[u8]) -> Result<usize, BoxError> {
        let input = &input[..input.len().min(SCAN_BYTES_SOFT_CAP)];
        if input.is_empty() || self.ready.len() >= READY_EVENTS_SOFT_CAP {
            return Ok(0);
        }

        // A ready-cap pause can only overlap this fixed initial block on the
        // next call; fully consumed blocks are never inspected again. This
        // bounds dense-input amplification by a constant and makes total
        // overflow-drain work linear, while sparse input quickly reaches the
        // full scan cap.
        let mut offset = 0;
        let mut block_len = SCAN_INITIAL_BLOCK_SIZE;
        while offset < input.len() {
            let block_start = offset;
            let end = (offset + block_len).min(input.len());
            let consumed = self.scan_block(&input[offset..end])?;
            offset += consumed;
            if consumed < end - block_start || self.ready.len() >= READY_EVENTS_SOFT_CAP {
                break;
            }
            block_len = (block_len * 2).min(SCAN_BYTES_SOFT_CAP);
        }
        Ok(offset)
    }

    /// Scan one artificial chunk boundary. The caller grows these blocks
    /// exponentially until the byte or ready-event cap is reached.
    fn scan_block(&mut self, input: &[u8]) -> Result<usize, BoxError> {
        if input.is_empty() {
            return Ok(0);
        }

        let mut offset = 0;

        if self.pending_cr {
            self.pending_cr = false;
            if input[0] == b'\n' {
                offset += 1;
            }
        }

        // complete a line left over from previous chunk(s)
        if !self.carry.is_empty() {
            match memchr2(b'\r', b'\n', &input[offset..]) {
                None => {
                    self.extend_carry(&input[offset..])?;
                    return Ok(input.len());
                }
                Some(pos) => {
                    self.extend_carry(&input[offset..offset + pos])?;
                    let is_cr = input[offset + pos] == b'\r';
                    offset += pos + 1;
                    if is_cr {
                        if offset == input.len() {
                            self.pending_cr = true;
                        } else if input[offset] == b'\n' {
                            offset += 1;
                        }
                    }
                    // take/restore the carry buffer so its allocation is reused,
                    // while keeping the borrow checker happy about `handle_line`
                    let line = std::mem::take(&mut self.carry);
                    let valid_up_to = std::mem::take(&mut self.carry_valid_up_to);
                    std::str::from_utf8(&line[valid_up_to..])
                        .map_err(|err| err.context("utf8 error: invalid sse line"))?;
                    debug_assert_eq!(valid_up_to, line.len());
                    // SAFETY: `extend_carry` validated the line incrementally,
                    // and the possible incomplete suffix was checked above.
                    let s = unsafe { std::str::from_utf8_unchecked(&line) };
                    self.handle_line(s)?;
                    self.carry = line;
                    self.carry.clear();
                    if self.ready.len() >= READY_EVENTS_SOFT_CAP {
                        return Ok(offset);
                    }
                }
            }
        }

        // validate the remaining input once; an incomplete UTF-8 sequence at
        // the very end is carried over, invalid bytes fail after the valid
        // prefix has been processed
        let rest = &input[offset..];
        let (valid, utf8_tail, utf8_err) = match std::str::from_utf8(rest) {
            Ok(s) => (s, &[][..], None),
            Err(err) => {
                let (head, tail) = rest.split_at(err.valid_up_to());
                // SAFETY: `valid_up_to` guarantees `head` is valid UTF-8
                let s = unsafe { std::str::from_utf8_unchecked(head) };
                match err.error_len() {
                    None => (s, tail, None),
                    Some(_) => (
                        s,
                        &[][..],
                        Some(err.context("utf8 error: invalid sse bytes")),
                    ),
                }
            }
        };

        let bytes = valid.as_bytes();
        let mut start = 0;
        if memchr::memchr(b'\r', bytes).is_none() {
            // hot path: no CR anywhere, so every terminator is a lone LF;
            // a single-needle scan is considerably faster than memchr2
            for pos in memchr::memchr_iter(b'\n', bytes) {
                self.handle_line(&valid[start..pos])?;
                start = pos + 1;
                if self.ready.len() >= READY_EVENTS_SOFT_CAP {
                    return Ok(offset + start);
                }
            }
        } else {
            for pos in memchr2_iter(b'\r', b'\n', bytes) {
                if pos < start {
                    // the LF half of a CRLF pair
                    continue;
                }
                let line = &valid[start..pos];
                let mut next = pos + 1;
                if bytes[pos] == b'\r' {
                    if next < bytes.len() {
                        if bytes[next] == b'\n' {
                            next += 1;
                        }
                    } else if utf8_tail.is_empty() && utf8_err.is_none() {
                        // chunk ends exactly on the CR: an LF may still follow
                        // (a non-empty tail or invalid byte can never be an LF)
                        self.pending_cr = true;
                    }
                }
                self.handle_line(line)?;
                start = next;
                if self.ready.len() >= READY_EVENTS_SOFT_CAP {
                    return Ok(offset + start);
                }
            }
        }

        if let Some(err) = utf8_err {
            return Err(err);
        }

        self.carry.extend_from_slice(&bytes[start..]);
        self.carry.extend_from_slice(utf8_tail);
        self.carry_valid_up_to = bytes.len() - start;
        Ok(input.len())
    }

    #[inline]
    fn handle_line(&mut self, line: &str) -> Result<(), BoxError> {
        self.builder.add(parse_line(line))?;
        if self.builder.is_complete {
            let event = self.builder.try_dispatch()?;
            self.ready.push_back(event);
        }
        Ok(())
    }
}

pin_project! {
    /// A Stream of SSE's used by the client.
    pub struct EventStream<S, T: EventDataRead = String> {
        #[pin]
        stream: S,
        state: DecodeState<T>,
        // unconsumed remainder of an upstream chunk, set aside while
        // `ready` was at capacity; drained (from `overflow_offset` on)
        // before the upstream stream is polled again
        overflow: Vec<u8>,
        overflow_offset: usize,
        pending_error: Option<BoxError>,
        stream_done: bool,
        terminated: bool,
    }
}

impl<S, T: EventDataRead> EventStream<S, T> {
    /// Initialize the EventStream with a Stream
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            state: DecodeState::default(),
            overflow: Vec::new(),
            overflow_offset: 0,
            pending_error: None,
            stream_done: false,
            terminated: false,
        }
    }

    /// Set the last event ID of the stream. Useful for initializing the stream with a previous
    /// last event ID
    pub fn try_set_last_event_id(&mut self, id: impl Into<SmolStr>) -> Result<(), BoxError> {
        let id = id.into();
        if id.contains(['\n', '\r', '\0']) {
            return Err(EventBuildError::invalid_characters(id).into_box_error());
        }
        self.state.last_event_id = Some(id);
        Ok(())
    }

    /// Get the last event ID of the stream
    pub fn last_event_id(&self) -> Option<&str> {
        self.state.last_event_id.as_deref()
    }
}

impl<S, B, E, T> Stream for EventStream<S, T>
where
    S: Stream<Item = Result<B, E>>,
    E: Into<BoxError>,
    B: AsRef<[u8]>,
    T: EventDataRead,
{
    type Item = Result<Event<T>, BoxError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let mut decoded_bytes = 0;
        let mut upstream_items = 0;

        loop {
            if let Some(event) = this.state.ready.pop_front() {
                // WHATWG: the last-event-ID buffer persists across events;
                // only overwrite it when the yielded event actually had an
                // id field (post-parse `Some(_)`, empty string included).
                // The checkpoint moves when the event is handed to the
                // caller, never while it still sits in the ready queue.
                if let Some(id) = event.id() {
                    this.state.last_event_id = Some(SmolStr::new(id));
                }
                return Poll::Ready(Some(Ok(event)));
            }
            if let Some(err) = this.pending_error.take() {
                // a decode error is fatal: the byte stream can no longer
                // be interpreted reliably beyond this point
                *this.terminated = true;
                return Poll::Ready(Some(Err(err)));
            }
            if *this.terminated {
                return Poll::Ready(None);
            }

            if decoded_bytes >= POLL_BYTES_SOFT_CAP
                || upstream_items >= POLL_UPSTREAM_ITEMS_SOFT_CAP
            {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }

            // refill from a set-aside chunk remainder before polling upstream
            if *this.overflow_offset < this.overflow.len() {
                let remaining_budget = POLL_BYTES_SOFT_CAP - decoded_bytes;
                let end = (*this.overflow_offset + remaining_budget).min(this.overflow.len());
                match this.state.scan(&this.overflow[*this.overflow_offset..end]) {
                    Ok(consumed) => {
                        debug_assert!(consumed > 0, "non-empty overflow scan must make progress");
                        *this.overflow_offset += consumed;
                        decoded_bytes += consumed;
                        if *this.overflow_offset >= this.overflow.len() {
                            this.overflow.clear();
                            *this.overflow_offset = 0;
                        }
                    }
                    Err(err) => {
                        this.overflow.clear();
                        *this.overflow_offset = 0;
                        *this.pending_error = Some(err);
                    }
                }
                continue;
            }

            if *this.stream_done {
                *this.terminated = true;
                if let Err(err) = this.state.finish() {
                    *this.pending_error = Some(err);
                }
                continue;
            }

            match this.stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    upstream_items += 1;
                    let bytes = chunk.as_ref();
                    let remaining_budget = POLL_BYTES_SOFT_CAP - decoded_bytes;
                    let offered = &bytes[..bytes.len().min(remaining_budget)];
                    match this.state.feed(offered) {
                        Ok(consumed) if consumed < bytes.len() => {
                            decoded_bytes += consumed;
                            // The ready queue or per-poll byte budget stopped
                            // this chunk; set its unconsumed tail aside once.
                            this.overflow.extend_from_slice(&bytes[consumed..]);
                        }
                        Ok(consumed) => {
                            decoded_bytes += consumed;
                        }
                        Err(err) => {
                            *this.pending_error = Some(err);
                        }
                    }
                }
                Poll::Ready(Some(Err(err))) => {
                    // transport errors pass through without terminating the
                    // decoder: the caller decides whether to keep polling
                    return Poll::Ready(Some(Err(err.into())));
                }
                Poll::Ready(None) => {
                    *this.stream_done = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::allow_attributes,
        reason = "test macros use `#[allow(unused_mut)]` because the binding is mutated only by some variadic arms — `#[expect]` would warn unfulfilled when no arm fires"
    )]

    use crate::{BodyExtractExt, sse::JsonEventData};

    use super::*;
    use rama_core::futures::prelude::*;
    use serde::{Deserialize, Serialize};
    use serde_json::json;
    use std::convert::Infallible;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::{Wake, Waker};

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct AlwaysReadyEmpty {
        polls: Arc<AtomicUsize>,
    }

    impl Stream for AlwaysReadyEmpty {
        type Item = Result<Vec<u8>, Infallible>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Some(Ok(Vec::new())))
        }
    }

    #[test]
    fn ready_cap_stops_within_the_initial_scan_block() {
        let mut state = DecodeState::<String> {
            started: true,
            ..Default::default()
        };

        let dense_lf = vec![b'\n'; SCAN_BYTES_SOFT_CAP];
        assert_eq!(READY_EVENTS_SOFT_CAP, state.scan(&dense_lf).unwrap());

        let mut state = DecodeState::<String> {
            started: true,
            ..Default::default()
        };
        let dense_crlf = b"\r\n".repeat(READY_EVENTS_SOFT_CAP);
        assert_eq!(dense_crlf.len(), state.scan(&dense_crlf).unwrap());

        // A leading LF can belong to a CR terminator from the prior window.
        let mut state = DecodeState::<String> {
            started: true,
            pending_cr: true,
            ..Default::default()
        };
        let after_cr = vec![b'\n'; READY_EVENTS_SOFT_CAP + 1];
        assert_eq!(after_cr.len(), state.scan(&after_cr).unwrap());

        // A carried prefix makes the first terminated line non-empty.
        let mut state = DecodeState::<String> {
            started: true,
            ..Default::default()
        };
        state.carry.push(b'x');
        state.carry_valid_up_to = 1;
        assert_eq!(after_cr.len(), state.scan(&after_cr).unwrap());
    }

    #[test]
    fn one_poll_has_a_cumulative_byte_budget() {
        let upstream = stream::iter([Ok::<_, Infallible>(vec![b'x'; POLL_BYTES_SOFT_CAP * 2])]);
        let mut stream = std::pin::pin!(EventStream::<_, String>::new(upstream));
        let wake_count = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(stream.as_mut().poll_next(&mut cx), Poll::Pending));
        assert_eq!(1, wake_count.0.load(Ordering::Relaxed));
        assert_eq!(POLL_BYTES_SOFT_CAP, stream.state.carry.len());
        assert_eq!(POLL_BYTES_SOFT_CAP, stream.overflow.len());

        assert!(matches!(stream.as_mut().poll_next(&mut cx), Poll::Pending));
        assert_eq!(2, wake_count.0.load(Ordering::Relaxed));
        assert!(matches!(
            stream.as_mut().poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[test]
    fn empty_ready_chunks_have_a_poll_attempt_budget() {
        let upstream_polls = Arc::new(AtomicUsize::new(0));
        let upstream = AlwaysReadyEmpty {
            polls: Arc::clone(&upstream_polls),
        };
        let mut stream = std::pin::pin!(EventStream::<_, String>::new(upstream));
        let wake_count = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&wake_count));
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(stream.as_mut().poll_next(&mut cx), Poll::Pending));
        assert_eq!(
            POLL_UPSTREAM_ITEMS_SOFT_CAP,
            upstream_polls.load(Ordering::Relaxed)
        );
        assert_eq!(1, wake_count.0.load(Ordering::Relaxed));
    }

    #[test]
    fn carried_utf8_is_validated_incrementally() {
        let mut state = DecodeState::<String>::default();
        assert_eq!(7, state.feed(b"data: \xf0").unwrap());
        assert_eq!(6, state.carry_valid_up_to);
        state.feed(b"(").unwrap_err();
    }

    macro_rules! event {
        (
            $data:expr,
            $(event = $name:literal,)*
            $(id = $id:literal,)*
            $(comment = $comment:literal,)*
        ) => {
            {
                #[allow(unused_mut)]
                let mut event = Event {
                    data: Some($data),
                    ..Default::default()
                };
                $(
                    event.try_set_event($name).unwrap();
                )*
                $(
                    event.try_set_id($id).unwrap();
                )*
                $(
                    event.try_set_comment($comment).unwrap();
                )*
                event
            }
        };
        (
            @,
            $(event = $name:literal,)*
            $(id = $id:literal,)*
            $(comment = $comment:literal,)*
        ) => {
            {
                #[allow(unused_mut)]
                let mut event = Event::<String>::default();
                $(
                    event.try_set_event($name).unwrap();
                )*
                $(
                    event.try_set_id($id).unwrap();
                )*
                $(
                    event.try_set_comment($comment).unwrap();
                )*
                event
            }
        };
    }

    /// decode a full input in one chunk, expecting at most one event
    fn parse_single<T: EventDataRead>(input: &str) -> (Option<Event<T>>, DecodeState<T>) {
        let mut state = DecodeState::<T>::default();
        let bytes = input.as_bytes();
        let mut offset = 0;
        while offset < bytes.len() {
            offset += state.feed(&bytes[offset..]).unwrap();
        }
        state.finish().unwrap();
        let event = state.ready.pop_front();
        assert!(
            state.ready.is_empty(),
            "input yielded more than one event: '{input}'"
        );
        (event, state)
    }

    #[tokio::test]
    async fn test_string_event_serialize() {
        for (expected, event) in [
            ("", event!(@,)),
            (
                "event: ping\ndata: 42\n\n",
                event!("42".to_owned(), event = "ping",),
            ),
            (
                "data: example message\n\n",
                event!("example message".to_owned(),),
            ),
            (
                "data: a\ndata: b\ndata: c\ndata: d\ndata: e\ndata: f\n\n",
                event!("a\nb\nc\nd\ne\nf".to_owned(),),
            ),
            (
                ": this is a comment\n: another comment\nid: 42\nevent: some-event\ndata: and some data\n\n",
                event!(
                    "and some data".to_owned(),
                    event = "some-event",
                    id = "42",
                    comment = "this is a comment",
                    comment = "another comment",
                ),
            ),
        ] {
            let buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            assert_eq!(expected, buffer);
        }
    }

    #[tokio::test]
    async fn test_string_event_deserialize() {
        for (input, expected) in [
            ("", None),
            (
                "data: 42\nevent: ping\n\n",
                Some(event!("42".to_owned(), event = "ping",)),
            ),
            (
                "event: ping\ndata: 42\n\n",
                Some(event!("42".to_owned(), event = "ping",)),
            ),
            (
                "data: example message\n\n",
                Some(event!("example message".to_owned(),)),
            ),
            (
                "data: a\ndata: b\ndata: c\ndata: d\ndata: e\ndata: f\n\n",
                Some(event!("a\nb\nc\nd\ne\nf".to_owned(),)),
            ),
            (
                ": this is a comment\n: another comment\nid: 42\nevent: some-event\ndata: and some data\n\n",
                Some(event!(
                    "and some data".to_owned(),
                    event = "some-event",
                    id = "42",
                    comment = "this is a comment",
                    comment = "another comment",
                )),
            ),
        ] {
            let (event_out, state) = parse_single::<String>(input);
            assert!(
                state.carry.is_empty(),
                "input: '{input}'; state: '{state:?}'"
            );
            assert!(
                !state.builder.is_complete,
                "input: '{input}'; state: '{state:?}'"
            );
            assert_eq!(Event::default(), state.builder.event, "input: '{input}'");
            assert_eq!(expected, event_out, "input: '{input}'");
        }
    }

    #[tokio::test]
    async fn test_string_event_serialize_deserialize() {
        for event in [
            event!("foo".to_owned(), event = "ping",),
            event!(
                "and some data".to_owned(),
                event = "some-event",
                id = "42",
                comment = "this is a comment",
                comment = "another comment",
            ),
        ] {
            let buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            let (event_out, state) = parse_single::<String>(&buffer);
            assert!(state.carry.is_empty());
            assert!(!state.builder.is_complete);
            assert_eq!(Event::default(), state.builder.event);
            assert_eq!(Some(event), event_out);
        }
    }

    #[tokio::test]
    async fn test_json_event_serialize() {
        for (expected, event) in [
            ("data: {}\n\n", event!(JsonEventData(json!({})),)),
            (
                "data: {\"name\":\"john\"}\n\n",
                event!(JsonEventData(json!({"name": "john"})),),
            ),
        ] {
            let buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            assert_eq!(expected, buffer);
        }
    }

    #[tokio::test]
    async fn test_json_event_deserialize() {
        #[derive(Debug, Deserialize, Default, PartialEq, Eq)]
        struct Data {
            points: Option<Vec<u32>>,
        }
        type PointsEvent = Event<JsonEventData<Data>>;

        for (input, expected) in [
            (
                "data: {}\n\n",
                Some(event!(JsonEventData(Data::default()),)),
            ),
            (
                "data: {\"points\":[]}\nevent: message\n\n",
                Some(event!(
                    JsonEventData(Data {
                        points: Some(vec![])
                    }),
                    event = "message",
                )),
            ),
            (
                "data: {\"points\":[4,2]}\nevent: ping\n\n",
                Some(event!(
                    JsonEventData(Data {
                        points: Some(vec![4, 2])
                    }),
                    event = "ping",
                )),
            ),
        ] {
            let (event_out, state) = parse_single::<JsonEventData<Data>>(input);
            assert!(
                state.carry.is_empty(),
                "input: '{input}'; state: '{state:?}'"
            );
            assert!(
                !state.builder.is_complete,
                "input: '{input}'; state: '{state:?}'"
            );
            assert_eq!(
                PointsEvent::default(),
                state.builder.event,
                "input: '{input}'"
            );
            assert_eq!(expected, event_out, "input: '{input}'");
        }
    }

    #[tokio::test]
    async fn test_json_event_serialize_deserialize() {
        #[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
        struct Log {
            text: String,
        }
        type LogEvent = Event<JsonEventData<Log>>;

        for event in [
            event!(
                JsonEventData(Log {
                    text: "a log line".to_owned()
                }),
                event = "message",
            ),
            event!(
                JsonEventData(Log {
                    text: "another log line".to_owned()
                }),
                event = "final",
                id = "L3",
                comment = "this is",
                comment = " a log",
            ),
        ] {
            let buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            let (event_out, state) = parse_single::<JsonEventData<Log>>(&buffer);
            assert!(state.carry.is_empty());
            assert!(!state.builder.is_complete);
            assert_eq!(LogEvent::default(), state.builder.event);
            assert_eq!(Some(event), event_out);
        }
    }

    #[tokio::test]
    async fn test_multiline_event_serialize() {
        for (expected, event) in [
            ("data: \n\n", event!(Vec::<String>::default(),)),
            ("data: a\n\n", event!(vec!["a".to_owned()],)),
            (
                "data: a\ndata: b\n\n",
                event!(vec!["a".to_owned(), "b".to_owned()],),
            ),
        ] {
            let buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            assert_eq!(expected, buffer);
        }
    }

    #[tokio::test]
    async fn test_multiline_event_deserialize() {
        for (input, expected) in [
            ("", None),
            ("data: \n\n", Some(event!(vec![String::default()],))),
            ("data: a\n\n", Some(event!(vec!["a".to_owned()],))),
            (
                "data: a\ndata: b\n\n",
                Some(event!(vec!["a".to_owned(), "b".to_owned()],)),
            ),
        ] {
            let (event_out, state) = parse_single::<Vec<String>>(input);
            assert!(
                state.carry.is_empty(),
                "input: '{input}'; state: '{state:?}'"
            );
            assert!(
                !state.builder.is_complete,
                "input: '{input}'; state: '{state:?}'"
            );
            assert_eq!(
                Event::<Vec<String>>::default(),
                state.builder.event,
                "input: '{input}'"
            );
            assert_eq!(expected, event_out, "input: '{input}'");
        }
    }

    #[tokio::test]
    async fn test_multiline_event_serialize_deserialize() {
        type MultilineEvent = Event<Vec<String>>;

        for event in [
            event!(vec!["foo".to_owned(), "bar".to_owned()], event = "message",),
            event!(
                vec!["foo".to_owned()],
                event = "final",
                id = "L3",
                comment = "this is",
                comment = " a log",
            ),
        ] {
            let buffer = event.serialize().unwrap().try_into_string().await.unwrap();
            let (event_out, state) = parse_single::<Vec<String>>(&buffer);
            assert!(state.carry.is_empty());
            assert!(!state.builder.is_complete);
            assert_eq!(MultilineEvent::default(), state.builder.event);
            assert_eq!(Some(event), event_out);
        }
    }

    #[tokio::test]
    async fn valid_data_fields() {
        for (input, expected) in [
            (
                vec!["data: Hello, world!\n\n"],
                vec![event!("Hello, world!".to_owned(),)],
            ),
            (
                vec!["data: Hello,", " world!\n\n"],
                vec![event!("Hello, world!".to_owned(),)],
            ),
            (
                vec!["data: Hello,", "", " world!\n\n"],
                vec![event!("Hello, world!".to_owned(),)],
            ),
            (
                vec!["data: Hello,\ndata: world!\n\n"],
                vec![event!("Hello,\nworld!".to_owned(),)],
            ),
            (
                vec!["data: Hello,\n\ndata: world!\n\n"],
                vec![event!("Hello,".to_owned(),), event!("world!".to_owned(),)],
            ),
        ] {
            let stream = EventStream::new(stream::iter(input.iter().map(Ok::<_, Infallible>)));
            let output = stream.try_collect::<Vec<_>>().await.unwrap();
            assert_eq!(expected, output, "input: '{input:?}'; output: '{output:?}'");
        }
    }

    #[tokio::test]
    async fn spec_examples() {
        for (input, expected) in [
            (
                vec![
                    "data: This is the first message.

data: This is the second message, it
data: has two lines.

data: This is the third message.

",
                ],
                vec![
                    event!("This is the first message.".to_owned(),),
                    event!("This is the second message, it\nhas two lines.".to_owned(),),
                    event!("This is the third message.".to_owned(),),
                ],
            ),
            (
                vec![
                    "event: add
data: 73857293

event: remove
data: 2153

event: add
data: 113411

    ",
                ],
                vec![
                    event!("73857293".to_owned(), event = "add",),
                    event!("2153".to_owned(), event = "remove",),
                    event!("113411".to_owned(), event = "add",),
                ],
            ),
            (
                vec![
                    "data: YHOO
data: +2
data: 10

    ",
                ],
                vec![event!("YHOO\n+2\n10".to_owned(),)],
            ),
            (
                vec![
                    ": test stream

data: first event
id: 1

data:second event
id

data:  third event

    ",
                ],
                vec![
                    event!(@, comment = "test stream",),
                    event!("first event".to_owned(), id = "1",),
                    // WHATWG: bare `id` (no value) sets the last-event-ID buffer
                    // to the empty string, so the dispatched event carries
                    // `id = ""` rather than `id = None`.
                    event!("second event".to_owned(), id = "",),
                    event!(" third event".to_owned(),),
                ],
            ),
            (
                vec![
                    "data

data
data

data:
",
                ],
                vec![event!("".to_owned(),), event!("\n".to_owned(),)],
            ),
            (
                vec![
                    "data:test

data: test

",
                ],
                vec![event!("test".to_owned(),), event!("test".to_owned(),)],
            ),
        ] {
            let stream = EventStream::new(stream::iter(input.iter().map(Ok::<_, Infallible>)));
            let expect = format!("input: '{input:?}'");
            let output = stream.try_collect::<Vec<_>>().await.expect(&expect);
            assert_eq!(expected, output, "input: '{input:?}'; output: '{output:?}'");
        }
    }

    /// WHATWG: a bare `event` field (no value) sets the event-type buffer
    /// to the empty string, which dispatches as the default `message` event
    /// — _and_ overrides any earlier `event:` line within the same event.
    #[tokio::test]
    async fn empty_event_field_clears_event_name() {
        let input = "event: ping\nevent\ndata: 42\n\n";
        let stream = EventStream::new(stream::iter([Ok::<_, Infallible>(input)]));
        let output = stream.try_collect::<Vec<_>>().await.unwrap();
        assert_eq!(output, vec![event!("42".to_owned(),)]);
    }

    /// WHATWG: a bare `id` field (no value) sets the last-event-ID buffer
    /// to the empty string; the dispatched event carries `id = ""`.
    #[tokio::test]
    async fn empty_id_field_sets_empty_last_event_id() {
        let input = "id: prior\ndata: a\n\nid\ndata: b\n\n";
        let mut stream = EventStream::new(stream::iter([Ok::<_, Infallible>(input)]));
        let events: Vec<_> = (&mut stream).try_collect::<Vec<_>>().await.unwrap();
        assert_eq!(
            events,
            vec![
                event!("a".to_owned(), id = "prior",),
                event!("b".to_owned(), id = "",),
            ],
        );
        assert_eq!(stream.last_event_id(), Some(""));
    }

    /// WHATWG: an `id` containing U+0000 makes the entire field ignored.
    #[tokio::test]
    async fn id_with_nul_is_ignored() {
        let input = "id: ok\ndata: a\n\nid: bad\u{0000}id\ndata: b\n\n";
        let mut stream = EventStream::new(stream::iter([Ok::<_, Infallible>(input)]));
        let events: Vec<_> = (&mut stream).try_collect::<Vec<_>>().await.unwrap();
        assert_eq!(
            events,
            vec![
                event!("a".to_owned(), id = "ok",),
                // `id` line is ignored: the event has no id, but the
                // last-event-ID buffer keeps the previous value.
                event!("b".to_owned(),),
            ],
        );
        assert_eq!(stream.last_event_id(), Some("ok"));
    }

    /// WHATWG: the last-event-ID buffer persists across events that don't
    /// carry an explicit `id` field.
    #[tokio::test]
    async fn last_event_id_persists_across_events_without_id() {
        let input = "id: seven\ndata: a\n\ndata: b\n\ndata: c\n\n";
        let mut stream = EventStream::new(stream::iter([Ok::<_, Infallible>(input)]));
        let events: Vec<_> = (&mut stream).try_collect::<Vec<_>>().await.unwrap();
        assert_eq!(
            events,
            vec![
                event!("a".to_owned(), id = "seven",),
                event!("b".to_owned(),),
                event!("c".to_owned(),),
            ],
        );
        assert_eq!(stream.last_event_id(), Some("seven"));
    }

    /// WHATWG: the `retry` value MUST consist of only ASCII digits.
    /// Rust's `u64::parse` accepts a leading `+`, which the spec disallows.
    #[tokio::test]
    async fn retry_only_accepts_ascii_digits() {
        for (input, want_retry_ms) in [
            ("retry: 1500\ndata: a\n\n", Some(1500_u64)),
            ("retry: +5\ndata: a\n\n", None),
            ("retry: -1\ndata: a\n\n", None),
            ("retry: 5ms\ndata: a\n\n", None),
            ("retry: abc\ndata: a\n\n", None),
            ("retry:\ndata: a\n\n", None),
        ] {
            let stream = EventStream::<_, String>::new(stream::iter([Ok::<_, Infallible>(input)]));
            let events: Vec<_> = stream.try_collect::<Vec<_>>().await.unwrap();
            assert_eq!(events.len(), 1, "input: {input:?}");
            assert_eq!(
                events[0].retry().map(|d| d.as_millis() as u64),
                want_retry_ms,
                "input: {input:?}",
            );
        }
    }

    /// JSON reader on an event without any `data:` line should surface
    /// `Ok(None)` rather than erroring on `serde_json::from_str("")`.
    #[tokio::test]
    async fn json_reader_surfaces_none_when_no_data() {
        // Two events: the first carries no data field at all.
        let input = ": preamble\nid: 1\n\ndata: {\"v\":2}\nid: 2\n\n";
        let stream = EventStream::<_, JsonEventData<serde_json::Value>>::new(stream::iter([Ok::<
            _,
            Infallible,
        >(
            input,
        )]));
        let events: Vec<_> = stream.try_collect::<Vec<_>>().await.unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].data().is_none());
        assert_eq!(events[1].data().map(|d| d.0.clone()), Some(json!({"v": 2})),);
    }
}
