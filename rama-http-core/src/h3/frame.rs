//! A bounded, incremental HTTP/3 frame decoder (RFC 9114 §7.1).
//!
//! Bytes are fed in arbitrary chunks; complete frames come out one at a time, with a "need more"
//! signal in between. It distinguishes incomplete input (need more), malformed input (a protocol
//! error) and a truncated end of stream (via [`FrameDecoder::is_at_frame_boundary`]).
//!
//! Memory is bounded: DATA payloads are streamed rather than buffered, unknown and reserved frame
//! payloads are skipped without allocating their advertised length, and every buffered (known)
//! frame is rejected before buffering if it exceeds the configured cap. Frame type and length are
//! read with a fragmentation-safe variable-length integer decoder, so a length split across chunks
//! never loses framing.

use rama_core::bytes::{Buf, Bytes, BytesMut};
use rama_http_types::proto::h3::{FrameHeader, FrameType, Settings, SettingsError, VarIntDecoder};

/// The default cap on a single buffered (non-DATA) frame's payload.
pub const DEFAULT_MAX_FRAME_SIZE: usize = rama_utils::octets::mib(1);

/// An event produced by [`FrameDecoder::poll`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FrameEvent {
    /// A frame header emitted before payload processing when header events are enabled.
    Header(FrameHeader),
    /// The start of a DATA frame; `len` payload bytes follow as [`FrameEvent::DataChunk`]s.
    DataHeader {
        /// The total DATA payload length.
        len: u64,
    },
    /// A chunk of the current DATA frame's payload.
    DataChunk(Bytes),
    /// A fully buffered HEADERS payload (a QPACK-encoded field section).
    Headers(Bytes),
    /// A decoded SETTINGS frame.
    Settings(Settings),
    /// A CANCEL_PUSH frame carrying a push ID.
    CancelPush(u64),
    /// A GOAWAY frame carrying a stream or push ID.
    GoAway(u64),
    /// A MAX_PUSH_ID frame carrying the maximum push ID.
    MaxPushId(u64),
    /// A PUSH_PROMISE frame: a push ID and the buffered encoded field section.
    PushPromise {
        /// The promised push ID.
        push_id: u64,
        /// The QPACK-encoded field section.
        encoded_headers: Bytes,
    },
    /// An RFC 9218 priority update. The field value shares frame payload storage.
    PriorityUpdate {
        /// Whether the identifier names a push rather than a request stream.
        push: bool,
        /// Prioritized request stream or push identifier.
        element_id: u64,
        /// Structured Priority field value.
        field_value: Bytes,
    },
    /// An unknown or reserved frame type whose payload was skipped without buffering.
    Ignored {
        /// The frame type.
        ty: FrameType,
        /// The skipped payload length.
        len: u64,
    },
}

/// An error decoding an HTTP/3 frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FrameError {
    /// A frame type reused from HTTP/2 was received (RFC 9114 §7.2.8): `H3_FRAME_UNEXPECTED`.
    UnexpectedH2Frame(FrameType),
    /// A buffered frame's payload exceeded the configured cap: `H3_EXCESSIVE_LOAD`.
    FrameTooLarge {
        /// The offending frame type.
        ty: FrameType,
        /// The advertised payload length.
        len: u64,
    },
    /// Input was not accepted because the previous chunk has not been drained or the new chunk
    /// exceeds the input limit. This is local backpressure, not a peer protocol error.
    InputBufferFull,
    /// SETTINGS exceeded the local entry budget: `H3_EXCESSIVE_LOAD`.
    TooManySettings,
    /// A known frame's payload was malformed: `H3_FRAME_ERROR`.
    Malformed(FrameType),
    /// A SETTINGS frame was invalid: `H3_SETTINGS_ERROR`.
    Settings(SettingsError),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnexpectedH2Frame(ty) => write!(f, "unexpected HTTP/2 frame {ty:?}"),
            Self::FrameTooLarge { ty, len } => write!(f, "frame {ty:?} too large ({len} bytes)"),
            Self::InputBufferFull => {
                f.write_str("drain the frame decoder or supply a smaller input chunk")
            }
            Self::TooManySettings => f.write_str("too many HTTP/3 settings"),
            Self::Malformed(ty) => write!(f, "malformed {ty:?} frame"),
            Self::Settings(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<SettingsError> for FrameError {
    fn from(e: SettingsError) -> Self {
        match e {
            SettingsError::Malformed => Self::Malformed(FrameType::SETTINGS),
            SettingsError::TooMany => Self::TooManySettings,
            e => Self::Settings(e),
        }
    }
}

enum State {
    /// Reading the frame type varint.
    Type,
    /// Reading the length varint, having read this type.
    Len(FrameType),
    /// Header delivered; payload processing has not started.
    Payload(FrameHeader),
    /// Streaming a DATA payload with this many bytes remaining.
    Data(u64),
    /// Buffering a known frame's payload until it reaches this target length.
    Buffer { ty: FrameType, len: usize },
    /// Skipping an unknown/reserved frame's payload, this many bytes remaining.
    Skip(u64),
}

/// A bounded, incremental HTTP/3 frame decoder.
pub struct FrameDecoder {
    emit_headers: bool,
    max_frame_size: usize,
    max_input_size: usize,
    inbox: Bytes,
    state: State,
    varint: VarIntDecoder,
    payload: BytesMut,
}

impl FrameDecoder {
    /// Create a decoder that buffers at most `max_frame_size` bytes for any single non-DATA frame.
    #[must_use]
    pub fn new(max_frame_size: usize) -> Self {
        Self::with_input_limit(max_frame_size, DEFAULT_MAX_FRAME_SIZE)
    }

    /// Set independent limits for a buffered frame and a single input chunk.
    ///
    /// At most one input chunk is retained. Poll until more input is needed before feeding again.
    /// A zero input limit accepts only empty chunks.
    #[must_use]
    pub fn with_input_limit(max_frame_size: usize, max_input_size: usize) -> Self {
        Self {
            emit_headers: false,
            max_frame_size,
            max_input_size,
            inbox: Bytes::new(),
            state: State::Type,
            varint: VarIntDecoder::new(),
            payload: BytesMut::new(),
        }
    }

    /// Enable early frame-header events for stream role/state validation.
    ///
    /// The header is delivered before allocating or consuming its payload.
    #[must_use]
    pub fn with_header_events(mut self) -> Self {
        self.emit_headers = true;
        self
    }

    /// Copy a received chunk, rejecting it before allocation if the inbox is occupied or the
    /// chunk exceeds the input limit. Poll until `Ok(None)` and retry; split oversized chunks.
    /// Prefer [`Self::feed_bytes`] to avoid this copy.
    pub fn feed(&mut self, input: &[u8]) -> Result<(), FrameError> {
        self.check_input(input.len())?;
        if !input.is_empty() {
            self.inbox = Bytes::copy_from_slice(input);
        }
        Ok(())
    }

    /// Transfer an owned received chunk without copying. On success `input` becomes empty;
    /// on backpressure it is unchanged, so the caller can drain the decoder and retry or split it.
    pub fn feed_bytes(&mut self, input: &mut Bytes) -> Result<(), FrameError> {
        self.check_input(input.len())?;
        if !input.is_empty() {
            self.inbox = core::mem::take(input);
        }
        Ok(())
    }

    fn check_input(&self, len: usize) -> Result<(), FrameError> {
        if len > self.max_input_size || (len != 0 && !self.inbox.is_empty()) {
            Err(FrameError::InputBufferFull)
        } else {
            Ok(())
        }
    }

    /// Whether the decoder is between frames with nothing buffered — i.e. a clean place for the
    /// stream to end. If this is `false` at end of stream, the stream was truncated mid-frame.
    #[must_use]
    pub fn is_at_frame_boundary(&self) -> bool {
        matches!(self.state, State::Type) && !self.varint.in_progress() && self.inbox.is_empty()
    }

    /// Try to produce the next event. Returns `Ok(None)` when more input is required.
    pub fn poll(&mut self) -> Result<Option<FrameEvent>, FrameError> {
        loop {
            match self.state {
                State::Type => match self.varint.decode(&mut self.inbox) {
                    Some(v) => self.state = State::Len(FrameType::new(v.into_inner())),
                    None => return Ok(None),
                },
                State::Len(ty) => match self.varint.decode(&mut self.inbox) {
                    Some(len) => {
                        if self.emit_headers {
                            let header = FrameHeader::new(ty, len.into_inner());
                            self.state = State::Payload(header);
                            return Ok(Some(FrameEvent::Header(header)));
                        }
                        if let Some(event) = self.begin_payload(ty, len.into_inner())? {
                            return Ok(Some(event));
                        }
                    }
                    None => return Ok(None),
                },
                State::Payload(header) => {
                    if let Some(event) = self.begin_payload(header.ty, header.len)? {
                        return Ok(Some(event));
                    }
                }
                State::Data(0) | State::Skip(0) => {
                    self.state = State::Type;
                }
                State::Data(remaining) => {
                    if self.inbox.is_empty() {
                        return Ok(None);
                    }
                    let take = usize::min(
                        usize::try_from(remaining).unwrap_or(usize::MAX),
                        self.inbox.len(),
                    );
                    let chunk = self.inbox.split_to(take);
                    self.state = State::Data(remaining - take as u64);
                    return Ok(Some(FrameEvent::DataChunk(chunk)));
                }
                State::Skip(remaining) => {
                    if self.inbox.is_empty() {
                        return Ok(None);
                    }
                    let take = usize::min(
                        usize::try_from(remaining).unwrap_or(usize::MAX),
                        self.inbox.len(),
                    );
                    self.inbox.advance(take);
                    self.state = State::Skip(remaining - take as u64);
                }
                State::Buffer { ty, len } => {
                    let have = self.payload.len();
                    if have == 0 && self.inbox.len() >= len {
                        let payload = self.inbox.split_to(len);
                        self.state = State::Type;
                        return Ok(Some(finish_buffered(ty, payload)?));
                    }
                    if have < len {
                        if self.inbox.is_empty() {
                            return Ok(None);
                        }
                        // Only fragmented payloads need storage. Reserve the bounded full length
                        // once so subsequent fragments do not repeatedly grow and copy it.
                        self.payload.reserve(len - have);
                        let take = usize::min(len - have, self.inbox.len());
                        let chunk = self.inbox.split_to(take);
                        self.payload.extend_from_slice(&chunk);
                        if self.payload.len() < len {
                            return Ok(None);
                        }
                    }
                    let payload = self.payload.split().freeze();
                    self.state = State::Type;
                    return Ok(Some(finish_buffered(ty, payload)?));
                }
            }
        }
    }

    /// Decide how to handle a frame given its type and length; may immediately yield an event
    /// (DataHeader, Ignored) or transition into a buffering/skipping/streaming state.
    fn begin_payload(&mut self, ty: FrameType, len: u64) -> Result<Option<FrameEvent>, FrameError> {
        if ty.is_h2_reserved() {
            return Err(FrameError::UnexpectedH2Frame(ty));
        }
        if ty == FrameType::DATA {
            self.state = State::Data(len);
            return Ok(Some(FrameEvent::DataHeader { len }));
        }
        if is_buffered(ty) {
            if len > self.max_frame_size as u64 {
                return Err(FrameError::FrameTooLarge { ty, len });
            }
            self.payload.clear();
            self.state = State::Buffer {
                ty,
                len: len as usize,
            };
            return Ok(None);
        }
        // unknown or reserved: skip the payload without buffering it
        self.state = State::Skip(len);
        Ok(Some(FrameEvent::Ignored { ty, len }))
    }
}

/// Parse a fully-buffered known-frame payload into an event.
fn finish_buffered(ty: FrameType, payload: Bytes) -> Result<FrameEvent, FrameError> {
    match ty {
        FrameType::HEADERS => Ok(FrameEvent::Headers(payload)),
        FrameType::SETTINGS => Ok(FrameEvent::Settings(Settings::decode(&payload)?)),
        FrameType::CANCEL_PUSH => Ok(FrameEvent::CancelPush(single_varint(ty, &payload)?)),
        FrameType::GOAWAY => Ok(FrameEvent::GoAway(single_varint(ty, &payload)?)),
        FrameType::MAX_PUSH_ID => Ok(FrameEvent::MaxPushId(single_varint(ty, &payload)?)),
        FrameType::PRIORITY_UPDATE_REQUEST | FrameType::PRIORITY_UPDATE_PUSH => {
            let mut cursor: &[u8] = &payload;
            let element_id = VarIntDecoder::new()
                .decode(&mut cursor)
                .ok_or(FrameError::Malformed(ty))?
                .into_inner();
            let consumed = payload.len() - cursor.len();
            Ok(FrameEvent::PriorityUpdate {
                push: ty == FrameType::PRIORITY_UPDATE_PUSH,
                element_id,
                field_value: payload.slice(consumed..),
            })
        }
        FrameType::PUSH_PROMISE => {
            let mut cursor: &[u8] = &payload;
            let push_id = VarIntDecoder::new()
                .decode(&mut cursor)
                .ok_or(FrameError::Malformed(ty))?
                .into_inner();
            let consumed = payload.len() - cursor.len();
            Ok(FrameEvent::PushPromise {
                push_id,
                encoded_headers: payload.slice(consumed..),
            })
        }
        // `is_buffered` gates which types reach here; anything else is a framing error.
        _ => Err(FrameError::Malformed(ty)),
    }
}

/// Whether a frame type is a small/known frame whose payload we buffer and parse (as opposed to
/// DATA, which is streamed, or unknown/reserved, which is skipped).
fn is_buffered(ty: FrameType) -> bool {
    matches!(
        ty,
        FrameType::HEADERS
            | FrameType::SETTINGS
            | FrameType::CANCEL_PUSH
            | FrameType::GOAWAY
            | FrameType::MAX_PUSH_ID
            | FrameType::PUSH_PROMISE
            | FrameType::PRIORITY_UPDATE_REQUEST
            | FrameType::PRIORITY_UPDATE_PUSH
    )
}

/// Decode a payload that must be exactly one variable-length integer.
fn single_varint(ty: FrameType, payload: &[u8]) -> Result<u64, FrameError> {
    let mut cursor = payload;
    let value = VarIntDecoder::new()
        .decode(&mut cursor)
        .ok_or(FrameError::Malformed(ty))?;
    if cursor.has_remaining() {
        return Err(FrameError::Malformed(ty));
    }
    Ok(value.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::proto::h3::{FrameHeader, SettingId};

    fn drain(dec: &mut FrameDecoder) -> Vec<FrameEvent> {
        let mut out = Vec::new();
        while let Some(ev) = dec.poll().unwrap() {
            out.push(ev);
        }
        out
    }

    fn frame(ty: FrameType, payload: &[u8]) -> Vec<u8> {
        let mut buf = BytesMut::new();
        FrameHeader::new(ty, payload.len() as u64)
            .encode(&mut buf)
            .unwrap();
        buf.extend_from_slice(payload);
        buf.to_vec()
    }

    #[test]
    fn input_backpressure_is_bounded_and_retryable() {
        let mut dec = FrameDecoder::with_input_limit(8, 4);
        let mut oversized = Bytes::from_static(b"12345");
        assert_eq!(
            dec.feed_bytes(&mut oversized),
            Err(FrameError::InputBufferFull)
        );
        assert_eq!(oversized, b"12345"[..]);
        assert!(dec.is_at_frame_boundary());
        assert_eq!(dec.feed(&oversized), Err(FrameError::InputBufferFull));
        let mut wire = Bytes::from(frame(FrameType::HEADERS, b"ab"));
        dec.feed_bytes(&mut wire).unwrap();
        assert!(wire.is_empty());
        assert_eq!(dec.feed(b"x"), Err(FrameError::InputBufferFull));
        assert_eq!(
            drain(&mut dec),
            vec![FrameEvent::Headers(Bytes::from_static(b"ab"))]
        );
        dec.feed(&frame(FrameType::HEADERS, b"cd")).unwrap();
        assert_eq!(
            drain(&mut dec),
            vec![FrameEvent::Headers(Bytes::from_static(b"cd"))]
        );
    }

    #[test]
    fn owned_payloads_share_input_storage() {
        for ty in [FrameType::HEADERS, FrameType::DATA, FrameType::PUSH_PROMISE] {
            let mut wire = Bytes::from(frame(ty, b"\x00abc"));
            let expected = wire
                .as_ptr()
                .wrapping_add(if ty == FrameType::PUSH_PROMISE { 3 } else { 2 });
            let mut dec = FrameDecoder::new(4);
            dec.feed_bytes(&mut wire).unwrap();
            let event = dec.poll().unwrap().unwrap();
            let payload = match event {
                FrameEvent::Headers(b) => b,
                FrameEvent::PushPromise {
                    encoded_headers, ..
                } => encoded_headers,
                FrameEvent::DataHeader { .. } => match dec.poll().unwrap().unwrap() {
                    FrameEvent::DataChunk(b) => b,
                    other => panic!("unexpected {other:?}"),
                },
                other => panic!("unexpected {other:?}"),
            };
            assert_eq!(payload.as_ptr(), expected);
        }
    }

    #[test]
    fn every_frame_split_and_truncation() {
        for (ty, payload) in [
            (FrameType::HEADERS, &b"headers"[..]),
            (FrameType::SETTINGS, &b"\x06\x40\x01"[..]),
            (FrameType::CANCEL_PUSH, &b"\x40\x01"[..]),
            (FrameType::GOAWAY, &b"\x40\x01"[..]),
            (FrameType::MAX_PUSH_ID, &b"\x40\x01"[..]),
            (FrameType::PUSH_PROMISE, &b"\x40\x01headers"[..]),
        ] {
            // Non-minimal type and length varints are legal, including across chunk boundaries.
            let mut wire = vec![0x40, ty.value() as u8, 0x40, payload.len() as u8];
            wire.extend_from_slice(payload);
            let mut whole = FrameDecoder::new(payload.len());
            whole.feed(&wire).unwrap();
            let expected = drain(&mut whole);
            for split in 1..wire.len() {
                let mut dec = FrameDecoder::new(payload.len());
                dec.feed(&wire[..split]).unwrap();
                assert!(drain(&mut dec).is_empty());
                assert!(!dec.is_at_frame_boundary());
                dec.feed(&wire[split..]).unwrap();
                assert_eq!(drain(&mut dec), expected);
                assert!(dec.is_at_frame_boundary());
            }
        }
    }

    #[test]
    fn streaming_and_skipping_do_not_use_the_buffered_frame_budget() {
        for ty in [FrameType::DATA, FrameType::new(0x21)] {
            let mut dec = FrameDecoder::with_input_limit(0, 8);
            let mut header = BytesMut::new();
            FrameHeader::new(ty, 80).encode(&mut header).unwrap();
            dec.feed(&header).unwrap();
            assert!(dec.poll().unwrap().is_some());
            assert_eq!(dec.poll(), Ok(None));
            for _ in 0..10 {
                let mut input = Bytes::from_static(b"abcdefgh");
                dec.feed_bytes(&mut input).unwrap();
                let events = drain(&mut dec);
                assert_eq!(events.len(), usize::from(ty == FrameType::DATA));
                assert!(dec.payload.is_empty());
                assert_eq!(dec.payload.capacity(), 0);
            }
            assert!(dec.is_at_frame_boundary());
        }
    }

    #[test]
    fn rejects_invalid_fixed_layout_payloads() {
        for ty in [
            FrameType::CANCEL_PUSH,
            FrameType::GOAWAY,
            FrameType::MAX_PUSH_ID,
        ] {
            for payload in [&b""[..], &b"\x40"[..], &b"\x01\x02"[..]] {
                let mut dec = FrameDecoder::new(8);
                dec.feed(&frame(ty, payload)).unwrap();
                assert_eq!(dec.poll(), Err(FrameError::Malformed(ty)));
            }
        }
        let mut dec = FrameDecoder::new(8);
        dec.feed(&frame(FrameType::PUSH_PROMISE, b"\x40")).unwrap();
        assert_eq!(
            dec.poll(),
            Err(FrameError::Malformed(FrameType::PUSH_PROMISE))
        );
    }

    #[test]
    fn settings_errors_have_distinct_protocol_classifications() {
        for payload in [&b"\x06"[..], &b"\x40"[..], &b"\x06\x40"[..]] {
            let mut dec = FrameDecoder::new(16);
            dec.feed(&frame(FrameType::SETTINGS, payload)).unwrap();
            assert_eq!(dec.poll(), Err(FrameError::Malformed(FrameType::SETTINGS)));
        }
        assert_eq!(
            FrameError::from(SettingsError::TooMany),
            FrameError::TooManySettings
        );
        assert_eq!(
            FrameError::from(SettingsError::Duplicate(SettingId::new(6))),
            FrameError::Settings(SettingsError::Duplicate(SettingId::new(6)))
        );
    }

    #[test]
    fn decodes_settings_frame() {
        let mut settings = Settings::new();
        settings
            .set(SettingId::QPACK_MAX_TABLE_CAPACITY, 4096)
            .unwrap();
        settings.set(SettingId::QPACK_BLOCKED_STREAMS, 16).unwrap();
        let mut payload = BytesMut::new();
        settings.encode_payload(&mut payload).unwrap();
        let wire = frame(FrameType::SETTINGS, &payload);

        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
        dec.feed(&wire).unwrap();
        let events = drain(&mut dec);
        assert_eq!(events, vec![FrameEvent::Settings(settings)]);
        assert!(dec.is_at_frame_boundary());
    }

    #[test]
    fn streams_data_and_buffers_headers() {
        let mut wire = frame(FrameType::HEADERS, b"\x00\x00header-block");
        wire.extend_from_slice(&frame(FrameType::DATA, b"hello world"));

        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
        dec.feed(&wire).unwrap();
        let events = drain(&mut dec);
        assert_eq!(
            events,
            vec![
                FrameEvent::Headers(Bytes::from_static(b"\x00\x00header-block")),
                FrameEvent::DataHeader { len: 11 },
                FrameEvent::DataChunk(Bytes::from_static(b"hello world")),
            ]
        );
    }

    #[test]
    fn skips_unknown_frame_without_buffering() {
        // reserved/grease frame type 0x21, 5-byte payload
        let mut wire = frame(FrameType::new(0x21), b"\x01\x02\x03\x04\x05");
        wire.extend_from_slice(&frame(FrameType::DATA, b"x"));
        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
        dec.feed(&wire).unwrap();
        let events = drain(&mut dec);
        assert_eq!(
            events[0],
            FrameEvent::Ignored {
                ty: FrameType::new(0x21),
                len: 5
            }
        );
        assert_eq!(events[1], FrameEvent::DataHeader { len: 1 });
        assert_eq!(events[2], FrameEvent::DataChunk(Bytes::from_static(b"x")));
    }

    #[test]
    fn rejects_h2_reserved_frame() {
        let wire = frame(FrameType::new(0x02), b"");
        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
        dec.feed(&wire).unwrap();
        assert_eq!(
            dec.poll(),
            Err(FrameError::UnexpectedH2Frame(FrameType::new(0x02)))
        );
    }

    #[test]
    fn rejects_oversized_buffered_frame_before_allocating() {
        // advertise a huge HEADERS length; must error before buffering
        let mut wire = BytesMut::new();
        FrameHeader::new(FrameType::HEADERS, 10_000_000)
            .encode(&mut wire)
            .unwrap();
        let mut dec = FrameDecoder::new(4096);
        dec.feed(&wire).unwrap();
        assert_eq!(
            dec.poll(),
            Err(FrameError::FrameTooLarge {
                ty: FrameType::HEADERS,
                len: 10_000_000
            })
        );
    }

    #[test]
    fn incremental_byte_by_byte() {
        let mut settings = Settings::new();
        settings
            .set(SettingId::MAX_FIELD_SECTION_SIZE, 65536)
            .unwrap();
        let mut payload = BytesMut::new();
        settings.encode_payload(&mut payload).unwrap();
        let wire = frame(FrameType::SETTINGS, &payload);

        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
        let mut produced = None;
        for (i, byte) in wire.iter().enumerate() {
            dec.feed(&[*byte]).unwrap();
            let ev = dec.poll().unwrap();
            if i + 1 < wire.len() {
                assert!(ev.is_none(), "premature event at byte {i}");
            } else {
                produced = ev;
            }
        }
        assert_eq!(produced, Some(FrameEvent::Settings(settings)));
        assert!(dec.is_at_frame_boundary());
    }

    #[test]
    fn detects_truncated_stream() {
        // a complete header claiming 4 bytes, but only 2 delivered
        let mut wire = BytesMut::new();
        FrameHeader::new(FrameType::GOAWAY, 4)
            .encode(&mut wire)
            .unwrap();
        wire.extend_from_slice(&[0x00, 0x00]);
        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
        dec.feed(&wire).unwrap();
        assert_eq!(dec.poll().unwrap(), None);
        assert!(
            !dec.is_at_frame_boundary(),
            "mid-frame truncation is observable"
        );
    }

    #[test]
    fn goaway_round_trip() {
        // GOAWAY payload is a single varint; 4 encodes as one byte.
        let wire = frame(FrameType::GOAWAY, &[0x04]);
        let mut dec = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
        dec.feed(&wire).unwrap();
        assert_eq!(drain(&mut dec), vec![FrameEvent::GoAway(4)]);
    }
}
