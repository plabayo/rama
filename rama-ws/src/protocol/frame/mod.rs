//! Utilities to work with raw WebSocket frames.

use crate::protocol::{error::ProtocolError, frame::mask::apply_mask, message::Message};
use rama_core::{
    bytes::{self, Bytes, BytesMut},
    telemetry::tracing::trace,
};
use rama_utils::octets::kib;
use std::io::{self, Cursor, Error as IoError, ErrorKind as IoErrorKind, Read, Write};

pub mod coding;

mod mask;
mod types;
mod utf8;

pub use self::{
    types::{CloseFrame, Frame, FrameHeader},
    utf8::Utf8Bytes,
};

/// Read buffer size used for `FrameSocket`.
const READ_BUF_LEN: usize = kib(4);

/// Upper bound of one read; the buffer only grows to it as data arrives.
const MAX_READ_LEN: usize = kib(128);

/// Payloads up to this size are copied out, so a kept message never pins the read buffer.
const COPIED_PAYLOAD_MAX_LEN: usize = kib(4);

/// A reader and writer for WebSocket frames.
#[derive(Debug)]
pub struct FrameSocket<Stream> {
    /// The underlying network stream.
    stream: Stream,
    /// Codec for reading/writing frames.
    codec: FrameCodec,
}

impl<Stream> FrameSocket<Stream> {
    /// Create a new frame socket.
    pub fn new(stream: Stream) -> Self {
        Self {
            stream,
            codec: FrameCodec::new(READ_BUF_LEN),
        }
    }

    /// Create a new frame socket from partially read data.
    pub fn from_partially_read(stream: Stream, part: Vec<u8>) -> Self {
        Self {
            stream,
            codec: FrameCodec::from_partially_read(part, READ_BUF_LEN),
        }
    }

    /// Extract a stream from the socket.
    pub fn into_inner(mut self) -> (Stream, BytesMut) {
        self.codec.in_buffer.truncate(self.codec.filled);
        (self.stream, self.codec.in_buffer)
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &Stream {
        &self.stream
    }

    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }
}

impl<Stream> FrameSocket<Stream>
where
    Stream: Read,
{
    /// Read a frame from stream.
    pub fn read(&mut self, max_size: Option<usize>) -> Result<Option<Frame>, ProtocolError> {
        self.codec
            .read_frame(&mut self.stream, max_size, false, true)
    }
}

impl<Stream> FrameSocket<Stream>
where
    Stream: Write,
{
    /// Writes and immediately flushes a frame.
    /// Equivalent to calling [`write`](Self::write) then [`flush`](Self::flush).
    pub fn send(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        self.write(frame)?;
        self.flush()
    }

    /// Write a frame to stream.
    ///
    /// A subsequent call should be made to [`flush`](Self::flush) to flush writes.
    ///
    /// This function guarantees that the frame is queued unless [`ProtocolError::WriteBufferFull`]
    /// is returned.
    /// In order to handle WouldBlock or Incomplete, call [`flush`](Self::flush) afterwards.
    pub fn write(&mut self, frame: Frame) -> Result<(), ProtocolError> {
        self.codec.buffer_frame(&mut self.stream, frame)
    }

    /// Flush writes.
    pub fn flush(&mut self) -> Result<(), ProtocolError> {
        self.codec.write_out_buffer(&mut self.stream)?;
        Ok(self.stream.flush()?)
    }
}

/// A codec for WebSocket frames.
#[derive(Debug)]
pub(super) struct FrameCodec {
    /// Buffer to read data from the stream: received bytes up to `filled`, then spare room
    /// that is zeroed once per allocation.
    in_buffer: BytesMut,
    filled: usize,
    /// Smallest room offered to a read.
    min_read_len: usize,
    /// Room offered to the next read; it follows what the reads return.
    read_len: usize,
    /// Buffer to send packets to the network.
    out_buffer: BytesMut,
    /// Capacity limit for `out_buffer`.
    max_out_buffer_len: usize,
    /// Buffer target length to reach before writing to the stream
    /// on calls to `buffer_frame`.
    ///
    /// Setting this to non-zero will buffer small writes from hitting
    /// the stream.
    out_buffer_write_len: usize,
    /// Header and remaining size of the incoming packet being processed.
    header: Option<(FrameHeader, u64)>,
}

impl FrameCodec {
    /// Create a new frame codec.
    pub(super) fn new(in_buf_len: usize) -> Self {
        Self {
            in_buffer: BytesMut::new(),
            filled: 0,
            min_read_len: in_buf_len.max(FrameHeader::MAX_SIZE),
            read_len: in_buf_len.max(FrameHeader::MAX_SIZE),
            out_buffer: <_>::default(),
            max_out_buffer_len: usize::MAX,
            out_buffer_write_len: 0,
            header: None,
        }
    }

    /// Create a new frame codec from partially read data.
    pub(super) fn from_partially_read(part: Vec<u8>, min_in_buf_len: usize) -> Self {
        Self {
            filled: part.len(),
            in_buffer: BytesMut::from(Bytes::from(part)),
            min_read_len: min_in_buf_len.max(FrameHeader::MAX_SIZE),
            read_len: min_in_buf_len.max(FrameHeader::MAX_SIZE),
            out_buffer: <_>::default(),
            max_out_buffer_len: usize::MAX,
            out_buffer_write_len: 0,
            header: None,
        }
    }

    /// Sets a maximum size for the out buffer.
    pub(super) fn set_max_out_buffer_len(&mut self, max: usize) {
        self.max_out_buffer_len = max;
    }

    /// Sets [`Self::buffer_frame`] buffer target length to reach before
    /// writing to the stream.
    pub(super) fn set_out_buffer_write_len(&mut self, len: usize) {
        self.out_buffer_write_len = len;
    }

    /// Read a frame from the provided stream.
    pub(super) fn read_frame(
        &mut self,
        stream: &mut impl Read,
        max_size: Option<usize>,
        unmask: bool,
        accept_unmasked: bool,
    ) -> Result<Option<Frame>, ProtocolError> {
        let max_size = max_size.unwrap_or(usize::MAX);

        let len = loop {
            if self.header.is_none() {
                let mut cursor = Cursor::new(&self.in_buffer[..self.filled]);
                self.header = FrameHeader::parse(&mut cursor)?;
                let advanced = cursor.position() as usize;
                bytes::Buf::advance(&mut self.in_buffer, advanced);
                self.filled -= advanced;

                if let Some((_, len)) = &self.header {
                    // Enforce frame size limit early. Compare in u64 before
                    // narrowing so a length above usize::MAX can't wrap on
                    // 32-bit/wasm32 targets and slip past the check.
                    if *len > max_size as u64 {
                        return Err(ProtocolError::MessageTooLong {
                            size: *len as usize,
                            max_size,
                        });
                    }
                }
            }

            if let Some((_, len)) = &self.header {
                let len = *len as usize;
                if len <= self.filled {
                    break len;
                }
            }

            // Not enough data in buffer.
            if self.read_in(stream)? == 0 {
                trace!("no frame received");
                return Ok(None);
            }
        };

        #[expect(
            clippy::expect_used,
            reason = "we can only reach here in case header is Some (see payload loop)"
        )]
        let (mut header, length) = self.header.take().expect("Bug: no frame header");
        debug_assert_eq!(len as u64, length);

        let mask = if unmask {
            let mask = header.mask.take();
            // The server MUST close the connection upon receiving a
            // frame that is not masked. (RFC 6455)
            // The only exception here is if the user explicitly accepts given
            // stream by setting WebSocketConfig.accept_unmasked_frames to true
            if mask.is_none() && !accept_unmasked {
                return Err(ProtocolError::UnmaskedFrameFromClient);
            }
            mask
        } else {
            None
        };

        let payload = if len <= COPIED_PAYLOAD_MAX_LEN {
            let mut payload = self.in_buffer[..len].to_vec();
            bytes::Buf::advance(&mut self.in_buffer, len);
            if let Some(mask) = mask {
                apply_mask(&mut payload, mask);
            }
            Bytes::from(payload)
        } else {
            let mut payload = self.in_buffer.split_to(len);
            if let Some(mask) = mask {
                // A server MUST remove masking for data frames received from a client
                // as described in Section 5.3. (RFC 6455)
                apply_mask(&mut payload, mask);
            }
            payload.freeze()
        };
        self.filled -= len;

        let frame = Frame::from_payload(header, payload);
        trace!("received frame {frame}");
        Ok(Some(frame))
    }

    /// Read into the spare room of `in_buffer`, adding room first when it ran out.
    fn read_in(&mut self, stream: &mut impl Read) -> io::Result<usize> {
        if self.filled == self.in_buffer.len() {
            if self.in_buffer.capacity() == self.filled {
                // Doubles with what arrived: a declared frame length alone never sizes it.
                self.in_buffer.reserve(self.filled.max(self.read_len));
            }
            let len = self.in_buffer.capacity().min(self.filled + self.read_len);
            self.in_buffer.resize(len, 0);
        }
        let room = self.in_buffer.len() - self.filled;
        let size = stream.read(&mut self.in_buffer[self.filled..])?;
        self.filled += size;
        // A full read doubles the room, a short one halves it.
        if size == room {
            self.read_len = (self.read_len * 2).min(MAX_READ_LEN.max(self.min_read_len));
        } else if size < room / 4 {
            self.read_len = (self.read_len / 2).max(self.min_read_len);
        }
        Ok(size)
    }

    /// Writes a frame into the `out_buffer`.
    /// If the out buffer size is over the `out_buffer_write_len` will also write
    /// the out buffer into the provided `stream`.
    ///
    /// To ensure buffered frames are written call [`Self::write_out_buffer`].
    ///
    /// May write to the stream, will **not** flush.
    pub(super) fn buffer_frame<Stream>(
        &mut self,
        stream: &mut Stream,
        frame: Frame,
    ) -> Result<(), ProtocolError>
    where
        Stream: Write,
    {
        if frame.len() + self.out_buffer.len() > self.max_out_buffer_len {
            return Err(ProtocolError::WriteBufferFull(Message::Frame(frame)));
        }

        trace!("writing frame {frame}");

        self.out_buffer.reserve(frame.len());
        frame.format_into_buf(&mut self.out_buffer);

        if self.out_buffer.len() > self.out_buffer_write_len {
            self.write_out_buffer(stream)
        } else {
            Ok(())
        }
    }

    /// Writes the out_buffer to the provided stream.
    ///
    /// Does **not** flush.
    pub(super) fn write_out_buffer<Stream>(
        &mut self,
        stream: &mut Stream,
    ) -> Result<(), ProtocolError>
    where
        Stream: Write,
    {
        let mut pos = 0;
        loop {
            if pos == self.out_buffer.len() {
                self.out_buffer.clear();
                return Ok(());
            }
            match stream.write(&self.out_buffer[pos..]) {
                Ok(0) => {
                    // Drop already-written bytes before returning so that
                    // a retry starts from the correct position.
                    bytes::Buf::advance(&mut self.out_buffer, pos);
                    return Err(IoError::new(
                        IoErrorKind::ConnectionReset,
                        "Connection reset while sending",
                    )
                    .into());
                }
                Ok(n) => pos += n,
                Err(err) => {
                    // Advance past the written prefix without moving the unwritten tail.
                    bytes::Buf::advance(&mut self.out_buffer, pos);
                    return Err(err.into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::error::ProtocolError;
    use std::assert_matches;

    use super::{
        Frame, FrameCodec, FrameSocket,
        coding::{OpCode, OpCodeData},
    };

    use std::io::{self, Cursor};

    #[test]
    fn read_frames() {
        let raw = Cursor::new(vec![
            0x82, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x82, 0x03, 0x03, 0x02, 0x01,
            0x99,
        ]);
        let mut sock = FrameSocket::new(raw);

        assert_eq!(
            sock.read(None).unwrap().unwrap().into_payload(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07][..]
        );
        assert_eq!(
            sock.read(None).unwrap().unwrap().into_payload(),
            &[0x03, 0x02, 0x01][..]
        );
        assert!(sock.read(None).unwrap().is_none());

        let (_, rest) = sock.into_inner();
        assert_eq!(rest, vec![0x99]);
    }

    #[test]
    fn from_partially_read() {
        let raw = Cursor::new(vec![0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let mut sock = FrameSocket::from_partially_read(raw, vec![0x82, 0x07, 0x01]);
        assert_eq!(
            sock.read(None).unwrap().unwrap().into_payload(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07][..]
        );
    }

    #[test]
    fn write_frames() {
        let mut sock = FrameSocket::new(Vec::new());

        let frame = Frame::ping(vec![0x04, 0x05]);
        sock.send(frame).unwrap();

        let frame = Frame::pong(vec![0x01]);
        sock.send(frame).unwrap();

        let (buf, _) = sock.into_inner();
        assert_eq!(buf, vec![0x89, 0x02, 0x04, 0x05, 0x8a, 0x01, 0x01]);
    }

    #[test]
    fn declared_length_does_not_size_the_read_buffer() {
        // A header announcing 8 MiB, one payload byte, then the peer goes quiet.
        let raw = Cursor::new(vec![
            0x82, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01,
        ]);
        let mut sock = FrameSocket::new(raw);
        assert!(sock.read(None).unwrap().is_none());
        let capacity = sock.codec.in_buffer.capacity();
        assert!(capacity < 1 << 20, "{capacity}");
    }

    /// Hands out at most `step` bytes per read.
    struct TrickleRead {
        wire: Cursor<Vec<u8>>,
        step: usize,
    }

    impl io::Read for TrickleRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = buf.len().min(self.step);
            self.wire.read(&mut buf[..len])
        }
    }

    fn masked_frame(payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0x82];
        match payload.len() {
            len if len < 126 => frame.push(0x80 | len as u8),
            len if len <= 0xffff => {
                frame.push(0x80 | 126);
                frame.extend_from_slice(&(len as u16).to_be_bytes());
            }
            len => {
                frame.push(0x80 | 127);
                frame.extend_from_slice(&(len as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
        frame
    }

    fn payloads() -> Vec<Vec<u8>> {
        [0, 1, 125, 126, 4095, 4096, 4097, 70_000, 300_000]
            .into_iter()
            .map(|len| (0..len).map(|i| (i % 251) as u8).collect())
            .collect()
    }

    #[test]
    fn masked_frames_survive_any_read_size() {
        let payloads = payloads();
        let wire: Vec<u8> = payloads
            .iter()
            .flat_map(|payload| masked_frame(payload, [0x6d, 0xb6, 0xb2, 0x80]))
            .collect();
        for step in [1, 7, 4096, 1 << 20] {
            let mut stream = TrickleRead {
                wire: Cursor::new(wire.clone()),
                step,
            };
            let mut codec = FrameCodec::new(super::READ_BUF_LEN);
            for payload in &payloads {
                let frame = loop {
                    if let Some(frame) = codec.read_frame(&mut stream, None, true, false).unwrap() {
                        break frame;
                    }
                };
                assert_eq!(frame.payload(), &payload[..], "step {step}");
            }
            assert!(
                codec
                    .read_frame(&mut stream, None, true, false)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn small_payloads_do_not_pin_the_read_buffer() {
        let wire = [
            masked_frame(b"small", [1, 2, 3, 4]),
            masked_frame(&[7; 70_000], [1, 2, 3, 4]),
        ]
        .concat();
        let mut stream = Cursor::new(wire);
        let mut codec = FrameCodec::new(super::READ_BUF_LEN);
        let small = codec
            .read_frame(&mut stream, None, true, false)
            .unwrap()
            .unwrap();
        let buffer = codec.in_buffer.as_ptr_range();
        assert!(!buffer.contains(&small.payload().as_ptr()));
        assert_eq!(small.payload(), b"small");

        let large = loop {
            if let Some(frame) = codec.read_frame(&mut stream, None, true, false).unwrap() {
                break frame;
            }
        };
        // large payloads are handed out without a copy
        assert!(codec.in_buffer.capacity() < 70_000);
        assert_eq!(large.payload(), &[7; 70_000][..]);
    }

    #[test]
    fn idle_codec_allocates_nothing_and_reads_small() {
        let mut codec = FrameCodec::new(super::READ_BUF_LEN);
        assert_eq!(codec.in_buffer.capacity(), 0);
        let mut stream = Cursor::new(masked_frame(b"hi", [1, 2, 3, 4]));
        assert!(
            codec
                .read_frame(&mut stream, None, true, false)
                .unwrap()
                .is_some()
        );
        assert!(codec.in_buffer.capacity() <= super::READ_BUF_LEN);
    }

    #[test]
    fn frames_larger_than_the_read_buffer_still_assemble() {
        let payload = vec![0x5a; 3 * super::READ_BUF_LEN + 7];
        let mut raw = vec![0x82, 0x7f];
        raw.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        raw.extend_from_slice(&payload);
        let mut sock = FrameSocket::new(Cursor::new(raw));
        assert_eq!(
            sock.read(None).unwrap().unwrap().into_payload(),
            &payload[..]
        );
    }

    /// Accepts at most 7 bytes per write and fails every other write with `WouldBlock`.
    #[derive(Default)]
    struct TrickleWrite {
        wire: Vec<u8>,
        block: bool,
    }

    impl io::Write for TrickleWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.block = !self.block;
            if self.block {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let len = buf.len().min(7);
            self.wire.extend_from_slice(&buf[..len]);
            Ok(len)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// `Ok(true)` once done, `Ok(false)` when the writer would block.
    fn done_or_blocked(result: Result<(), ProtocolError>) -> bool {
        match result {
            Ok(()) => true,
            Err(ProtocolError::Io(err)) if err.kind() == io::ErrorKind::WouldBlock => false,
            Err(err) => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn write_frames_in_partial_writes() {
        let frames = || {
            (0..4).map(|i| {
                Frame::message(
                    vec![i; 10 + 40 * i as usize],
                    OpCode::Data(OpCodeData::Binary),
                    true,
                )
            })
        };
        let mut expected = Vec::new();
        for frame in frames() {
            frame.format(&mut expected).unwrap();
        }

        // Queue each frame while earlier ones are still partly written.
        let mut sock = FrameSocket::new(TrickleWrite::default());
        for frame in frames() {
            done_or_blocked(sock.write(frame));
            done_or_blocked(sock.flush());
        }
        while !done_or_blocked(sock.flush()) {}

        assert_eq!(sock.into_inner().0.wire, expected);
    }

    #[test]
    fn parse_overflow() {
        let raw = Cursor::new(vec![
            0x83, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
        ]);
        let mut sock = FrameSocket::new(raw);
        _ = sock.read(None); // should not crash
    }

    #[test]
    fn size_limit_hit() {
        let raw = Cursor::new(vec![0x82, 0x07, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        let mut sock = FrameSocket::new(raw);
        assert_matches!(
            sock.read(Some(5)),
            Err(ProtocolError::MessageTooLong {
                size: 7,
                max_size: 5
            }),
        );
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn length_above_usize_max_rejected() {
        // 64-bit payload length 0x1_0000_0005 does not fit a 32-bit usize; it
        // must be rejected rather than wrapping to 5 when narrowed.
        let raw = Cursor::new(vec![
            0x82, 0x7f, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05,
        ]);
        let mut sock = FrameSocket::new(raw);
        assert_matches!(
            sock.read(None),
            Err(ProtocolError::MessageTooLong {
                size: 5,
                max_size: usize::MAX
            }),
        );
    }
}
