use super::*;

use core::error::Error;
use core::fmt;
use core::str;

use std::io::{self, BufRead};

/// Wraps a `std::io::BufRead` buffered byte stream and decode it as UTF-8.
pub struct BufReadDecoder<B: BufRead> {
    buf_read: B,
    bytes_consumed: usize,
    incomplete: Incomplete,
}

#[derive(Debug)]
pub enum BufReadDecoderError<'a> {
    /// Represents one UTF-8 error in the byte stream.
    ///
    /// In lossy decoding, each such error should be replaced with U+FFFD.
    /// (See `BufReadDecoder::next_lossy` and `BufReadDecoderError::lossy`.)
    InvalidByteSequence(&'a [u8]),

    /// An I/O error from the underlying byte stream
    Io(io::Error),
}

impl BufReadDecoderError<'_> {
    /// Replace UTF-8 errors with U+FFFD
    pub fn lossy(self) -> Result<&'static str, io::Error> {
        match self {
            BufReadDecoderError::Io(error) => Err(error),
            BufReadDecoderError::InvalidByteSequence(_) => Ok(REPLACEMENT_CHARACTER),
        }
    }
}

impl fmt::Display for BufReadDecoderError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BufReadDecoderError::InvalidByteSequence(bytes) => {
                write!(f, "invalid byte sequence: {bytes:02x?}")
            }
            BufReadDecoderError::Io(ref err) => write!(f, "underlying bytestream error: {err}"),
        }
    }
}

impl Error for BufReadDecoderError<'_> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            BufReadDecoderError::InvalidByteSequence(_) => None,
            BufReadDecoderError::Io(ref err) => Some(err),
        }
    }
}

impl<B: BufRead> BufReadDecoder<B> {
    /// This is to `Read::read_to_string` what `String::from_utf8_lossy` is to `String::from_utf8`.
    pub fn read_to_string_lossy(buf_read: B) -> io::Result<String> {
        let mut decoder = Self::new(buf_read);
        let mut string = String::new();
        while let Some(result) = decoder.next_lossy() {
            string.push_str(result?)
        }
        Ok(string)
    }

    pub fn new(buf_read: B) -> Self {
        Self {
            buf_read,
            bytes_consumed: 0,
            incomplete: Incomplete::empty(),
        }
    }

    /// Same as `BufReadDecoder::next_strict`, but replace UTF-8 errors with U+FFFD.
    pub fn next_lossy(&mut self) -> Option<io::Result<&str>> {
        self.next_strict()
            .map(|result| result.or_else(|e| e.lossy()))
    }

    /// Decode and consume the next chunk of UTF-8 input.
    ///
    /// This method is intended to be called repeatedly until it returns `None`,
    /// which represents EOF from the underlying byte stream.
    /// This is similar to `Iterator::next`,
    /// except that decoded chunks borrow the decoder (~iterator)
    /// so they need to be handled or copied before the next chunk can start decoding.
    pub fn next_strict(&mut self) -> Option<Result<&str, BufReadDecoderError<'_>>> {
        macro_rules! try_io {
            ($io_result: expr) => {
                match $io_result {
                    Ok(value) => value,
                    Err(error) => return Some(Err(BufReadDecoderError::Io(error))),
                }
            };
        }
        loop {
            if self.bytes_consumed > 0 {
                self.buf_read.consume(self.bytes_consumed);
                self.bytes_consumed = 0;
            }
            let buf = try_io!(self.buf_read.fill_buf());

            if self.incomplete.is_empty() {
                if buf.is_empty() {
                    return None; // EOF
                }
                // Only an incomplete code point at the very start needs more
                // input; that is at most 3 bytes, so the first 4 decide it.
                let head = &buf[..buf.len().min(4)];
                if let Err(DecodeError::Incomplete {
                    valid_prefix: "", ..
                }) = decode(head)
                {
                    self.bytes_consumed = buf.len();
                    self.incomplete = Incomplete::new(buf);
                    // need more input bytes
                    continue;
                }
                // The borrow of `buf` cannot be returned from inside this
                // loop, so `fill_buf` is called again below. A `BufRead`
                // may return other bytes then, so those are what get decoded.
                break;
            }

            if buf.is_empty() {
                // EOF with incomplete code point
                return Some(Err(BufReadDecoderError::InvalidByteSequence(
                    self.incomplete.take_buffer(),
                )));
            }
            let (consumed, opt_result) = self.incomplete.try_complete_offsets(buf);
            self.bytes_consumed = consumed;
            let Some(result) = opt_result else {
                // need more input bytes
                continue;
            };
            let bytes = self.incomplete.take_buffer();
            return Some(match result {
                // SAFETY: `from_utf8_unchecked` needs valid UTF-8. By the
                // safety-usable invariants of `try_complete_offsets` (an
                // `Ok` result means the first `buffer_len` buffered bytes are
                // valid UTF-8) and `take_buffer` (it returns exactly those
                // bytes), with nothing in between touching `self.incomplete`.
                Ok(()) => Ok(unsafe { str::from_utf8_unchecked(bytes) }),
                Err(()) => Err(BufReadDecoderError::InvalidByteSequence(bytes)),
            });
        }

        let buf = try_io!(self.buf_read.fill_buf());
        Some(match decode(buf) {
            Ok(valid) => {
                self.bytes_consumed = valid.len();
                Ok(valid)
            }
            Err(
                DecodeError::Invalid { valid_prefix, .. }
                | DecodeError::Incomplete { valid_prefix, .. },
            ) if !valid_prefix.is_empty() => {
                self.bytes_consumed = valid_prefix.len();
                Ok(valid_prefix)
            }
            Err(DecodeError::Invalid {
                invalid_sequence, ..
            }) => {
                self.bytes_consumed = invalid_sequence.len();
                Err(BufReadDecoderError::InvalidByteSequence(invalid_sequence))
            }
            // An incomplete code point at the start that the first
            // `fill_buf` did not show: only a `BufRead` that changed its
            // buffer gets here. Reported as invalid rather than buffered.
            Err(DecodeError::Incomplete { .. }) => {
                self.bytes_consumed = buf.len();
                Err(BufReadDecoderError::InvalidByteSequence(buf))
            }
        })
    }
}
