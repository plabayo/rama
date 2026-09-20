use core::{
    cmp::Ordering,
    fmt,
    ops::{Mul, Rem},
};

use rama_core::bytes::{Buf, BufMut};

use crate::coding::{self, Codec, UnexpectedEnd};

#[cfg(feature = "fuzz-utils")]
use arbitrary::Arbitrary;

/// An integer less than 2^62
///
/// Values of this type are suitable for encoding as QUIC variable-length integer.
// It would be neat if we could express to Rust that the top two bits are available for use as enum
// discriminants
#[derive(Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VarInt(u64);

impl VarInt {
    /// The largest representable value
    pub const MAX: Self = Self((1 << 62) - 1);

    /// Construct a `VarInt` infallibly
    pub const fn from_u32(x: u32) -> Self {
        Self(x as u64)
    }

    /// Succeeds iff `x` < 2^62
    pub fn from_u64(x: u64) -> Result<Self, VarIntBoundsExceeded> {
        if x < 2u64.pow(62) {
            Ok(Self(x))
        } else {
            Err(VarIntBoundsExceeded::new())
        }
    }

    /// Create a VarInt without ensuring it's in range
    ///
    /// # Safety
    ///
    /// `x` must be less than 2^62.
    pub const unsafe fn from_u64_unchecked(x: u64) -> Self {
        Self(x)
    }

    /// Extract the integer value
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    /// Compute the number of bytes needed to encode this value
    pub const fn size(self) -> usize {
        let x = self.0;
        if x < 2u64.pow(6) {
            1
        } else if x < 2u64.pow(14) {
            2
        } else if x < 2u64.pow(30) {
            4
        } else {
            debug_assert!(x < 2u64.pow(62), "malformed VarInt");
            8
        }
    }
}

impl From<VarInt> for u64 {
    fn from(x: VarInt) -> Self {
        x.0
    }
}

impl From<u8> for VarInt {
    fn from(x: u8) -> Self {
        Self(x.into())
    }
}

impl From<u16> for VarInt {
    fn from(x: u16) -> Self {
        Self(x.into())
    }
}

impl From<u32> for VarInt {
    fn from(x: u32) -> Self {
        Self(x.into())
    }
}

impl TryFrom<u64> for VarInt {
    type Error = VarIntBoundsExceeded;
    /// Succeeds iff `x` < 2^62
    fn try_from(x: u64) -> Result<Self, VarIntBoundsExceeded> {
        Self::from_u64(x)
    }
}

impl TryFrom<u128> for VarInt {
    type Error = VarIntBoundsExceeded;
    /// Succeeds iff `x` < 2^62
    fn try_from(x: u128) -> Result<Self, VarIntBoundsExceeded> {
        let Ok(x) = x.try_into() else {
            return Err(VarIntBoundsExceeded::new());
        };
        Self::from_u64(x)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = VarIntBoundsExceeded;
    /// Succeeds iff `x` < 2^62
    fn try_from(x: usize) -> Result<Self, VarIntBoundsExceeded> {
        Self::try_from(x as u64)
    }
}

impl fmt::Debug for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// Compare and do plain integer arithmetic against `u64` without unwrapping. Arithmetic yields a
// `u64`, not a `VarInt`, because the result may exceed what a variable-length integer can hold.
impl PartialEq<u64> for VarInt {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialOrd<u64> for VarInt {
    fn partial_cmp(&self, other: &u64) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}

impl Rem<u64> for VarInt {
    type Output = u64;
    fn rem(self, rhs: u64) -> u64 {
        self.0 % rhs
    }
}

impl Mul<u64> for VarInt {
    type Output = u64;
    fn mul(self, rhs: u64) -> u64 {
        self.0 * rhs
    }
}

#[cfg(feature = "fuzz-utils")]
impl<'arbitrary> Arbitrary<'arbitrary> for VarInt {
    fn arbitrary(u: &mut arbitrary::Unstructured<'arbitrary>) -> arbitrary::Result<Self> {
        Ok(Self(u.int_in_range(0..=Self::MAX.0)?))
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "value too large for varint encoding"]
    /// Error returned when constructing a `VarInt` from a value >= 2^62.
    #[derive(Copy)]
    pub struct VarIntBoundsExceeded;
}

impl Codec for VarInt {
    #[expect(
        clippy::unwrap_used,
        clippy::unreachable,
        reason = "`buf[..2]`/`buf[..4]` are fixed-size prefixes of the 8-byte array and the two-bit tag makes the match exhaustive"
    )]
    fn decode<B: Buf>(r: &mut B) -> coding::Result<Self> {
        if !r.has_remaining() {
            return Err(UnexpectedEnd::new());
        }
        let mut buf = [0; 8];
        buf[0] = r.get_u8();
        let tag = buf[0] >> 6;
        buf[0] &= 0b0011_1111;
        let x = match tag {
            0b00 => u64::from(buf[0]),
            0b01 => {
                if r.remaining() < 1 {
                    return Err(UnexpectedEnd::new());
                }
                r.copy_to_slice(&mut buf[1..2]);
                u64::from(u16::from_be_bytes(buf[..2].try_into().unwrap()))
            }
            0b10 => {
                if r.remaining() < 3 {
                    return Err(UnexpectedEnd::new());
                }
                r.copy_to_slice(&mut buf[1..4]);
                u64::from(u32::from_be_bytes(buf[..4].try_into().unwrap()))
            }
            0b11 => {
                if r.remaining() < 7 {
                    return Err(UnexpectedEnd::new());
                }
                r.copy_to_slice(&mut buf[1..8]);
                u64::from_be_bytes(buf)
            }
            _ => unreachable!(),
        };
        Ok(Self(x))
    }

    #[expect(
        clippy::unreachable,
        reason = "`VarInt` values are below 2^62 by construction: `from_u64` checks and `from_u64_unchecked` is `unsafe` with that contract"
    )]
    fn encode<B: BufMut>(&self, w: &mut B) {
        let x = self.0;
        if x < 2u64.pow(6) {
            w.put_u8(x as u8);
        } else if x < 2u64.pow(14) {
            w.put_u16((0b01 << 14) | x as u16);
        } else if x < 2u64.pow(30) {
            w.put_u32((0b10 << 30) | x as u32);
        } else if x < 2u64.pow(62) {
            w.put_u64((0b11 << 62) | x);
        } else {
            unreachable!("malformed VarInt")
        }
    }
}

/// Incremental, fragmentation-safe decoder for a single QUIC variable-length integer.
///
/// [`VarInt`]'s [`Codec::decode`](crate::coding::Codec::decode) consumes the leading byte before it
/// can report that a multi-byte integer was truncated, so retrying it on input delivered in
/// arbitrary chunks — an HTTP/3 stream, for instance — silently loses framing. This decoder retains
/// partial state across calls instead: feed it whatever bytes are currently available and it
/// consumes only the bytes belonging to the integer, returning [`None`] when it needs more. It
/// never consumes a byte it cannot account for, so the same decoder can be driven from
/// non-contiguous buffers. After it returns [`Some`], it resets and is ready for the next integer.
#[derive(Debug, Clone)]
pub struct VarIntDecoder {
    buf: [u8; 8],
    /// Total bytes the encoding occupies, known once the first byte is read (`0` before that).
    len: u8,
    /// Bytes read into `buf` so far.
    filled: u8,
}

impl Default for VarIntDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl VarIntDecoder {
    /// Create a decoder with no buffered state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; 8],
            len: 0,
            filled: 0,
        }
    }

    /// Whether bytes of an in-progress integer are buffered.
    ///
    /// A caller that reaches end of input while this is `true` holds a truncated integer and should
    /// treat it as a framing error rather than a clean end.
    #[must_use]
    pub const fn in_progress(&self) -> bool {
        self.filled > 0
    }

    /// Feed the currently available bytes.
    ///
    /// Consumes only the bytes belonging to the integer being decoded. Returns `Some(value)` once a
    /// complete integer has been read (resetting for reuse), or `None` if more input is required, in
    /// which case the buffered progress is retained for the next call.
    pub fn decode<B: Buf>(&mut self, r: &mut B) -> Option<VarInt> {
        if self.filled == 0 {
            if !r.has_remaining() {
                return None;
            }
            let first = r.get_u8();
            // tag 0b00/01/10/11 -> 1/2/4/8 encoded bytes
            self.len = 1 << (first >> 6);
            self.buf[0] = first & 0b0011_1111;
            self.filled = 1;
        }
        while self.filled < self.len {
            if !r.has_remaining() {
                return None;
            }
            let start = usize::from(self.filled);
            let take = usize::min(usize::from(self.len - self.filled), r.remaining());
            r.copy_to_slice(&mut self.buf[start..start + take]);
            self.filled += take as u8;
        }
        let value = match self.len {
            1 => u64::from(self.buf[0]),
            2 => u64::from(u16::from_be_bytes([self.buf[0], self.buf[1]])),
            4 => u64::from(u32::from_be_bytes([
                self.buf[0],
                self.buf[1],
                self.buf[2],
                self.buf[3],
            ])),
            // `len` is one of 1/2/4/8 by construction; 8 is the only remaining case.
            _ => u64::from_be_bytes(self.buf),
        };
        self.reset();
        // SAFETY: the top two bits of `buf[0]` were masked off, so `value < 2^62`.
        Some(unsafe { VarInt::from_u64_unchecked(value) })
    }

    fn reset(&mut self) {
        self.buf = [0; 8];
        self.len = 0;
        self.filled = 0;
    }
}

#[cfg(test)]
mod incremental_tests {
    use super::*;
    use alloc::vec::Vec;

    /// One value of each encoded width (RFC 9000 §A.1 sample values).
    fn samples() -> [(u64, usize); 4] {
        [
            (37, 1),
            (15293, 2),
            (494_878_333, 4),
            (151_288_809_941_952_652, 8),
        ]
    }

    fn encode(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        VarInt::from_u64(v).unwrap().encode(&mut out);
        out
    }

    #[test]
    fn encoded_widths_match_samples() {
        for (v, width) in samples() {
            assert_eq!(encode(v).len(), width, "width mismatch for {v}");
        }
    }

    #[test]
    fn decodes_all_at_once() {
        for (v, _) in samples() {
            let mut dec = VarIntDecoder::new();
            let mut buf = &encode(v)[..];
            assert_eq!(dec.decode(&mut buf).map(VarInt::into_inner), Some(v));
            assert!(!dec.in_progress());
        }
    }

    #[test]
    fn decodes_byte_by_byte() {
        for (v, width) in samples() {
            let enc = encode(v);
            let mut dec = VarIntDecoder::new();
            for (i, byte) in enc.iter().enumerate() {
                let mut chunk = &[*byte][..];
                let got = dec.decode(&mut chunk);
                assert!(!chunk.has_remaining(), "byte {i} not consumed for {v}");
                if i + 1 < width {
                    assert_eq!(got, None, "premature value at byte {i} for {v}");
                    assert!(dec.in_progress());
                } else {
                    assert_eq!(got.map(VarInt::into_inner), Some(v));
                    assert!(!dec.in_progress());
                }
            }
        }
    }

    #[test]
    fn decodes_at_every_split_point() {
        for (v, width) in samples() {
            let enc = encode(v);
            for split in 0..=width {
                let mut dec = VarIntDecoder::new();
                let mut head = &enc[..split];
                let first = dec.decode(&mut head);
                assert!(!head.has_remaining());
                if split == width {
                    assert_eq!(first.map(VarInt::into_inner), Some(v));
                    continue;
                }
                assert_eq!(first, None, "value before full input (split {split}, {v})");
                let mut tail = &enc[split..];
                let second = dec.decode(&mut tail);
                assert!(!tail.has_remaining());
                assert_eq!(second.map(VarInt::into_inner), Some(v));
            }
        }
    }

    #[test]
    fn decodes_from_non_contiguous_buffer() {
        for (v, width) in samples() {
            if width < 2 {
                continue;
            }
            let enc = encode(v);
            let (a, b) = enc.split_at(1);
            let mut chained = Buf::chain(a, b);
            let mut dec = VarIntDecoder::new();
            assert_eq!(dec.decode(&mut chained).map(VarInt::into_inner), Some(v));
        }
    }

    #[test]
    fn empty_input_yields_none() {
        let mut dec = VarIntDecoder::new();
        let mut empty: &[u8] = &[];
        assert_eq!(dec.decode(&mut empty), None);
        assert!(!dec.in_progress());
    }

    #[test]
    fn eof_mid_integer_is_observable() {
        // truncated 8-byte integer: feed all but the last byte
        let enc = encode(151_288_809_941_952_652);
        let mut dec = VarIntDecoder::new();
        let mut partial = &enc[..enc.len() - 1];
        assert_eq!(dec.decode(&mut partial), None);
        assert!(
            dec.in_progress(),
            "caller can detect a truncated integer at EOF"
        );
    }

    #[test]
    fn reused_for_back_to_back_integers() {
        let mut stream = Vec::new();
        for (v, _) in samples() {
            stream.extend_from_slice(&encode(v));
        }
        let mut buf = &stream[..];
        let mut dec = VarIntDecoder::new();
        for (v, _) in samples() {
            assert_eq!(dec.decode(&mut buf).map(VarInt::into_inner), Some(v));
        }
        assert!(!buf.has_remaining());
    }
}
