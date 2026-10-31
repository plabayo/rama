//! Decoder for the MaxMind DB data section, over any [`Section`] source.
//!
//! Every read is bounds-checked against the backing source and every offset
//! computation uses checked arithmetic, so a malformed or hostile database
//! can only ever produce a [`GeoIpError::Corrupt`] — never a panic, an
//! out-of-bounds read, or an unbounded loop. Pointer following and structural
//! nesting are both depth-capped.

use crate::std::boxed::Box;
use crate::std::vec::Vec;

use crate::address::ip::geo::GeoIpError;

/// Maximum number of pointers followed while resolving a single field. The
/// spec forbids a pointer pointing at another pointer (so one hop suffices),
/// but we allow a small margin and reject anything pathological.
const MAX_POINTER_DEPTH: usize = 32;

/// Maximum structural nesting (maps/arrays) traversed while skipping a field.
const MAX_NEST_DEPTH: usize = 64;

type Result<T> = core::result::Result<T, GeoIpError>;

const fn corrupt(why: &'static str) -> GeoIpError {
    GeoIpError::Corrupt(why)
}

/// Byte source the decoder and the tree walk read from.
///
/// Implementations must report the same errors for the same out-of-range
/// request, so every source decodes a database identically.
pub(crate) trait Section {
    /// The byte at `off`.
    fn byte(&self, off: usize) -> Result<u8>;

    /// Fill `out` with the bytes starting at `off`.
    fn read_into(&self, off: usize, out: &mut [u8]) -> Result<()>;

    /// Run `f` over the `len` bytes starting at `off`.
    fn with_slice<R>(&self, off: usize, len: usize, f: impl FnOnce(&[u8]) -> R) -> Result<R>;
}

/// The `len` bytes at `off` of `buf`, with the errors every [`Section`] uses.
pub(crate) fn slice_at(buf: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off.checked_add(len).ok_or(corrupt("length overflow"))?;
    buf.get(off..end).ok_or(corrupt("slice out of bounds"))
}

/// Error of a [`Section::byte`] read past the end.
pub(crate) const OFFSET_OUT_OF_BOUNDS: GeoIpError = corrupt("offset out of bounds");

impl Section for [u8] {
    #[inline]
    fn byte(&self, off: usize) -> Result<u8> {
        self.get(off).copied().ok_or(OFFSET_OUT_OF_BOUNDS)
    }

    #[inline]
    fn read_into(&self, off: usize, out: &mut [u8]) -> Result<()> {
        out.copy_from_slice(slice_at(self, off, out.len())?);
        Ok(())
    }

    #[inline]
    fn with_slice<R>(&self, off: usize, len: usize, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        Ok(f(slice_at(self, off, len)?))
    }
}

impl<T: Section + ?Sized> Section for &T {
    #[inline]
    fn byte(&self, off: usize) -> Result<u8> {
        (**self).byte(off)
    }

    #[inline]
    fn read_into(&self, off: usize, out: &mut [u8]) -> Result<()> {
        (**self).read_into(off, out)
    }

    #[inline]
    fn with_slice<R>(&self, off: usize, len: usize, f: impl FnOnce(&[u8]) -> R) -> Result<R> {
        (**self).with_slice(off, len, f)
    }
}

/// A cheap, copyable cursor over a database source for a given section base.
///
/// `base` is the offset (into `src`) that pointer values are relative to:
/// the data section start when decoding records, or the metadata section
/// start when decoding metadata.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Decoder<S> {
    src: S,
    base: usize,
}

impl<S: Section> Decoder<S> {
    pub(crate) fn new(src: S, base: usize) -> Self {
        Self { src, base }
    }

    fn byte(&self, off: usize) -> Result<u8> {
        self.src.byte(off)
    }

    /// Decode the type number and the header length (1, or 2 for an extended
    /// type) of the field at `off`.
    fn data_type(&self, off: usize) -> Result<(u8, usize)> {
        let b = self.byte(off)?;
        let t = b >> 5;
        if t == 0 {
            let ext = self.byte(off + 1)?;
            let t = ext.checked_add(7).ok_or(corrupt("invalid extended type"))?;
            Ok((t, 2))
        } else {
            Ok((t, 1))
        }
    }

    /// For a non-pointer field at `off` with header length `hl`, decode the
    /// payload size and the offset at which the payload begins.
    fn size_and_payload(&self, off: usize, hl: usize) -> Result<(usize, usize)> {
        let size = (self.byte(off)? & 0x1f) as usize;
        let mut po = off.checked_add(hl).ok_or(corrupt("offset overflow"))?;
        let size = match size {
            29 => {
                let n = self.byte(po)? as usize;
                po = po.checked_add(1).ok_or(corrupt("offset overflow"))?;
                29 + n
            }
            30 => {
                let n = ((self.byte(po)? as usize) << 8) | (self.byte(po + 1)? as usize);
                po = po.checked_add(2).ok_or(corrupt("offset overflow"))?;
                285 + n
            }
            31 => {
                let n = ((self.byte(po)? as usize) << 16)
                    | ((self.byte(po + 1)? as usize) << 8)
                    | (self.byte(po + 2)? as usize);
                po = po.checked_add(3).ok_or(corrupt("offset overflow"))?;
                65821 + n
            }
            other => other,
        };
        Ok((size, po))
    }

    /// Decode a pointer field at `off`, returning its resolved target offset
    /// and the total byte length of the pointer field itself.
    fn pointer(&self, off: usize) -> Result<(usize, usize)> {
        let b = self.byte(off)?;
        let size = ((b >> 3) & 0x03) as usize;
        let v0 = (b & 0x07) as usize;
        let (value, total) = match size {
            0 => {
                let n = self.byte(off + 1)? as usize;
                ((v0 << 8) | n, 2)
            }
            1 => {
                let b1 = self.byte(off + 1)? as usize;
                let b2 = self.byte(off + 2)? as usize;
                (((v0 << 16) | (b1 << 8) | b2) + 2048, 3)
            }
            2 => {
                let b1 = self.byte(off + 1)? as usize;
                let b2 = self.byte(off + 2)? as usize;
                let b3 = self.byte(off + 3)? as usize;
                (((v0 << 24) | (b1 << 16) | (b2 << 8) | b3) + 526_336, 4)
            }
            _ => {
                let mut bytes = [0u8; 4];
                self.src.read_into(off + 1, &mut bytes)?;
                (u32::from_be_bytes(bytes) as usize, 5)
            }
        };
        let target = self
            .base
            .checked_add(value)
            .ok_or(corrupt("pointer overflow"))?;
        Ok((target, total))
    }

    /// Follow pointers from `off` until reaching a non-pointer field.
    fn resolve(&self, off: usize) -> Result<usize> {
        self.resolve_depth(off, 0)
    }

    fn resolve_depth(&self, off: usize, depth: usize) -> Result<usize> {
        if depth > MAX_POINTER_DEPTH {
            return Err(corrupt("pointer chain too deep"));
        }
        let (t, _) = self.data_type(off)?;
        if t == 1 {
            let (target, _) = self.pointer(off)?;
            self.resolve_depth(target, depth + 1)
        } else {
            Ok(off)
        }
    }

    /// Return the offset just past the field starting at `off`.
    fn field_end(&self, off: usize) -> Result<usize> {
        self.field_end_depth(off, 0)
    }

    fn field_end_depth(&self, off: usize, depth: usize) -> Result<usize> {
        if depth > MAX_NEST_DEPTH {
            return Err(corrupt("structure nested too deep"));
        }
        let (t, hl) = self.data_type(off)?;
        if t == 1 {
            let (_, total) = self.pointer(off)?;
            return off.checked_add(total).ok_or(corrupt("offset overflow"));
        }
        let (size, po) = self.size_and_payload(off, hl)?;
        match t {
            7 => {
                let mut p = po;
                for _ in 0..size {
                    p = self.field_end_depth(p, depth + 1)?; // key
                    p = self.field_end_depth(p, depth + 1)?; // value
                }
                Ok(p)
            }
            11 => {
                let mut p = po;
                for _ in 0..size {
                    p = self.field_end_depth(p, depth + 1)?;
                }
                Ok(p)
            }
            // boolean (14) and deprecated end-marker (13) carry no payload.
            13 | 14 => Ok(po),
            _ => po.checked_add(size).ok_or(corrupt("offset overflow")),
        }
    }

    /// Resolve `off`, require its field type to equal `expected`, and return
    /// the decoded `(size, payload_offset)`. `what` names the expected type for
    /// the error message.
    fn typed_payload(
        &self,
        off: usize,
        expected: u8,
        what: &'static str,
    ) -> Result<(usize, usize)> {
        let off = self.resolve(off)?;
        let (t, hl) = self.data_type(off)?;
        if t != expected {
            return Err(corrupt(what));
        }
        self.size_and_payload(off, hl)
    }

    /// Look up `key` in the map at `map_off`, returning the offset of its
    /// value if present.
    pub(crate) fn map_get(&self, map_off: usize, key: &str) -> Result<Option<usize>> {
        let (count, po) = self.typed_payload(map_off, 7, "expected a map")?;
        let mut p = po;
        for _ in 0..count {
            let key_res = self.resolve(p)?;
            let (kt, khl) = self.data_type(key_res)?;
            if kt != 2 {
                return Err(corrupt("map key is not a string"));
            }
            let (ksize, kpo) = self.size_and_payload(key_res, khl)?;
            let matches = self
                .src
                .with_slice(kpo, ksize, |kbytes| kbytes == key.as_bytes())?;
            let after_key = self.field_end(p)?;
            if matches {
                return Ok(Some(after_key));
            }
            p = self.field_end(after_key)?;
        }
        Ok(None)
    }

    /// Resolve a UTF-8 string field and run `f` over it.
    pub(crate) fn with_str<R>(&self, off: usize, f: impl FnOnce(&str) -> R) -> Result<R> {
        let (size, po) = self.typed_payload(off, 2, "expected a string")?;
        self.src
            .with_slice(po, size, |bytes| core::str::from_utf8(bytes).ok().map(f))?
            .ok_or(corrupt("string is not valid utf-8"))
    }

    /// Resolve and copy out a UTF-8 string field.
    pub(crate) fn read_box_str(&self, off: usize) -> Result<Box<str>> {
        self.with_str(off, |s| Box::from(s))
    }

    fn read_uint(&self, off: usize, max_bytes: usize) -> Result<u128> {
        let off = self.resolve(off)?;
        let (t, hl) = self.data_type(off)?;
        // unsigned int types: u16=5, u32=6, u64=9, u128=10
        if !matches!(t, 5 | 6 | 9 | 10) {
            return Err(corrupt("expected an unsigned integer"));
        }
        let (size, po) = self.size_and_payload(off, hl)?;
        if size > max_bytes {
            return Err(corrupt("integer wider than expected"));
        }
        let mut buf = [0u8; 16];
        let bytes = buf
            .get_mut(..size)
            .ok_or(corrupt("integer wider than expected"))?;
        self.src.read_into(po, bytes)?;
        Ok(bytes.iter().fold(0u128, |v, &b| (v << 8) | u128::from(b)))
    }

    pub(crate) fn read_u16(&self, off: usize) -> Result<u16> {
        u16::try_from(self.read_uint(off, 2)?)
            .ok()
            .ok_or(corrupt("u16 out of range"))
    }

    pub(crate) fn read_u32(&self, off: usize) -> Result<u32> {
        u32::try_from(self.read_uint(off, 4)?)
            .ok()
            .ok_or(corrupt("u32 out of range"))
    }

    pub(crate) fn read_u64(&self, off: usize) -> Result<u64> {
        u64::try_from(self.read_uint(off, 8)?)
            .ok()
            .ok_or(corrupt("u64 out of range"))
    }

    pub(crate) fn read_f64(&self, off: usize) -> Result<f64> {
        let (size, po) = self.typed_payload(off, 3, "expected a double")?;
        if size != 8 {
            return Err(corrupt("double must be 8 bytes"));
        }
        let mut b = [0u8; 8];
        self.src.read_into(po, &mut b)?;
        Ok(f64::from_be_bytes(b))
    }

    /// Resolve an array field and return the (resolved) offset of each element.
    pub(crate) fn array_offsets(&self, off: usize) -> Result<Vec<usize>> {
        let (count, po) = self.typed_payload(off, 11, "expected an array")?;
        let mut out = Vec::new();
        let mut p = po;
        for _ in 0..count {
            out.push(self.resolve(p)?);
            p = self.field_end(p)?;
        }
        Ok(out)
    }
}

impl<'a> Decoder<&'a [u8]> {
    /// Resolve and decode a UTF-8 string field, borrowing the buffer.
    pub(crate) fn read_str(&self, off: usize) -> Result<&'a str> {
        let (size, po) = self.typed_payload(off, 2, "expected a string")?;
        let bytes = slice_at(self.src, po, size)?;
        core::str::from_utf8(bytes)
            .ok()
            .ok_or(corrupt("string is not valid utf-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A buffer with the data section starting at offset 0 (base = 0):
    //   [0] string "hi"      -> control 0x42, 'h','i'
    //   [3] pointer -> 0     -> control 0x20, 0x00  (size 0, value 0)
    fn buf() -> Vec<u8> {
        vec![0x42, b'h', b'i', 0x20, 0x00]
    }

    #[test]
    fn reads_inline_string() {
        let b = buf();
        let d = Decoder::new(b.as_slice(), 0);
        assert_eq!(d.read_str(0).unwrap(), "hi");
    }

    #[test]
    fn follows_pointer_to_string() {
        let b = buf();
        let d = Decoder::new(b.as_slice(), 0);
        // offset 3 is a pointer to offset 0
        assert_eq!(d.read_str(3).unwrap(), "hi");
    }

    #[test]
    fn out_of_bounds_is_error_not_panic() {
        let b = buf();
        let d = Decoder::new(b.as_slice(), 0);
        d.read_str(99).unwrap_err();
        // truncated string: claims 5 bytes but buffer too short
        let bad = vec![0x45, b'x'];
        let d2 = Decoder::new(bad.as_slice(), 0);
        d2.read_str(0).unwrap_err();
    }

    #[test]
    fn pointer_cycle_is_rejected() {
        // a pointer at offset 0 pointing to itself (value 0, base 0)
        let bad = vec![0x20, 0x00];
        let d = Decoder::new(bad.as_slice(), 0);
        d.read_str(0).unwrap_err();
    }

    #[test]
    fn map_key_must_be_a_string() {
        // map{ <u16 5> : "x" } — the key is an integer, not a string
        let bad = vec![0xE1, 0xA1, 0x05, 0x41, b'x'];
        let d = Decoder::new(bad.as_slice(), 0);
        d.map_get(0, "x").unwrap_err();
    }

    #[test]
    fn integer_wider_than_expected_is_rejected() {
        // a uint16-typed field claiming 4 payload bytes
        let bad = vec![0xA4, 0x00, 0x00, 0x00, 0x01];
        let d = Decoder::new(bad.as_slice(), 0);
        d.read_u16(0).unwrap_err();
    }

    #[test]
    fn array_offsets_rejects_non_array() {
        // a string where an array is expected
        let bad = vec![0x42, b'h', b'i'];
        let d = Decoder::new(bad.as_slice(), 0);
        d.array_offsets(0).unwrap_err();
    }
}
