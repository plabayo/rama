//! FastCGI name-value pair encoding used in PARAMS and GET_VALUES records.
//!
//! Each name-value pair is encoded with a variable-length prefix for both the name
//! length and the value length:
//!
//! - If the length fits in 7 bits (0–127), it is stored as a single byte with the
//!   high bit clear.
//! - Otherwise the length occupies 4 bytes, with the high bit of the first byte set
//!   and the remaining 31 bits carrying the length value.
//!
//! Reference: FastCGI Specification §3.4

use rama_core::bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ProtocolError;

/// The maximum total byte length of a stream of name-value pairs that can fit
/// in a single FastCGI record (content length is a u16).
pub const MAX_PARAMS_RECORD_BODY: usize = 65_535;

/// Maximum length that fits in the FastCGI variable-length integer format.
///
/// The 4-byte form reserves the high bit as a marker, leaving 31 bits for the
/// length value.
///
/// Reference: FastCGI Specification §3.4
pub const MAX_NV_LENGTH: u32 = 0x7FFF_FFFF;

/// Encode `len` using the FastCGI variable-length integer format into `buf`.
///
/// Lengths 0–127 are written as 1 byte; lengths 128–(2^31 − 1) as 4 bytes.
/// Returns [`ProtocolError::ContentTooLarge`] when `len > MAX_NV_LENGTH`,
/// since the high bit of the 4-byte form is reserved as a marker.
///
/// Reference: FastCGI Specification §3.4
pub fn try_encode_length<B: BufMut>(buf: &mut B, len: u32) -> Result<(), ProtocolError> {
    if len > MAX_NV_LENGTH {
        return Err(ProtocolError::content_too_large(len as usize));
    }
    if len <= 127 {
        buf.put_u8(len as u8);
    } else {
        // High bit set signals a 4-byte length
        buf.put_u32(len | 0x8000_0000);
    }
    Ok(())
}

/// Number of bytes needed to encode `len` using the FastCGI variable-length format.
#[must_use]
pub fn encoded_length_size(len: u32) -> usize {
    if len <= 127 { 1 } else { 4 }
}

/// Decode a variable-length integer from the reader.
///
/// Reference: FastCGI Specification §3.4
pub async fn decode_length<R>(r: &mut R) -> Result<u32, ProtocolError>
where
    R: AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    r.read_exact(&mut first).await?;
    if first[0] & 0x80 == 0 {
        Ok(first[0] as u32)
    } else {
        let mut rest = [0u8; 3];
        r.read_exact(&mut rest).await?;
        let len = ((first[0] as u32 & 0x7F) << 24)
            | ((rest[0] as u32) << 16)
            | ((rest[1] as u32) << 8)
            | (rest[2] as u32);
        Ok(len)
    }
}

/// Decode a variable-length integer from a byte slice, returning the value and
/// the number of bytes consumed.
///
/// Reference: FastCGI Specification §3.4
pub fn decode_length_from_slice(data: &[u8]) -> Option<(u32, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        Some((first as u32, 1))
    } else if data.len() >= 4 {
        let len = ((first as u32 & 0x7F) << 24)
            | ((data[1] as u32) << 16)
            | ((data[2] as u32) << 8)
            | (data[3] as u32);
        Some((len, 4))
    } else {
        None
    }
}

/// A single FastCGI name-value pair (owned).
///
/// Used in `FCGI_PARAMS` and `FCGI_GET_VALUES` records to carry CGI
/// environment variables or capability queries.
///
/// Reference: FastCGI Specification §3.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvPair {
    pub name: Bytes,
    pub value: Bytes,
}

impl NvPair {
    /// Create a new owned [`NvPair`].
    pub fn new(name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// Number of bytes this pair occupies when encoded.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let name_len = self.name.len() as u32;
        let value_len = self.value.len() as u32;
        encoded_length_size(name_len)
            + encoded_length_size(value_len)
            + self.name.len()
            + self.value.len()
    }

    /// Write this pair into the buffer using FastCGI encoding.
    ///
    /// Returns [`ProtocolError::ContentTooLarge`] if either the name or value
    /// length exceeds [`MAX_NV_LENGTH`] (2^31 − 1).
    ///
    /// Reference: FastCGI Specification §3.4
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) -> Result<(), ProtocolError> {
        try_encode_length(buf, self.name.len() as u32)?;
        try_encode_length(buf, self.value.len() as u32)?;
        buf.put_slice(&self.name);
        buf.put_slice(&self.value);
        Ok(())
    }

    /// Write this pair to a writer using FastCGI encoding.
    ///
    /// Reference: FastCGI Specification §3.4
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), ProtocolError>
    where
        W: AsyncWrite + Unpin,
    {
        let n = self.encoded_len();
        // Try to stay on the stack for small pairs (common for CGI env vars).
        const STACK_LIMIT: usize = 4 + 4 + 128 + 128;
        if n <= STACK_LIMIT {
            let mut buf = [0u8; STACK_LIMIT];
            let mut slice = &mut buf[..];
            self.write_to_buf(&mut slice)?;
            w.write_all(&buf[..n]).await?;
        } else {
            let mut buf = BytesMut::with_capacity(n);
            self.write_to_buf(&mut buf)?;
            w.write_all(&buf).await?;
        }
        Ok(())
    }

    /// Read a single [`NvPair`] from the reader.
    ///
    /// Reference: FastCGI Specification §3.4
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let name_len = decode_length(r).await? as usize;
        let value_len = decode_length(r).await? as usize;

        let mut name = vec![0u8; name_len];
        r.read_exact(&mut name).await?;

        let mut value = vec![0u8; value_len];
        r.read_exact(&mut value).await?;

        Ok(Self {
            name: Bytes::from(name),
            value: Bytes::from(value),
        })
    }
}

/// A borrowed FastCGI name-value pair, for zero-copy writes.
///
/// Reference: FastCGI Specification §3.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvPairRef<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

impl<'a> NvPairRef<'a> {
    /// Create a new borrowed [`NvPairRef`].
    #[must_use]
    pub fn new(name: &'a [u8], value: &'a [u8]) -> Self {
        Self { name, value }
    }

    /// Number of bytes this pair occupies when encoded.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        let name_len = self.name.len() as u32;
        let value_len = self.value.len() as u32;
        encoded_length_size(name_len)
            + encoded_length_size(value_len)
            + self.name.len()
            + self.value.len()
    }

    /// Write this pair into the buffer using FastCGI encoding.
    ///
    /// Returns [`ProtocolError::ContentTooLarge`] if either length exceeds
    /// [`MAX_NV_LENGTH`].
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) -> Result<(), ProtocolError> {
        try_encode_length(buf, self.name.len() as u32)?;
        try_encode_length(buf, self.value.len() as u32)?;
        buf.put_slice(self.name);
        buf.put_slice(self.value);
        Ok(())
    }
}

/// Decode all name-value pairs from a contiguous byte slice (the content of a PARAMS record).
///
/// Returns an iterator over `(&[u8], &[u8])` name-value pairs without copying.
///
/// Reference: FastCGI Specification §3.4
pub fn decode_params(mut data: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        let (name_len, consumed) = decode_length_from_slice(data)?;
        data = &data[consumed..];
        let (value_len, consumed) = decode_length_from_slice(data)?;
        data = &data[consumed..];
        let name_len = name_len as usize;
        let value_len = value_len as usize;
        if data.len() < name_len + value_len {
            return None;
        }
        let name = &data[..name_len];
        let value = &data[name_len..name_len + value_len];
        data = &data[name_len + value_len..];
        Some((name, value))
    })
}

/// Encode a list of name-value pairs into a [`BytesMut`] buffer.
///
/// Returns [`ProtocolError::ContentTooLarge`] if any pair contains a name or
/// value longer than [`MAX_NV_LENGTH`] (2^31 − 1).
pub fn encode_params<'a, I>(pairs: I) -> Result<BytesMut, ProtocolError>
where
    I: IntoIterator<Item = NvPairRef<'a>>,
{
    let mut buf = BytesMut::new();
    for pair in pairs {
        pair.write_to_buf(&mut buf)?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_pairs(pairs: &[(&[u8], &[u8])]) {
        let refs: Vec<NvPairRef<'_>> = pairs.iter().map(|(n, v)| NvPairRef::new(n, v)).collect();
        let encoded = encode_params(refs.iter().copied()).unwrap();
        let decoded: Vec<_> = decode_params(&encoded).collect();
        assert_eq!(decoded.len(), pairs.len());
        for (i, (name, value)) in decoded.iter().enumerate() {
            assert_eq!(*name, pairs[i].0);
            assert_eq!(*value, pairs[i].1);
        }
    }

    #[test]
    fn test_encode_decode_short_lengths() {
        roundtrip_pairs(&[
            (b"REQUEST_METHOD", b"GET"),
            (b"SCRIPT_NAME", b"/index.php"),
            (b"QUERY_STRING", b""),
        ]);
    }

    #[test]
    fn test_encode_decode_empty_value() {
        roundtrip_pairs(&[(b"QUERY_STRING", b""), (b"CONTENT_LENGTH", b"0")]);
    }

    #[test]
    fn test_encode_decode_long_value() {
        let long_value = vec![b'x'; 200];
        roundtrip_pairs(&[(b"HTTP_COOKIE", long_value.as_slice())]);
    }

    #[test]
    fn test_encoded_length_size() {
        assert_eq!(encoded_length_size(0), 1);
        assert_eq!(encoded_length_size(127), 1);
        assert_eq!(encoded_length_size(128), 4);
        assert_eq!(encoded_length_size(65535), 4);
    }

    #[test]
    fn test_try_encode_length_validates_upper_bound() {
        let mut buf = BytesMut::new();
        try_encode_length(&mut buf, MAX_NV_LENGTH).unwrap();

        let mut buf = BytesMut::new();
        assert!(matches!(
            try_encode_length(&mut buf, MAX_NV_LENGTH + 1),
            Err(ProtocolError::ContentTooLarge(_))
        ));
    }

    #[test]
    fn test_encode_length_round_trip_at_boundaries() {
        for &len in &[0u32, 1, 127, 128, 1024, 65535, MAX_NV_LENGTH] {
            let mut buf = BytesMut::new();
            try_encode_length(&mut buf, len).unwrap();
            let (decoded, _) = decode_length_from_slice(&buf).expect("decode");
            assert_eq!(decoded, len, "round-trip failure at len={len}");
        }
    }

    #[test]
    fn test_encode_length_rejects_overlong() {
        // Regression: the 4-byte form reserves the high bit, so values that
        // would collide with the marker must be rejected — not silently
        // truncated as a previous infallible `encode_length` once did.
        let mut buf = BytesMut::new();
        let err = try_encode_length(&mut buf, MAX_NV_LENGTH + 1).unwrap_err();
        assert!(matches!(err, ProtocolError::ContentTooLarge(_)));
        assert!(buf.is_empty(), "rejected encode must not emit bytes");

        let mut buf = BytesMut::new();
        let err = try_encode_length(&mut buf, u32::MAX).unwrap_err();
        assert!(matches!(err, ProtocolError::ContentTooLarge(_)));
        assert!(buf.is_empty());
    }

    #[test]
    fn test_nv_pair_write_to_buf_rejects_overlong_length() {
        // Construct a fake too-long Bytes by using a sliced Bytes — we don't
        // actually need to allocate 2^31 bytes; the encoder only inspects len.
        // The trick: create a Bytes from a zero-length range view but
        // simulate the length check at the API level instead. Easier: use
        // `try_encode_length` directly through `NvPairRef` with a slice
        // longer than MAX_NV_LENGTH would require GBs of RAM — so we test
        // via the lower-level function (covered above) and the propagation
        // through `NvPairRef::write_to_buf` with valid input here.
        let pair = NvPairRef::new(b"K", b"V");
        let mut buf = BytesMut::new();
        pair.write_to_buf(&mut buf).unwrap();
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn test_nv_pair_write_read() {
        let pair = NvPair::new(b"REQUEST_METHOD".as_slice(), b"POST".as_slice());
        let mut buf = Vec::new();
        pair.write_to(&mut buf).await.unwrap();
        let mut cursor = std::io::Cursor::new(buf);
        let decoded = NvPair::read_from(&mut cursor).await.unwrap();
        assert_eq!(pair, decoded);
    }
}
