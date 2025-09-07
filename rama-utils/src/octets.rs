/// A helper function that unpacks a sequence of 2 bytes found in the buffer with
/// starting at the given offset, into a u16.
///
/// # Examples
///
/// ```
/// use rama_utils::octets::unpack_octets_as_u16;
/// let buf: [u8; 2] = [0, 1];
/// assert_eq!(1u16, unpack_octets_as_u16(&buf, 0));
/// ```
///
/// # Panics
///
/// In case the buffer is too small.
#[inline]
#[must_use]
pub fn unpack_octets_as_u16(buf: &[u8], offset: usize) -> u16 {
    ((buf[offset] as u16) << 8) | (buf[offset + 1] as u16)
}

/// A helper function that unpacks a sequence of 4 bytes found in the buffer with
/// starting at the given offset, into a u32.
///
/// # Examples
///
/// ```
/// use rama_utils::octets::unpack_octets_as_u32;
/// let buf: [u8; 4] = [0, 0, 0, 1];
/// assert_eq!(1u32, unpack_octets_as_u32(&buf, 0));
/// ```
///
/// # Panics
///
/// In case the buffer is too small.
#[inline]
#[must_use]
pub fn unpack_octets_as_u32(buf: &[u8], offset: usize) -> u32 {
    ((buf[offset] as u32) << 24)
        | ((buf[offset + 1] as u32) << 16)
        | ((buf[offset + 2] as u32) << 8)
        | (buf[offset + 3] as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unpack_octets_as_u16() {
        let buf: [u8; 2] = [0, 1];
        assert_eq!(1u16, unpack_octets_as_u16(&buf, 0));
    }

    #[test]
    fn test_unpack_octets_as_u32() {
        let buf: [u8; 4] = [0, 0, 0, 1];
        assert_eq!(1u32, unpack_octets_as_u32(&buf, 0));
    }
}
