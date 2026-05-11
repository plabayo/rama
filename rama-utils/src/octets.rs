/// Multiply by 1024 to express a byte count in kibibytes (KiB).
///
/// Returns `usize`; use [`kib_u64`] when you need a `u64`.
///
/// ```
/// use rama_utils::octets::kib;
/// const LIMIT: usize = kib(8);
/// assert_eq!(LIMIT, 8 * 1024);
/// ```
#[inline]
#[must_use]
pub const fn kib(n: usize) -> usize {
    n * 1024
}

/// Multiply by 1024² to express a byte count in mebibytes (MiB).
///
/// Returns `usize`; use [`mib_u64`] when you need a `u64`.
///
/// ```
/// use rama_utils::octets::mib;
/// const LIMIT: usize = mib(2);
/// assert_eq!(LIMIT, 2 * 1024 * 1024);
/// ```
#[inline]
#[must_use]
pub const fn mib(n: usize) -> usize {
    n * 1024 * 1024
}

/// `u64` variant of [`kib`].
///
/// ```
/// use rama_utils::octets::kib_u64;
/// const LIMIT: u64 = kib_u64(8);
/// assert_eq!(LIMIT, 8 * 1024);
/// ```
#[inline]
#[must_use]
pub const fn kib_u64(n: u64) -> u64 {
    n * 1024
}

/// `u64` variant of [`mib`].
///
/// ```
/// use rama_utils::octets::mib_u64;
/// const LIMIT: u64 = mib_u64(2);
/// assert_eq!(LIMIT, 2 * 1024 * 1024);
/// ```
#[inline]
#[must_use]
pub const fn mib_u64(n: u64) -> u64 {
    n * 1024 * 1024
}

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

    #[test]
    fn test_kib_mib() {
        assert_eq!(kib(0), 0);
        assert_eq!(kib(1), 1024);
        assert_eq!(kib(256), 256 * 1024);
        assert_eq!(mib(0), 0);
        assert_eq!(mib(1), 1024 * 1024);
        assert_eq!(mib(8), 8 * 1024 * 1024);
    }

    #[test]
    fn test_kib_mib_u64() {
        assert_eq!(kib_u64(0), 0);
        assert_eq!(kib_u64(1), 1024);
        assert_eq!(kib_u64(256), 256 * 1024);
        assert_eq!(mib_u64(0), 0);
        assert_eq!(mib_u64(1), 1024 * 1024);
        assert_eq!(mib_u64(8), 8 * 1024 * 1024);
    }

    #[test]
    fn test_kib_mib_const_context() {
        const K: usize = kib(4);
        const M: usize = mib(2);
        const K64: u64 = kib_u64(4);
        const M64: u64 = mib_u64(2);
        assert_eq!(K, 4 * 1024);
        assert_eq!(M, 2 * 1024 * 1024);
        assert_eq!(K64, 4 * 1024);
        assert_eq!(M64, 2 * 1024 * 1024);
    }
}
