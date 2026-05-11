use core::ops::Mul;

mod sealed {
    pub trait Sealed {}
}

/// Marker trait for integer types that can be scaled by the byte-unit helpers
/// [`kib`] and [`mib`].
///
/// Sealed — implemented for the standard integer types that can fit at least
/// one MiB: `u32`, `u64`, `u128`, `usize`, `i32`, `i64`, `i128`, `isize`.
pub trait Octets: sealed::Sealed + Copy + Mul<Output = Self> {
    /// The value `1024` in `Self`.
    const KIB: Self;
    /// The value `1024 * 1024` in `Self`.
    const MIB: Self;
}

macro_rules! impl_octets {
    ($($t:ty),* $(,)?) => {
        $(
            impl sealed::Sealed for $t {}
            impl Octets for $t {
                const KIB: Self = 1024;
                const MIB: Self = 1024 * 1024;
            }
        )*
    };
}

impl_octets!(u32, u64, u128, usize, i32, i64, i128, isize);

/// Multiply by 1024 to express a byte count in kibibytes (KiB).
///
/// Generic over any standard integer type (see [`Octets`]), so callers do not
/// need to cast between `u64` and `usize` at the call site.
///
/// ```
/// use rama_utils::octets::kib;
/// assert_eq!(kib(8_u64), 8 * 1024);
/// assert_eq!(kib(8_usize), 8 * 1024);
/// ```
#[inline]
#[must_use]
pub fn kib<T: Octets>(n: T) -> T {
    n * T::KIB
}

/// Multiply by 1024² to express a byte count in mebibytes (MiB).
///
/// Generic over any standard integer type (see [`Octets`]).
///
/// ```
/// use rama_utils::octets::mib;
/// assert_eq!(mib(2_u64), 2 * 1024 * 1024);
/// assert_eq!(mib(2_usize), 2 * 1024 * 1024);
/// ```
#[inline]
#[must_use]
pub fn mib<T: Octets>(n: T) -> T {
    n * T::MIB
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
    fn test_kib_mib_u64() {
        assert_eq!(kib(0_u64), 0);
        assert_eq!(kib(1_u64), 1024);
        assert_eq!(kib(256_u64), 256 * 1024);
        assert_eq!(mib(0_u64), 0);
        assert_eq!(mib(1_u64), 1024 * 1024);
        assert_eq!(mib(8_u64), 8 * 1024 * 1024);
    }

    #[test]
    fn test_kib_mib_usize() {
        assert_eq!(kib(4_usize), 4 * 1024);
        assert_eq!(mib(2_usize), 2 * 1024 * 1024);
    }

    #[test]
    fn test_kib_mib_u32() {
        assert_eq!(kib(3_u32), 3 * 1024);
        assert_eq!(mib(5_u32), 5 * 1024 * 1024);
    }

    #[test]
    fn test_kib_mib_signed() {
        assert_eq!(kib(-1_i32), -1024);
        assert_eq!(mib(-2_i64), -2 * 1024 * 1024);
    }

    #[test]
    fn test_kib_mib_return_type_matches_input() {
        let a: u32 = kib(1_u32);
        let b: u64 = kib(1_u64);
        let c: u128 = kib(1_u128);
        let d: usize = kib(1_usize);
        let e: isize = mib(1_isize);
        assert_eq!(a as u128, 1024);
        assert_eq!(b as u128, 1024);
        assert_eq!(c, 1024);
        assert_eq!(d, 1024);
        assert_eq!(e, 1024 * 1024);
    }
}
