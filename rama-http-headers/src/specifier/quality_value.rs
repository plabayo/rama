#[allow(unused, deprecated)]
use std::ascii::AsciiExt;
use std::cmp;
use std::default::Default;
use std::fmt;
use std::str;

use rama_utils::collections::NonEmptySmallVec;
use rama_utils::collections::NonEmptyVec;

use crate::Error;

use self::internal::IntoQuality;

/// Represents a quality used in quality values.
///
/// Can be created with the `q` function.
///
/// # Implementation notes
///
/// The quality value is defined as a number between 0 and 1 with three decimal places. This means
/// there are 1001 possible values. Since floating point numbers are not exact and the smallest
/// floating point data type (`f32`) consumes four bytes, rama uses an `u16` value to store the
/// quality internally. For performance reasons you may set quality directly to a value between
/// 0 and 1000 e.g. `Quality(532)` matches the quality `q=0.532`.
///
/// [RFC7231 Section 5.3.1](https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.1)
/// gives more information on quality values in HTTP header fields.
#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct Quality(u16);

impl Quality {
    #[inline]
    #[must_use]
    pub fn new_clamped(v: u16) -> Self {
        Self(v.clamp(0, 1000))
    }

    #[inline]
    #[must_use]
    pub const fn one() -> Self {
        Self(1000)
    }

    #[inline]
    #[must_use]
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl str::FromStr for Quality {
    type Err = Error;

    // Parse a q-value as specified in RFC 7231 section 5.3.1.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut c = s.chars();
        // Parse "q=" (case-insensitively).
        match c.next() {
            Some('q' | 'Q') => (),
            _ => return Err(Error::invalid()),
        };
        match c.next() {
            Some('=') => (),
            _ => return Err(Error::invalid()),
        };

        // Parse leading digit. Since valid q-values are between 0.000 and 1.000, only "0" and "1"
        // are allowed.
        let mut value = match c.next() {
            Some('0') => 0,
            Some('1') => 1000,
            _ => return Err(Error::invalid()),
        };

        // Parse optional decimal point.
        match c.next() {
            Some('.') => (),
            None => return Ok(Self(value)),
            _ => return Err(Error::invalid()),
        };

        // Parse optional fractional digits. The value of each digit is multiplied by `factor`.
        // Since the q-value is represented as an integer between 0 and 1000, `factor` is `100` for
        // the first digit, `10` for the next, and `1` for the digit after that.
        let mut factor = 100;
        loop {
            match c.next() {
                Some(n @ '0'..='9') => {
                    // If `factor` is less than `1`, three digits have already been parsed. A
                    // q-value having more than 3 fractional digits is invalid.
                    if factor < 1 {
                        return Err(Error::invalid());
                    }
                    // Add the digit's value multiplied by `factor` to `value`.
                    value += factor * (n as u16 - '0' as u16);
                }
                None => {
                    // No more characters to parse. Check that the value representing the q-value is
                    // in the valid range.
                    return if value <= 1000 {
                        Ok(Self(value))
                    } else {
                        Err(Error::invalid())
                    };
                }
                _ => return Err(Error::invalid()),
            };
            factor /= 10;
        }
    }
}

impl Default for Quality {
    fn default() -> Self {
        Self(1000)
    }
}

/// Represents an item with a quality value as defined in
/// [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-5.3.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct QualityValue<T> {
    /// The actual contents of the field.
    pub value: T,
    /// The quality (client or server preference) for the value.
    pub quality: Quality,
}

pub fn sort_quality_values_non_empty_smallvec<const N: usize, T>(
    values: &mut NonEmptySmallVec<N, QualityValue<T>>,
) {
    values.sort_by_cached_key(|qv| u16::MAX - qv.quality.as_u16());
}

pub fn sort_quality_values_non_empty_vec<T>(values: &mut NonEmptyVec<QualityValue<T>>) {
    values.sort_by_cached_key(|qv| u16::MAX - qv.quality.as_u16());
}

impl<T: Copy> Copy for QualityValue<T> {}

impl<T> QualityValue<T> {
    /// Creates a new `QualityValue` from an item and a quality.
    pub const fn new(value: T, quality: Quality) -> Self {
        Self { value, quality }
    }

    /// Creates a new `QualityValue` from an item value alone.
    pub const fn new_value(value: T) -> Self {
        Self {
            value,
            quality: Quality::one(),
        }
    }

    /*
    /// Convenience function to set a `Quality` from a float or integer.
    ///
    /// Implemented for `u16` and `f32`.
    ///
    /// # Panic
    ///
    /// Panics if value is out of range.
    pub fn with_q<Q: IntoQuality>(mut self, q: Q) -> QualityValue<T> {
        self.quality = q.into_quality();
        self
    }
    */
}

impl<T> From<T> for QualityValue<T> {
    fn from(value: T) -> Self {
        Self {
            value,
            quality: Quality::default(),
        }
    }
}

impl<T: PartialEq> cmp::PartialOrd for QualityValue<T> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.quality.partial_cmp(&other.quality)
    }
}

impl<T: fmt::Display> fmt::Display for QualityValue<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.value, f)?;
        match self.quality.0 {
            1000 => Ok(()),
            0 => f.write_str("; q=0"),
            x => write!(f, "; q=0.{}", format!("{x:03}").trim_end_matches('0')),
        }
    }
}

impl<T: str::FromStr> str::FromStr for QualityValue<T> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        // Set defaults used if parsing fails.
        let mut raw_item = s;
        let mut quality = Quality::one();

        let mut parts = s.rsplitn(2, ';').map(|x| x.trim());
        if let (Some(first), Some(second), None) = (parts.next(), parts.next(), parts.next()) {
            if first.len() < 2 {
                return Err(Error::invalid());
            }
            if first.starts_with("q=") || first.starts_with("Q=") {
                quality = Quality::from_str(first)?;
                raw_item = second;
            }
        }
        match raw_item.parse::<T>() {
            // we already checked above that the quality is within range
            Ok(item) => Ok(Self::new(item, quality)),
            Err(_) => Err(Error::invalid()),
        }
    }
}

#[inline]
fn from_f32(f: f32) -> Quality {
    Quality((f.clamp(0f32, 1f32) * 1000f32) as u16)
}

#[cfg(test)]
fn q<T: IntoQuality>(val: T) -> Quality {
    val.into_quality()
}

impl<T> From<T> for Quality
where
    T: IntoQuality,
{
    fn from(x: T) -> Self {
        x.into_quality()
    }
}

mod internal {
    use super::Quality;

    // TryFrom is probably better, but it's not stable. For now, we want to
    // keep the functionality of the `q` function, while allowing it to be
    // generic over `f32` and `u16`.
    //
    // `q` would panic before, so keep that behavior. `TryFrom` can be
    // introduced later for a non-panicking conversion.

    pub trait IntoQuality: Sealed + Sized {
        fn into_quality(self) -> Quality;
    }

    impl IntoQuality for f32 {
        fn into_quality(self) -> Quality {
            super::from_f32(self)
        }
    }

    impl IntoQuality for u16 {
        #[inline(always)]
        fn into_quality(self) -> Quality {
            Quality::new_clamped(self)
        }
    }

    pub trait Sealed {}
    impl Sealed for u16 {}
    impl Sealed for f32 {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quality_item_fmt_q_1() {
        let x = QualityValue::from("foo");
        assert_eq!(x.to_string(), "foo");
    }
    #[test]
    fn test_quality_item_fmt_q_0001() {
        let x = QualityValue::new("foo", Quality(1));
        assert_eq!(x.to_string(), "foo; q=0.001");
    }
    #[test]
    fn test_quality_item_fmt_q_05() {
        let x = QualityValue::new("foo", Quality(500));
        assert_eq!(x.to_string(), "foo; q=0.5");
    }

    #[test]
    fn test_quality_item_fmt_q_0() {
        let x = QualityValue::new("foo", Quality(0));
        assert_eq!(x.to_string(), "foo; q=0");
    }

    #[test]
    fn test_quality_item_from_str1() {
        let x: QualityValue<String> = "chunked".parse().unwrap();
        assert_eq!(
            x,
            QualityValue {
                value: "chunked".to_owned(),
                quality: Quality(1000),
            }
        );
    }
    #[test]
    fn test_quality_item_from_str2() {
        let x: QualityValue<String> = "chunked; q=1".parse().unwrap();
        assert_eq!(
            x,
            QualityValue {
                value: "chunked".to_owned(),
                quality: Quality(1000),
            }
        );
    }
    #[test]
    fn test_quality_item_from_str3() {
        let x: QualityValue<String> = "gzip; q=0.5".parse().unwrap();
        assert_eq!(
            x,
            QualityValue {
                value: "gzip".to_owned(),
                quality: Quality(500),
            }
        );
    }
    #[test]
    fn test_quality_item_from_str4() {
        let x: QualityValue<String> = "gzip; q=0.273".parse().unwrap();
        assert_eq!(
            x,
            QualityValue {
                value: "gzip".to_owned(),
                quality: Quality(273),
            }
        );
    }
    #[test]
    fn test_quality_item_from_str5() {
        assert!("gzip; q=0.2739999".parse::<QualityValue<String>>().is_err());
    }

    #[test]
    fn test_quality_item_from_str6() {
        assert!("gzip; q=2".parse::<QualityValue<String>>().is_err());
    }
    #[test]
    fn test_quality_item_ordering() {
        let x: QualityValue<String> = "gzip; q=0.5".parse().unwrap();
        let y: QualityValue<String> = "gzip; q=0.273".parse().unwrap();
        assert!(x > y)
    }

    #[test]
    fn test_quality() {
        assert_eq!(q(0.5), Quality(500));
    }

    #[test]
    fn test_fuzzing_bugs() {
        assert!("99999;".parse::<QualityValue<String>>().is_err());
        assert!("\x0d;;;=\u{d6aa}==".parse::<QualityValue<String>>().is_ok())
    }
}
