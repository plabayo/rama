#[expect(unused, deprecated)]
use std::ascii::AsciiExt;
use std::cmp;
use std::default::Default;
use std::fmt;
use std::iter;
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
        let mut factor: u16 = 100;
        loop {
            match c.next() {
                Some(n @ '0'..='9') => {
                    // If `factor` is less than `1`, three digits have already been parsed. A
                    // q-value having more than 3 fractional digits is invalid.
                    if factor < 1 {
                        return Err(Error::invalid());
                    }
                    // Add the digit's value multiplied by `factor` to `value`.
                    let digit = (n as u16).saturating_sub('0' as u16);
                    value = value.saturating_add(factor.saturating_mul(digit));
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
    values.sort_by_cached_key(|qv| cmp::Reverse(qv.quality));
}

pub fn sort_quality_values_non_empty_vec<T>(values: &mut NonEmptyVec<QualityValue<T>>) {
    values.sort_by_cached_key(|qv| cmp::Reverse(qv.quality));
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
            x if x % 10 != 0 => write!(f, "; q=0.{x:03}"),
            x if x % 100 != 0 => write!(f, "; q=0.{:02}", x / 10),
            x => write!(f, "; q=0.{}", x / 100),
        }
    }
}

impl<T: str::FromStr> str::FromStr for QualityValue<T> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        // `item *( OWS ";" OWS [ name "=" value ] )` with one `q` weight (RFC 9110 §5.6.6, §12.4.2)
        let s = trim_ows(s);
        let mut parts = item_parts(s);
        let name = parts.next().ok_or_else(Error::invalid)??.1;
        if trim_ows(name).is_empty() {
            return Err(Error::invalid());
        }
        let mut quality = None;
        let mut item_end = s.len();
        let mut pending_empty = false;
        let mut normalise = false;
        for part in parts {
            let (separator, part) = part?;
            let part = trim_ows(part);
            if part.is_empty() {
                pending_empty = true;
                continue;
            }
            if part.starts_with("q=") || part.starts_with("Q=") {
                // any parameter named `q` is the weight, wherever it sits (RFC 9110 §12.5.1)
                if quality.is_some() {
                    return Err(Error::invalid());
                }
                quality = Some(Quality::from_str(part)?);
                item_end = separator;
                continue;
            }
            // `parameter-name "=" parameter-value`, with a non-empty token name
            if !part.contains('=') || part.starts_with('=') {
                return Err(Error::invalid());
            }
            // a parameter after the weight, or after an empty one, needs a rebuilt item
            normalise |= pending_empty || quality.is_some();
            pending_empty = false;
        }
        let parsed = if normalise {
            // drop empty parameters and the weight so the item re-encodes to what it decodes from
            let mut item = String::with_capacity(s.len());
            let parts = item_parts(s).filter_map(|part| part.ok().map(|(_, part)| trim_ows(part)));
            for (index, part) in parts.enumerate() {
                let is_weight = index > 0 && (part.starts_with("q=") || part.starts_with("Q="));
                if part.is_empty() || is_weight {
                    continue;
                }
                if index > 0 {
                    item.push(';');
                }
                item.push_str(part);
            }
            item.parse::<T>()
        } else {
            s.get(..item_end)
                .unwrap_or_default()
                .trim_end_matches([';', ' ', '\t'])
                .parse::<T>()
        };
        parsed
            .map(|item| Self::new(item, quality.unwrap_or_else(Quality::one)))
            .map_err(|_err| Error::invalid())
    }
}

fn trim_ows(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// The `;`-separated parts of a list item, each with the offset of the `;` before it.
///
/// Quoted strings, including their quoted-pairs, never split; an unterminated one fails.
fn item_parts(s: &str) -> impl Iterator<Item = Result<(usize, &str), Error>> {
    let mut start = Some(0_usize);
    iter::from_fn(move || {
        let from = start.take()?;
        let rest = s.get(from..)?;
        let mut in_quotes = false;
        let mut escaped = false;
        for (offset, byte) in rest.bytes().enumerate() {
            if escaped {
                escaped = false;
            } else if in_quotes {
                match byte {
                    b'\\' => escaped = true,
                    b'"' => in_quotes = false,
                    _ => {}
                }
            } else if byte == b'"' {
                in_quotes = true;
            } else if byte == b';' {
                let end = from.saturating_add(offset);
                start = Some(end.saturating_add(1));
                return Some(Ok((
                    from.saturating_sub(1),
                    s.get(from..end).unwrap_or_default(),
                )));
            }
        }
        Some(if in_quotes {
            Err(Error::invalid())
        } else {
            Ok((from.saturating_sub(1), rest))
        })
    })
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
    use crate::util::for_each_small_input;
    use rama_utils::collections::non_empty_vec;

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
    fn test_quality_item_fmt_trims_only_trailing_zeroes() {
        for (quality, expected) in [
            (10, "foo; q=0.01"),
            (100, "foo; q=0.1"),
            (101, "foo; q=0.101"),
            (120, "foo; q=0.12"),
        ] {
            let value = QualityValue::new("foo", Quality(quality));
            assert_eq!(value.to_string(), expected);
        }
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
        "gzip; q=0.2739999"
            .parse::<QualityValue<String>>()
            .unwrap_err();
    }

    #[test]
    fn test_quality_item_from_str6() {
        "gzip; q=2".parse::<QualityValue<String>>().unwrap_err();
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
    fn test_weight_without_item_is_rejected() {
        for input in [
            ";q=1", " ;q=0.5", ";", ";;q=1", ";0;q=1", ";q=;;q=1", ";\t;q=1.", " ; a=b",
        ] {
            assert!(input.parse::<QualityValue<String>>().is_err(), "{input:?}");
        }
    }

    #[test]
    fn test_parameters_follow_the_grammar() {
        // a parameter is `name=value`, and the weight comes once
        for input in [
            "a;q=2;q=1",
            "a;b;q=1",
            "text/html;q=2;q=1",
            "a;b",
            "a;=b",
            "a;q=0.5;q=1",
            "a;p=\"x",
            "a;p=\"x;q=1",
        ] {
            assert!(input.parse::<QualityValue<String>>().is_err(), "{input:?}");
        }
    }

    #[test]
    fn test_empty_parameters_are_dropped() {
        for (input, value, quality) in [
            ("f;;q=1", "f", 1000),
            ("f;", "f", 1000),
            ("f; ;q=0.5", "f", 500),
            ("text/html;;q=0.5", "text/html", 500),
            ("a;;b=1", "a;b=1", 1000),
            ("a;;b=1;q=0.2", "a;b=1", 200),
            ("text/html;p=\"a;;b\";q=0.5", "text/html;p=\"a;;b\"", 500),
            // any parameter named `q` is the weight (RFC 9110 §12.5.1)
            ("text/html;q=0.5;level=1", "text/html;level=1", 500),
            ("*/*;q=0.1;charset=utf-8", "*/*;charset=utf-8", 100),
            ("a;q=0.5;;b=1", "a;b=1", 500),
            (" text/html;q=0.5", "text/html", 500),
            ("text/html;q=0.5\t", "text/html", 500),
            // an item name is never taken as the weight
            ("q=1;;a=b", "q=1;a=b", 1000),
            ("q=1;q=0.5;a=b", "q=1;a=b", 500),
            // only OWS (SP, HTAB) is trimmed (RFC 9110 §5.6.3)
            ("\u{a0}a;q=0.5", "\u{a0}a", 500),
            ("a;q=0.5;b=\u{a0}", "a;b=\u{a0}", 500),
        ] {
            let qv = input.parse::<QualityValue<String>>().unwrap();
            assert_eq!(qv.value, value, "{input:?}");
            assert_eq!(qv.quality, Quality(quality), "{input:?}");
            // re-encoding yields an equivalent item
            let again = qv.to_string().parse::<QualityValue<String>>().unwrap();
            assert_eq!(again.value, qv.value, "{input:?}");
        }
    }

    #[test]
    fn test_quality_from_str_extremes() {
        assert_eq!("q=0.999".parse::<Quality>().unwrap(), Quality(999));
        assert_eq!("Q=1.000".parse::<Quality>().unwrap(), Quality(1000));
        assert_eq!("q=0.".parse::<Quality>().unwrap(), Quality(0));
        for value in [
            "q=1.999",
            "q=1.001",
            "q=0.9999",
            "q=9",
            "q=",
            "q",
            "",
            "q=0.a",
            "q=\u{0660}",
        ] {
            assert!(value.parse::<Quality>().is_err(), "value: {value:?}");
        }
    }

    #[test]
    fn test_small_inputs_never_panic() {
        for_each_small_input(b"qQ=019. ;a", 6, |input| {
            let Ok(s) = str::from_utf8(input) else {
                return;
            };
            if let Ok(quality) = s.parse::<Quality>() {
                assert!(quality.as_u16() <= 1000, "input: {s:?}");
            }
            if let Ok(qv) = s.parse::<QualityValue<String>>() {
                assert!(qv.quality.as_u16() <= 1000, "input: {s:?}");
                _ = qv.to_string();
            }
        });
    }

    #[test]
    fn test_sort_quality_values_is_stable_descending() {
        let mut values = non_empty_vec![
            QualityValue::new("a", Quality(0)),
            QualityValue::new("b", Quality(1000)),
            QualityValue::new("c", Quality(500)),
            QualityValue::new("d", Quality(1000)),
        ];
        sort_quality_values_non_empty_vec(&mut values);
        let order: Vec<_> = values.iter().map(|qv| qv.value).collect();
        assert_eq!(order, ["b", "d", "c", "a"]);
    }

    #[test]
    fn test_fuzzing_bugs() {
        assert_eq!(
            "99999;".parse::<QualityValue<String>>().unwrap().value,
            "99999"
        );
        "\x0d;;;=\u{d6aa}=="
            .parse::<QualityValue<String>>()
            .unwrap_err();
    }
}
