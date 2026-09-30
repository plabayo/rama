use std::fmt;
use std::ops::{Bound, RangeBounds};

use rama_http_types::{HeaderName, HeaderValue};

use crate::{
    Error, HeaderDecode, HeaderEncode, TypedHeader,
    util::{self, parse_digits},
};

/// Content-Range, described in [RFC7233](https://tools.ietf.org/html/rfc7233#section-4.2)
///
/// # ABNF
///
/// ```text
/// Content-Range       = byte-content-range
///                     / other-content-range
///
/// byte-content-range  = bytes-unit SP
///                       ( byte-range-resp / unsatisfied-range )
///
/// byte-range-resp     = byte-range "/" ( complete-length / "*" )
/// byte-range          = first-byte-pos "-" last-byte-pos
/// unsatisfied-range   = "*/" complete-length
///
/// complete-length     = 1*DIGIT
///
/// other-content-range = other-range-unit SP other-range-resp
/// other-range-resp    = *CHAR
/// ```
///
/// # Example
///
/// ```
/// use rama_http_headers::ContentRange;
///
/// // 100 bytes (included byte 199), with a full length of 3,400
/// let cr = ContentRange::bytes(100..200, 3400).unwrap();
/// ```
//NOTE: only supporting bytes-content-range, YAGNI the extension
#[derive(Clone, Debug, PartialEq)]
pub struct ContentRange {
    /// First and last bytes of the range, omitted if request could not be
    /// satisfied
    range: Option<(u64, u64)>,

    /// Total length of the instance, can be omitted if unknown
    complete_length: Option<u64>,
}

rama_utils::macros::error::static_str_error! {
    #[doc = "content range is not valid"]
    pub struct InvalidContentRange;
}

impl ContentRange {
    /// Construct a new `Content-Range: bytes ..` header.
    ///
    /// Errors if the range is empty or does not end before `complete_length`.
    pub fn bytes(
        range: impl RangeBounds<u64>,
        complete_length: impl Into<Option<u64>>,
    ) -> Result<Self, InvalidContentRange> {
        let complete_length = complete_length.into();

        let start = match range.start_bound() {
            Bound::Included(&s) => Some(s),
            Bound::Excluded(&s) => s.checked_add(1),
            Bound::Unbounded => Some(0),
        };

        let end = match range.end_bound() {
            Bound::Included(&e) => Some(e),
            Bound::Excluded(&e) => e.checked_sub(1),
            Bound::Unbounded => complete_length.and_then(|max| max.checked_sub(1)),
        };

        let (Some(start), Some(end)) = (start, end) else {
            return Err(InvalidContentRange);
        };
        if !is_valid_byte_range_resp(start, end, complete_length) {
            return Err(InvalidContentRange);
        }

        Ok(Self {
            range: Some((start, end)),
            complete_length,
        })
    }

    /// Create a new `ContentRange` stating the range could not be satisfied.
    ///
    /// The passed argument is the complete length of the entity.
    #[must_use]
    pub fn unsatisfied_bytes(complete_length: u64) -> Self {
        Self {
            range: None,
            complete_length: Some(complete_length),
        }
    }

    /// Get the byte range if satisified.
    ///
    /// Note that these byte ranges are inclusive on both ends.
    #[must_use]
    pub fn bytes_range(&self) -> Option<(u64, u64)> {
        self.range
    }

    /// Get the bytes complete length if available.
    #[must_use]
    pub fn bytes_len(&self) -> Option<u64> {
        self.complete_length
    }
}

impl TypedHeader for ContentRange {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CONTENT_RANGE
    }
}

impl HeaderDecode for ContentRange {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|s| split_in_two(s, ' '))
            .and_then(|(unit, spec)| {
                if unit != "bytes" {
                    // For now, this only supports bytes-content-range. nani?
                    return None;
                }

                let (range, complete_length) = split_in_two(spec, '/')?;

                let complete_length = if complete_length == "*" {
                    None
                } else {
                    Some(parse_digits(complete_length)?)
                };

                let range = if range == "*" {
                    None
                } else {
                    let (first_byte, last_byte) = split_in_two(range, '-')?;
                    let first_byte = parse_digits(first_byte)?;
                    let last_byte = parse_digits(last_byte)?;
                    if !is_valid_byte_range_resp(first_byte, last_byte, complete_length) {
                        return None;
                    }
                    Some((first_byte, last_byte))
                };

                // unsatisfied-range = "*/" complete-length
                if range.is_none() && complete_length.is_none() {
                    return None;
                }

                Some(Self {
                    range,
                    complete_length,
                })
            })
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for ContentRange {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        struct Adapter<'a>(&'a ContentRange);

        impl fmt::Display for Adapter<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bytes ")?;

                if let Some((first_byte, last_byte)) = self.0.range {
                    write!(f, "{first_byte}-{last_byte}")?;
                } else {
                    f.write_str("*")?;
                }

                f.write_str("/")?;

                if let Some(v) = self.0.complete_length {
                    write!(f, "{v}")
                } else {
                    f.write_str("*")
                }
            }
        }

        values.extend(util::fmt(Adapter(self)));
    }
}

/// RFC 9110 §14.4: `first <= last` and `last < complete-length` when known.
fn is_valid_byte_range_resp(first: u64, last: u64, complete_length: Option<u64>) -> bool {
    first <= last && complete_length.is_none_or(|len| last < len)
}

fn split_in_two(s: &str, separator: char) -> Option<(&str, &str)> {
    let mut iter = s.splitn(2, separator);
    match (iter.next(), iter.next()) {
        (Some(a), Some(b)) => Some((a, b)),
        _ => None,
    }
}

/*
test_header!(test_bytes,
    vec![b"bytes 0-499/500"],
    Some(ContentRange(ContentRangeSpec::Bytes {
        range: Some((0, 499)),
        complete_length: Some(500)
    })));

test_header!(test_bytes_unknown_len,
    vec![b"bytes 0-499/*"],
    Some(ContentRange(ContentRangeSpec::Bytes {
        range: Some((0, 499)),
        complete_length: None
    })));

test_header!(test_bytes_unknown_range,
    vec![b"bytes */
500"],
            Some(ContentRange(ContentRangeSpec::Bytes {
                range: None,
                complete_length: Some(500)
            })));

        test_header!(test_unregistered,
            vec![b"seconds 1-2"],
            Some(ContentRange(ContentRangeSpec::Unregistered {
                unit: "seconds".to_owned(),
                resp: "1-2".to_owned()
            })));

        test_header!(test_no_len,
            vec![b"bytes 0-499"],
            None::<ContentRange>);

        test_header!(test_only_unit,
            vec![b"bytes"],
            None::<ContentRange>);

        test_header!(test_end_less_than_start,
            vec![b"bytes 499-0/500"],
            None::<ContentRange>);

        test_header!(test_blank,
            vec![b""],
            None::<ContentRange>);

        test_header!(test_bytes_many_spaces,
            vec![b"bytes 1-2/500 3"],
            None::<ContentRange>);

        test_header!(test_bytes_many_slashes,
            vec![b"bytes 1-2/500/600"],
            None::<ContentRange>);

        test_header!(test_bytes_many_dashes,
            vec![b"bytes 1-2-3/500"],
            None::<ContentRange>);
*/

#[cfg(test)]
mod tests {
    use std::iter;

    use super::*;
    use crate::common::{test_decode, test_encode};
    use crate::util::for_each_small_input;

    #[test]
    fn bytes_constructor_rejects_unrepresentable_without_panic() {
        for (range, len) in [
            ((Bound::Excluded(u64::MAX), Bound::Unbounded), Some(10)),
            ((Bound::Included(0), Bound::Excluded(0)), Some(10)),
            ((Bound::Unbounded, Bound::Unbounded), Some(0)),
            ((Bound::Included(5), Bound::Included(3)), Some(10)),
            ((Bound::Included(0), Bound::Included(10)), Some(10)),
            ((Bound::Unbounded, Bound::Unbounded), None),
        ] {
            assert!(
                ContentRange::bytes(range, len).is_err(),
                "range: {range:?}, len: {len:?}"
            );
        }
    }

    #[test]
    fn bytes_constructor_encodes() {
        for (range, len, expected) in [
            (
                (Bound::Included(0), Bound::Excluded(5)),
                Some(13),
                "bytes 0-4/13",
            ),
            ((Bound::Unbounded, Bound::Unbounded), Some(1), "bytes 0-0/1"),
            (
                (Bound::Excluded(0), Bound::Included(u64::MAX)),
                None,
                "bytes 1-18446744073709551615/*",
            ),
        ] {
            let content_range = ContentRange::bytes(range, len).unwrap();
            assert_eq!(test_encode(content_range)["content-range"], expected);
        }
    }

    #[test]
    fn decode_valid() {
        for (value, range, len) in [
            ("bytes 0-499/500", Some((0, 499)), Some(500)),
            ("bytes 0-499/*", Some((0, 499)), None),
            ("bytes */500", None, Some(500)),
        ] {
            let content_range: ContentRange = test_decode(&[value]).unwrap();
            assert_eq!(content_range.bytes_range(), range, "value: {value:?}");
            assert_eq!(content_range.bytes_len(), len, "value: {value:?}");
        }
    }

    #[test]
    fn small_inputs_never_panic() {
        for_each_small_input(b"01-/* ", 6, |input| {
            let Ok(value) = HeaderValue::from_bytes(&[b"bytes ".as_slice(), input].concat()) else {
                return;
            };
            let Ok(content_range) = ContentRange::decode(&mut iter::once(&value)) else {
                return;
            };
            if let Some((first, last)) = content_range.bytes_range() {
                assert!(first <= last, "input: {input:?}");
                if let Some(len) = content_range.bytes_len() {
                    assert!(last < len, "input: {input:?}");
                }
            } else {
                assert!(content_range.bytes_len().is_some(), "input: {input:?}");
            }
            assert!(
                content_range.encode_to_value().is_some(),
                "input: {input:?}"
            );
        });
    }

    #[test]
    fn decode_rejects_invalid() {
        for value in [
            "",
            "bytes",
            "seconds 1-2",
            "bytes 0-499",
            "bytes 499-0/500",
            "bytes 0-500/500",
            "bytes 0-0/0",
            "bytes */*",
            "bytes 1-2/500 3",
            "bytes 1-2/500/600",
            "bytes 1-2-3/500",
            "bytes 0-18446744073709551616/*",
            "bytes +0-1/2",
            "bytes 0-+1/2",
            "bytes 0-1/+2",
            "bytes */+2",
        ] {
            assert!(
                test_decode::<ContentRange>(&[value]).is_none(),
                "value: {value:?}"
            );
        }
    }
}
