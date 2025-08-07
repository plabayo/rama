use std::ops::{Bound, RangeBounds};

use rama_http_types::{HeaderName, HeaderValue};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Range` header, defined in [RFC7233](https://tools.ietf.org/html/rfc7233#section-3.1)
///
/// The "Range" header field on a GET request modifies the method
/// semantics to request transfer of only one or more subranges of the
/// selected representation data, rather than the entire selected
/// representation data.
///
/// # ABNF
///
/// ```text
/// Range = byte-ranges-specifier / other-ranges-specifier
/// other-ranges-specifier = other-range-unit "=" other-range-set
/// other-range-set = 1*VCHAR
///
/// bytes-unit = "bytes"
///
/// byte-ranges-specifier = bytes-unit "=" byte-range-set
/// byte-range-set = 1#(byte-range-spec / suffix-byte-range-spec)
/// byte-range-spec = first-byte-pos "-" [last-byte-pos]
/// first-byte-pos = 1*DIGIT
/// last-byte-pos = 1*DIGIT
/// ```
///
/// # Example values
///
/// * `bytes=1000-`
/// * `bytes=-2000`
/// * `bytes=0-1,30-40`
/// * `bytes=0-10,20-90,-100`
///
/// # Examples
///
/// ```
/// use rama_http_headers::Range;
///
///
/// let range = Range::bytes(0..1234).unwrap();
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct Range(HeaderValue);

rama_utils::macros::error::static_str_error! {
    #[doc = "range is not valid"]
    pub struct InvalidRange;
}

impl Range {
    /// Creates a `Range` header from bounds.
    pub fn bytes(bounds: impl RangeBounds<u64>) -> Result<Self, InvalidRange> {
        let v = match (bounds.start_bound(), bounds.end_bound()) {
            (Bound::Included(start), Bound::Included(end)) => format!("bytes={start}-{end}"),
            (Bound::Included(start), Bound::Excluded(&end)) => {
                format!("bytes={start}-{}", end - 1)
            }
            (Bound::Included(start), Bound::Unbounded) => format!("bytes={start}-"),
            // These do not directly translate.
            //(Bound::Unbounded, Bound::Included(end)) => format!("bytes=-{}", end),
            //(Bound::Unbounded, Bound::Excluded(&end)) => format!("bytes=-{}", end - 1),
            _ => return Err(InvalidRange),
        };

        Ok(Self(HeaderValue::try_from(v).unwrap()))
    }

    /// Iterate the range sets as a tuple of bounds, if valid with length.
    ///
    /// The length of the content is passed as an argument, and all ranges
    /// that can be satisfied will be iterated.
    pub fn satisfiable_ranges(
        &self,
        len: u64,
    ) -> impl Iterator<Item = (Bound<u64>, Bound<u64>)> + '_ {
        let s = self
            .0
            .to_str()
            .expect("valid string checked in Header::decode()");

        s["bytes=".len()..].split(',').filter_map(move |spec| {
            let mut iter = spec.trim().splitn(2, '-');
            let start = parse_bound(iter.next()?)?;
            let end = parse_bound(iter.next()?)?;

            // Unbounded ranges in HTTP are actually a suffix
            // For example, `-100` means the last 100 bytes.
            if start == Bound::Unbounded
                && let Bound::Included(end) = end
            {
                if len < end {
                    // Last N bytes is larger than available!
                    return None;
                }
                return Some((Bound::Included(len - end), Bound::Unbounded));
            }
            // else fall through

            Some((start, end))
        })
    }
}

fn parse_bound(s: &str) -> Option<Bound<u64>> {
    if s.is_empty() {
        return Some(Bound::Unbounded);
    }

    s.parse().ok().map(Bound::Included)
}

impl TypedHeader for Range {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::RANGE
    }
}

impl HeaderDecode for Range {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .next()
            .and_then(|val| {
                if val.to_str().ok()?.starts_with("bytes=") {
                    Some(Self(val.clone()))
                } else {
                    None
                }
            })
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for Range {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(self.0.clone()));
    }
}

/*

impl ByteRangeSpec {
    /// Given the full length of the entity, attempt to normalize the byte range
    /// into an satisfiable end-inclusive (from, to) range.
    ///
    /// The resulting range is guaranteed to be a satisfiable range within the bounds
    /// of `0 <= from <= to < full_length`.
    ///
    /// If the byte range is deemed unsatisfiable, `None` is returned.
    /// An unsatisfiable range is generally cause for a server to either reject
    /// the client request with a `416 Range Not Satisfiable` status code, or to
    /// simply ignore the range header and serve the full entity using a `200 OK`
    /// status code.
    ///
    /// This function closely follows [RFC 7233][1] section 2.1.
    /// As such, it considers ranges to be satisfiable if they meet the following
    /// conditions:
    ///
    /// > If a valid byte-range-set includes at least one byte-range-spec with
    /// a first-byte-pos that is less than the current length of the
    /// representation, or at least one suffix-byte-range-spec with a
    /// non-zero suffix-length, then the byte-range-set is satisfiable.
    /// Otherwise, the byte-range-set is unsatisfiable.
    ///
    /// The function also computes remainder ranges based on the RFC:
    ///
    /// > If the last-byte-pos value is
    /// absent, or if the value is greater than or equal to the current
    /// length of the representation data, the byte range is interpreted as
    /// the remainder of the representation (i.e., the server replaces the
    /// value of last-byte-pos with a value that is one less than the current
    /// length of the selected representation).
    ///
    /// [1]: https://tools.ietf.org/html/rfc7233
    pub fn to_satisfiable_range(&self, full_length: u64) -> Option<(u64, u64)> {
        // If the full length is zero, there is no satisfiable end-inclusive range.
        if full_length == 0 {
            return None;
        }
        match self {
            &ByteRangeSpec::FromTo(from, to) => {
                if from < full_length && from <= to {
                    Some((from, ::std::cmp::min(to, full_length - 1)))
                } else {
                    None
                }
            },
            &ByteRangeSpec::AllFrom(from) => {
                if from < full_length {
                    Some((from, full_length - 1))
                } else {
                    None
                }
            },
            &ByteRangeSpec::Last(last) => {
                if last > 0 {
                    // From the RFC: If the selected representation is shorter
                    // than the specified suffix-length,
                    // the entire representation is used.
                    if last > full_length {
                        Some((0, full_length - 1))
                    } else {
                        Some((full_length - last, full_length - 1))
                    }
                } else {
                    None
                }
            }
        }
    }
}

impl Range {
    /// Get the most common byte range header ("bytes=from-to")
    pub fn bytes(from: u64, to: u64) -> Range {
        Range::Bytes(vec![ByteRangeSpec::FromTo(from, to)])
    }

    /// Get byte range header with multiple subranges
    /// ("bytes=from1-to1,from2-to2,fromX-toX")
    pub fn bytes_multi(ranges: Vec<(u64, u64)>) -> Range {
        Range::Bytes(ranges.iter().map(|r| ByteRangeSpec::FromTo(r.0, r.1)).collect())
    }
}


impl fmt::Display for ByteRangeSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ByteRangeSpec::FromTo(from, to) => write!(f, "{}-{}", from, to),
            ByteRangeSpec::Last(pos) => write!(f, "-{}", pos),
            ByteRangeSpec::AllFrom(pos) => write!(f, "{}-", pos),
        }
    }
}


impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Range::Bytes(ref ranges) => {
                try!(write!(f, "bytes="));

                for (i, range) in ranges.iter().enumerate() {
                    if i != 0 {
                        try!(f.write_str(","));
                    }
                    try!(Display::fmt(range, f));
                }
                Ok(())
            },
            Range::Unregistered(ref unit, ref range_str) => {
                write!(f, "{}={}", unit, range_str)
            },
        }
    }
}

impl FromStr for Range {
    type Err = ::Error;

    fn from_str(s: &str) -> ::Result<Range> {
        let mut iter = s.splitn(2, '=');

        match (iter.next(), iter.next()) {
            (Some("bytes"), Some(ranges)) => {
                let ranges = from_comma_delimited(ranges);
                if ranges.is_empty() {
                    return Err(::Error::Header);
                }
                Ok(Range::Bytes(ranges))
            }
            (Some(unit), Some(range_str)) if unit != "" && range_str != "" => {
                Ok(Range::Unregistered(unit.to_owned(), range_str.to_owned()))

            },
            _ => Err(::Error::Header)
        }
    }
}

impl FromStr for ByteRangeSpec {
    type Err = ::Error;

    fn from_str(s: &str) -> ::Result<ByteRangeSpec> {
        let mut parts = s.splitn(2, '-');

        match (parts.next(), parts.next()) {
            (Some(""), Some(end)) => {
                end.parse().or(Err(::Error::Header)).map(ByteRangeSpec::Last)
            },
            (Some(start), Some("")) => {
                start.parse().or(Err(::Error::Header)).map(ByteRangeSpec::AllFrom)
            },
            (Some(start), Some(end)) => {
                match (start.parse(), end.parse()) {
                    (Ok(start), Ok(end)) if start <= end => Ok(ByteRangeSpec::FromTo(start, end)),
                    _ => Err(::Error::Header)
                }
            },
            _ => Err(::Error::Header)
        }
    }
}

fn from_comma_delimited<T: FromStr>(s: &str) -> Vec<T> {
    s.split(',')
        .filter_map(|x| match x.trim() {
            "" => None,
            y => Some(y)
        })
        .filter_map(|x| x.parse().ok())
        .collect()
}

impl Header for Range {

    fn header_name() -> &'static str {
        static NAME: &'static str = "Range";
        NAME
    }

    fn parse_header(raw: &Raw) -> ::Result<Range> {
        from_one_raw_str(raw)
    }

    fn fmt_header(&self, f: &mut ::Formatter) -> fmt::Result {
        f.fmt_line(self)
    }

}

#[test]
fn test_parse_bytes_range_valid() {
    let r: Range = Header::parse_header(&"bytes=1-100".into()).unwrap();
    let r2: Range = Header::parse_header(&"bytes=1-100,-".into()).unwrap();
    let r3 =  Range::bytes(1, 100);
    assert_eq!(r, r2);
    assert_eq!(r2, r3);

    let r: Range = Header::parse_header(&"bytes=1-100,200-".into()).unwrap();
    let r2: Range = Header::parse_header(&"bytes= 1-100 , 101-xxx,  200- ".into()).unwrap();
    let r3 =  Range::Bytes(
        vec![ByteRangeSpec::FromTo(1, 100), ByteRangeSpec::AllFrom(200)]
    );
    assert_eq!(r, r2);
    assert_eq!(r2, r3);

    let r: Range = Header::parse_header(&"bytes=1-100,-100".into()).unwrap();
    let r2: Range = Header::parse_header(&"bytes=1-100, ,,-100".into()).unwrap();
    let r3 =  Range::Bytes(
        vec![ByteRangeSpec::FromTo(1, 100), ByteRangeSpec::Last(100)]
    );
    assert_eq!(r, r2);
    assert_eq!(r2, r3);

    let r: Range = Header::parse_header(&"custom=1-100,-100".into()).unwrap();
    let r2 =  Range::Unregistered("custom".to_owned(), "1-100,-100".to_owned());
    assert_eq!(r, r2);

}

#[test]
fn test_parse_unregistered_range_valid() {
    let r: Range = Header::parse_header(&"custom=1-100,-100".into()).unwrap();
    let r2 =  Range::Unregistered("custom".to_owned(), "1-100,-100".to_owned());
    assert_eq!(r, r2);

    let r: Range = Header::parse_header(&"custom=abcd".into()).unwrap();
    let r2 =  Range::Unregistered("custom".to_owned(), "abcd".to_owned());
    assert_eq!(r, r2);

    let r: Range = Header::parse_header(&"custom=xxx-yyy".into()).unwrap();
    let r2 =  Range::Unregistered("custom".to_owned(), "xxx-yyy".to_owned());
    assert_eq!(r, r2);
}

#[test]
fn test_parse_invalid() {
    let r: ::Result<Range> = Header::parse_header(&"bytes=1-a,-".into());
    assert_eq!(r.ok(), None);

    let r: ::Result<Range> = Header::parse_header(&"bytes=1-2-3".into());
    assert_eq!(r.ok(), None);

    let r: ::Result<Range> = Header::parse_header(&"abc".into());
    assert_eq!(r.ok(), None);

    let r: ::Result<Range> = Header::parse_header(&"bytes=1-100=".into());
    assert_eq!(r.ok(), None);

    let r: ::Result<Range> = Header::parse_header(&"bytes=".into());
    assert_eq!(r.ok(), None);

    let r: ::Result<Range> = Header::parse_header(&"custom=".into());
    assert_eq!(r.ok(), None);

    let r: ::Result<Range> = Header::parse_header(&"=1-100".into());
    assert_eq!(r.ok(), None);
}

#[test]
fn test_fmt() {
    use Headers;

    let mut headers = Headers::new();

    headers.set(
        Range::Bytes(
            vec![ByteRangeSpec::FromTo(0, 1000), ByteRangeSpec::AllFrom(2000)]
    ));
    assert_eq!(&headers.to_string(), "Range: bytes=0-1000,2000-\r\n");

    headers.clear();
    headers.set(Range::Bytes(vec![]));

    assert_eq!(&headers.to_string(), "Range: bytes=\r\n");

    headers.clear();
    headers.set(Range::Unregistered("custom".to_owned(), "1-xxx".to_owned()));

    assert_eq!(&headers.to_string(), "Range: custom=1-xxx\r\n");
}

#[test]
fn test_byte_range_spec_to_satisfiable_range() {
    assert_eq!(Some((0, 0)), ByteRangeSpec::FromTo(0, 0).to_satisfiable_range(3));
    assert_eq!(Some((1, 2)), ByteRangeSpec::FromTo(1, 2).to_satisfiable_range(3));
    assert_eq!(Some((1, 2)), ByteRangeSpec::FromTo(1, 5).to_satisfiable_range(3));
    assert_eq!(None, ByteRangeSpec::FromTo(3, 3).to_satisfiable_range(3));
    assert_eq!(None, ByteRangeSpec::FromTo(2, 1).to_satisfiable_range(3));
    assert_eq!(None, ByteRangeSpec::FromTo(0, 0).to_satisfiable_range(0));

    assert_eq!(Some((0, 2)), ByteRangeSpec::AllFrom(0).to_satisfiable_range(3));
    assert_eq!(Some((2, 2)), ByteRangeSpec::AllFrom(2).to_satisfiable_range(3));
    assert_eq!(None, ByteRangeSpec::AllFrom(3).to_satisfiable_range(3));
    assert_eq!(None, ByteRangeSpec::AllFrom(5).to_satisfiable_range(3));
    assert_eq!(None, ByteRangeSpec::AllFrom(0).to_satisfiable_range(0));

    assert_eq!(Some((1, 2)), ByteRangeSpec::Last(2).to_satisfiable_range(3));
    assert_eq!(Some((2, 2)), ByteRangeSpec::Last(1).to_satisfiable_range(3));
    assert_eq!(Some((0, 2)), ByteRangeSpec::Last(5).to_satisfiable_range(3));
    assert_eq!(None, ByteRangeSpec::Last(0).to_satisfiable_range(3));
    assert_eq!(None, ByteRangeSpec::Last(2).to_satisfiable_range(0));
}

bench_header!(bytes_multi, Range, { vec![b"bytes=1-1001,2001-3001,10001-".to_vec()]});
bench_header!(custom_unit, Range, { vec![b"other=0-100000".to_vec()]});
*/

#[test]
fn test_to_satisfiable_range_suffix() {
    let range = super::test_decode::<Range>(&["bytes=-100"]).unwrap();
    let bounds = range.satisfiable_ranges(350).next().unwrap();
    assert_eq!(bounds, (Bound::Included(250), Bound::Unbounded));
}

#[test]
fn test_to_unsatisfiable_range_suffix() {
    let range = super::test_decode::<Range>(&["bytes=-350"]).unwrap();
    let bounds = range.satisfiable_ranges(100).next();
    assert_eq!(bounds, None);
}
