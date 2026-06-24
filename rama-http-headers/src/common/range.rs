use std::fmt;
use std::ops::{Bound, RangeBounds};

use rama_core::telemetry::tracing;
use rama_http_types::{HeaderName, HeaderValue};

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader, util};

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
/// // A client asking for the last 500 bytes of a representation.
/// let range = Range::suffix(500);
///
/// // Resolve against a known content length into the inclusive
/// // `(first, last)` byte range to serve. `None` would mean `416`.
/// assert_eq!(range.first_satisfiable_range(2000), Some((1500, 1999)));
/// ```
//NOTE: only the `bytes` range unit is supported; other units are rejected on decode.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Range(HeaderValue);

rama_utils::macros::error::static_str_error! {
    #[doc = "range is not valid"]
    pub struct InvalidRange;
}

impl Range {
    /// Creates a `Range` header from bounds (e.g. `0..100`, `0..=99`, `100..`).
    ///
    /// A range open at the start does not map to a `bytes=` spec; use
    /// [`Range::suffix`] for the suffix (`bytes=-N`) form instead.
    pub fn bytes(bounds: impl RangeBounds<u64>) -> Result<Self, InvalidRange> {
        let v = match (bounds.start_bound(), bounds.end_bound()) {
            (Bound::Included(start), Bound::Included(end)) => format!("bytes={start}-{end}"),
            (Bound::Included(start), Bound::Excluded(&end)) => {
                // `start..end` excludes `end`; an empty range (e.g. `0..0`) has no last byte.
                let Some(last) = end.checked_sub(1) else {
                    return Err(InvalidRange);
                };
                format!("bytes={start}-{last}")
            }
            (Bound::Included(start), Bound::Unbounded) => format!("bytes={start}-"),
            // Anything open at the start is a suffix range, see `Range::suffix`.
            _ => return Err(InvalidRange),
        };

        match HeaderValue::try_from(v) {
            Ok(v) => Ok(Self(v)),
            Err(err) => {
                tracing::debug!("failed to create Range header from bytes: {err}");
                Err(InvalidRange)
            }
        }
    }

    /// Creates a suffix `Range` header (`bytes=-n`) requesting the final
    /// `n` bytes of the selected representation.
    #[must_use]
    pub fn suffix(n: u64) -> Self {
        Self(util::fmt(format_args!("bytes=-{n}")))
    }

    /// Iterate over the [`ByteRangeSpec`]s in this header.
    ///
    /// Syntactically invalid specs (and the empty entries that a stray comma
    /// produces) are silently skipped, matching how servers tolerate them.
    pub fn iter(&self) -> impl Iterator<Item = ByteRangeSpec> + '_ {
        self.range_set().split(',').filter_map(parse_spec)
    }

    /// Resolve every satisfiable range against a known `content_length`.
    ///
    /// Each yielded `(first, last)` is inclusive and clamped to the
    /// representation; unsatisfiable specs are dropped. See
    /// [`ByteRangeSpec::to_satisfiable_range`].
    pub fn satisfiable_ranges(&self, content_length: u64) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.iter()
            .filter_map(move |spec| spec.to_satisfiable_range(content_length))
    }

    /// Resolve the first satisfiable range against a known `content_length`.
    ///
    /// This is the common case for single-range byte serving: it returns the
    /// inclusive `(first, last)` to serve, or `None` (⇒ `416 Range Not
    /// Satisfiable`) when no spec in the header can be satisfied.
    #[must_use]
    pub fn first_satisfiable_range(&self, content_length: u64) -> Option<(u64, u64)> {
        self.iter()
            .find_map(|spec| spec.to_satisfiable_range(content_length))
    }

    /// The `byte-range-set`, i.e. everything after the `bytes=` unit prefix.
    fn range_set(&self) -> &str {
        #[expect(
            clippy::expect_used,
            reason = "value is validated as a UTF-8 `bytes=…` string in HeaderDecode::decode"
        )]
        let s = self
            .0
            .to_str()
            .expect("valid string checked in HeaderDecode::decode()");
        s.strip_prefix("bytes=").unwrap_or("")
    }
}

/// A single entry of a [`Range`] header's `byte-range-set`, as defined in
/// [RFC7233 §2.1](https://tools.ietf.org/html/rfc7233#section-2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ByteRangeSpec {
    /// `first-last`: an inclusive range from `first` to `last`.
    FromTo(u64, u64),
    /// `first-`: from `first` to the end of the representation.
    AllFrom(u64),
    /// `-suffix`: the final `suffix` bytes of the representation.
    Last(u64),
}

impl ByteRangeSpec {
    /// Resolve this spec against a known `content_length` into an inclusive
    /// `(first, last)` byte range, following [RFC7233 §2.1][rfc].
    ///
    /// The end is clamped to `content_length - 1`, a suffix (`-n`) range is
    /// anchored to the end of the representation (a suffix at least as long as
    /// the representation yields the whole of it), and `None` is returned when
    /// the range is unsatisfiable — the cue for a `416 Range Not Satisfiable`
    /// response. A returned range always satisfies `0 <= first <= last < content_length`.
    ///
    /// [rfc]: https://tools.ietf.org/html/rfc7233#section-2.1
    #[must_use]
    pub fn to_satisfiable_range(&self, content_length: u64) -> Option<(u64, u64)> {
        if content_length == 0 {
            // An empty representation has no satisfiable range.
            return None;
        }
        let last = content_length - 1;
        match *self {
            Self::FromTo(first, to) if first <= to && first < content_length => {
                Some((first, to.min(last)))
            }
            Self::AllFrom(first) if first < content_length => Some((first, last)),
            Self::Last(suffix) if suffix > 0 => Some((content_length.saturating_sub(suffix), last)),
            _ => None,
        }
    }
}

impl fmt::Display for ByteRangeSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::FromTo(first, last) => write!(f, "{first}-{last}"),
            Self::AllFrom(first) => write!(f, "{first}-"),
            Self::Last(suffix) => write!(f, "-{suffix}"),
        }
    }
}

fn parse_spec(spec: &str) -> Option<ByteRangeSpec> {
    let (first, last) = spec.trim().split_once('-')?;
    match (first, last) {
        // A bare `-` carries no suffix length and is meaningless.
        ("", "") => None,
        ("", suffix) => Some(ByteRangeSpec::Last(suffix.parse().ok()?)),
        (first, "") => Some(ByteRangeSpec::AllFrom(first.parse().ok()?)),
        (first, last) => {
            let first = first.parse().ok()?;
            let last = last.parse().ok()?;
            (first <= last).then_some(ByteRangeSpec::FromTo(first, last))
        }
    }
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

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;

    fn range(s: &str) -> Range {
        test_decode(&[s]).unwrap()
    }

    fn specs(s: &str) -> Vec<ByteRangeSpec> {
        range(s).iter().collect()
    }

    #[test]
    fn decode_rejects_non_bytes_unit() {
        assert!(test_decode::<Range>(&["seconds=1-2"]).is_none());
        assert!(test_decode::<Range>(&["1-2"]).is_none());
        assert!(test_decode::<Range>(&["bytes"]).is_none());
    }

    #[test]
    fn iter_parses_specs() {
        assert_eq!(specs("bytes=1-100"), [ByteRangeSpec::FromTo(1, 100)]);
        assert_eq!(
            specs("bytes=1-100,200-"),
            [ByteRangeSpec::FromTo(1, 100), ByteRangeSpec::AllFrom(200)],
        );
        assert_eq!(
            specs("bytes=0-10,20-90,-100"),
            [
                ByteRangeSpec::FromTo(0, 10),
                ByteRangeSpec::FromTo(20, 90),
                ByteRangeSpec::Last(100),
            ],
        );
    }

    #[test]
    fn iter_trims_and_skips_invalid() {
        // surrounding whitespace is tolerated; empty/malformed specs are skipped.
        assert_eq!(
            specs("bytes= 1-100 , 101-xxx ,  200- , ,, -100 , 5-2"),
            [
                ByteRangeSpec::FromTo(1, 100),
                ByteRangeSpec::AllFrom(200),
                ByteRangeSpec::Last(100),
            ],
        );
        assert!(specs("bytes=1-2-3").is_empty());
        assert!(specs("bytes=").is_empty());
        assert!(specs("bytes=-").is_empty());
    }

    #[test]
    fn spec_from_to_resolution() {
        use ByteRangeSpec::FromTo;
        assert_eq!(FromTo(0, 0).to_satisfiable_range(3), Some((0, 0)));
        assert_eq!(FromTo(1, 2).to_satisfiable_range(3), Some((1, 2)));
        assert_eq!(FromTo(1, 5).to_satisfiable_range(3), Some((1, 2))); // clamped
        assert_eq!(FromTo(3, 3).to_satisfiable_range(3), None); // first == len
        assert_eq!(FromTo(2, 1).to_satisfiable_range(3), None); // first > last
        assert_eq!(FromTo(0, 0).to_satisfiable_range(0), None); // empty repr
    }

    #[test]
    fn spec_all_from_resolution() {
        use ByteRangeSpec::AllFrom;
        assert_eq!(AllFrom(0).to_satisfiable_range(3), Some((0, 2)));
        assert_eq!(AllFrom(2).to_satisfiable_range(3), Some((2, 2)));
        assert_eq!(AllFrom(3).to_satisfiable_range(3), None);
        assert_eq!(AllFrom(5).to_satisfiable_range(3), None);
        assert_eq!(AllFrom(0).to_satisfiable_range(0), None);
    }

    #[test]
    fn spec_last_resolution() {
        use ByteRangeSpec::Last;
        assert_eq!(Last(2).to_satisfiable_range(3), Some((1, 2)));
        assert_eq!(Last(1).to_satisfiable_range(3), Some((2, 2)));
        // a suffix at least as long as the representation yields the whole of it.
        assert_eq!(Last(3).to_satisfiable_range(3), Some((0, 2)));
        assert_eq!(Last(5).to_satisfiable_range(3), Some((0, 2)));
        assert_eq!(Last(0).to_satisfiable_range(3), None);
        assert_eq!(Last(2).to_satisfiable_range(0), None);
    }

    #[test]
    fn first_satisfiable_range_suffix() {
        assert_eq!(
            range("bytes=-100").first_satisfiable_range(350),
            Some((250, 349)),
        );
        // suffix longer than the representation → the whole representation (RFC 7233 §2.1).
        assert_eq!(
            range("bytes=-350").first_satisfiable_range(100),
            Some((0, 99)),
        );
    }

    #[test]
    fn first_satisfiable_range_skips_unsatisfiable() {
        // the first spec is out of range, so the next satisfiable one is used.
        assert_eq!(
            range("bytes=500-600,0-1").first_satisfiable_range(100),
            Some((0, 1)),
        );
        // every spec is out of range → 416.
        assert_eq!(range("bytes=500-,600-").first_satisfiable_range(100), None);
    }

    #[test]
    fn satisfiable_ranges_resolves_and_clamps() {
        let resolved: Vec<_> = range("bytes=0-1,30-40,500-600,-5")
            .satisfiable_ranges(100)
            .collect();
        // 500-600 dropped (unsatisfiable); -5 → last 5 bytes; others kept.
        assert_eq!(resolved, [(0, 1), (30, 40), (95, 99)]);
    }

    #[test]
    fn bytes_constructor_encodes() {
        assert_eq!(
            test_encode(Range::bytes(0..1234).unwrap())["range"],
            "bytes=0-1233"
        );
        assert_eq!(
            test_encode(Range::bytes(0..=99).unwrap())["range"],
            "bytes=0-99"
        );
        assert_eq!(
            test_encode(Range::bytes(100..).unwrap())["range"],
            "bytes=100-"
        );
    }

    #[test]
    fn bytes_constructor_rejects_unrepresentable() {
        Range::bytes(..).unwrap_err(); // open start
        Range::bytes(..100).unwrap_err(); // open start
        Range::bytes(0..0).unwrap_err(); // empty (would underflow last)
    }

    #[test]
    fn suffix_constructor() {
        assert_eq!(test_encode(Range::suffix(500))["range"], "bytes=-500");
        assert_eq!(
            Range::suffix(500).first_satisfiable_range(2000),
            Some((1500, 1999))
        );
    }

    #[test]
    fn spec_display_roundtrips_through_iter() {
        let rendered: Vec<String> = range("bytes=0-10,20-,-100")
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(rendered, ["0-10", "20-", "-100"]);
    }
}
