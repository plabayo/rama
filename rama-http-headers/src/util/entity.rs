use std::{fmt, iter, str::FromStr};

use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext as _};
use rama_core::telemetry::tracing;
use rama_http_types::HeaderValue;
use rama_utils::collections::NonEmptyVec;

use super::IterExt;
use crate::{
    Error,
    util::{
        FlatCsvSeparator, try_decode_flat_csv_header_values_as_non_empty_vec,
        try_encode_non_empty_vec_of_bytes_as_flat_csv_header_value,
    },
};

/// An entity tag, defined in [RFC7232](https://tools.ietf.org/html/rfc7232#section-2.3)
///
/// An entity tag consists of a string enclosed by two literal double quotes.
/// Preceding the first double quote is an optional weakness indicator,
/// which always looks like `W/`. Examples for valid tags are `"xyzzy"` and `W/"xyzzy"`.
///
/// # ABNF
///
/// ```text
/// entity-tag = [ weak ] opaque-tag
/// weak       = %x57.2F ; "W/", case-sensitive
/// opaque-tag = DQUOTE *etagc DQUOTE
/// etagc      = %x21 / %x23-7E / obs-text
///            ; VCHAR except double quotes, plus obs-text
/// ```
///
/// # Comparison
/// To check if two entity tags are equivalent in an application always use the `strong_eq` or
/// `weak_eq` methods based on the context of the Tag. Only use `==` to check if two tags are
/// identical.
///
/// The example below shows the results for a set of entity-tag pairs and
/// both the weak and strong comparison function results:
///
/// | ETag 1  | ETag 2  | Strong Comparison | Weak Comparison |
/// |---------|---------|-------------------|-----------------|
/// | `W/"1"` | `W/"1"` | no match          | match           |
/// | `W/"1"` | `W/"2"` | no match          | no match        |
/// | `W/"1"` | `"1"`   | no match          | match           |
/// | `"1"`   | `"1"`   | match             | match           |
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct EntityTag<T = HeaderValue>(T);

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EntityTagRange {
    Any,
    Tags(NonEmptyVec<EntityTag>),
}

// ===== impl EntityTag =====

impl<T: AsRef<[u8]>> EntityTag<T> {
    /// Get the opaque tag, `None` if the value is not a well-formed entity-tag.
    pub(crate) fn tag(&self) -> Option<&[u8]> {
        split_entity_tag(self.0.as_ref()).map(|(_, tag)| tag)
    }

    /// Return if this is a "weak" tag.
    pub(crate) fn is_weak(&self) -> bool {
        matches!(split_entity_tag(self.0.as_ref()), Some((true, _)))
    }

    /// For strong comparison two entity-tags are equivalent if both are not weak and their
    /// opaque-tags match character-by-character.
    pub(crate) fn strong_eq<R>(&self, other: &EntityTag<R>) -> bool
    where
        R: AsRef<[u8]>,
    {
        matches!(
            (split_entity_tag(self.0.as_ref()), split_entity_tag(other.0.as_ref())),
            (Some((false, a)), Some((false, b))) if a == b
        )
    }

    /// For weak comparison two entity-tags are equivalent if their
    /// opaque-tags match character-by-character, regardless of either or
    /// both being tagged as "weak".
    pub(crate) fn weak_eq<R>(&self, other: &EntityTag<R>) -> bool
    where
        R: AsRef<[u8]>,
    {
        matches!((self.tag(), other.tag()), (Some(a), Some(b)) if a == b)
    }

    /// The inverse of `EntityTag.strong_eq()`.
    #[cfg(test)]
    pub(crate) fn strong_ne(&self, other: &EntityTag) -> bool {
        !self.strong_eq(other)
    }

    /// The inverse of `EntityTag.weak_eq()`.
    #[cfg(test)]
    pub(crate) fn weak_ne(&self, other: &EntityTag) -> bool {
        !self.weak_eq(other)
    }

    pub(crate) fn parse(src: T) -> Option<Self> {
        split_entity_tag(src.as_ref())?;
        Some(Self(src))
    }
}

/// Split a valid `[W/]"<tag>"` into its weakness flag and opaque tag.
fn split_entity_tag(bytes: &[u8]) -> Option<(bool, &[u8])> {
    let (weak, opaque) = match bytes.strip_prefix(b"W/") {
        Some(opaque) => (true, opaque),
        None => (false, bytes),
    };
    let tag = opaque.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    check_slice_validity(tag).then_some((weak, tag))
}

impl EntityTag {
    /*
    /// Constructs a new EntityTag.
    /// # Panics
    /// If the tag contains invalid characters.
    pub fn new(weak: bool, tag: String) -> EntityTag {
        assert!(check_slice_validity(&tag), "Invalid tag: {:?}", tag);
        EntityTag { weak: weak, tag: tag }
    }

    /// Constructs a new weak EntityTag.
    /// # Panics
    /// If the tag contains invalid characters.
    pub fn weak(tag: String) -> EntityTag {
        EntityTag::new(true, tag)
    }

    /// Constructs a new strong EntityTag.
    /// # Panics
    /// If the tag contains invalid characters.
    pub fn strong(tag: String) -> EntityTag {
        EntityTag::new(false, tag)
    }
    */

    #[cfg(test)]
    pub(crate) fn from_static(bytes: &'static str) -> Self {
        let val = HeaderValue::from_static(bytes);
        match Self::from_val(&val) {
            Some(tag) => tag,
            None => {
                panic!("invalid static string for EntityTag: {bytes:?}");
            }
        }
    }

    pub(crate) fn from_owned(val: HeaderValue) -> Option<Self> {
        EntityTag::parse(val.as_bytes())?;
        Some(Self(val))
    }

    pub(crate) fn from_val(val: &HeaderValue) -> Option<Self> {
        EntityTag::parse(val.as_bytes()).map(|_entity| Self(val.clone()))
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for EntityTag<T> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: fmt::Debug> fmt::Debug for EntityTag<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl super::TryFromValues for EntityTag {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        values
            .just_one()
            .and_then(Self::from_val)
            .ok_or_else(Error::invalid)
    }
}

impl FromStr for EntityTag {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let val = HeaderValue::from_str(s).context("entity-tag is not a valid header value")?;
        Self::from_owned(val).ok_or_else(|| BoxError::from_static_str("invalid entity-tag"))
    }
}

impl From<EntityTag> for HeaderValue {
    fn from(tag: EntityTag) -> Self {
        tag.0
    }
}

impl<'a> From<&'a EntityTag> for HeaderValue {
    fn from(tag: &'a EntityTag) -> Self {
        tag.0.clone()
    }
}

/// check that each char in the slice is either:
/// 1. `%x21`, or
/// 2. in the range `%x23` to `%x7E`, or
/// 3. above `%x80`
fn check_slice_validity(slice: &[u8]) -> bool {
    // HeaderValue also admits SP and HTAB, which are not `etagc`.
    slice
        .iter()
        .all(|&c| matches!(c, 0x21 | 0x23..=0x7e | 0x80..=0xff))
}

// ===== impl EntityTagRange =====

impl EntityTagRange {
    pub(crate) fn matches_strong(&self, entity: &EntityTag) -> bool {
        self.matches_if(entity, |a, b| a.strong_eq(b))
    }

    pub(crate) fn matches_weak(&self, entity: &EntityTag) -> bool {
        self.matches_if(entity, |a, b| a.weak_eq(b))
    }

    fn matches_if<F>(&self, entity: &EntityTag, func: F) -> bool
    where
        F: Fn(&EntityTag, &EntityTag) -> bool,
    {
        match *self {
            Self::Any => true,
            Self::Tags(ref tags) => tags.iter().any(|tag| func(tag, entity)),
        }
    }
}

impl super::TryFromValues for EntityTagRange {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        let first = values.next().ok_or_else(Error::invalid)?;
        let second = values.next();
        // `*` is not an entity-tag: it is only valid as the sole member.
        if second.is_none() && first.as_bytes().trim_ascii() == b"*" {
            return Ok(Self::Any);
        }

        match try_decode_flat_csv_header_values_as_non_empty_vec::<EntityTag>(
            iter::once(first).chain(second).chain(values),
            FlatCsvSeparator::Comma,
        ) {
            Ok(tags) => Ok(Self::Tags(tags)),
            Err(err) => {
                tracing::trace!("invalid entity tags: {err}");
                Err(crate::Error::invalid())
            }
        }
    }
}

impl TryFrom<&EntityTagRange> for HeaderValue {
    type Error = BoxError;

    fn try_from(tag: &EntityTagRange) -> Result<Self, Self::Error> {
        match tag {
            EntityTagRange::Any => Ok(Self::from_static("*")),
            EntityTagRange::Tags(tags) => {
                try_encode_non_empty_vec_of_bytes_as_flat_csv_header_value(
                    tags,
                    FlatCsvSeparator::Comma,
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{TryFromValues as _, for_each_small_input};

    fn parse(slice: &[u8]) -> Option<EntityTag> {
        let val = HeaderValue::from_bytes(slice).ok()?;
        EntityTag::from_val(&val)
    }

    #[test]
    fn test_etag_parse_success() {
        // Expected success
        let tag = parse(b"\"foobar\"").unwrap();
        assert!(!tag.is_weak());
        assert_eq!(tag.tag(), Some(b"foobar".as_slice()));

        let weak = parse(b"W/\"weaktag\"").unwrap();
        assert!(weak.is_weak());
        assert_eq!(weak.tag(), Some(b"weaktag".as_slice()));

        let obs_text = parse(b"\"\x80\xff\"").unwrap();
        assert_eq!(obs_text.tag(), Some(b"\x80\xff".as_slice()));
    }

    #[test]
    fn test_etag_parse_failures() {
        // Expected failures
        macro_rules! fails {
            ($slice:expr) => {
                assert_eq!(parse($slice), None);
            };
        }

        fails!(b"no-dquote");
        fails!(b"w/\"the-first-w-is-case sensitive\"");
        fails!(b"W/\"");
        fails!(b"");
        fails!(b"\"unmatched-dquotes1");
        fails!(b"unmatched-dquotes2\"");
        fails!(b"\"inner\"quotes\"");
    }

    /*
    #[test]
    fn test_etag_fmt() {
        assert_eq!(format!("{}", EntityTag::strong("foobar".to_owned())), "\"foobar\"");
        assert_eq!(format!("{}", EntityTag::strong("".to_owned())), "\"\"");
        assert_eq!(format!("{}", EntityTag::weak("weak-etag".to_owned())), "W/\"weak-etag\"");
        assert_eq!(format!("{}", EntityTag::weak("\u{0065}".to_owned())), "W/\"\x65\"");
        assert_eq!(format!("{}", EntityTag::weak("".to_owned())), "W/\"\"");
    }
    */

    #[test]
    fn test_cmp() {
        // | ETag 1  | ETag 2  | Strong Comparison | Weak Comparison |
        // |---------|---------|-------------------|-----------------|
        // | `W/"1"` | `W/"1"` | no match          | match           |
        // | `W/"1"` | `W/"2"` | no match          | no match        |
        // | `W/"1"` | `"1"`   | no match          | match           |
        // | `"1"`   | `"1"`   | match             | match           |
        let mut etag1 = EntityTag::from_static("W/\"1\"");
        let mut etag2 = etag1.clone();
        assert!(!etag1.strong_eq(&etag2));
        assert!(etag1.weak_eq(&etag2));
        assert!(etag1.strong_ne(&etag2));
        assert!(!etag1.weak_ne(&etag2));

        etag2 = EntityTag::from_static("W/\"2\"");
        assert!(!etag1.strong_eq(&etag2));
        assert!(!etag1.weak_eq(&etag2));
        assert!(etag1.strong_ne(&etag2));
        assert!(etag1.weak_ne(&etag2));

        etag2 = EntityTag::from_static("\"1\"");
        assert!(!etag1.strong_eq(&etag2));
        assert!(etag1.weak_eq(&etag2));
        assert!(etag1.strong_ne(&etag2));
        assert!(!etag1.weak_ne(&etag2));

        etag1 = EntityTag::from_static("\"1\"");
        assert!(etag1.strong_eq(&etag2));
        assert!(etag1.weak_eq(&etag2));
        assert!(!etag1.strong_ne(&etag2));
        assert!(!etag1.weak_ne(&etag2));
    }

    const MALFORMED: &[&str] = &[
        "",
        "x",
        "W",
        "W/",
        "W/\"",
        "\"",
        "*",
        "\"a b\"",
        "\"a\tb\"",
        "W/\"a b\"",
        "w/\"a\"",
        "\"a\"b\"",
        "\"a\" ",
    ];

    #[test]
    fn test_etag_parse_rejects_malformed_without_panic() {
        for input in MALFORMED {
            assert_eq!(parse(input.as_bytes()), None, "input: {input:?}");
        }
    }

    #[test]
    fn test_etag_from_str_validates() {
        let valid = EntityTag::from_static("W/\"1\"");
        for input in MALFORMED {
            let result = input.parse::<EntityTag>();
            if let Ok(tag) = &result {
                _ = tag.tag();
                _ = tag.is_weak();
                _ = tag.strong_eq(&valid);
                _ = tag.weak_eq(&valid);
            }
            assert!(result.is_err(), "input: {input:?}");
        }

        let tag = "W/\"a,b\"".parse::<EntityTag>().unwrap();
        assert!(tag.is_weak());
        assert_eq!(tag.tag(), Some(b"a,b".as_slice()));
        let tag = "\"\"".parse::<EntityTag>().unwrap();
        assert!(!tag.is_weak());
        assert_eq!(tag.tag(), Some(b"".as_slice()));
    }

    #[test]
    fn test_etag_accessors_are_total() {
        let valid = EntityTag::from_static("\"\"");
        for input in MALFORMED {
            let tag = EntityTag(HeaderValue::from_str(input).unwrap());
            assert_eq!(tag.tag(), None, "input: {input:?}");
            assert!(!tag.is_weak(), "input: {input:?}");
            assert!(!tag.weak_eq(&valid), "input: {input:?}");
            assert!(!valid.weak_eq(&tag), "input: {input:?}");
            assert!(!tag.weak_eq(&tag), "input: {input:?}");
            assert!(!tag.strong_eq(&tag), "input: {input:?}");
        }
    }

    fn decode_range(values: &[&str]) -> Result<EntityTagRange, Error> {
        let values: Vec<_> = values
            .iter()
            .map(|v| HeaderValue::from_str(v).unwrap())
            .collect();
        EntityTagRange::try_from_values(&mut values.iter())
    }

    #[test]
    fn test_etag_range_rejects_malformed_without_panic() {
        let valid = EntityTag::from_static("\"a\"");
        for values in [
            &["x"][..],
            &[""],
            &["W"],
            &["W/"],
            &["W/\""],
            &["\""],
            &["*, \"a\""],
            &["\"a\", *"],
            &["*", "\"a\""],
            &["*", "*"],
            &["\"a b\""],
            &["\"a\", x"],
            &["\"a\", \"b"],
        ] {
            let result = decode_range(values);
            if let Ok(range) = &result {
                _ = range.matches_strong(&valid);
                _ = range.matches_weak(&valid);
            }
            assert!(result.is_err(), "values: {values:?}");
        }
    }

    #[test]
    fn test_etag_small_inputs_never_panic() {
        let valid = EntityTag::from_static("W/\"a\"");
        for_each_small_input(b"\"W/, \t*a\x80", 6, |input| {
            let Ok(val) = HeaderValue::from_bytes(input) else {
                return;
            };
            if let Some(tag) = EntityTag::from_val(&val) {
                assert!(tag.tag().is_some(), "input: {input:?}");
                _ = tag.strong_eq(&valid);
            }
            if let Ok(tag) = val.to_str().unwrap_or_default().parse::<EntityTag>() {
                assert!(tag.tag().is_some(), "input: {input:?}");
            }
            if let Ok(range) = EntityTagRange::try_from_values(&mut iter::once(&val)) {
                if let EntityTagRange::Tags(tags) = &range {
                    assert!(tags.iter().all(|tag| tag.tag().is_some()), "{input:?}");
                }
                _ = range.matches_strong(&valid);
                _ = range.matches_weak(&valid);
                _ = HeaderValue::try_from(&range);
            }
        });
    }

    #[test]
    fn test_etag_range_decodes_any_and_lists() {
        assert_eq!(decode_range(&["*"]).unwrap(), EntityTagRange::Any);
        assert_eq!(decode_range(&[" * "]).unwrap(), EntityTagRange::Any);

        let range = decode_range(&["\"a\", W/\"b,c\"", "\"d\""]).unwrap();
        let EntityTagRange::Tags(tags) = &range else {
            panic!("expected tags, got {range:?}");
        };
        assert_eq!(tags.len(), 3);
        assert!(range.matches_strong(&EntityTag::from_static("\"a\"")));
        assert!(!range.matches_strong(&EntityTag::from_static("\"b,c\"")));
        assert!(range.matches_weak(&EntityTag::from_static("\"b,c\"")));
        assert!(range.matches_weak(&EntityTag::from_static("W/\"d\"")));
        assert!(!range.matches_weak(&EntityTag::from_static("\"e\"")));
    }
}
