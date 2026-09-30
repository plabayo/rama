use std::fmt;
use std::iter::FromIterator;
use std::str::FromStr;
use std::time::Duration;

use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::{HeaderName, HeaderValue};

use crate::util::{self, Seconds, csv, parse_delta_seconds};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Cache-Control` header, defined in [RFC7234](https://tools.ietf.org/html/rfc7234#section-5.2)
/// with extensions in [RFC8246](https://www.rfc-editor.org/rfc/rfc8246)
///
/// The `Cache-Control` header field is used to specify directives for
/// caches along the request/response chain.  Such cache directives are
/// unidirectional in that the presence of a directive in a request does
/// not imply that the same directive is to be given in the response.
///
/// ## ABNF
///
/// ```text
/// Cache-Control   = 1#cache-directive
/// cache-directive = token [ "=" ( token / quoted-string ) ]
/// ```
///
/// ## Example values
///
/// * `no-cache`
/// * `private, community="UCI"`
/// * `max-age=30`
///
/// # Example
///
/// ```
/// use rama_http_headers::CacheControl;
///
/// let cc = CacheControl::new();
/// ```
#[derive(PartialEq, Clone, Debug)]
pub struct CacheControl {
    flags: Flags,
    max_age: Option<Seconds>,
    max_stale: Option<Seconds>,
    min_fresh: Option<Seconds>,
    s_max_age: Option<Seconds>,
}

#[derive(Debug, Clone, PartialEq)]
struct Flags {
    bits: u64,
}

impl Flags {
    const NO_CACHE: Self = Self { bits: 0b000000001 };
    const NO_STORE: Self = Self { bits: 0b000000010 };
    const NO_TRANSFORM: Self = Self { bits: 0b000000100 };
    const ONLY_IF_CACHED: Self = Self { bits: 0b000001000 };
    const MUST_REVALIDATE: Self = Self { bits: 0b000010000 };
    const PUBLIC: Self = Self { bits: 0b000100000 };
    const PRIVATE: Self = Self { bits: 0b001000000 };
    const PROXY_REVALIDATE: Self = Self { bits: 0b010000000 };
    const IMMUTABLE: Self = Self { bits: 0b100000000 };
    const MUST_UNDERSTAND: Self = Self { bits: 0b1000000000 };

    fn empty() -> Self {
        Self { bits: 0 }
    }

    #[expect(clippy::needless_pass_by_value)]
    fn contains(&self, flag: Self) -> bool {
        (self.bits & flag.bits) != 0
    }

    #[expect(clippy::needless_pass_by_value)]
    fn insert(&mut self, flag: Self) {
        self.bits |= flag.bits;
    }
}

impl Default for CacheControl {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl CacheControl {
    /// Construct a new empty `CacheControl` header.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flags: Flags::empty(),
            max_age: None,
            max_stale: None,
            min_fresh: None,
            s_max_age: None,
        }
    }

    // presets

    /// `public, immutable, max-age=31536000` — for content-hashed /
    /// versioned URLs (e.g. `/theme.css?v=<git-sha>`).
    ///
    /// The URL changes whenever the content changes, so the cached response
    /// is safe to keep for a year; `immutable` additionally stops the browser
    /// from revalidating on reload. Reach for this only on content-hashed
    /// URLs — on a stable URL whose body can change in place, use
    /// [`Self::no_cache`] or [`Self::short_shared_revalidate`] instead.
    #[must_use]
    pub fn immutable_one_year() -> Self {
        Self::new()
            .with_public()
            .with_immutable()
            .with_max_age_seconds(31_536_000)
    }

    /// `no-cache` — the response is cacheable but must be revalidated with
    /// the origin before reuse.
    ///
    /// The right default for service-worker scripts, HTML, or anything whose
    /// URL is stable but whose body may change in place.
    #[must_use]
    pub fn no_cache() -> Self {
        Self::new().with_no_cache()
    }

    /// `public, max-age=<secs>, must-revalidate` — a short shared cache for
    /// non-fingerprinted but rarely-changing files (`robots.txt`,
    /// `sitemap.xml`, `security.txt`).
    ///
    /// Lets a CDN absorb crawler bursts without making content updates
    /// invisible for long.
    #[must_use]
    pub fn short_shared_revalidate(max_age_seconds: u32) -> Self {
        Self::new()
            .with_public()
            .with_max_age_seconds(u64::from(max_age_seconds))
            .with_must_revalidate()
    }

    // getters

    /// Check if the `no-cache` directive is set.
    #[must_use]
    pub fn has_no_cache(self) -> bool {
        self.flags.contains(Flags::NO_CACHE)
    }

    /// Check if the `no-store` directive is set.
    #[must_use]
    pub fn has_no_store(self) -> bool {
        self.flags.contains(Flags::NO_STORE)
    }

    /// Check if the `no-transform` directive is set.
    #[must_use]
    pub fn has_no_transform(self) -> bool {
        self.flags.contains(Flags::NO_TRANSFORM)
    }

    /// Check if the `only-if-cached` directive is set.
    #[must_use]
    pub fn has_only_if_cached(self) -> bool {
        self.flags.contains(Flags::ONLY_IF_CACHED)
    }

    /// Check if the `public` directive is set.
    #[must_use]
    pub fn has_public(self) -> bool {
        self.flags.contains(Flags::PUBLIC)
    }

    /// Check if the `private` directive is set.
    #[must_use]
    pub fn has_private(self) -> bool {
        self.flags.contains(Flags::PRIVATE)
    }

    /// Check if the `immutable` directive is set.
    #[must_use]
    pub fn has_immutable(self) -> bool {
        self.flags.contains(Flags::IMMUTABLE)
    }

    /// Check if the `must-revalidate` directive is set.
    #[must_use]
    pub fn has_must_revalidate(&self) -> bool {
        self.flags.contains(Flags::MUST_REVALIDATE)
    }

    /// Check if the `must-understand` directive is set.
    #[must_use]
    pub fn has_must_understand(self) -> bool {
        self.flags.contains(Flags::MUST_UNDERSTAND)
    }

    /// Get the value of the `max-age` directive if set.
    pub fn max_age(&self) -> Option<Duration> {
        self.max_age.map(Into::into)
    }

    /// Get the value of the `max-stale` directive if set.
    pub fn max_stale(&self) -> Option<Duration> {
        self.max_stale.map(Into::into)
    }

    /// Get the value of the `min-fresh` directive if set.
    pub fn min_fresh(&self) -> Option<Duration> {
        self.min_fresh.map(Into::into)
    }

    /// Get the value of the `s-maxage` directive if set.
    pub fn s_max_age(&self) -> Option<Duration> {
        self.s_max_age.map(Into::into)
    }

    // setters

    rama_utils::macros::generate_set_and_with! {
        /// Set the `no-cache` directive.
        pub fn no_cache(mut self) -> Self {
            self.flags.insert(Flags::NO_CACHE);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `no-store` directive.
        pub fn no_store(mut self) -> Self {
            self.flags.insert(Flags::NO_STORE);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `no-transform` directive.
        pub fn no_transform(mut self) -> Self {
            self.flags.insert(Flags::NO_TRANSFORM);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `only-if-cached` directive.
        pub fn only_if_cached(mut self) -> Self {
            self.flags.insert(Flags::ONLY_IF_CACHED);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `private` directive.
        pub fn private(mut self) -> Self {
            self.flags.insert(Flags::PRIVATE);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `public` directive.
        pub fn public(mut self) -> Self {
            self.flags.insert(Flags::PUBLIC);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `immutable` directive.
        pub fn immutable(mut self) -> Self {
            self.flags.insert(Flags::IMMUTABLE);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `must-revalidate` directive.
        pub fn must_revalidate(mut self) -> Self {
            self.flags.insert(Flags::MUST_REVALIDATE);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `must-understand` directive.
        pub fn must_understand(mut self) -> Self {
            self.flags.insert(Flags::MUST_UNDERSTAND);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `max-age` directive.
        pub fn max_age_duration_rounded(mut self, dur: Duration) -> Self {
            self.max_age = Some(Seconds::from_duration_rounded(dur));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `max-age` directive.
        pub fn max_age_seconds(mut self, seconds: u64) -> Self {
            self.max_age = Some(Seconds::new(seconds));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Try to set the `max-age` directive.
        pub fn max_age_duration(mut self, dur: Duration) -> Result<Self, BoxError> {
            self.max_age = Some(Seconds::try_from_duration(dur).context("duration contains sub nano seconds")?);
            Ok(self)
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `max-stale` directive.
        pub fn max_stale_duration_rounded(mut self, dur: Duration) -> Self {
            self.max_stale = Some(Seconds::from_duration_rounded(dur));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `max-stale` directive.
        pub fn max_stale_seconds(mut self, seconds: u64) -> Self {
            self.max_stale = Some(Seconds::new(seconds));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Try to set the `max-stale` directive.
        pub fn max_stale_duration(mut self, dur: Duration) -> Result<Self, BoxError> {
            self.max_stale = Some(Seconds::try_from_duration(dur).context("duration contains sub nano seconds")?);
            Ok(self)
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `min-fresh` directive.
        pub fn min_fresh_duration_rounded(mut self, dur: Duration) -> Self {
            self.min_fresh = Some(Seconds::from_duration_rounded(dur));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `min-fresh` directive.
        pub fn min_fresh_seconds(mut self, seconds: u64) -> Self {
            self.min_fresh = Some(Seconds::new(seconds));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Try to set the `min-fresh` directive.
        pub fn min_fresh_duration(mut self, dur: Duration) -> Result<Self, BoxError> {
            self.min_fresh = Some(Seconds::try_from_duration(dur).context("duration contains sub nano seconds")?);
            Ok(self)
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `s-maxage` directive.
        pub fn s_max_age_duration_rounded(mut self, dur: Duration) -> Self {
            self.s_max_age = Some(Seconds::from_duration_rounded(dur));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the `s-maxage` directive.
        pub fn s_max_age_seconds(mut self, seconds: u64) -> Self {
            self.s_max_age = Some(Seconds::new(seconds));
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Try to set the `s-maxage` directive.
        pub fn s_max_age_duration(mut self, dur: Duration) -> Result<Self, BoxError> {
            self.s_max_age = Some(Seconds::try_from_duration(dur).context("duration contains sub nano seconds")?);
            Ok(self)
        }
    }
}

impl TypedHeader for CacheControl {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CACHE_CONTROL
    }
}

impl HeaderDecode for CacheControl {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        csv::from_comma_delimited(values).map(|FromIter(cc)| cc)
    }
}

impl HeaderEncode for CacheControl {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(util::fmt(Fmt(self)));
    }
}

// Adapter to be used in Header::decode
struct FromIter(CacheControl);

impl FromIterator<KnownDirective> for FromIter {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = KnownDirective>,
    {
        let mut cc = CacheControl::new();

        // ignore all unknown directives
        let iter = iter.into_iter().filter_map(|dir| match dir {
            KnownDirective::Known(dir) => Some(dir),
            KnownDirective::Unknown => None,
        });

        for directive in iter {
            match directive {
                Directive::NoCache => {
                    cc.flags.insert(Flags::NO_CACHE);
                }
                Directive::NoStore => {
                    cc.flags.insert(Flags::NO_STORE);
                }
                Directive::NoTransform => {
                    cc.flags.insert(Flags::NO_TRANSFORM);
                }
                Directive::OnlyIfCached => {
                    cc.flags.insert(Flags::ONLY_IF_CACHED);
                }
                Directive::MustRevalidate => {
                    cc.flags.insert(Flags::MUST_REVALIDATE);
                }
                Directive::MustUnderstand => {
                    cc.flags.insert(Flags::MUST_UNDERSTAND);
                }
                Directive::Public => {
                    cc.flags.insert(Flags::PUBLIC);
                }
                Directive::Private => {
                    cc.flags.insert(Flags::PRIVATE);
                }
                Directive::Immutable => {
                    cc.flags.insert(Flags::IMMUTABLE);
                }
                Directive::ProxyRevalidate => {
                    cc.flags.insert(Flags::PROXY_REVALIDATE);
                }
                // the first of repeated directives wins (RFC 9111 §4.2.1)
                Directive::MaxAge(secs) => {
                    cc.max_age.get_or_insert(Seconds::new(secs));
                }
                Directive::MaxStale(secs) => {
                    cc.max_stale.get_or_insert(Seconds::new(secs));
                }
                Directive::MinFresh(secs) => {
                    cc.min_fresh.get_or_insert(Seconds::new(secs));
                }
                Directive::SMaxAge(secs) => {
                    cc.s_max_age.get_or_insert(Seconds::new(secs));
                }
            }
        }

        Self(cc)
    }
}

struct Fmt<'a>(&'a CacheControl);

impl fmt::Display for Fmt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let if_flag = |f: Flags, dir: Directive| {
            if self.0.flags.contains(f) {
                Some(dir)
            } else {
                None
            }
        };

        let slice = &[
            if_flag(Flags::NO_CACHE, Directive::NoCache),
            if_flag(Flags::NO_STORE, Directive::NoStore),
            if_flag(Flags::NO_TRANSFORM, Directive::NoTransform),
            if_flag(Flags::ONLY_IF_CACHED, Directive::OnlyIfCached),
            if_flag(Flags::MUST_REVALIDATE, Directive::MustRevalidate),
            if_flag(Flags::PUBLIC, Directive::Public),
            if_flag(Flags::PRIVATE, Directive::Private),
            if_flag(Flags::IMMUTABLE, Directive::Immutable),
            if_flag(Flags::MUST_UNDERSTAND, Directive::MustUnderstand),
            if_flag(Flags::PROXY_REVALIDATE, Directive::ProxyRevalidate),
            self.0
                .max_age
                .as_ref()
                .map(|s| Directive::MaxAge(s.as_u64())),
            self.0
                .max_stale
                .as_ref()
                .map(|s| Directive::MaxStale(s.as_u64())),
            self.0
                .min_fresh
                .as_ref()
                .map(|s| Directive::MinFresh(s.as_u64())),
            self.0
                .s_max_age
                .as_ref()
                .map(|s| Directive::SMaxAge(s.as_u64())),
        ];

        let iter = slice.iter().filter_map(|o| *o);

        csv::fmt_comma_delimited(f, iter)
    }
}

#[derive(Clone, Copy)]
enum KnownDirective {
    Known(Directive),
    Unknown,
}

#[derive(Clone, Copy)]
enum Directive {
    NoCache,
    NoStore,
    NoTransform,
    OnlyIfCached,

    // request directives
    MaxAge(u64),
    MaxStale(u64),
    MinFresh(u64),

    // response directives
    MustRevalidate,
    MustUnderstand,
    Public,
    Private,
    Immutable,
    ProxyRevalidate,
    SMaxAge(u64),
}

impl fmt::Display for Directive {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(
            match *self {
                Self::NoCache => "no-cache",
                Self::NoStore => "no-store",
                Self::NoTransform => "no-transform",
                Self::OnlyIfCached => "only-if-cached",

                Self::MaxAge(secs) => return write!(f, "max-age={secs}"),
                Self::MaxStale(secs) => return write!(f, "max-stale={secs}"),
                Self::MinFresh(secs) => return write!(f, "min-fresh={secs}"),

                Self::MustRevalidate => "must-revalidate",
                Self::MustUnderstand => "must-understand",
                Self::Public => "public",
                Self::Private => "private",
                Self::Immutable => "immutable",
                Self::ProxyRevalidate => "proxy-revalidate",
                Self::SMaxAge(secs) => return write!(f, "s-maxage={secs}"),
            },
            f,
        )
    }
}

impl FromStr for KnownDirective {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // canonical valueless directives need no split nor case folding
        let canonical = match s {
            "" => return Err(()),
            "no-cache" => Some(Directive::NoCache),
            "no-store" => Some(Directive::NoStore),
            "no-transform" => Some(Directive::NoTransform),
            "only-if-cached" => Some(Directive::OnlyIfCached),
            "must-revalidate" => Some(Directive::MustRevalidate),
            "public" => Some(Directive::Public),
            "private" => Some(Directive::Private),
            "immutable" => Some(Directive::Immutable),
            "must-understand" => Some(Directive::MustUnderstand),
            "proxy-revalidate" => Some(Directive::ProxyRevalidate),
            // a `&str` match is cheaper than `from_name`'s (name, value) byte-tuple match
            _ => None,
        };
        if let Some(directive) = canonical {
            return Ok(Self::Known(directive));
        }
        // directive names are case-insensitive (RFC 9111 §5.2)
        let mut name = [0; MAX_DIRECTIVE_NAME_LEN];
        let mut len = 0_usize;
        let mut value = None;
        let mut spaced = false;
        for (idx, byte) in s.bytes().enumerate() {
            if byte == b'=' {
                value = s.get(idx.saturating_add(1)..).map(unquote);
                break;
            }
            if matches!(byte, b' ' | b'\t') {
                spaced = true;
                continue;
            }
            if spaced {
                // whitespace inside a name makes it another (unknown) token
                return Ok(Self::Unknown);
            }
            let Some(slot) = name.get_mut(len) else {
                return Ok(Self::Unknown);
            };
            *slot = byte.to_ascii_lowercase();
            len = len.saturating_add(1);
        }
        // whitespace around `=` is invalid, which a freshness directive treats as stale
        if spaced && value.is_some() {
            value = Some("");
        }
        Ok(Self::from_name(name.get(..len).unwrap_or_default(), value))
    }
}

impl KnownDirective {
    fn from_name(name: &[u8], value: Option<&str>) -> Self {
        let seconds = || value.and_then(|value| parse_delta_seconds(value.bytes()));
        match (name, value) {
            // a field-qualified form is kept as its stricter unqualified form (RFC 9111 §5.2.2.4)
            (b"no-cache", _) => Self::Known(Directive::NoCache),
            (b"no-store", None) => Self::Known(Directive::NoStore),
            (b"no-transform", None) => Self::Known(Directive::NoTransform),
            (b"only-if-cached", None) => Self::Known(Directive::OnlyIfCached),
            (b"must-revalidate", None) => Self::Known(Directive::MustRevalidate),
            (b"public", None) => Self::Known(Directive::Public),
            (b"private", _) => Self::Known(Directive::Private),
            (b"immutable", None) => Self::Known(Directive::Immutable),
            (b"must-understand", None) => Self::Known(Directive::MustUnderstand),
            (b"proxy-revalidate", None) => Self::Known(Directive::ProxyRevalidate),
            // invalid freshness information makes a response stale (RFC 9111 §4.2.1)
            (b"max-age", _) => Self::Known(Directive::MaxAge(seconds().unwrap_or(0))),
            (b"s-maxage", _) => Self::Known(Directive::SMaxAge(seconds().unwrap_or(0))),
            (b"max-stale", _) => {
                seconds().map_or(Self::Unknown, |secs| Self::Known(Directive::MaxStale(secs)))
            }
            (b"min-fresh", _) => {
                seconds().map_or(Self::Unknown, |secs| Self::Known(Directive::MinFresh(secs)))
            }
            _ => Self::Unknown,
        }
    }
}

/// Longest known directive name (`proxy-revalidate`).
const MAX_DIRECTIVE_NAME_LEN: usize = 16;

/// Strip one pair of surrounding quotes, as directive arguments may be quoted-strings.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{test_decode, test_encode};

    #[test]
    fn test_parse_multiple_headers() {
        assert_eq!(
            test_decode::<CacheControl>(&["no-cache", "private"]).unwrap(),
            CacheControl::new().with_no_cache().with_private(),
        );
    }

    #[test]
    fn test_parse_argument() {
        assert_eq!(
            test_decode::<CacheControl>(&["max-age=100, private"]).unwrap(),
            CacheControl::new().with_max_age_seconds(100).with_private(),
        );
    }

    #[test]
    fn test_parse_quote_form() {
        assert_eq!(
            test_decode::<CacheControl>(&["max-age=\"200\""]).unwrap(),
            CacheControl::new().with_max_age_seconds(200),
        );
    }

    #[test]
    fn test_parse_quoted_comma() {
        assert_eq!(
            test_decode::<CacheControl>(&["foo=\"a, private, immutable, b\", no-cache"]).unwrap(),
            CacheControl::new().with_no_cache(),
            "unknown extensions are ignored but shouldn't fail parsing",
        )
    }

    #[test]
    fn quoted_pairs_do_not_hide_later_directives() {
        assert_eq!(
            test_decode::<CacheControl>(&[r#"no-cache="\"", no-store"#]).unwrap(),
            CacheControl::new().with_no_cache().with_no_store(),
        );
        assert_eq!(
            test_decode::<CacheControl>(&[r#"foo="a\",b", max-age=5"#]).unwrap(),
            CacheControl::new().with_max_age_seconds(5),
        );
        // an unterminated quoted-string keeps the directives before it, and swallows those after
        assert_eq!(
            test_decode::<CacheControl>(&[r#"no-store, foo="open, max-age=5"#]).unwrap(),
            CacheControl::new().with_no_store(),
        );
        assert_eq!(
            test_decode::<CacheControl>(&[r#"max-age=5, foo="open, no-store"#]).unwrap(),
            CacheControl::new().with_max_age_seconds(5),
        );
    }

    #[test]
    fn test_parse_extension() {
        assert_eq!(
            test_decode::<CacheControl>(&["foo, no-cache, bar=baz"]).unwrap(),
            CacheControl::new().with_no_cache(),
            "unknown extensions are ignored but shouldn't fail parsing",
        );
    }

    #[test]
    fn test_immutable() {
        let cc = CacheControl::new().with_immutable();
        let headers = test_encode(cc.clone());
        assert_eq!(headers["cache-control"], "immutable");
        assert_eq!(test_decode::<CacheControl>(&["immutable"]).unwrap(), cc);
        assert!(cc.has_immutable());
    }

    #[test]
    fn test_must_revalidate() {
        let cc = CacheControl::new().with_must_revalidate();
        let headers = test_encode(cc.clone());
        assert_eq!(headers["cache-control"], "must-revalidate");
        assert_eq!(
            test_decode::<CacheControl>(&["must-revalidate"]).unwrap(),
            cc
        );
        assert!(cc.has_must_revalidate());
    }

    #[test]
    fn test_must_understand() {
        let cc = CacheControl::new().with_must_understand();
        let headers = test_encode(cc.clone());
        assert_eq!(headers["cache-control"], "must-understand");
        assert_eq!(
            test_decode::<CacheControl>(&["must-understand"]).unwrap(),
            cc
        );
        assert!(cc.has_must_understand());
    }

    #[test]
    fn invalid_freshness_is_stale_and_keeps_other_directives() {
        for value in [
            "max-age=lolz",
            "max-age=+5",
            "max-age=-1",
            "max-age=\"\"",
            "max-age=\"5",
            "max-age=1.5",
            "max-age=",
            "max-age",
        ] {
            let cc =
                test_decode::<CacheControl>(&[&format!("no-store, private, {value}")]).unwrap();
            assert_eq!(cc.max_age(), Some(Duration::ZERO), "{value}");
            assert!(cc.clone().has_no_store(), "{value}");
            assert!(cc.has_private(), "{value}");
        }
        let cc = test_decode::<CacheControl>(&["s-maxage=x"]).unwrap();
        assert_eq!(cc.s_max_age(), Some(Duration::ZERO));
    }

    #[test]
    fn invalid_request_limits_are_ignored() {
        let cc = test_decode::<CacheControl>(&["no-cache, max-stale=x, min-fresh=-1"]).unwrap();
        assert_eq!(cc.max_stale(), None);
        assert_eq!(cc.min_fresh(), None);
        assert!(cc.has_no_cache());
    }

    #[test]
    fn qualified_no_cache_and_private_keep_their_flag() {
        let cc = test_decode::<CacheControl>(&[r#"private="set-cookie", max-age=60"#]).unwrap();
        assert_eq!(cc.max_age(), Some(Duration::from_secs(60)));
        assert!(cc.has_private());
        let cc = test_decode::<CacheControl>(&[r#"no-cache="set-cookie, x-a""#]).unwrap();
        assert!(cc.has_no_cache());
    }

    #[test]
    fn whitespace_around_equals_is_invalid_freshness() {
        // `cache-directive = token [ "=" ... ]` allows no whitespace around `=`
        for value in ["max-age =60", "max-age\t=60", "max-age = 60", "max-age= 60"] {
            let cc = test_decode::<CacheControl>(&[value]).unwrap();
            assert_eq!(cc.max_age(), Some(Duration::ZERO), "{value}");
        }
        let cc = test_decode::<CacheControl>(&["max-age =60, max-age=120"]).unwrap();
        assert_eq!(cc.max_age(), Some(Duration::ZERO));
        let cc = test_decode::<CacheControl>(&[r#"private ="set-cookie""#]).unwrap();
        assert!(cc.has_private());
    }

    #[test]
    fn whitespace_inside_a_name_is_unknown() {
        for value in [
            "pub lic",
            "immu table",
            "no-st ore",
            "max -age=60",
            "pri\tvate",
        ] {
            assert_eq!(
                test_decode::<CacheControl>(&[value]),
                Some(CacheControl::new()),
                "{value}"
            );
        }
    }

    #[test]
    fn repeated_freshness_uses_the_first() {
        for (value, expected) in [
            ("max-age=60, max-age=120", 60),
            ("max-age=x, max-age=60", 0),
            ("max-age=0, max-age=60", 0),
        ] {
            let cc = test_decode::<CacheControl>(&[value]).unwrap();
            assert_eq!(cc.max_age(), Some(Duration::from_secs(expected)), "{value}");
        }
        let cc = test_decode::<CacheControl>(&["s-maxage=5", "s-maxage=500"]).unwrap();
        assert_eq!(cc.s_max_age(), Some(Duration::from_secs(5)));
        let cc =
            test_decode::<CacheControl>(&["max-stale=5, min-fresh=6, max-stale=50, min-fresh=60"])
                .unwrap();
        assert_eq!(cc.max_stale(), Some(Duration::from_secs(5)));
        assert_eq!(cc.min_fresh(), Some(Duration::from_secs(6)));
    }

    #[test]
    fn directive_names_are_case_insensitive() {
        let cc = test_decode::<CacheControl>(&["No-Store, PRIVATE, Max-Age=5"]).unwrap();
        assert_eq!(cc.max_age(), Some(Duration::from_secs(5)));
        assert!(cc.clone().has_no_store());
        assert!(cc.has_private());
    }

    #[test]
    fn delta_seconds_overflow_clamps() {
        let cc = test_decode::<CacheControl>(&[
            "no-store, max-age=99999999999999999999, s-maxage=\"18446744073709551616\"",
        ])
        .unwrap();
        assert!(cc.clone().has_no_store());
        assert_eq!(cc.max_age(), Some(Duration::from_secs(2_147_483_648)));
        assert_eq!(cc.s_max_age(), Some(Duration::from_secs(2_147_483_648)));

        let cc =
            test_decode::<CacheControl>(&["max-stale=18446744073709551615, min-fresh=0"]).unwrap();
        assert_eq!(cc.max_stale(), Some(Duration::from_secs(2_147_483_648)));
        assert_eq!(cc.min_fresh(), Some(Duration::ZERO));
        let headers = test_encode(cc);
        assert_eq!(
            headers["cache-control"],
            "max-stale=2147483648, min-fresh=0"
        );
    }

    #[test]
    fn adversarial_directives_do_not_panic() {
        for value in ["=", "=5", "max-age=", "max-age", "\"=\"", "no-cache="] {
            assert!(test_decode::<CacheControl>(&[value]).is_some(), "{value}");
        }
        for value in ["max-agé=5", "é=5", "é=", "=é", "no-store=1"] {
            assert!(
                matches!(value.parse(), Ok(KnownDirective::Unknown)),
                "{value}"
            );
        }
        for value in ["max-age=é", "max-age=\"é\"", "max-age=5é"] {
            assert!(
                matches!(
                    value.parse(),
                    Ok(KnownDirective::Known(Directive::MaxAge(0)))
                ),
                "{value}"
            );
        }
    }

    #[test]
    fn encode_one_flag_directive() {
        let cc = CacheControl::new().with_no_cache();

        let headers = test_encode(cc);
        assert_eq!(headers["cache-control"], "no-cache");
    }

    #[test]
    fn encode_one_param_directive() {
        let cc = CacheControl::new().with_max_age_seconds(300);

        let headers = test_encode(cc);
        assert_eq!(headers["cache-control"], "max-age=300");
    }

    #[test]
    fn encode_two_directive() {
        let headers = test_encode(CacheControl::new().with_no_cache().with_private());
        assert_eq!(headers["cache-control"], "no-cache, private");

        let headers = test_encode(
            CacheControl::new()
                .with_no_cache()
                .with_max_age_seconds(100),
        );
        assert_eq!(headers["cache-control"], "no-cache, max-age=100");
    }

    #[test]
    fn preset_immutable_one_year() {
        let headers = test_encode(CacheControl::immutable_one_year());
        assert_eq!(
            headers["cache-control"],
            "public, immutable, max-age=31536000"
        );
    }

    #[test]
    fn preset_no_cache() {
        let headers = test_encode(CacheControl::no_cache());
        assert_eq!(headers["cache-control"], "no-cache");
    }

    #[test]
    fn preset_short_shared_revalidate() {
        let headers = test_encode(CacheControl::short_shared_revalidate(3600));
        assert_eq!(
            headers["cache-control"],
            "must-revalidate, public, max-age=3600"
        );
    }
}
