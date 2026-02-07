use std::fmt;
use std::iter::FromIterator;
use std::str::FromStr;
use std::time::Duration;

use rama_core::error::{BoxError, ErrorContext as _};
use rama_http_types::{HeaderName, HeaderValue};

use crate::util::{self, Seconds, csv};
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

    #[allow(clippy::needless_pass_by_value)]
    fn contains(&self, flag: Self) -> bool {
        (self.bits & flag.bits) != 0
    }

    #[allow(clippy::needless_pass_by_value)]
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

    // getters

    /// Check if the `no-cache` directive is set.
    #[must_use]
    pub fn no_cache(self) -> bool {
        self.flags.contains(Flags::NO_CACHE)
    }

    /// Check if the `no-store` directive is set.
    #[must_use]
    pub fn no_store(self) -> bool {
        self.flags.contains(Flags::NO_STORE)
    }

    /// Check if the `no-transform` directive is set.
    #[must_use]
    pub fn no_transform(self) -> bool {
        self.flags.contains(Flags::NO_TRANSFORM)
    }

    /// Check if the `only-if-cached` directive is set.
    #[must_use]
    pub fn only_if_cached(self) -> bool {
        self.flags.contains(Flags::ONLY_IF_CACHED)
    }

    /// Check if the `public` directive is set.
    #[must_use]
    pub fn public(self) -> bool {
        self.flags.contains(Flags::PUBLIC)
    }

    /// Check if the `private` directive is set.
    #[must_use]
    pub fn private(self) -> bool {
        self.flags.contains(Flags::PRIVATE)
    }

    /// Check if the `immutable` directive is set.
    #[must_use]
    pub fn immutable(self) -> bool {
        self.flags.contains(Flags::IMMUTABLE)
    }

    /// Check if the `must-revalidate` directive is set.
    #[must_use]
    pub fn must_revalidate(&self) -> bool {
        self.flags.contains(Flags::MUST_REVALIDATE)
    }

    /// Check if the `must-understand` directive is set.
    #[must_use]
    pub fn must_understand(self) -> bool {
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
        values.extend(::std::iter::once(util::fmt(Fmt(self))));
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
                Directive::MaxAge(secs) => {
                    cc.max_age = Some(Seconds::new(secs));
                }
                Directive::MaxStale(secs) => {
                    cc.max_stale = Some(Seconds::new(secs));
                }
                Directive::MinFresh(secs) => {
                    cc.min_fresh = Some(Seconds::new(secs));
                }
                Directive::SMaxAge(secs) => {
                    cc.s_max_age = Some(Seconds::new(secs));
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
        Ok(Self::Known(match s {
            "no-cache" => Directive::NoCache,
            "no-store" => Directive::NoStore,
            "no-transform" => Directive::NoTransform,
            "only-if-cached" => Directive::OnlyIfCached,
            "must-revalidate" => Directive::MustRevalidate,
            "public" => Directive::Public,
            "private" => Directive::Private,
            "immutable" => Directive::Immutable,
            "must-understand" => Directive::MustUnderstand,
            "proxy-revalidate" => Directive::ProxyRevalidate,
            "" => return Err(()),
            _ => match s.find('=') {
                Some(idx) if idx + 1 < s.len() => {
                    match (&s[..idx], (s[idx + 1..]).trim_matches('"')) {
                        ("max-age", secs) => secs.parse().map(Directive::MaxAge).map_err(|_| ())?,
                        ("max-stale", secs) => {
                            secs.parse().map(Directive::MaxStale).map_err(|_| ())?
                        }
                        ("min-fresh", secs) => {
                            secs.parse().map(Directive::MinFresh).map_err(|_| ())?
                        }
                        ("s-maxage", secs) => {
                            secs.parse().map(Directive::SMaxAge).map_err(|_| ())?
                        }
                        _unknown => return Ok(Self::Unknown),
                    }
                }
                Some(_) | None => return Ok(Self::Unknown),
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;

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
        assert!(cc.immutable());
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
        assert!(cc.must_revalidate());
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
        assert!(cc.must_understand());
    }

    #[test]
    fn test_parse_bad_syntax() {
        assert_eq!(test_decode::<CacheControl>(&["max-age=lolz"]), None);
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
}
