use std::fmt;
use std::time::Duration;

use rama_http_types::{HeaderName, HeaderValue};

use crate::util::{self, IterExt, Seconds};
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `StrictTransportSecurity` header, defined in [RFC6797](https://tools.ietf.org/html/rfc6797)
///
/// This specification defines a mechanism enabling web sites to declare
/// themselves accessible only via secure connections and/or for users to be
/// able to direct their user agent(s) to interact with given sites only over
/// secure connections.  This overall policy is referred to as HTTP Strict
/// Transport Security (HSTS).  The policy is declared by web sites via the
/// Strict-Transport-Security HTTP response header field and/or by other means,
/// such as user agent configuration, for example.
///
/// # ABNF
///
/// ```text
///      [ directive ]  *( ";" [ directive ] )
///
///      directive                 = directive-name [ "=" directive-value ]
///      directive-name            = token
///      directive-value           = token | quoted-string
///
/// ```
///
/// # Example values
///
/// * `max-age=31536000`
/// * `max-age=15768000 ; includeSubdomains`
/// * `max-age=31536000; includeSubDomains; preload`
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use rama_http_headers::StrictTransportSecurity;
///
/// let sts = StrictTransportSecurity::including_subdomains_for_max_seconds(31_536_000)
///     .with_preload();
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct StrictTransportSecurity {
    /// Signals the UA that the HSTS Policy applies to this HSTS Host as well as
    /// any subdomains of the host's domain name.
    include_subdomains: bool,

    /// Signals that the host is (or wishes to be) on the Chromium/Mozilla
    /// HSTS preload list. Not part of RFC 6797 but is the convention
    /// required for <https://hstspreload.org> eligibility.
    preload: bool,

    /// Specifies the number of seconds, after the reception of the STS header
    /// field, during which the UA regards the host (from whom the message was
    /// received) as a Known HSTS Host.
    max_age: Seconds,
}

impl StrictTransportSecurity {
    // NOTE: The two constructors exist to make a user *have* to decide if
    // subdomains can be included or not, instead of forgetting due to an
    // incorrect assumption about a default.

    /// Create an STS header that includes subdomains
    #[must_use]
    pub fn including_subdomains_for_max_seconds(max_age: u64) -> Self {
        Self {
            max_age: Seconds::new(max_age),
            include_subdomains: true,
            preload: false,
        }
    }

    /// Create an STS header that includes subdomains
    ///
    /// The given [`Duration`] is rounded by ignoring any sub nano seconds.
    /// Use [`Self::including_subdomains_for_max_duration`] in case you want to make
    /// that a fallible case instead.
    #[must_use]
    pub fn including_subdomains_for_max_duration_rounded(dur: Duration) -> Self {
        Self {
            max_age: Seconds::from_duration_rounded(dur),
            include_subdomains: true,
            preload: false,
        }
    }

    /// Try to create a STS header that includes subdomains
    ///
    /// # Error
    ///
    /// Errors in case the given [`Duration`] contains sub nano seconds,
    /// use [`Self::including_subdomains_for_max_seconds`] or
    /// [`Self::including_subdomains_for_max_duration_rounded`] for a infallible constructor.
    #[must_use]
    pub fn including_subdomains_for_max_duration(dur: Duration) -> Option<Self> {
        Seconds::try_from_duration(dur).map(|max_age| Self {
            max_age,
            include_subdomains: true,
            preload: false,
        })
    }

    /// Create an STS header that excludes subdomains
    #[must_use]
    pub fn excluding_subdomains_for_max_seconds(max_age: u64) -> Self {
        Self {
            max_age: Seconds::new(max_age),
            include_subdomains: false,
            preload: false,
        }
    }

    /// Create an STS header that excludes subdomains
    ///
    /// The given [`Duration`] is rounded by ignoring any sub nano seconds.
    /// Use [`Self::excluding_subdomains_for_max_duration`] in case you want to make
    /// that a fallible case instead.
    #[must_use]
    pub fn excluding_subdomains_for_max_duration_rounded(dur: Duration) -> Self {
        Self {
            max_age: Seconds::from_duration_rounded(dur),
            include_subdomains: false,
            preload: false,
        }
    }

    /// Try to create a STS header that excludes subdomains
    ///
    /// # Error
    ///
    /// Errors in case the given [`Duration`] contains sub nano seconds,
    /// use [`Self::excluding_subdomains_for_max_seconds`] or
    /// [`Self::excluding_subdomains_for_max_duration_rounded`] for a infallible constructor.
    #[must_use]
    pub fn excluding_subdomains_for_max_duration(dur: Duration) -> Option<Self> {
        Seconds::try_from_duration(dur).map(|max_age| Self {
            max_age,
            include_subdomains: false,
            preload: false,
        })
    }

    rama_utils::macros::generate_set_and_with! {
        /// Mark this STS header as `preload`-eligible.
        ///
        /// The `preload` directive is a Chromium/Mozilla extension required for
        /// [HSTS preload list](https://hstspreload.org) eligibility — sites
        /// listed there get HSTS protection on the user's *very first* visit.
        /// Per the preload list submission rules `preload` is only meaningful
        /// alongside `max-age` ≥ 31536000 and `includeSubDomains`; this builder
        /// does not enforce that, but callers should set both.
        pub fn preload(mut self, preload: bool) -> Self {
            self.preload = preload;
            self
        }
    }

    // getters

    /// Get whether this should include subdomains.
    #[must_use]
    pub fn include_subdomains(&self) -> bool {
        self.include_subdomains
    }

    /// Get whether the `preload` directive is set.
    #[must_use]
    pub fn preload(&self) -> bool {
        self.preload
    }

    /// Get the max-age.
    #[must_use]
    pub fn max_age(&self) -> Duration {
        self.max_age.into()
    }
}

enum Directive {
    MaxAge(u64),
    IncludeSubdomains,
    Preload,
    Unknown,
}

fn from_str(s: &str) -> Result<StrictTransportSecurity, Error> {
    s.split(';')
        .map(str::trim)
        .map(|sub| {
            if sub.eq_ignore_ascii_case("includeSubdomains") {
                Some(Directive::IncludeSubdomains)
            } else if sub.eq_ignore_ascii_case("preload") {
                Some(Directive::Preload)
            } else {
                let mut sub = sub.splitn(2, '=');
                match (sub.next(), sub.next()) {
                    (Some(left), Some(right)) if left.trim().eq_ignore_ascii_case("max-age") => {
                        right
                            .trim()
                            .trim_matches('"')
                            .parse()
                            .ok()
                            .map(Directive::MaxAge)
                    }
                    _ => Some(Directive::Unknown),
                }
            }
        })
        .try_fold((None, None, None), |res, dir| match (res, dir) {
            ((None, sub, pre), Some(Directive::MaxAge(age))) => Some((Some(age), sub, pre)),
            ((age, None, pre), Some(Directive::IncludeSubdomains)) => Some((age, Some(()), pre)),
            ((age, sub, None), Some(Directive::Preload)) => Some((age, sub, Some(()))),
            ((Some(_), _, _), Some(Directive::MaxAge(_)))
            | ((_, Some(_), _), Some(Directive::IncludeSubdomains))
            | ((_, _, Some(_)), Some(Directive::Preload))
            | (_, None) => None,
            (res, _) => Some(res),
        })
        .and_then(|res| match res {
            (Some(age), sub, pre) => Some(StrictTransportSecurity {
                max_age: Seconds::new(age),
                include_subdomains: sub.is_some(),
                preload: pre.is_some(),
            }),
            _ => None,
        })
        .ok_or_else(Error::invalid)
}

impl TypedHeader for StrictTransportSecurity {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::STRICT_TRANSPORT_SECURITY
    }
}

impl HeaderDecode for StrictTransportSecurity {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .just_one()
            .and_then(|v| v.to_str().ok())
            .map(from_str)
            .unwrap_or_else(|| Err(Error::invalid()))
    }
}

impl HeaderEncode for StrictTransportSecurity {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        struct Adapter<'a>(&'a StrictTransportSecurity);

        impl fmt::Display for Adapter<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "max-age={}", self.0.max_age)?;
                if self.0.include_subdomains {
                    f.write_str("; includeSubDomains")?;
                }
                if self.0.preload {
                    f.write_str("; preload")?;
                }
                Ok(())
            }
        }

        values.extend(::std::iter::once(util::fmt(Adapter(self))));
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::*;

    #[test]
    fn test_parse_max_age() {
        let h = test_decode::<StrictTransportSecurity>(&["max-age=31536000"]).unwrap();
        assert_eq!(
            h,
            StrictTransportSecurity {
                include_subdomains: false,
                preload: false,
                max_age: Seconds::new(31536000),
            }
        );
    }

    #[test]
    fn test_parse_max_age_no_value() {
        assert_eq!(test_decode::<StrictTransportSecurity>(&["max-age"]), None,);
    }

    #[test]
    fn test_parse_quoted_max_age() {
        let h = test_decode::<StrictTransportSecurity>(&["max-age=\"31536000\""]).unwrap();
        assert_eq!(
            h,
            StrictTransportSecurity {
                include_subdomains: false,
                preload: false,
                max_age: Seconds::new(31536000),
            }
        );
    }

    #[test]
    fn test_parse_spaces_max_age() {
        let h = test_decode::<StrictTransportSecurity>(&["max-age = 31536000"]).unwrap();
        assert_eq!(
            h,
            StrictTransportSecurity {
                include_subdomains: false,
                preload: false,
                max_age: Seconds::new(31536000),
            }
        );
    }

    #[test]
    fn test_parse_include_subdomains() {
        let h = test_decode::<StrictTransportSecurity>(&["max-age=15768000 ; includeSubDomains"])
            .unwrap();
        assert_eq!(
            h,
            StrictTransportSecurity {
                include_subdomains: true,
                preload: false,
                max_age: Seconds::new(15768000),
            }
        );
    }

    #[test]
    fn test_parse_no_max_age() {
        assert_eq!(
            test_decode::<StrictTransportSecurity>(&["includeSubdomains"]),
            None,
        );
    }

    #[test]
    fn test_parse_max_age_nan() {
        assert_eq!(
            test_decode::<StrictTransportSecurity>(&["max-age = izzy"]),
            None,
        );
    }

    #[test]
    fn test_parse_duplicate_directives() {
        assert_eq!(
            test_decode::<StrictTransportSecurity>(&["max-age=1; max-age=2"]),
            None,
        );
    }

    #[test]
    fn test_parse_preload() {
        for raw in [
            "max-age=31536000; includeSubDomains; preload",
            "max-age=31536000; includeSubDomains; Preload",
            "max-age=31536000; includeSubDomains; PRELOAD",
        ] {
            let h = test_decode::<StrictTransportSecurity>(&[raw]).unwrap_or_else(|| {
                panic!("failed to decode {raw}");
            });
            assert_eq!(
                h,
                StrictTransportSecurity {
                    include_subdomains: true,
                    preload: true,
                    max_age: Seconds::new(31536000),
                }
            );
        }
    }

    #[test]
    fn test_parse_preload_without_subdomains() {
        let h = test_decode::<StrictTransportSecurity>(&["max-age=31536000; preload"]).unwrap();
        assert_eq!(
            h,
            StrictTransportSecurity {
                include_subdomains: false,
                preload: true,
                max_age: Seconds::new(31536000),
            }
        );
    }

    #[test]
    fn test_parse_duplicate_preload_rejected() {
        assert_eq!(
            test_decode::<StrictTransportSecurity>(&["max-age=1; preload; preload"]),
            None,
        );
    }

    #[test]
    fn test_encode_canonical_order() {
        let sts = StrictTransportSecurity::including_subdomains_for_max_seconds(31_536_000)
            .with_preload();
        let map = super::super::test_encode(sts);
        let raw = map
            .get(StrictTransportSecurity::name())
            .expect("header set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, "max-age=31536000; includeSubDomains; preload");
    }

    #[test]
    fn test_encode_preload_excluding_subdomains() {
        let sts = StrictTransportSecurity::excluding_subdomains_for_max_seconds(31_536_000)
            .with_preload();
        let map = super::super::test_encode(sts);
        let raw = map
            .get(StrictTransportSecurity::name())
            .expect("header set")
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(raw, "max-age=31536000; preload");
    }

    #[test]
    fn test_preload_round_trip_idempotent() {
        let sts = StrictTransportSecurity::including_subdomains_for_max_seconds(31_536_000)
            .with_preload();
        let map = super::super::test_encode(sts.clone());
        let raw = map
            .get(StrictTransportSecurity::name())
            .expect("header set")
            .to_str()
            .unwrap()
            .to_owned();
        let parsed = test_decode::<StrictTransportSecurity>(&[raw.as_str()])
            .expect("re-decode of canonical form");
        assert_eq!(parsed, sts);
    }
}

//bench_header!(bench, StrictTransportSecurity, { vec![b"max-age=15768000 ; includeSubDomains".to_vec()] });
