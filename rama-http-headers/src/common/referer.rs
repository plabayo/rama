use std::fmt;
use std::str::FromStr;

use crate::util::HeaderValueString;

/// `Referer` header, defined in
/// [RFC7231](https://datatracker.ietf.org/doc/html/rfc7231#section-5.5.2)
///
/// The `Referer` \[sic\] header field allows the user agent to specify a
/// URI reference for the resource from which the target URI was obtained
/// (i.e., the "referrer", though the field name is misspelled).  A user
/// agent MUST NOT include the fragment and userinfo components of the
/// URI reference, if any, when generating the Referer field value.
///
/// ## ABNF
///
/// ```text
/// Referer = absolute-URI / partial-URI
/// ```
///
/// ## Example values
///
/// * `http://www.example.org/hypertext/Overview.html`
///
/// # Examples
///
/// ```
/// use rama_http_headers::Referer;
///
/// let r = Referer::from_static("/People.html#tim");
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Referer(HeaderValueString);

derive_header! {
    Referer(_),
    name: REFERER
}

impl Referer {
    /// Create a `Referer` with a static string.
    ///
    /// # Panic
    ///
    /// Panics if the string is not a legal header value.
    #[must_use]
    pub const fn from_static(s: &'static str) -> Self {
        Self(HeaderValueString::from_static(s))
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "referer is not valid"]
    pub struct InvalidReferer;
}

impl FromStr for Referer {
    type Err = InvalidReferer;
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        HeaderValueString::from_str(src)
            .map(Referer)
            .map_err(|_| InvalidReferer)
    }
}

impl fmt::Display for Referer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
