use std::borrow::Cow;
use std::cmp::min;
use std::str::FromStr;

use crate::__eq_ignore_ascii_case as eq_ignore_ascii_case;
use crate::error::{ErrorContext, OpaqueError};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Web protocols that are relevant to Rama.
///
/// Please [file an issue or open a PR][repo] if you need support for more protocols.
/// When doing so please provide sufficient motivation and ensure
/// it has no unintended consequences.
///
/// [repo]: https://github.com/plabayo/rama
pub enum Protocol {
    /// The `http` protocol.
    Http,
    /// The `https` protocol.
    Https,
    /// The `ws` protocol.
    ///
    /// (Websocket over HTTP)
    /// <https://datatracker.ietf.org/doc/html/rfc6455>
    Ws,
    /// The `wss` protocol.
    ///
    /// (Websocket over HTTPS)
    /// <https://datatracker.ietf.org/doc/html/rfc6455>
    Wss,
    /// The `socks5` protocol.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc1928>
    Socks5,
    /// The `socks5h` protocol.
    ///
    /// Not official, but rather a convention that was introduced in version 4 of socks,
    /// by curl and documented at <https://curl.se/libcurl/c/CURLOPT_PROXY.html>.
    ///
    /// The difference with [`Self::Socks5`] is that the proxy resolves the URL hostname.
    Socks5h,
    /// Custom protocol.
    Custom(Cow<'static, str>),
}

const SCHEME_HTTP: &str = "http";
const SCHEME_HTTPS: &str = "https";
const SCHEME_SOCKS5: &str = "socks5";
const SCHEME_SOCKS5H: &str = "socks5h";
const SCHEME_WS: &str = "ws";
const SCHEME_WSS: &str = "wss";

impl Protocol {
    /// Creates a Protocol from a str a compile time.
    ///
    /// This function requires the static string to be a valid protocol.
    ///
    /// It is intended to be used to facilitate the compile-time creation of
    /// custom Protocols, as known protocols are easier created by using the desired
    /// variant directly.
    ///
    /// # Panics
    ///
    /// This function panics at **compile time** when the static string is not a valid protocol.
    pub const fn from_static(s: &'static str) -> Self {
        // NOTE: once unwrapping is possible in const we can piggy back on
        // `try_to_convert_str_to_non_custom_protocol`

        if eq_ignore_ascii_case!(s, SCHEME_HTTPS) {
            Protocol::Https
        } else if s.is_empty() || eq_ignore_ascii_case!(s, SCHEME_HTTP) {
            Protocol::Http
        } else if eq_ignore_ascii_case!(s, SCHEME_SOCKS5) {
            Protocol::Socks5
        } else if eq_ignore_ascii_case!(s, SCHEME_SOCKS5H) {
            Protocol::Socks5h
        } else if eq_ignore_ascii_case!(s, SCHEME_WS) {
            Protocol::Ws
        } else if eq_ignore_ascii_case!(s, SCHEME_WSS) {
            Protocol::Wss
        } else if validate_scheme_str(s) {
            Protocol::Custom(Cow::Borrowed(s))
        } else {
            panic!("invalid static protocol str");
        }
    }

    /// Returns `true` if this protocol is "secure" by itself.
    pub fn secure(&self) -> bool {
        match self {
            Protocol::Https | Protocol::Wss => true,
            Protocol::Ws
            | Protocol::Http
            | Protocol::Socks5
            | Protocol::Socks5h
            | Protocol::Custom(_) => false,
        }
    }

    /// Returns the scheme str for this protocol.
    pub fn as_scheme(&self) -> &str {
        match self {
            Protocol::Https => SCHEME_HTTPS,
            Protocol::Http => SCHEME_HTTP,
            Protocol::Socks5 => SCHEME_SOCKS5,
            Protocol::Socks5h => SCHEME_SOCKS5H,
            Protocol::Ws => SCHEME_WS,
            Protocol::Wss => SCHEME_WSS,
            Protocol::Custom(s) => s.as_ref(),
        }
    }

    /// Return a port that can be used as default in case no port is defined.
    ///
    /// NOTE that this is not going to be valid for non-http ports.
    pub fn default_port(&self) -> u16 {
        match self {
            Protocol::Https | Protocol::Wss => 443,
            Protocol::Http | Protocol::Ws => 80,
            Protocol::Socks5 | Protocol::Socks5h | Protocol::Custom(_) => 80, // \_(ツ)_/¯
        }
    }
}

crate::__static_str_error! {
    pub struct InvalidProtocolStr = "invalid protocol string";
}

fn try_to_convert_str_to_non_custom_protocol(
    s: &str,
) -> Result<Option<Protocol>, InvalidProtocolStr> {
    Ok(Some(if eq_ignore_ascii_case!(s, SCHEME_HTTPS) {
        Protocol::Https
    } else if s.is_empty() || eq_ignore_ascii_case!(s, SCHEME_HTTP) {
        Protocol::Http
    } else if eq_ignore_ascii_case!(s, SCHEME_SOCKS5) {
        Protocol::Socks5
    } else if eq_ignore_ascii_case!(s, SCHEME_SOCKS5H) {
        Protocol::Socks5h
    } else if eq_ignore_ascii_case!(s, SCHEME_WS) {
        Protocol::Ws
    } else if eq_ignore_ascii_case!(s, SCHEME_WSS) {
        Protocol::Wss
    } else if validate_scheme_str(s) {
        return Ok(None);
    } else {
        return Err(InvalidProtocolStr);
    }))
}

impl TryFrom<&str> for Protocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(try_to_convert_str_to_non_custom_protocol(s)?
            .unwrap_or_else(|| Protocol::Custom(Cow::Owned(s.to_owned()))))
    }
}

impl TryFrom<String> for Protocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(try_to_convert_str_to_non_custom_protocol(&s)?
            .unwrap_or(Protocol::Custom(Cow::Owned(s))))
    }
}

impl TryFrom<&String> for Protocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: &String) -> Result<Self, Self::Error> {
        Ok(try_to_convert_str_to_non_custom_protocol(s)?
            .unwrap_or_else(|| Protocol::Custom(Cow::Owned(s.clone()))))
    }
}

impl FromStr for Protocol {
    type Err = InvalidProtocolStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl From<crate::http::Scheme> for Protocol {
    #[inline]
    fn from(s: crate::http::Scheme) -> Self {
        s.as_str()
            .try_into()
            .expect("http crate Scheme is pre-validated by promise")
    }
}

impl From<&crate::http::Scheme> for Protocol {
    fn from(s: &crate::http::Scheme) -> Self {
        s.as_str()
            .try_into()
            .expect("http crate Scheme is pre-validated by promise")
    }
}

impl From<Option<crate::http::Scheme>> for Protocol {
    fn from(s: Option<crate::http::Scheme>) -> Self {
        s.map(Into::into).unwrap_or(Protocol::Http)
    }
}

impl From<Option<&crate::http::Scheme>> for Protocol {
    fn from(s: Option<&crate::http::Scheme>) -> Self {
        s.map(Into::into).unwrap_or(Protocol::Http)
    }
}

impl PartialEq<str> for Protocol {
    fn eq(&self, other: &str) -> bool {
        match self {
            Protocol::Https => other.eq_ignore_ascii_case(SCHEME_HTTPS),
            Protocol::Http => other.eq_ignore_ascii_case(SCHEME_HTTP) || other.is_empty(),
            Protocol::Socks5 => other.eq_ignore_ascii_case(SCHEME_SOCKS5),
            Protocol::Socks5h => other.eq_ignore_ascii_case(SCHEME_SOCKS5H),
            Protocol::Ws => other.eq_ignore_ascii_case("ws"),
            Protocol::Wss => other.eq_ignore_ascii_case("wss"),
            Protocol::Custom(s) => other.eq_ignore_ascii_case(s),
        }
    }
}

impl PartialEq<String> for Protocol {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<&str> for Protocol {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<Protocol> for str {
    fn eq(&self, other: &Protocol) -> bool {
        other == self
    }
}

impl PartialEq<Protocol> for String {
    fn eq(&self, other: &Protocol) -> bool {
        other == self.as_str()
    }
}

impl PartialEq<Protocol> for &str {
    fn eq(&self, other: &Protocol) -> bool {
        other == *self
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_scheme().fmt(f)
    }
}

pub(crate) fn try_to_extract_protocol_from_uri_scheme(
    s: &[u8],
) -> Result<(Protocol, usize), OpaqueError> {
    if s.is_empty() {
        return Err(OpaqueError::from_display("empty uri contains no scheme"));
    }

    for i in 0..min(s.len(), 512) {
        let b = s[i];

        if b == b':' {
            // Not enough data remaining
            if s.len() < i + 3 {
                break;
            }

            // Not a scheme
            if &s[i + 1..i + 3] != b"//" {
                break;
            }

            let str =
                std::str::from_utf8(&s[..i]).context("interpret scheme bytes as utf-8 str")?;
            let protocol = str
                .try_into()
                .context("parse scheme utf-8 str as protocol")?;
            return Ok((protocol, i + 3));
        }
    }

    Ok((Protocol::Http, 0))
}

#[inline]
const fn validate_scheme_str(s: &str) -> bool {
    validate_scheme_slice(s.as_bytes())
}

const fn validate_scheme_slice(s: &[u8]) -> bool {
    if s.is_empty() || s.len() > MAX_SCHEME_LEN {
        return false;
    }

    let mut i = 0;
    while i < s.len() {
        if SCHEME_CHARS[s[i] as usize] == 0 {
            return false;
        }
        i += 1;
    }
    true
}

// Require the scheme to not be too long in order to enable further
// optimizations later.
const MAX_SCHEME_LEN: usize = 64;

// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
//
// SCHEME_CHARS is a table of valid characters in the scheme part of a URI.  An
// entry in the table is 0 for invalid characters. For valid characters the
// entry is itself (i.e.  the entry for 43 is b'+' because b'+' == 43u8). An
// important characteristic of this table is that all entries above 127 are
// invalid. This makes all of the valid entries a valid single-byte UTF-8 code
// point. This means that a slice of such valid entries is valid UTF-8.
#[rustfmt::skip]
const SCHEME_CHARS: [u8; 256] = [
    //  0      1      2      3      4      5      6      7      8      9
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //   x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  1x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  2x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  3x
        0,     0,     0,  b'+',     0,  b'-',  b'.',     0,  b'0',  b'1', //  4x
     b'2',  b'3',  b'4',  b'5',  b'6',  b'7',  b'8',  b'9',  b':',     0, //  5x
        0,     0,     0,     0,     0,  b'A',  b'B',  b'C',  b'D',  b'E', //  6x
     b'F',  b'G',  b'H',  b'I',  b'J',  b'K',  b'L',  b'M',  b'N',  b'O', //  7x
     b'P',  b'Q',  b'R',  b'S',  b'T',  b'U',  b'V',  b'W',  b'X',  b'Y', //  8x
     b'Z',     0,     0,     0,     0,     0,     0,  b'a',  b'b',  b'c', //  9x
     b'd',  b'e',  b'f',  b'g',  b'h',  b'i',  b'j',  b'k',  b'l',  b'm', // 10x
     b'n',  b'o',  b'p',  b'q',  b'r',  b's',  b't',  b'u',  b'v',  b'w', // 11x
     b'x',  b'y',  b'z',     0,     0,     0,  b'~',     0,     0,     0, // 12x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 13x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 14x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 15x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 16x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 17x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 18x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 19x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 20x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 21x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 22x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 23x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 24x
        0,     0,     0,     0,     0,     0                              // 25x
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        assert_eq!("http".parse(), Ok(Protocol::Http));
        assert_eq!("".parse(), Ok(Protocol::Http));
        assert_eq!("https".parse(), Ok(Protocol::Https));
        assert_eq!("ws".parse(), Ok(Protocol::Ws));
        assert_eq!("wss".parse(), Ok(Protocol::Wss));
        assert_eq!("socks5".parse(), Ok(Protocol::Socks5));
        assert_eq!("socks5h".parse(), Ok(Protocol::Socks5h));
        assert_eq!("custom".parse(), Ok(Protocol::from_static("custom")));
    }

    #[test]
    fn test_from_http_scheme() {
        for s in [
            "http", "https", "ws", "wss", "socks5", "socks5h", "", "custom",
        ]
        .iter()
        {
            let uri = crate::http::Uri::from_str(format!("{}://example.com", s).as_str()).unwrap();
            assert_eq!(Protocol::from(uri.scheme()), *s);
        }
    }

    #[test]
    fn test_scheme_secure() {
        assert!(!Protocol::Http.secure());
        assert!(Protocol::Https.secure());
        assert!(!Protocol::Socks5.secure());
        assert!(!Protocol::Socks5h.secure());
        assert!(!Protocol::Ws.secure());
        assert!(Protocol::Wss.secure());
        assert!(!Protocol::from_static("custom").secure());
    }

    #[test]
    fn test_try_to_extract_protocol_from_uri_scheme() {
        for (s, expected) in [
            ("", None),
            ("http://example.com", Some((Protocol::Http, 7))),
            ("https://example.com", Some((Protocol::Https, 8))),
            ("ws://example.com", Some((Protocol::Ws, 5))),
            ("wss://example.com", Some((Protocol::Wss, 6))),
            ("socks5://example.com", Some((Protocol::Socks5, 9))),
            ("socks5h://example.com", Some((Protocol::Socks5h, 10))),
            (
                "custom://example.com",
                Some((Protocol::from_static("custom"), 9)),
            ),
            (" http://example.com", None),
            ("longlonglongwaytoolongforsomethingusefulorvaliddontyouthinkmydearreader://example.com", None),
        ] {
            let result = try_to_extract_protocol_from_uri_scheme(s.as_bytes());
            match expected {
                Some(t) => match result {
                    Err(err) => panic!("unexpected err: {err} (case: {s}"),
                    Ok(p) => assert_eq!(t, p, "case: {}", s),
                },
                None => assert!(result.is_err(), "case: {}, result: {:?}", s, result),
            }
        }
    }
}
