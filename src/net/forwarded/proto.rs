use crate::__eq_ignore_ascii_case as eq_ignore_ascii_case;
use crate::net::Protocol;
use std::borrow::Cow;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Protocols that were forwarded.
///
/// These are a subset of [`Protocol`].
///
/// Please [file an issue or open a PR][repo] if you need support for more protocols.
/// When doing so please provide sufficient motivation and ensure
/// it has no unintended consequences.
///
/// [repo]: https://github.com/plabayo/rama
pub struct ForwardedProtocol(ProtocolKind);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ProtocolKind {
    /// The `http` protocol.
    Http,
    /// The `https` protocol.
    Https,
    /// Custom protocol.
    Custom(Cow<'static, str>),
}

const SCHEME_HTTP: &str = "http";
const SCHEME_HTTPS: &str = "https";

impl ForwardedProtocol {
    /// Creates a ForwardedProtocol from a str a compile time.
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

        ForwardedProtocol(if eq_ignore_ascii_case!(s, SCHEME_HTTPS) {
            ProtocolKind::Https
        } else if s.is_empty() || eq_ignore_ascii_case!(s, SCHEME_HTTP) {
            ProtocolKind::Http
        } else if validate_scheme_str(s) {
            ProtocolKind::Custom(Cow::Borrowed(s))
        } else {
            panic!("invalid static protocol str");
        })
    }

    /// Create a new http protocol.
    pub fn http() -> Self {
        Self(ProtocolKind::Http)
    }

    /// Create a new https protocol.
    pub fn https() -> Self {
        Self(ProtocolKind::Https)
    }

    /// Returns `true` if this protocol is http(s).
    pub fn is_http(&self) -> bool {
        match &self.0 {
            ProtocolKind::Http | ProtocolKind::Https => true,
            ProtocolKind::Custom(_) => false,
        }
    }

    /// Returns `true` if this protocol is "secure" by itself.
    pub fn is_secure(&self) -> bool {
        match self.0 {
            ProtocolKind::Https => true,
            ProtocolKind::Http | ProtocolKind::Custom(_) => false,
        }
    }

    /// Returns the scheme str for this protocol.
    pub fn as_scheme(&self) -> &str {
        match &self.0 {
            ProtocolKind::Https => SCHEME_HTTPS,
            ProtocolKind::Http => SCHEME_HTTP,
            ProtocolKind::Custom(s) => s.as_ref(),
        }
    }

    #[inline]
    /// Consumes the protocol and returns a [`Protocol`].
    pub fn into_protocol(self) -> Protocol {
        self.into()
    }

    /// Return a port that can be used as default in case no port is defined.
    ///
    /// NOTE that this is not going to be valid for non-http ports.
    pub fn default_port(&self) -> u16 {
        match self.0 {
            ProtocolKind::Https => 443,
            ProtocolKind::Http => 80,
            ProtocolKind::Custom(_) => 80, // \_(ツ)_/¯
        }
    }

    /// Returns the [`ForwardedProtocol`] as a string.
    pub fn as_str(&self) -> &str {
        match &self.0 {
            ProtocolKind::Https => SCHEME_HTTPS,
            ProtocolKind::Http => SCHEME_HTTP,
            ProtocolKind::Custom(s) => s.as_ref(),
        }
    }
}

impl From<ForwardedProtocol> for Protocol {
    fn from(p: ForwardedProtocol) -> Self {
        match p.0 {
            ProtocolKind::Https => Protocol::Https,
            ProtocolKind::Http => Protocol::Http,
            ProtocolKind::Custom(s) => {
                Protocol::try_from(s.to_string()).expect("always to be valid")
            }
        }
    }
}

impl From<Protocol> for ForwardedProtocol {
    fn from(value: Protocol) -> Self {
        ForwardedProtocol(match value {
            Protocol::Http => ProtocolKind::Http,
            Protocol::Https => ProtocolKind::Https,
            // We assume that all protocols are valid Fowarded Protocols, which is fair enough
            _ => ProtocolKind::Custom(value.to_string().into()),
        })
    }
}

crate::__static_str_error! {
    #[doc = "invalid fowarded protocol string"]
    pub struct InvalidProtocolStr;
}

fn try_to_convert_str_to_non_custom_protocol(
    s: &str,
) -> Result<Option<ForwardedProtocol>, InvalidProtocolStr> {
    Ok(Some(ForwardedProtocol(
        if eq_ignore_ascii_case!(s, SCHEME_HTTPS) {
            ProtocolKind::Https
        } else if s.is_empty() || eq_ignore_ascii_case!(s, SCHEME_HTTP) {
            ProtocolKind::Http
        } else if validate_scheme_str(s) {
            return Ok(None);
        } else {
            return Err(InvalidProtocolStr);
        },
    )))
}

impl TryFrom<&str> for ForwardedProtocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(try_to_convert_str_to_non_custom_protocol(s)?
            .unwrap_or_else(|| ForwardedProtocol(ProtocolKind::Custom(Cow::Owned(s.to_owned())))))
    }
}

impl TryFrom<String> for ForwardedProtocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(try_to_convert_str_to_non_custom_protocol(&s)?
            .unwrap_or(ForwardedProtocol(ProtocolKind::Custom(Cow::Owned(s)))))
    }
}

impl TryFrom<&String> for ForwardedProtocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: &String) -> Result<Self, Self::Error> {
        Ok(try_to_convert_str_to_non_custom_protocol(s)?
            .unwrap_or_else(|| ForwardedProtocol(ProtocolKind::Custom(Cow::Owned(s.clone())))))
    }
}

impl FromStr for ForwardedProtocol {
    type Err = InvalidProtocolStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl PartialEq<str> for ForwardedProtocol {
    fn eq(&self, other: &str) -> bool {
        match &self.0 {
            ProtocolKind::Https => other.eq_ignore_ascii_case(SCHEME_HTTPS),
            ProtocolKind::Http => other.eq_ignore_ascii_case(SCHEME_HTTP) || other.is_empty(),
            ProtocolKind::Custom(s) => other.eq_ignore_ascii_case(s),
        }
    }
}

impl PartialEq<String> for ForwardedProtocol {
    fn eq(&self, other: &String) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<&str> for ForwardedProtocol {
    fn eq(&self, other: &&str) -> bool {
        self == *other
    }
}

impl PartialEq<ForwardedProtocol> for str {
    fn eq(&self, other: &ForwardedProtocol) -> bool {
        other == self
    }
}

impl PartialEq<ForwardedProtocol> for String {
    fn eq(&self, other: &ForwardedProtocol) -> bool {
        other == self.as_str()
    }
}

impl PartialEq<ForwardedProtocol> for &str {
    fn eq(&self, other: &ForwardedProtocol) -> bool {
        other == *self
    }
}

impl std::fmt::Display for ForwardedProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_scheme().fmt(f)
    }
}

impl PartialEq<ForwardedProtocol> for Protocol {
    fn eq(&self, other: &ForwardedProtocol) -> bool {
        match self {
            Protocol::Https => other.0 == ProtocolKind::Https,
            Protocol::Http => other.0 == ProtocolKind::Http,
            _ => eq_ignore_ascii_case!(self.as_str(), other.as_str()),
        }
    }
}

impl PartialEq<Protocol> for ForwardedProtocol {
    fn eq(&self, other: &Protocol) -> bool {
        other == self
    }
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
     b'2',  b'3',  b'4',  b'5',  b'6',  b'7',  b'8',  b'9',     0,     0, //  5x
        0,     0,     0,     0,     0,  b'A',  b'B',  b'C',  b'D',  b'E', //  6x
     b'F',  b'G',  b'H',  b'I',  b'J',  b'K',  b'L',  b'M',  b'N',  b'O', //  7x
     b'P',  b'Q',  b'R',  b'S',  b'T',  b'U',  b'V',  b'W',  b'X',  b'Y', //  8x
     b'Z',     0,     0,     0,     0,     0,     0,  b'a',  b'b',  b'c', //  9x
     b'd',  b'e',  b'f',  b'g',  b'h',  b'i',  b'j',  b'k',  b'l',  b'm', // 10x
     b'n',  b'o',  b'p',  b'q',  b'r',  b's',  b't',  b'u',  b'v',  b'w', // 11x
     b'x',  b'y',  b'z',     0,     0,     0,     0,     0,     0,     0, // 12x
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
    fn test_protocol_from_str() {
        assert_eq!("http".parse(), Ok(ForwardedProtocol::http()));
        assert_eq!("".parse(), Ok(ForwardedProtocol::http()));
        assert_eq!("https".parse(), Ok(ForwardedProtocol::https()));
        assert_eq!(
            "custom".parse(),
            Ok(ForwardedProtocol::from_static("custom"))
        );
    }

    #[test]
    fn test_protocol_secure() {
        assert!(!ForwardedProtocol::http().is_secure());
        assert!(ForwardedProtocol::https().is_secure());
        assert!(!ForwardedProtocol::from_static("custom").is_secure());
    }

    #[test]
    fn test_fowarded_protocol_to_protocol_and_back() {
        for protocol in [
            Protocol::Http,
            Protocol::Https,
            Protocol::Ws,
            Protocol::Socks5,
            Protocol::from_static("foo"),
        ] {
            let forwarded_protocol = ForwardedProtocol::from(protocol.clone());
            let output_protocol: Protocol = forwarded_protocol.into();
            assert_eq!(protocol, output_protocol);
        }
    }

    #[test]
    fn test_protocol_eq_fowarded_protocol() {
        for (protocol, forwarded_protocol) in [
            (Protocol::Http, ForwardedProtocol::http()),
            (Protocol::Https, ForwardedProtocol::https()),
            (Protocol::Ws, ForwardedProtocol::from_static("ws")),
            (Protocol::Socks5, ForwardedProtocol::from_static("socks5")),
            (
                Protocol::from_static("foo"),
                ForwardedProtocol::from_static("foo"),
            ),
        ] {
            assert_eq!(protocol, forwarded_protocol);
        }
    }
}
