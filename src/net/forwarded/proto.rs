use crate::__eq_ignore_ascii_case as eq_ignore_ascii_case;
use crate::net::Protocol;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ProtocolKind {
    /// The `http` protocol.
    Http,
    /// The `https` protocol.
    Https,
}

const HTTP_STR: &str = "http";
const HTTPS_STR: &str = "https";

impl ForwardedProtocol {
    /// `HTTP` protocol.
    pub const HTTP: ForwardedProtocol = ForwardedProtocol(ProtocolKind::Http);

    /// `HTTPS` protocol.
    pub const HTTPS: ForwardedProtocol = ForwardedProtocol(ProtocolKind::Https);

    /// Returns `true` if this protocol is http(s).
    pub fn is_http(&self) -> bool {
        match &self.0 {
            ProtocolKind::Http | ProtocolKind::Https => true,
        }
    }

    /// Returns `true` if this protocol is "secure" by itself.
    pub fn is_secure(&self) -> bool {
        match self.0 {
            ProtocolKind::Https => true,
            ProtocolKind::Http => false,
        }
    }

    /// Returns the scheme str for this protocol.
    pub fn as_scheme(&self) -> &str {
        match &self.0 {
            ProtocolKind::Https => HTTPS_STR,
            ProtocolKind::Http => HTTP_STR,
        }
    }

    #[inline]
    /// Consumes the protocol and returns a [`Protocol`].
    pub fn into_protocol(self) -> Protocol {
        self.into()
    }

    /// Returns the [`ForwardedProtocol`] as a string.
    pub fn as_str(&self) -> &str {
        match &self.0 {
            ProtocolKind::Https => HTTPS_STR,
            ProtocolKind::Http => HTTP_STR,
        }
    }
}

impl From<ForwardedProtocol> for Protocol {
    fn from(p: ForwardedProtocol) -> Self {
        match p.0 {
            ProtocolKind::Https => Protocol::HTTPS,
            ProtocolKind::Http => Protocol::HTTP,
        }
    }
}

crate::__static_str_error! {
    #[doc = "unknown protocol"]
    pub struct UnknownProtocol;
}

impl TryFrom<Protocol> for ForwardedProtocol {
    type Error = UnknownProtocol;

    fn try_from(p: Protocol) -> Result<Self, Self::Error> {
        if p.is_http() {
            if p.is_secure() {
                Ok(ForwardedProtocol(ProtocolKind::Https))
            } else {
                Ok(ForwardedProtocol(ProtocolKind::Http))
            }
        } else {
            Err(UnknownProtocol)
        }
    }
}

impl TryFrom<&Protocol> for ForwardedProtocol {
    type Error = UnknownProtocol;

    fn try_from(p: &Protocol) -> Result<Self, Self::Error> {
        if p.is_http() {
            if p.is_secure() {
                Ok(ForwardedProtocol(ProtocolKind::Https))
            } else {
                Ok(ForwardedProtocol(ProtocolKind::Http))
            }
        } else {
            Err(UnknownProtocol)
        }
    }
}

crate::__static_str_error! {
    #[doc = "invalid forwarded protocol string"]
    pub struct InvalidProtocolStr;
}

impl TryFrom<&str> for ForwardedProtocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if eq_ignore_ascii_case!(s, HTTP_STR) {
            Ok(ForwardedProtocol(ProtocolKind::Http))
        } else if eq_ignore_ascii_case!(s, HTTPS_STR) {
            Ok(ForwardedProtocol(ProtocolKind::Https))
        } else {
            Err(InvalidProtocolStr)
        }
    }
}

impl TryFrom<String> for ForwardedProtocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

impl TryFrom<&String> for ForwardedProtocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: &String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
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
            ProtocolKind::Https => other.eq_ignore_ascii_case(HTTPS_STR),
            ProtocolKind::Http => other.eq_ignore_ascii_case(HTTP_STR) || other.is_empty(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_from_str() {
        assert_eq!("http".parse(), Ok(ForwardedProtocol::HTTP));
        assert_eq!("https".parse(), Ok(ForwardedProtocol::HTTPS));
    }

    #[test]
    fn test_protocol_secure() {
        assert!(!ForwardedProtocol::HTTP.is_secure());
        assert!(ForwardedProtocol::HTTPS.is_secure());
    }
}
