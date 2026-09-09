use core::{cmp::min, str::FromStr};

use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    extensions::Extension,
};
use rama_utils::{macros::str::eq_ignore_ascii_case, str::smol_str::SmolStr};

use crate::std::string::String;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Extension)]
#[extension(tags(net))]
/// Web protocols that are relevant to Rama.
///
/// Please [file an issue or open a PR][repo] if you need support for more protocols.
/// When doing so please provide sufficient motivation and ensure
/// it has no unintended consequences.
///
/// [repo]: https://github.com/plabayo/rama
pub struct Protocol(ProtocolKind);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
enum ProtocolKind {
    /// The `http` protocol.
    Http,
    /// The `https` protocol.
    Https,
    /// The `icap` protocol.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc3507>
    Icap,
    /// Direct TLS transport for ICAP, conventionally spelled `icaps`.
    ///
    /// RFC 3507 defines TLS negotiation through Upgrade rather than a secure
    /// URI scheme. Direct TLS and the `icaps` spelling are deployment
    /// conventions, not IANA-registered protocol elements.
    Icaps,
    /// The `ws` protocol.
    ///
    /// (WebSocket over HTTP)
    /// <https://datatracker.ietf.org/doc/html/rfc6455>
    Ws,
    /// The `wss` protocol.
    ///
    /// (WebSocket over HTTPS)
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
    /// The `file` protocol. Local-filesystem URI scheme — the
    /// `hier-part` is an absolute path on the host running the URI
    /// consumer; nothing is sent over the network. Defined by
    /// [RFC 8089](https://datatracker.ietf.org/doc/html/rfc8089).
    ///
    /// Has no default port — `file:` is not a network protocol.
    File,
    /// The `data` protocol. The URI carries its own payload
    /// (`data:[<mediatype>][;base64],<data>`); consumers decode it in
    /// place instead of dialing or opening anything. Defined by
    /// [RFC 2397](https://datatracker.ietf.org/doc/html/rfc2397).
    ///
    /// Has no default port — `data:` is not a network protocol.
    Data,
    /// Custom protocol.
    Custom(SmolStr),
}

impl Protocol {
    /// `HTTP` protocol scheme
    pub const HTTP_SCHEME: &str = "http";

    /// `HTTP` protocol default port
    pub const HTTP_DEFAULT_PORT: u16 = 80;

    /// Common alternate `HTTP` protocol port.
    pub const HTTP_ALT_PORT: u16 = 8080;

    /// Common default port for an HTTP proxy address without an explicit port.
    ///
    /// This follows the long-standing curl proxy-address convention. It is
    /// distinct from [`HTTP_DEFAULT_PORT`][Self::HTTP_DEFAULT_PORT], which is
    /// the default port for an HTTP origin server.
    pub const HTTP_PROXY_DEFAULT_PORT: u16 = 1080;

    /// `HTTP` protocol.
    pub const HTTP: Self = Self(ProtocolKind::Http);

    /// `HTTPS` protocol scheme
    pub const HTTPS_SCHEME: &str = "https";

    /// `HTTPS` protocol default port
    pub const HTTPS_DEFAULT_PORT: u16 = 443;

    /// Common alternate `HTTPS` protocol port.
    pub const HTTPS_ALT_PORT: u16 = 8443;

    /// `HTTPS` protocol.
    pub const HTTPS: Self = Self(ProtocolKind::Https);

    /// `ICAP` protocol scheme.
    pub const ICAP_SCHEME: &str = "icap";

    /// `ICAP` protocol default port.
    pub const ICAP_DEFAULT_PORT: u16 = 1344;

    /// `ICAP` protocol.
    pub const ICAP: Self = Self(ProtocolKind::Icap);

    /// Direct TLS `ICAP` protocol scheme.
    ///
    /// This is a deployed convention and is not registered by IANA.
    pub const ICAPS_SCHEME: &str = "icaps";

    /// Conventional direct TLS `ICAP` protocol default port.
    ///
    /// Port 11344 is widely deployed but is not assigned by RFC 3507.
    pub const ICAPS_DEFAULT_PORT: u16 = 11344;

    /// Direct TLS `ICAP` protocol.
    pub const ICAPS: Self = Self(ProtocolKind::Icaps);

    /// `WS` protocol scheme
    pub const WS_SCHEME: &str = "ws";

    /// `WS` protocol default port
    pub const WS_DEFAULT_PORT: u16 = Self::HTTP_DEFAULT_PORT;

    /// `WS` protocol.
    pub const WS: Self = Self(ProtocolKind::Ws);

    /// `WSS` protocol scheme
    pub const WSS_SCHEME: &str = "wss";

    /// `WSS` protocol default port
    pub const WSS_DEFAULT_PORT: u16 = Self::HTTPS_DEFAULT_PORT;

    /// `WSS` protocol.
    pub const WSS: Self = Self(ProtocolKind::Wss);

    /// `SOCKS5` protocol scheme
    pub const SOCKS5_SCHEME: &str = "socks5";

    /// `SOCKS5` protocol default port
    pub const SOCKS5_DEFAULT_PORT: u16 = 1080;

    /// `SOCKS5` protocol.
    pub const SOCKS5: Self = Self(ProtocolKind::Socks5);

    /// `SOCKS5H` protocol scheme
    pub const SOCKS5H_SCHEME: &str = "socks5h";

    /// `SOCKS5H` protocol default port
    pub const SOCKS5H_DEFAULT_PORT: u16 = Self::SOCKS5_DEFAULT_PORT;

    /// `SOCKS5H` protocol.
    pub const SOCKS5H: Self = Self(ProtocolKind::Socks5h);

    /// `FILE` protocol scheme. RFC 8089 — `file:///path/to/x`.
    pub const FILE_SCHEME: &str = "file";

    /// The `file` protocol. Local-filesystem URI scheme: the URI
    /// references a path on the host running the URI consumer.
    /// Consumers (CLI tools, file fetchers) open the path directly
    /// rather than dialing a network endpoint.
    pub const FILE: Self = Self(ProtocolKind::File);

    /// `DATA` protocol scheme. RFC 2397 — `data:[<mediatype>][;base64],<data>`.
    pub const DATA_SCHEME: &str = "data";

    /// The `data` protocol. Self-contained URI scheme: the URI itself
    /// carries the payload, which consumers decode in place rather
    /// than dialing a network endpoint or opening a file.
    pub const DATA: Self = Self(ProtocolKind::Data);

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
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "static-str invariant: panic at compile time when the static is not a valid protocol"
    )]
    pub const fn from_static(s: &'static str) -> Self {
        // NOTE: once unwrapping is possible in const we can piggy back on
        // `try_to_convert_str_to_non_custom_protocol`

        Self(if eq_ignore_ascii_case!(s, Self::HTTPS_SCHEME) {
            ProtocolKind::Https
        } else if eq_ignore_ascii_case!(s, Self::HTTP_SCHEME) {
            ProtocolKind::Http
        } else if eq_ignore_ascii_case!(s, Self::ICAP_SCHEME) {
            ProtocolKind::Icap
        } else if eq_ignore_ascii_case!(s, Self::ICAPS_SCHEME) {
            ProtocolKind::Icaps
        } else if eq_ignore_ascii_case!(s, Self::SOCKS5_SCHEME) {
            ProtocolKind::Socks5
        } else if eq_ignore_ascii_case!(s, Self::SOCKS5H_SCHEME) {
            ProtocolKind::Socks5h
        } else if eq_ignore_ascii_case!(s, Self::WS_SCHEME) {
            ProtocolKind::Ws
        } else if eq_ignore_ascii_case!(s, Self::WSS_SCHEME) {
            ProtocolKind::Wss
        } else if eq_ignore_ascii_case!(s, Self::FILE_SCHEME) {
            ProtocolKind::File
        } else if eq_ignore_ascii_case!(s, Self::DATA_SCHEME) {
            ProtocolKind::Data
        } else if validate_scheme_str(s) {
            ProtocolKind::Custom(SmolStr::new_static(s))
        } else {
            panic!("invalid static protocol str");
        })
    }

    /// Returns `true` if this protocol is http(s).
    #[must_use]
    pub fn is_http(&self) -> bool {
        match &self.0 {
            ProtocolKind::Http | ProtocolKind::Https => true,
            ProtocolKind::Ws
            | ProtocolKind::Wss
            | ProtocolKind::Icap
            | ProtocolKind::Icaps
            | ProtocolKind::Socks5
            | ProtocolKind::Socks5h
            | ProtocolKind::File
            | ProtocolKind::Data
            | ProtocolKind::Custom(_) => false,
        }
    }

    /// Returns `true` if this protocol is ws(s).
    #[must_use]
    pub fn is_ws(&self) -> bool {
        match &self.0 {
            ProtocolKind::Ws | ProtocolKind::Wss => true,
            ProtocolKind::Http
            | ProtocolKind::Https
            | ProtocolKind::Icap
            | ProtocolKind::Icaps
            | ProtocolKind::Socks5
            | ProtocolKind::Socks5h
            | ProtocolKind::File
            | ProtocolKind::Data
            | ProtocolKind::Custom(_) => false,
        }
    }

    /// Returns `true` for application protocols implemented on top of HTTP.
    ///
    /// The HTTP version and transport are orthogonal to this classification:
    /// HTTP/3 is still HTTP-based even though it runs over QUIC.
    #[must_use]
    pub fn is_http_based(&self) -> bool {
        match &self.0 {
            ProtocolKind::Http | ProtocolKind::Https | ProtocolKind::Ws | ProtocolKind::Wss => true,
            ProtocolKind::Icap
            | ProtocolKind::Icaps
            | ProtocolKind::Socks5
            | ProtocolKind::Socks5h
            | ProtocolKind::File
            | ProtocolKind::Data
            | ProtocolKind::Custom(_) => false,
        }
    }

    /// Returns `true` if this protocol is socks5.
    #[must_use]
    pub fn is_socks5(&self) -> bool {
        match &self.0 {
            ProtocolKind::Socks5 | ProtocolKind::Socks5h => true,
            ProtocolKind::Http
            | ProtocolKind::Https
            | ProtocolKind::Icap
            | ProtocolKind::Icaps
            | ProtocolKind::Ws
            | ProtocolKind::Wss
            | ProtocolKind::File
            | ProtocolKind::Data
            | ProtocolKind::Custom(_) => false,
        }
    }

    /// Returns `true` if this protocol is ICAP.
    #[must_use]
    pub fn is_icap(&self) -> bool {
        match &self.0 {
            ProtocolKind::Icap | ProtocolKind::Icaps => true,
            ProtocolKind::Http
            | ProtocolKind::Https
            | ProtocolKind::Ws
            | ProtocolKind::Wss
            | ProtocolKind::Socks5
            | ProtocolKind::Socks5h
            | ProtocolKind::File
            | ProtocolKind::Data
            | ProtocolKind::Custom(_) => false,
        }
    }

    /// Returns `true` if this protocol is "secure" by itself.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        match &self.0 {
            ProtocolKind::Https | ProtocolKind::Wss | ProtocolKind::Icaps => true,
            ProtocolKind::Ws
            | ProtocolKind::Http
            | ProtocolKind::Icap
            | ProtocolKind::Socks5
            | ProtocolKind::Socks5h
            | ProtocolKind::File
            | ProtocolKind::Data
            | ProtocolKind::Custom(_) => false,
        }
    }

    /// Returns the default port for this [`Protocol`].
    ///
    /// Modeled defaults: `http=80`, `https=443`, `ws=80`, `wss=443`,
    /// `socks5=1080`, `socks5h=1080`, `icap=1344`, and the conventional
    /// direct-TLS `icaps=11344`. Other schemes (`ftp:21`, `ssh:22`,
    /// `ldap:389`, …) return `None` — `Protocol`'s scope is the web-protocol
    /// set rama actively models.
    /// [`crate::uri::Uri::canonicalize`] only drops ports that match a
    /// modeled default, so `ftp://host:21/` keeps its `:21`. This
    /// diverges from WHATWG-URL (which strips `ftp:21`).
    ///
    /// The set of supported protocols grows with the needs that justify them.
    #[must_use]
    pub fn default_port(&self) -> Option<u16> {
        match &self.0 {
            ProtocolKind::Https => Some(Self::HTTPS_DEFAULT_PORT),
            ProtocolKind::Wss => Some(Self::WSS_DEFAULT_PORT),
            ProtocolKind::Http => Some(Self::HTTP_DEFAULT_PORT),
            ProtocolKind::Ws => Some(Self::WS_DEFAULT_PORT),
            ProtocolKind::Icap => Some(Self::ICAP_DEFAULT_PORT),
            ProtocolKind::Icaps => Some(Self::ICAPS_DEFAULT_PORT),
            ProtocolKind::Socks5 => Some(Self::SOCKS5_DEFAULT_PORT),
            ProtocolKind::Socks5h => Some(Self::SOCKS5H_DEFAULT_PORT),
            // `file:`/`data:` are not network protocols — no default port.
            ProtocolKind::File | ProtocolKind::Data | ProtocolKind::Custom(_) => None,
        }
    }

    /// Returns the default port when this protocol is used to reach a proxy.
    ///
    /// An HTTP proxy URL follows the long-standing curl convention of port
    /// 1080 when its authority omits a port. HTTPS, SOCKS5, and SOCKS5H use
    /// their protocol defaults. Other protocols do not have an implicit proxy
    /// port.
    #[must_use]
    pub fn proxy_default_port(&self) -> Option<u16> {
        match &self.0 {
            ProtocolKind::Http => Some(Self::HTTP_PROXY_DEFAULT_PORT),
            ProtocolKind::Https => Some(Self::HTTPS_DEFAULT_PORT),
            ProtocolKind::Socks5 => Some(Self::SOCKS5_DEFAULT_PORT),
            ProtocolKind::Socks5h => Some(Self::SOCKS5H_DEFAULT_PORT),
            ProtocolKind::Ws
            | ProtocolKind::Wss
            | ProtocolKind::Icap
            | ProtocolKind::Icaps
            | ProtocolKind::File
            | ProtocolKind::Data
            | ProtocolKind::Custom(_) => None,
        }
    }

    /// Returns the [`Protocol`] as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            ProtocolKind::Http => Self::HTTP_SCHEME,
            ProtocolKind::Https => Self::HTTPS_SCHEME,
            ProtocolKind::Icap => Self::ICAP_SCHEME,
            ProtocolKind::Icaps => Self::ICAPS_SCHEME,
            ProtocolKind::Ws => Self::WS_SCHEME,
            ProtocolKind::Wss => Self::WSS_SCHEME,
            ProtocolKind::Socks5 => Self::SOCKS5_SCHEME,
            ProtocolKind::Socks5h => Self::SOCKS5H_SCHEME,
            ProtocolKind::File => Self::FILE_SCHEME,
            ProtocolKind::Data => Self::DATA_SCHEME,
            ProtocolKind::Custom(s) => s.as_ref(),
        }
    }

    /// Return the RFC 3986 canonical presentation of this scheme.
    ///
    /// Known protocols are stored canonically already. A custom scheme is
    /// ASCII-lowercased, allocating only when its presentation contains an
    /// uppercase letter.
    #[must_use]
    pub fn canonicalize(self) -> Self {
        match self.0 {
            ProtocolKind::Custom(scheme)
                if scheme.bytes().any(|byte| byte.is_ascii_uppercase()) =>
            {
                Self(ProtocolKind::Custom(SmolStr::new(
                    scheme.to_ascii_lowercase(),
                )))
            }
            _ => self,
        }
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "invalid protocol string"]
    pub struct InvalidProtocolStr;
}

fn try_to_convert_str_to_non_custom_protocol(
    s: &str,
) -> Result<Option<Protocol>, InvalidProtocolStr> {
    Ok(Some(Protocol(
        if eq_ignore_ascii_case!(s, Protocol::HTTPS_SCHEME) {
            ProtocolKind::Https
        } else if eq_ignore_ascii_case!(s, Protocol::HTTP_SCHEME) {
            ProtocolKind::Http
        } else if eq_ignore_ascii_case!(s, Protocol::ICAP_SCHEME) {
            ProtocolKind::Icap
        } else if eq_ignore_ascii_case!(s, Protocol::ICAPS_SCHEME) {
            ProtocolKind::Icaps
        } else if eq_ignore_ascii_case!(s, Protocol::SOCKS5_SCHEME) {
            ProtocolKind::Socks5
        } else if eq_ignore_ascii_case!(s, Protocol::SOCKS5H_SCHEME) {
            ProtocolKind::Socks5h
        } else if eq_ignore_ascii_case!(s, Protocol::WS_SCHEME) {
            ProtocolKind::Ws
        } else if eq_ignore_ascii_case!(s, Protocol::WSS_SCHEME) {
            ProtocolKind::Wss
        } else if eq_ignore_ascii_case!(s, Protocol::FILE_SCHEME) {
            ProtocolKind::File
        } else if eq_ignore_ascii_case!(s, Protocol::DATA_SCHEME) {
            ProtocolKind::Data
        } else if validate_scheme_str(s) {
            return Ok(None);
        } else {
            return Err(InvalidProtocolStr);
        },
    )))
}

impl TryFrom<&str> for Protocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        // `SmolStr::new` — *not* `new_inline`. `new_inline` panics if the
        // input exceeds the 23-byte inline cap; the URI parser does not
        // cap scheme length (RFC 3986 doesn't either), so a custom scheme
        // > 23 bytes is a valid graceful input and must not abort.
        Ok(try_to_convert_str_to_non_custom_protocol(s)?
            .unwrap_or_else(|| Self(ProtocolKind::Custom(SmolStr::new(s)))))
    }
}

impl TryFrom<String> for Protocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(try_to_convert_str_to_non_custom_protocol(&s)?
            .unwrap_or(Self(ProtocolKind::Custom(SmolStr::new(s)))))
    }
}

impl TryFrom<&String> for Protocol {
    type Error = InvalidProtocolStr;

    fn try_from(s: &String) -> Result<Self, Self::Error> {
        Ok(try_to_convert_str_to_non_custom_protocol(s)?
            .unwrap_or_else(|| Self(ProtocolKind::Custom(SmolStr::new(s)))))
    }
}

impl FromStr for Protocol {
    type Err = InvalidProtocolStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl PartialEq<str> for Protocol {
    fn eq(&self, other: &str) -> bool {
        match &self.0 {
            ProtocolKind::Https => other.eq_ignore_ascii_case(Self::HTTPS_SCHEME),
            ProtocolKind::Http => other.eq_ignore_ascii_case(Self::HTTP_SCHEME) || other.is_empty(),
            ProtocolKind::Icap => other.eq_ignore_ascii_case(Self::ICAP_SCHEME),
            ProtocolKind::Icaps => other.eq_ignore_ascii_case(Self::ICAPS_SCHEME),
            ProtocolKind::Socks5 => other.eq_ignore_ascii_case(Self::SOCKS5_SCHEME),
            ProtocolKind::Socks5h => other.eq_ignore_ascii_case(Self::SOCKS5H_SCHEME),
            ProtocolKind::Ws => other.eq_ignore_ascii_case(Self::WS_SCHEME),
            ProtocolKind::Wss => other.eq_ignore_ascii_case(Self::WSS_SCHEME),
            ProtocolKind::File => other.eq_ignore_ascii_case(Self::FILE_SCHEME),
            ProtocolKind::Data => other.eq_ignore_ascii_case(Self::DATA_SCHEME),
            ProtocolKind::Custom(s) => other.eq_ignore_ascii_case(s),
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
    #[inline(always)]
    fn eq(&self, other: &Protocol) -> bool {
        other == *self
    }
}

impl core::fmt::Display for Protocol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.as_str().fmt(f)
    }
}

pub(crate) fn try_to_extract_protocol_from_uri_scheme(
    s: &[u8],
) -> Result<(Option<Protocol>, usize), BoxError> {
    if s.is_empty() {
        return Err(BoxError::from_static_str("empty uri contains no scheme"));
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
                core::str::from_utf8(&s[..i]).context("interpret scheme bytes as utf-8 str")?;
            let protocol = str
                .try_into()
                .context("parse scheme utf-8 str as protocol")?;
            return Ok((Some(protocol), i + 3));
        }
    }

    Ok((None, 0))
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
pub(crate) const MAX_SCHEME_LEN: usize = 64;

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

rama_utils::macros::serde_str::impl_serde_str!(as_str Protocol);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        assert_eq!("http".parse(), Ok(Protocol::HTTP));
        assert_eq!("https".parse(), Ok(Protocol::HTTPS));
        assert_eq!("icap".parse(), Ok(Protocol::ICAP));
        assert_eq!("icaps".parse(), Ok(Protocol::ICAPS));
        assert_eq!("ws".parse(), Ok(Protocol::WS));
        assert_eq!("wss".parse(), Ok(Protocol::WSS));
        assert_eq!("socks5".parse(), Ok(Protocol::SOCKS5));
        assert_eq!("socks5h".parse(), Ok(Protocol::SOCKS5H));
        assert_eq!("file".parse(), Ok(Protocol::FILE));
        assert_eq!("data".parse(), Ok(Protocol::DATA));
        assert_eq!("custom".parse(), Ok(Protocol::from_static("custom")));
    }

    #[test]
    fn canonicalize_lowercases_custom_schemes() {
        assert_eq!(
            Protocol::from_static("CuStOm").canonicalize().as_str(),
            "custom"
        );
        assert_eq!(Protocol::HTTPS.canonicalize(), Protocol::HTTPS);
    }

    #[test]
    fn icap_protocol() {
        assert_eq!(Protocol::from_static("ICAP"), Protocol::ICAP);
        assert_eq!("ICAP".parse(), Ok(Protocol::ICAP));
        assert_eq!(Protocol::ICAP.as_str(), Protocol::ICAP_SCHEME);
        assert_eq!(
            Protocol::ICAP.default_port(),
            Some(Protocol::ICAP_DEFAULT_PORT)
        );
        assert!(Protocol::ICAP.is_icap());
        assert!(!Protocol::ICAP.is_http());
        assert!(!Protocol::ICAP.is_ws());
        assert!(!Protocol::ICAP.is_socks5());
        assert!(!Protocol::ICAP.is_secure());

        assert_eq!(Protocol::from_static("ICAPS"), Protocol::ICAPS);
        assert_eq!("ICAPS".parse(), Ok(Protocol::ICAPS));
        assert_eq!(Protocol::ICAPS.as_str(), Protocol::ICAPS_SCHEME);
        assert_eq!(
            Protocol::ICAPS.default_port(),
            Some(Protocol::ICAPS_DEFAULT_PORT)
        );
        assert!(Protocol::ICAPS.is_icap());
        assert!(!Protocol::ICAPS.is_http());
        assert!(!Protocol::ICAPS.is_ws());
        assert!(!Protocol::ICAPS.is_socks5());
        assert!(Protocol::ICAPS.is_secure());
    }

    #[test]
    fn test_non_network_schemes() {
        for (protocol, scheme) in [
            (Protocol::FILE, Protocol::FILE_SCHEME),
            (Protocol::DATA, Protocol::DATA_SCHEME),
        ] {
            // guards the const ladder against the runtime ladder drifting apart
            assert_eq!(Protocol::from_static(scheme), protocol);
            assert_eq!(scheme.parse(), Ok(protocol.clone()));
            assert_eq!(scheme.to_uppercase().parse(), Ok(protocol.clone()));
            assert_eq!(protocol.as_str(), scheme);
            assert_eq!(protocol.default_port(), None);
            assert!(!protocol.is_http());
            assert!(!protocol.is_ws());
            assert!(!protocol.is_socks5());
            assert!(!protocol.is_secure());
        }
    }

    #[test]
    fn proxy_default_ports_are_transport_specific() {
        for (protocol, expected) in [
            (Protocol::HTTP, Some(Protocol::HTTP_PROXY_DEFAULT_PORT)),
            (Protocol::HTTPS, Some(Protocol::HTTPS_DEFAULT_PORT)),
            (Protocol::SOCKS5, Some(Protocol::SOCKS5_DEFAULT_PORT)),
            (Protocol::SOCKS5H, Some(Protocol::SOCKS5H_DEFAULT_PORT)),
            (Protocol::WS, None),
            (Protocol::WSS, None),
            (Protocol::ICAP, None),
            (Protocol::ICAPS, None),
            (Protocol::FILE, None),
            (Protocol::DATA, None),
            (Protocol::from_static("custom"), None),
        ] {
            assert_eq!(protocol.proxy_default_port(), expected, "{protocol}");
        }
    }

    #[test]
    fn empty_scheme_rejected() {
        // Per RFC 3986 §3.1 `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-"
        // / "." )` — empty is not valid. Reject explicitly rather than
        // silently defaulting to HTTP.
        "".parse::<Protocol>().unwrap_err();
        Protocol::try_from("").unwrap_err();
    }

    #[test]
    fn try_from_rejects_non_ascii_scheme() {
        // RFC 3986 §3.1: scheme is ASCII only. `validate_scheme_str`
        // catches non-ASCII bytes via the byte-set LUT (all entries
        // above 0x7F are 0). Confirms the typed constructor enforces
        // the same constraint as the parser's per-byte byte-set check.
        Protocol::try_from("müncheme").unwrap_err();
        Protocol::try_from("ab cd").unwrap_err();
        Protocol::try_from("ab\0").unwrap_err();
        // Valid: ASCII alpha + sub-delims allowed by the scheme grammar.
        Protocol::try_from("git+ssh").unwrap();
        Protocol::try_from("coap+tcp").unwrap();
    }

    #[test]
    fn regression_custom_scheme_over_smolstr_inline_cap_does_not_panic() {
        // Uri-fuzzer regression: a 25-byte all-ASCII custom scheme is a
        // perfectly valid RFC 3986 scheme but exceeds `SmolStr`'s 23-byte
        // inline cap. `Protocol::try_from(&str)` previously used
        // `SmolStr::new_inline`, which panics over the cap. Now uses
        // `SmolStr::new`, which heap-allocates beyond the cap.
        let long = "hhhhhhahhhhhhhhhhhhhhhhhh"; // 25 bytes
        assert_eq!(long.len(), 25);
        let proto: Protocol = long.try_into().unwrap();
        assert_eq!(proto.as_str(), long);

        // Also exercise the parser path that the fuzzer hit.
        let uri: crate::uri::Uri = format!("{long}:/aq").parse().unwrap();
        assert_eq!(uri.scheme().unwrap().as_str(), long);
    }

    #[test]
    fn test_scheme_is_secure() {
        assert!(!Protocol::HTTP.is_secure());
        assert!(Protocol::HTTPS.is_secure());
        assert!(!Protocol::SOCKS5.is_secure());
        assert!(!Protocol::SOCKS5H.is_secure());
        assert!(!Protocol::ICAP.is_secure());
        assert!(Protocol::ICAPS.is_secure());
        assert!(!Protocol::WS.is_secure());
        assert!(Protocol::WSS.is_secure());
        assert!(!Protocol::FILE.is_secure());
        assert!(!Protocol::DATA.is_secure());
        assert!(!Protocol::from_static("custom").is_secure());
    }

    #[test]
    fn test_scheme_is_http_based() {
        for protocol in [Protocol::HTTP, Protocol::HTTPS, Protocol::WS, Protocol::WSS] {
            assert!(protocol.is_http_based(), "protocol: {protocol}");
        }
        for protocol in [
            Protocol::ICAP,
            Protocol::ICAPS,
            Protocol::SOCKS5,
            Protocol::SOCKS5H,
            Protocol::FILE,
            Protocol::DATA,
            Protocol::from_static("custom"),
        ] {
            assert!(!protocol.is_http_based(), "protocol: {protocol}");
        }
    }

    #[test]
    fn test_try_to_extract_protocol_from_uri_scheme() {
        for (s, expected) in [
            ("", None),
            ("http://example.com", Some((Some(Protocol::HTTP), 7))),
            ("https://example.com", Some((Some(Protocol::HTTPS), 8))),
            ("ws://example.com", Some((Some(Protocol::WS), 5))),
            ("wss://example.com", Some((Some(Protocol::WSS), 6))),
            ("icap://example.com", Some((Some(Protocol::ICAP), 7))),
            ("icaps://example.com", Some((Some(Protocol::ICAPS), 8))),
            ("socks5://example.com", Some((Some(Protocol::SOCKS5), 9))),
            ("socks5h://example.com", Some((Some(Protocol::SOCKS5H), 10))),
            (
                "custom://example.com",
                Some((Some(Protocol::from_static("custom")), 9)),
            ),
            (" http://example.com", None),
            ("example.com", Some((None, 0))),
            ("127.0.0.1", Some((None, 0))),
            ("127.0.0.1:8080", Some((None, 0))),
            (
                "longlonglongwaytoolongforsomethingusefulorvaliddontyouthinkmydearreader://example.com",
                None,
            ),
        ] {
            let result = try_to_extract_protocol_from_uri_scheme(s.as_bytes());
            match expected {
                Some(t) => match result {
                    Err(err) => panic!("unexpected err: {err} (case: {s}"),
                    Ok(p) => assert_eq!(t, p, "case: {s}"),
                },
                None => assert!(result.is_err(), "case: {s}, result: {result:?}"),
            }
        }
    }
}
