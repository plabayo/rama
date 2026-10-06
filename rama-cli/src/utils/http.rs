use rama::{
    error::{BoxError, BoxErrorExt, ErrorExt as _},
    http,
    utils::str::smol_str::StrExt,
};
use std::str::FromStr;

/// The HTTP versions served over TCP.
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub enum TcpHttpVersion {
    /// HTTP/1.1 and h2, negotiated through ALPN or detected from the connection preface.
    Auto,
    H1,
    H2,
}

impl From<TcpHttpVersion> for Option<http::Version> {
    fn from(value: TcpHttpVersion) -> Self {
        match value {
            TcpHttpVersion::Auto => None,
            TcpHttpVersion::H1 => Some(http::Version::HTTP_11),
            TcpHttpVersion::H2 => Some(http::Version::HTTP_2),
        }
    }
}

/// The HTTP versions a serve command offers: `auto`, or a comma separated list of `h1`, `h2`
/// and `h3`.
///
/// `auto` serves HTTP/1.1 and h2 over TCP and, when TLS is enabled, HTTP/3 over QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HttpVersions {
    tcp: Option<TcpHttpVersion>,
    h3: Http3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Http3 {
    Off,
    WithTls,
    On,
}

impl HttpVersions {
    /// Every version the transport allows.
    pub const AUTO: Self = Self {
        tcp: Some(TcpHttpVersion::Auto),
        h3: Http3::WithTls,
    };

    /// The versions served over TCP, if any.
    #[must_use]
    pub fn tcp(self) -> Option<TcpHttpVersion> {
        self.tcp
    }

    /// Whether `h3` was asked for by name, rather than implied by `auto`.
    #[must_use]
    pub fn http3_explicit(self) -> bool {
        matches!(self.h3, Http3::On)
    }

    /// Whether HTTP/3 is served, given whether TLS is enabled.
    ///
    /// Asking for `h3` explicitly without TLS is an error: HTTP/3 always runs over TLS.
    pub fn http3(self, tls: bool) -> Result<bool, BoxError> {
        match (self.h3, tls) {
            (Http3::Off, _) | (Http3::WithTls, false) => Ok(false),
            (Http3::WithTls | Http3::On, true) => Ok(true),
            (Http3::On, false) => Err(BoxError::from_static_str("HTTP/3 requires TLS")),
        }
    }
}

impl Default for HttpVersions {
    fn default() -> Self {
        Self::AUTO
    }
}

impl FromStr for HttpVersions {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_lowercase_smolstr();
        if matches!(s.as_str(), "" | "auto") {
            return Ok(Self::AUTO);
        }
        let (mut h1, mut h2, mut h3) = (false, false, false);
        for version in s.split(',').map(str::trim) {
            match version {
                "h1" | "http1" | "http/1" | "http/1.0" | "http/1.1" => h1 = true,
                "h2" | "http2" | "http/2" | "http/2.0" => h2 = true,
                "h3" | "http3" | "http/3" | "http/3.0" => h3 = true,
                version => {
                    return Err(BoxError::from_static_str("unsupported http version")
                        .context_str_field("version", version));
                }
            }
        }
        Ok(Self {
            tcp: match (h1, h2) {
                (true, true) => Some(TcpHttpVersion::Auto),
                (true, false) => Some(TcpHttpVersion::H1),
                (false, true) => Some(TcpHttpVersion::H2),
                (false, false) => None,
            },
            h3: if h3 { Http3::On } else { Http3::Off },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_serves_http3_only_with_tls() {
        for input in ["", "auto", " AUTO "] {
            let versions: HttpVersions = input.parse().unwrap();
            assert_eq!(versions, HttpVersions::AUTO);
            assert_eq!(versions.tcp(), Some(TcpHttpVersion::Auto));
            assert!(!versions.http3(false).unwrap());
            assert!(versions.http3(true).unwrap());
        }
    }

    #[test]
    fn lists_select_tcp_and_quic_versions() {
        for (input, tcp, h3) in [
            ("h1", Some(TcpHttpVersion::H1), false),
            ("http/1.1", Some(TcpHttpVersion::H1), false),
            ("h2", Some(TcpHttpVersion::H2), false),
            ("h1,h2", Some(TcpHttpVersion::Auto), false),
            ("h2, h1", Some(TcpHttpVersion::Auto), false),
            ("h3", None, true),
            ("http/3", None, true),
            ("h1,h3", Some(TcpHttpVersion::H1), true),
            ("h1,h2,h3", Some(TcpHttpVersion::Auto), true),
            ("h2,h2", Some(TcpHttpVersion::H2), false),
        ] {
            let versions: HttpVersions = input.parse().unwrap();
            assert_eq!(versions.tcp(), tcp, "{input}");
            assert_eq!(versions.http3(true).unwrap(), h3, "{input}");
        }
    }

    #[test]
    fn explicit_http3_requires_tls() {
        let versions: HttpVersions = "h1,h3".parse().unwrap();
        versions.http3(false).unwrap_err();
        let versions: HttpVersions = "h1,h2".parse().unwrap();
        assert!(!versions.http3(false).unwrap());
    }

    #[test]
    fn unknown_or_empty_versions_are_refused() {
        for input in ["h4", "h1,", ",h2", "auto,h1", "h1,,h2", "quic"] {
            input.parse::<HttpVersions>().unwrap_err();
        }
    }
}
