use std::convert::Infallible;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// URL Schemes supported by `rama`.
///
/// This is used to determine the protocol of an incoming request,
/// and to ensure the entire chain can work with a sanatized scheme,
/// rather than having to deal with the raw string.
///
/// Please [file an issue or open a PR][repo] if you need more schemes.
/// When doing so please provide sufficient motivation and ensure
/// it has no unintended consequences.
///
/// [repo]: https://github.com/plabayo/rama
pub enum Scheme {
    /// An empty/missing scheme.
    Empty,
    /// The `http` scheme.
    Http,
    /// The `https` scheme.
    Https,
    /// The `ws` scheme.
    ///
    /// (Websocket over HTTP)
    /// <https://datatracker.ietf.org/doc/html/rfc6455>
    Ws,
    /// The `wss` scheme.
    ///
    /// (Websocket over HTTPS)
    /// <https://datatracker.ietf.org/doc/html/rfc6455>
    Wss,
    /// Custom scheme.
    Custom(String),
}

impl Scheme {
    /// Returns `true` if the scheme indicates a secure protocol.
    pub fn secure(&self) -> bool {
        match self {
            Scheme::Https | Scheme::Wss => true,
            Scheme::Empty | Scheme::Ws | Scheme::Http | Scheme::Custom(_) => false,
        }
    }
}

impl FromStr for Scheme {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Infallible> {
        Ok(match_ignore_ascii_case_str! {
            match (s) {
                "http" => Scheme::Http,
                "https" => Scheme::Https,
                "ws" => Scheme::Ws,
                "wss" => Scheme::Wss,
                "" => Scheme::Empty,
                _ => Scheme::Custom(s.to_owned()),
            }
        })
    }
}

impl From<crate::http::Scheme> for Scheme {
    #[inline]
    fn from(s: crate::http::Scheme) -> Self {
        Self::from(&s)
    }
}

impl From<&crate::http::Scheme> for Scheme {
    fn from(s: &crate::http::Scheme) -> Self {
        if s == &crate::http::Scheme::HTTP {
            Scheme::Http
        } else if s == &crate::http::Scheme::HTTPS {
            Scheme::Https
        } else if s == "ws" {
            Scheme::Ws
        } else if s == "wss" {
            Scheme::Wss
        } else if s == "" {
            Scheme::Empty
        } else {
            Scheme::Custom(s.to_string())
        }
    }
}

impl From<Option<crate::http::Scheme>> for Scheme {
    fn from(s: Option<crate::http::Scheme>) -> Self {
        match s {
            Some(s) => s.into(),
            None => Scheme::Empty,
        }
    }
}

impl From<Option<&crate::http::Scheme>> for Scheme {
    fn from(s: Option<&crate::http::Scheme>) -> Self {
        match s {
            Some(s) => s.into(),
            None => Scheme::Empty,
        }
    }
}

impl PartialEq<&str> for Scheme {
    fn eq(&self, other: &&str) -> bool {
        match self {
            Scheme::Empty => other.is_empty(),
            Scheme::Http => other.eq_ignore_ascii_case("http"),
            Scheme::Https => other.eq_ignore_ascii_case("https"),
            Scheme::Ws => other.eq_ignore_ascii_case("ws"),
            Scheme::Wss => other.eq_ignore_ascii_case("wss"),
            Scheme::Custom(s) => other.eq_ignore_ascii_case(s),
        }
    }
}

impl PartialEq<Scheme> for &str {
    fn eq(&self, other: &Scheme) -> bool {
        other.eq(self)
    }
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scheme::Empty => f.write_str(""),
            Scheme::Http => f.write_str("http"),
            Scheme::Https => f.write_str("https"),
            Scheme::Ws => f.write_str("ws"),
            Scheme::Wss => f.write_str("wss"),
            Scheme::Custom(s) => f.write_str(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        assert_eq!("http".parse(), Ok(Scheme::Http));
        assert_eq!("https".parse(), Ok(Scheme::Https));
        assert_eq!("ws".parse(), Ok(Scheme::Ws));
        assert_eq!("wss".parse(), Ok(Scheme::Wss));
        assert_eq!("".parse(), Ok(Scheme::Empty));
        assert_eq!("custom".parse(), Ok(Scheme::Custom("custom".to_owned())));
    }

    #[test]
    fn test_from_http_scheme() {
        for s in ["http", "https", "ws", "wss", "", "custom"].iter() {
            let uri = crate::http::Uri::from_str(format!("{}://example.com", s).as_str()).unwrap();
            assert_eq!(Scheme::from(uri.scheme()), *s);
        }
    }

    #[test]
    fn test_scheme_secure() {
        assert!(!Scheme::Http.secure());
        assert!(Scheme::Https.secure());
        assert!(!Scheme::Ws.secure());
        assert!(Scheme::Wss.secure());
        assert!(!Scheme::Empty.secure());
        assert!(!Scheme::Custom("custom".to_owned()).secure());
    }
}
