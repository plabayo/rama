use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// <https://tools.ietf.org/html/rfc6455>
    Ws,
    /// The `wss` scheme.
    ///
    /// (Websocket over HTTPS)
    /// <https://tools.ietf.org/html/rfc6455>
    Wss,
}

impl FromStr for Scheme {
    type Err = UnknownSchemeError;

    fn from_str(s: &str) -> Result<Self, UnknownSchemeError> {
        Ok(match_ignore_ascii_case_str! {
            match (s) {
                "http" => Scheme::Http,
                "https" => Scheme::Https,
                "ws" => Scheme::Ws,
                "wss" => Scheme::Wss,
                "" => Scheme::Empty,
                _ => return Err(UnknownSchemeError),
            }
        })
    }
}

impl TryFrom<crate::http::Scheme> for Scheme {
    type Error = UnknownSchemeError;

    #[inline]
    fn try_from(s: crate::http::Scheme) -> Result<Self, UnknownSchemeError> {
        Self::try_from(&s)
    }
}

impl TryFrom<&crate::http::Scheme> for Scheme {
    type Error = UnknownSchemeError;

    fn try_from(s: &crate::http::Scheme) -> Result<Self, UnknownSchemeError> {
        Ok(if s == &crate::http::Scheme::HTTP {
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
            return Err(UnknownSchemeError);
        })
    }
}

// TODO: add tests for `FromStr` and `TryFrom<crate::http::Scheme>`

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Error type for when an unknown [`Scheme`] is trying to be parsed.
pub struct UnknownSchemeError;

impl std::fmt::Display for UnknownSchemeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unknown (url) scheme")
    }
}

impl std::error::Error for UnknownSchemeError {}
