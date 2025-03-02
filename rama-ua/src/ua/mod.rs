use rama_core::error::OpaqueError;
use rama_http_types::headers::ClientHint;
use rama_utils::macros::match_ignore_ascii_case_str;
use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, str::FromStr};

mod info;
pub use info::{
    DeviceKind, HttpAgent, PlatformKind, TlsAgent, UserAgent, UserAgentInfo, UserAgentKind,
};

mod parse;
use parse::parse_http_user_agent_header;
pub(crate) use parse::{contains_ignore_ascii_case, starts_with_ignore_ascii_case};

/// Information that can be used to overwrite the [`UserAgent`] of an http request.
///
/// Used by the `UserAgentClassifier` (see `rama-http`) to overwrite the specified
/// information duing the classification of the [`UserAgent`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserAgentOverwrites {
    /// Overwrite the [`UserAgent`] of the http `Request` with a custom value.
    ///
    /// This value will be used instead of
    /// the 'User-Agent' http (header) value.
    ///
    /// This is useful in case you cannot set the User-Agent header in your request.
    pub ua: Option<String>,
    /// Overwrite the [`HttpAgent`] of the http `Request` with a custom value.
    pub http: Option<HttpAgent>,
    /// Overwrite the [`TlsAgent`] of the http `Request` with a custom value.
    pub tls: Option<TlsAgent>,
    /// Preserve the original [`UserAgent`] header of the http `Request`.
    pub preserve_ua: Option<bool>,
    /// Requested (High-Entropy) Client Hints.
    pub req_client_hints: Option<Vec<ClientHint>>,
    /// Hint a specific request intiator for UA Emulation. A related
    /// or default initiator might be chosen in case the hinted one is not available.
    ///
    /// In case this hint is not specified it will be gussed for you instead based
    /// on the request method and headers.
    pub req_init: Option<RequestInitiator>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestInitiator {
    Navigate,
    Form,
    Xhr,
    Fetch,
}

impl RequestInitiator {
    pub fn as_str(&self) -> &'static str {
        match self {
            RequestInitiator::Navigate => "navigate",
            RequestInitiator::Form => "form",
            RequestInitiator::Xhr => "xhr",
            RequestInitiator::Fetch => "fetch",
        }
    }
}

impl fmt::Display for RequestInitiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for RequestInitiator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RequestInitiator {
    fn deserialize<D>(deserializer: D) -> Result<RequestInitiator, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse::<RequestInitiator>()
            .map_err(serde::de::Error::custom)
    }
}

impl FromStr for RequestInitiator {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match_ignore_ascii_case_str! {
            match (s) {
                "navigate" => Ok(RequestInitiator::Navigate),
                "form" => Ok(RequestInitiator::Form),
                "xhr" => Ok(RequestInitiator::Xhr),
                "fetch" => Ok(RequestInitiator::Fetch),
                _ => Err(OpaqueError::from_display(format!("invalid request initiator: {}", s))),
            }
        }
    }
}

#[cfg(test)]
mod parse_tests;
