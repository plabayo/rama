use crate::headers::ClientHint;
use rama_error::OpaqueError;
use rama_utils::macros::match_ignore_ascii_case_str;
use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
/// Runtime hint to request a user agent to be preserved,
/// useful for systems that modify requests based on the context and request,
/// but still wish to support preserving the original header user-agent.
pub struct PreserveHeaderUserAgent;

impl PreserveHeaderUserAgent {
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }
}

/// ClientHints requested for the (http) Request.
pub type RequestClientHints = Vec<ClientHint>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// The initiator of the (http) Request.
pub enum RequestInitiator {
    /// normal navigate
    Navigate,
    /// form action
    Form,
    /// XML Http Request (Original Ajax tech in browsers), to fetch content from (Js) scripts
    Xhr,
    /// Fetch API ("Modern" async-able approach to fetch content from (Js) scripts)
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
