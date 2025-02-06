use highway::HighwayHasher;
use rama_core::error::OpaqueError;
use rama_http_types::proto::h2::PseudoHeader;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, hash::{Hash as _, Hasher as _}, str::FromStr};

use crate::{PlatformKind, UserAgentKind};

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub struct UserAgentHttpProfile {
    pub ua_kind: UserAgentKind,
    pub ua_kind_version: usize,
    pub platform_kind: PlatformKind,
    pub http: HttpProfile,
}

impl UserAgentHttpProfile {
    pub fn key(&self) -> u64 {
        let mut hasher = HighwayHasher::default();
        self.hash(&mut hasher);
        hasher.finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Hash)]
pub struct HttpProfile {
    pub ja4h: String,
    pub http_headers: Vec<(String, String)>,
    pub http_pseudo_headers: Vec<PseudoHeader>,
    pub initiator: Initiator,
    pub http_version: HttpVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum Initiator {
    Navigator,
    Fetch,
    XMLHttpRequest,
    Form,
}

impl std::fmt::Display for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Navigator => write!(f, "navigator"),
            Self::Fetch => write!(f, "fetch"),
            Self::XMLHttpRequest => write!(f, "xmlhttprequest"),
            Self::Form => write!(f, "form"),
        }
    }
}

impl FromStr for Initiator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "navigator" => Ok(Self::Navigator),
            "fetch" => Ok(Self::Fetch),
            "xmlhttprequest" => Ok(Self::XMLHttpRequest),
            "form" => Ok(Self::Form),
            _ => Err(s.to_owned()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpVersion {
    H1,
    H2,
    H3,
}

impl HttpVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::H1 => "http/1",
            Self::H2 => "h2",
            Self::H3 => "h3",
        }
    }
}

impl FromStr for HttpVersion {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_lowercase().as_str() {
            "h1" | "http1" | "http/1" | "http/1.0" | "http/1.1" => Self::H1,
            "h2" | "http2" | "http/2" | "http/2.0" => Self::H2,
            "h3" | "http3" | "http/3" | "http/3.0" => Self::H3,
            version => {
                return Err(OpaqueError::from_display(format!(
                    "unsupported http version: {version}"
                )))
            }
        })
    }
}

impl Serialize for HttpVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HttpVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        let s = <Cow<'de, str>>::deserialize(deserializer)?;
        HttpVersion::from_str(&s).map_err(serde::de::Error::custom)
    }
}

