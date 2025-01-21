use rama_core::error::OpaqueError;
use rama_http_types::proto::h2::PseudoHeader;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "memory-db", derive(venndb::VennDB))]
pub struct HttpProfile {
    #[cfg_attr(feature = "memory-db", venndb(key))]
    pub ja4h: String,
    pub http_headers: Vec<(String, String)>,
    pub http_pseudo_headers: Vec<PseudoHeader>,
    #[cfg_attr(feature = "memory-db", venndb(filter))]
    pub fetch_mode: Option<FetchMode>,
    #[cfg_attr(feature = "memory-db", venndb(filter))]
    pub resource_type: Option<FetchMode>,
    #[cfg_attr(feature = "memory-db", venndb(filter))]
    pub initiator: Option<Initiator>,
    #[cfg_attr(feature = "memory-db", venndb(filter))]
    pub http_version: Option<HttpVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum FetchMode {
    Cors,
    Navigate,
    NoCors,
    SameOrigin,
    Websocket,
}

impl std::fmt::Display for FetchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cors => write!(f, "cors"),
            Self::Navigate => write!(f, "navigate"),
            Self::NoCors => write!(f, "no-cors"),
            Self::SameOrigin => write!(f, "same-origin"),
            Self::Websocket => write!(f, "websocket"),
        }
    }
}

impl FromStr for FetchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cors" => Ok(Self::Cors),
            "navigate" => Ok(Self::Navigate),
            "no-cors" => Ok(Self::NoCors),
            "same-origin" => Ok(Self::SameOrigin),
            "websocket" => Ok(Self::Websocket),
            _ => Err(s.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum ResourceType {
    Document,
    Xhr,
    Form,
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Document => write!(f, "document"),
            Self::Xhr => write!(f, "xhr"),
            Self::Form => write!(f, "form"),
        }
    }
}

impl FromStr for ResourceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "document" => Ok(Self::Document),
            "xhr" => Ok(Self::Xhr),
            "form" => Ok(Self::Form),
            _ => Err(s.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub enum HttpVersion {
    H1,
    H2,
    H3,
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
