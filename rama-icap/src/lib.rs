//! ICAP (Internet Content Adaptation Protocol) implementation according to RFC 3507.
//! 
//! This module provides support for the ICAP protocol, which allows HTTP messages to be 
//! adapted/transformed by an ICAP server.

pub mod body;
pub mod proto;
pub mod client;
mod common;
mod error;
pub use self::error::{Error, Result};
/* use thiserror::Error;
use bytes::Bytes;
use futures_core::Stream;

/// Default ICAP port as specified in RFC 3507
pub const DEFAULT_ICAP_PORT: u16 = 1344;

/// Error types that can occur in ICAP operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid HTTP header value")]
    InvalidHeaderValue,
    #[error("Invalid HTTP header name")]
    InvalidHeaderName,
    #[error("Invalid ICAP version: {0}")]
    InvalidVersion(String),
    #[error("Invalid ICAP method: {0}")]
    InvalidMethod(String),
    #[error("Invalid status code")]
    InvalidStatus,
    #[error("Invalid ICAP message format: {0}")]
    InvalidFormat(String),
    #[error("Invalid encapsulated header: {0}")]
    InvalidEncapsulated(String),
    #[error("Missing required header: {0}")]
    MissingHeader(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
}

/// Result type for ICAP operations
pub type Result<T> = std::result::Result<T, Error>;

/// ICAP version string
pub const ICAP_VERSION: &str = "ICAP/1.0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Options,
    ReqMod,
    RespMod,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Options => "OPTIONS",
            Method::ReqMod => "REQMOD",
            Method::RespMod => "RESPMOD",
        }
    }

    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            Method::Options => b"OPTIONS",
            Method::ReqMod => b"REQMOD",
            Method::RespMod => b"RESPMOD",
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Options => write!(f, "OPTIONS"),
            Method::ReqMod => write!(f, "REQMOD"),
            Method::RespMod => write!(f, "RESPMOD"),
        }
    }
}


#[derive(Debug)]
pub struct ChunkedBody {
    body: Body,
    is_preview: bool,
    preview_size: usize,
    is_ieof: bool,
}

impl ChunkedBody {
    pub fn new(body: Body, is_preview: bool, preview_size: usize) -> Self {
        Self {
            body,
            is_preview,
            preview_size,
            is_ieof: false,
        }
    }

    pub fn from_stream<S>(stream: S, is_preview: bool, preview_size: usize) -> Self
    where
        S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
    {
        Self::new(Body::from_stream(stream), is_preview, preview_size)
    }

    pub fn set_ieof(&mut self, ieof: bool) {
        self.is_ieof = ieof;
    }

    pub fn is_preview(&self) -> bool {
        self.is_preview
    }

    pub fn preview_size(&self) -> usize {
        self.preview_size
    }

    pub fn is_ieof(&self) -> bool {
        self.is_ieof
    }

    pub fn into_stream(self) -> BodyDataStream {
        self.body.into_data_stream()
    }

    pub fn limited(self, limit: usize) -> Self {
        Self {
            body: self.body.limited(limit),
            is_preview: self.is_preview,
            preview_size: self.preview_size,
            is_ieof: self.is_ieof,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IcapHeaderName(String);

impl IcapHeaderName {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(Error::Protocol("Header name cannot be empty".to_string()));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for IcapHeaderName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

 */