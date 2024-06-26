//! This module contains the [`DnsResolveModeLayer`] and [`DnsResolveMode`] types.
//!
//! These types can be used to opt-in for eager DNS resolution,
//! which will resolve domain names to IP addresses even when not needed.
//! For example resolving them to make a connection to a target server over a proxy
//! by IP address instead of domain name.

use crate::error::{ErrorExt, OpaqueError};
use crate::http::HeaderValue;
use std::fmt;

mod service;
#[doc(inline)]
pub use service::DnsResolveModeService;

mod layer;
#[doc(inline)]
pub use layer::DnsResolveModeLayer;

mod username_parser;
#[doc(inline)]
pub use username_parser::DnsResolveModeUsernameParser;

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A vanity [`Extensions`] type for others to easily check if eager DNS resolution is enabled.
///
/// [`Extensions`]: crate::service::context::Extensions
pub struct DnsResolveMode(ResolveMode);

impl fmt::Display for DnsResolveMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            ResolveMode::Eager => write!(f, "eager"),
            ResolveMode::Lazy => write!(f, "lazy"),
        }
    }
}

impl DnsResolveMode {
    /// Creates a new "eager" resolve mod
    pub const fn eager() -> Self {
        Self(ResolveMode::Eager)
    }

    /// Creates a new "lazy" resolve mode
    pub const fn lazy() -> Self {
        Self(ResolveMode::Lazy)
    }

    /// Returns `true` if the [`DnsResolveMode`] is "eager".
    pub fn is_eager(&self) -> bool {
        match self.0 {
            ResolveMode::Eager => true,
            ResolveMode::Lazy => false,
        }
    }

    /// Returns `true` if the [`DnsResolveMode`] is "lazy".
    pub fn is_lazy(&self) -> bool {
        match self.0 {
            ResolveMode::Eager => false,
            ResolveMode::Lazy => true,
        }
    }
}

impl std::str::FromStr for DnsResolveMode {
    type Err = OpaqueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value)
    }
}

impl TryFrom<&str> for DnsResolveMode {
    type Error = OpaqueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match_ignore_ascii_case_str! {
            match (value) {
                "eager" => Ok(DnsResolveMode::eager()),
                "lazy" => Ok(DnsResolveMode::lazy()),
                _ => Err(OpaqueError::from_display("Invalid DNS resolve mode: unknown str")),
            }
        }
    }
}

impl TryFrom<&HeaderValue> for DnsResolveMode {
    type Error = OpaqueError;

    fn try_from(value: &HeaderValue) -> Result<Self, Self::Error> {
        match value.to_str() {
            Ok(value) => Self::try_from(value),
            Err(err) => Err(err.context("Invalid DNS resolve mode")),
        }
    }
}

#[derive(Debug, Clone, Default, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ResolveMode {
    Eager,
    #[default]
    Lazy,
}
