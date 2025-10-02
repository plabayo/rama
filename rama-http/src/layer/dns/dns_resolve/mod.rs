//! This module contains the [`DnsResolveModeLayer`] and [`DnsResolveMode`] types.
//!
//! These types can be used to opt-in for eager DNS resolution,
//! which will resolve domain names to IP addresses even when not needed.
//! For example resolving them to make a connection to a target server over a proxy
//! by IP address instead of domain name.

use crate::HeaderValue;
use rama_core::error::{ErrorExt, OpaqueError};
use rama_core::username::{ComposeError, Composer, UsernameLabelWriter};
use rama_utils::macros::match_ignore_ascii_case_str;
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
/// [`Extensions`]: rama_core::extensions::Extensions
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
    #[must_use]
    pub const fn eager() -> Self {
        Self(ResolveMode::Eager)
    }

    /// Creates a new "lazy" resolve mode
    #[must_use]
    pub const fn lazy() -> Self {
        Self(ResolveMode::Lazy)
    }

    /// Returns `true` if the [`DnsResolveMode`] is "eager".
    #[must_use]
    pub fn is_eager(&self) -> bool {
        match self.0 {
            ResolveMode::Eager => true,
            ResolveMode::Lazy => false,
        }
    }

    /// Returns `true` if the [`DnsResolveMode`] is "lazy".
    #[must_use]
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
                "eager" => Ok(Self::eager()),
                "lazy" => Ok(Self::lazy()),
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

impl<const SEPARATOR: char> UsernameLabelWriter<SEPARATOR> for DnsResolveMode {
    fn write_labels(&self, composer: &mut Composer<SEPARATOR>) -> Result<(), ComposeError> {
        composer.write_label("dns")?;
        match self.0 {
            ResolveMode::Eager => composer.write_label("eager"),
            ResolveMode::Lazy => composer.write_label("lazy"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::Extensions;
    use rama_core::username::{compose_username, parse_username};

    #[test]
    fn parse_username_label_compose_parse_dns_resolve_mode() {
        let test_cases = [DnsResolveMode::eager(), DnsResolveMode::lazy()];
        for test_case in test_cases {
            let fmt_username = compose_username("john".to_owned(), test_case).unwrap();
            let mut ext = Extensions::new();
            let username = parse_username(
                &mut ext,
                DnsResolveModeUsernameParser::default(),
                fmt_username,
            )
            .unwrap();
            assert_eq!("john", username);
            let result = ext.get::<DnsResolveMode>().unwrap();
            assert_eq!(test_case, *result);
        }
    }
}
