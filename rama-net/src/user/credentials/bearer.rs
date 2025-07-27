use rama_core::error::OpaqueError;
use std::{borrow::Cow, fmt, str::FromStr};

use crate::user::authority::StaticAuthorizer;

#[derive(Clone, PartialEq, Eq)]
/// Bearer credentials.
pub struct Bearer(Cow<'static, str>);

impl fmt::Debug for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Bearer").field(&"***").finish()
    }
}

impl Bearer {
    /// Try to create a [`Bearer`] from a [`String`].
    ///
    /// Returns an error in case the token contains non-visible ASCII chars.
    pub fn new(s: impl Into<String>) -> Result<Self, OpaqueError> {
        let s = s.into();
        if s.is_empty() {
            return Err(OpaqueError::from_display(
                "empty str cannot be used as Bearer",
            ));
        }
        if s.as_bytes().iter().any(|b| *b < 32 || *b >= 127) {
            return Err(OpaqueError::from_display(
                "string contains non visible ASCII characters",
            ));
        }

        Ok(Self(s.into()))
    }

    /// Try to create a [`Bearer`] from a [`&'static str`][str].
    ///
    /// # Panic
    ///
    /// Panics in case the token contains non-visible ASCII chars.
    #[must_use]
    pub fn new_static(s: &'static str) -> Self {
        if s.is_empty() {
            panic!("empty str cannot be used as Bearer");
        }
        let mut i = 0;
        let bytes = s.as_bytes();
        while i < bytes.len() {
            if bytes[i] < 32 || bytes[i] >= 127 {
                panic!("string contains non visible ASCII characters");
            }
            i += 1;
        }
        Self(s.into())
    }

    /// View the token part as a `&str`.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.0
    }

    /// Turn itself into a [`StaticAuthorizer`], so it can be used to authorize.
    ///
    /// Just a shortcut, QoL.
    #[must_use]
    pub fn into_authorizer(self) -> StaticAuthorizer<Self> {
        StaticAuthorizer::new(self)
    }
}

impl TryFrom<&str> for Bearer {
    type Error = OpaqueError;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_owned())
    }
}

impl TryFrom<String> for Bearer {
    type Error = OpaqueError;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl FromStr for Bearer {
    type Err = OpaqueError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl fmt::Display for Bearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
