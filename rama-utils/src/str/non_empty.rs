use crate::str::arcstr::ArcStr;
use std::{fmt, ops::Deref};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A read-only string which can never be empty.
pub struct NonEmptyStr(ArcStr);

impl NonEmptyStr {
    /// Create a new [`NonEmptyStr`] without checking if it's empty or not.
    ///
    /// # Safety
    ///
    /// Callee guarantees the given ArcStr is empty.
    ///
    /// Usually this is not what you want, but it can be userful to have
    /// in cases where you already have an [`ArcStr`] and have checked that
    /// it is not empty. Examples are cases where you decoded data from the wire,
    /// or constructed it at compile time with a literal that you length checked.
    #[must_use]
    pub const unsafe fn new_unchecked(s: ArcStr) -> Self {
        Self(s)
    }
}

impl AsRef<str> for NonEmptyStr {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl Deref for NonEmptyStr {
    type Target = str;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

crate::macros::error::static_str_error! {
    #[doc = "empty string"]
    pub struct EmptyStrErr;
}

/// Create a [`NonEmptyStr`] at compile time from a literal
///
/// # Panics
///
/// Panics in case the literal is empty.
#[macro_export]
#[doc(hidden)]
macro_rules! __non_empty_str {
    ($text:expr $(,)?) => {{
        if ($text).is_empty() {
            panic!("literal is empty");
        }
        // SAFETY: above check satisfied the contract
        unsafe { $crate::str::NonEmptyStr::new_unchecked($crate::str::arcstr::arcstr!($text)) }
    }};
}

impl fmt::Display for NonEmptyStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<NonEmptyStr> for String {
    fn from(value: NonEmptyStr) -> Self {
        value.0.to_string()
    }
}

impl TryFrom<String> for NonEmptyStr {
    type Error = EmptyStrErr;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Self::Error::default())
        } else {
            Ok(Self(value.into()))
        }
    }
}

impl TryFrom<ArcStr> for NonEmptyStr {
    type Error = EmptyStrErr;

    fn try_from(value: ArcStr) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Self::Error::default())
        } else {
            Ok(Self(value))
        }
    }
}

impl TryFrom<&String> for NonEmptyStr {
    type Error = EmptyStrErr;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Self::Error::default())
        } else {
            Ok(Self(value.into()))
        }
    }
}

impl TryFrom<&str> for NonEmptyStr {
    type Error = EmptyStrErr;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Self::Error::default())
        } else {
            Ok(Self(value.into()))
        }
    }
}

impl std::str::FromStr for NonEmptyStr {
    type Err = EmptyStrErr;

    #[inline(always)]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl PartialEq<str> for NonEmptyStr {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<String> for NonEmptyStr {
    fn eq(&self, other: &String) -> bool {
        self.0.as_str() == other
    }
}

impl PartialEq<&String> for NonEmptyStr {
    fn eq(&self, other: &&String) -> bool {
        self.0.as_str() == *other
    }
}

impl PartialEq<&str> for NonEmptyStr {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<NonEmptyStr> for str {
    fn eq(&self, other: &NonEmptyStr) -> bool {
        other == self
    }
}

impl PartialEq<NonEmptyStr> for String {
    fn eq(&self, other: &NonEmptyStr) -> bool {
        other == self
    }
}

impl PartialEq<NonEmptyStr> for &String {
    #[inline(always)]
    fn eq(&self, other: &NonEmptyStr) -> bool {
        other == *self
    }
}

impl PartialEq<NonEmptyStr> for &str {
    #[inline(always)]
    fn eq(&self, other: &NonEmptyStr) -> bool {
        other == *self
    }
}

impl serde::Serialize for NonEmptyStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for NonEmptyStr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = ArcStr::deserialize(deserializer)?;
        if s.is_empty() {
            return Err(serde::de::Error::custom(EmptyStrErr::default()));
        }
        Ok(Self(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_try_into_err(src: impl TryInto<NonEmptyStr>) {
        assert!(src.try_into().is_err());
    }

    #[cfg(not(loom))]
    fn assert_try_into_ok<S>(src: S)
    where
        S: TryInto<NonEmptyStr, Error: std::error::Error>
            + fmt::Debug
            + Clone
            + PartialEq<NonEmptyStr>,
    {
        let expected = src.clone();
        let value: NonEmptyStr = src.try_into().unwrap();
        assert_eq!(expected, value);
    }

    #[test]
    fn test_non_empty_string_construction_failure() {
        assert_try_into_err("");
        assert_try_into_err(String::from(""));
        #[allow(clippy::needless_borrows_for_generic_args)]
        assert_try_into_err(&String::from(""));
    }

    #[test]
    #[cfg(not(loom))]
    fn test_non_empty_string_construction_success() {
        assert_try_into_ok("a");
        assert_try_into_ok(String::from("b"));
        #[allow(clippy::needless_borrows_for_generic_args)]
        assert_try_into_ok(&String::from("c"));
    }

    #[test]
    #[cfg(not(loom))]
    fn test_serde_json_compat() {
        let source = r##"{"greeting": "Hello", "language": "en"}"##.to_owned();

        #[derive(Debug, serde::Deserialize)]
        struct Test {
            greeting: NonEmptyStr,
            language: NonEmptyStr,
        }

        let test: Test = serde_json::from_str(&source).unwrap();
        assert_eq!("Hello", test.greeting);
        assert_eq!("en", test.language);
    }
}
